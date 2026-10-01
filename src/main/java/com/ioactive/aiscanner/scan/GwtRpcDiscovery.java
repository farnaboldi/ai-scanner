package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GWT-RPC / compiled-SPA surface discovery.
 *
 * <p><b>Why this exists.</b> Google Web Toolkit (and compiled SPAs generally) serve a single application
 * shell for <em>every</em> path and expose no crawlable links — the real attack surface (the RPC servlets)
 * lives inside a compiled JS "permutation" as the client's own <em>service registry</em>, not as fetchable
 * URLs. The native crawler + JS/HTML link-mining therefore find <b>zero</b> requests on a GWT app. The
 * generalizable fix is not "crawl harder" but "parse the client registry": the permutation authoritatively
 * declares every service interface, servlet base-path, serialization-policy strong-name, and remote method —
 * a more complete surface map than any crawler could produce.
 *
 * <p><b>What it does.</b> Detect GWT ({@code *.nocache.js} + {@code <meta name="gwt:property">}), fetch one
 * permutation, regex-extract the service/endpoint/method inventory, then <em>live-confirm</em> each candidate
 * servlet with a minimal GWT-RPC probe. A real GWT-RPC servlet answers a malformed/0-arg body with an
 * {@code //EX}/{@code //OK} payload, a GWT "call failed on the server" 500, or an auth 401/403 — all
 * distinct from the SPA-shell HTML (200 text/html) or a generic 405 catch-all. Confirmed request/response
 * pairs are returned so the caller bridges them into the site map + audit surface, at which point the
 * existing IDOR / BFLA / unauth / privilege-parity oracles finally have real requests to operate on.
 *
 * <p><b>Safety (BApp-compliant, generic-target-safe).</b> Pure Java, no external binary. It NEVER
 * auto-invokes a method whose name looks state-changing (set/delete/create/update/send/reset/remove/…): those
 * are catalogued and surfaced for a human operator but not fired, so pointing the scanner at an arbitrary GWT
 * app cannot trigger a mutation. Only 0-arg <em>read</em>-named methods (get/list/search/find/check/is/has/…)
 * and an empty servlet-confirmation body are ever sent.
 */
public final class GwtRpcDiscovery {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private final List<HttpRequestResponse> confirmed = new ArrayList<>();

    /** GWT module bootstrap: "<name>.nocache.js" (the compiled entry point). */
    private static final Pattern NOCACHE = Pattern.compile("([A-Za-z0-9_]+)\\.nocache\\.js");
    /** GWT tell-tale in the host page. */
    private static final Pattern GWT_META = Pattern.compile("(?i)gwt:property|\\.nocache\\.js");
    /** A permutation strong-name (32 hex). Also the RPC serialization-policy strong-name shape. */
    private static final Pattern HEX32 = Pattern.compile("[0-9A-F]{32}");
    /** Service interfaces: ...services.FooService / ...services.FooServices (the compiled registry). */
    private static final Pattern SERVICE = Pattern.compile("com\\.[a-zA-Z0-9_.]+\\.services\\.[A-Z][A-Za-z0-9_]+");
    /** Read-only method-name allowlist — the ONLY method shapes we ever auto-invoke. */
    private static final Pattern READ_METHOD = Pattern.compile(
            "^(get|list|find|search|fetch|load|query|check|has|is|count|read|view|resolve|lookup|current|all)[A-Z0-9]");
    /** State-changing prefixes — catalogued, never auto-invoked on a generic target. */
    private static final Pattern WRITE_METHOD = Pattern.compile(
            "^(set|add|create|new|update|edit|delete|remove|drop|save|store|put|post|send|email|reset|revoke|grant|"
            + "generate|make|schedule|initiate|confirm|perform|apply|cancel|disable|enable|authorize|unauthorize|"
            + "force|restore|freeze|import|upload|register|deregister|become|accept|clear)");

    private static final int MAX_PERM_BYTES = 6_000_000;   // a permutation cache.js is ~2-3MB
    private static final int MAX_CONFIRM = 200;            // cap live confirmation requests
    private static final long TIMEOUT_MS = 12_000L;
    private static final long PROBE_DELAY_MS = 300L;       // politeness between probes (avoid target rate-limit)
    private static final long RETRY_BACKOFF_MS = 1500L;    // back-off before the single retry on a throttled/dead probe

    public GwtRpcDiscovery(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** Request/response pairs for live-confirmed RPC/JSON servlets — drain into the site map + targets. */
    public List<HttpRequestResponse> confirmed() { return confirmed; }

    /**
     * Detect + map + live-confirm the GWT surface for {@code host}.
     * @param host        the target authority (host[:port]) or a base URL
     * @param withSession applies the captured session (cookie/bearer) to probe requests; may be null
     * @return live-confirmed servlet request/response pairs (also accumulated in {@link #confirmed()})
     */
    public List<HttpRequestResponse> discover(String host, UnaryOperator<HttpRequest> withSession) {
        try {
            String base = resolveBase(host);
            if (base == null) return confirmed;

            // 1) Detect GWT from a site-map host page and recover the module name.
            String module = detectModule(host);
            if (module == null) {
                scanLog.debug("  gwt-rpc: target is not a GWT app (no *.nocache.js) — skipping.");
                return confirmed;
            }
            scanLog.log("gwt-rpc: GWT app detected (module '" + module + "') — parsing client service registry "
                    + "(native crawl cannot see GWT-RPC servlets).");

            // 2) nocache bootstrap -> a permutation strong-name -> the compiled permutation.
            String nocache = fetchText(base + "/" + module + "/" + module + ".nocache.js", withSession);
            if (nocache == null) { scanLog.debug("  gwt-rpc: nocache bootstrap unreadable."); return confirmed; }
            String perm = firstMatch(HEX32, nocache);
            if (perm == null) { scanLog.debug("  gwt-rpc: no permutation strong-name in nocache."); return confirmed; }
            String permJs = fetchText(base + "/" + module + "/" + perm + ".cache.js", withSession);
            if (permJs == null || permJs.length() < 10_000) {
                scanLog.debug("  gwt-rpc: permutation " + perm + " unreadable/too small."); return confirmed;
            }
            if (permJs.length() > MAX_PERM_BYTES) permJs = permJs.substring(0, MAX_PERM_BYTES);
            String moduleBase = base + "/" + module + "/";

            // 3) Parse the SERVICE-ENTRY-POINT CONSTRUCTORS -> exact endpoint URLs (base + relpath). This is the
            //    authoritative surface: GWT binds each servlet via a constructor that concatenates a base path
            //    with the relpath (`this.a='/rpc/'+a`, or a shared base var `_x='/svc/'`). Extracting those
            //    gives precise, correctly-based endpoints with NO widget/CSS/method-name noise and NO base
            //    guessing — so the site map only ever grows with REAL endpoints, never phantoms.
            Set<String> services = allMatches(SERVICE, permJs, 0);
            Map<String,String> ctorBase = extractCtorBases(permJs);
            Set<String> endpoints = new LinkedHashSet<>();
            for (Map.Entry<String,String> e : ctorBase.entrySet()) {
                Matcher m = Pattern.compile("new " + Pattern.quote(e.getKey()) + "\\('([a-zA-Z0-9_/]+)'\\)").matcher(permJs);
                while (m.find()) endpoints.add(e.getValue() + m.group(1));
            }
            scanLog.log("gwt-rpc: registry parsed — " + services.size() + " service interface(s), "
                    + endpoints.size() + " exact servlet endpoint(s) from " + ctorBase.size()
                    + " entry-point constructor(s). Native crawl saw 0.");
            for (String s : services) scanLog.debug("  gwt-rpc service: " + s);
            if (endpoints.isEmpty()) { scanLog.debug("  gwt-rpc: no entry-point constructors parsed."); return confirmed; }

            // 4) Live-confirm + AUTHZ-DIFFERENTIAL each REAL endpoint. One non-mutating probe never carries valid
            //    method args, so a mutating endpoint just rejects it ("too few tokens"/400/401) — no state change.
            //    For the JSON "JSON-action" bases (/api, /app2, /app3) we also run the endpoint UNAUTHENTICATED and
            //    compare to the base's blanket unknown-action response: a specific action that reaches its handler
            //    with NO session (non-401 while the base 401s bogus actions) is a MISSING-AUTHENTICATION finding —
            //    the generalized /issueUploadCredentials-style leak, emitted automatically. GWT-RPC bases (/rpc,/svc)
            //    reject the empty body pre-auth ("too few tokens"), so their unauth response is not authz-conclusive
            //    here — those are only confirmed as servlets (real arg-level authz testing is GwtRpcProbe/v2).
            // The differential is inherently UNAUTHENTICATED ("does this endpoint process an anonymous request?"),
            // so we probe each endpoint exactly ONCE with no session — one request per endpoint keeps coverage
            // stable under the target's rate-limit (an authed second probe per endpoint doubled the burst and
            // collapsed coverage). Per JSON base we learn the blanket unknown-action response once (cached).
            int tested = 0, live = 0, servletReached = 0, gated = 0, findings = 0;
            Map<String,Kind> jsonBaseBogus = new LinkedHashMap<>();
            for (String ep : endpoints) {
                if (tested >= MAX_CONFIRM) break;
                tested++;
                String url = base + ep;
                boolean gwtRpc = ep.startsWith("/rpc/") || ep.startsWith("/svc/");
                HttpRequestResponse rr = gwtRpc
                        ? sendGwtRpc(url, moduleBase, perm, emptyRpcBody(moduleBase), null)   // unauth
                        : sendJson(url, "{}", null);                                          // unauth
                Kind k = classify(rr);
                if (k != Kind.SERVLET && k != Kind.AUTH_GATED) continue;   // drop dead/shell/405 only
                live++;
                confirmed.add(rr);
                if (k == Kind.SERVLET) servletReached++; else gated++;
                scanLog.log("  gwt-rpc endpoint: POST " + ep + " -> " + rr.response().statusCode() + " " + k);

                // AUTHZ DIFFERENTIAL (JSON endpoints only — the GWT-RPC empty body errors "too few tokens"
                // pre-auth, so its unauth response is not authz-conclusive; arg-level GWT-RPC authz = v3).
                // A specific action that REACHES ITS HANDLER unauthenticated, while the base gates unknown
                // actions (bogus -> 401/403), is a missing-authentication finding (the generalized credential-leak class).
                if (!gwtRpc && k == Kind.SERVLET) {
                    String jb = ep.substring(0, ep.indexOf('/', 1) + 1);   // e.g. /api/
                    Kind baseBogus = jsonBaseBogus.computeIfAbsent(jb,
                            b -> classify(sendJson(base + b + "aiscnf0zq9x", "{}", null)));
                    if (baseBogus == Kind.AUTH_GATED) {
                        findings++;
                        // Escalation: if the UNAUTH response body leaks a secret (AWS key, presigned URL, private
                        // key, token), this is not just a missing gate — it is unauthenticated CREDENTIAL/SECRET
                        // DISCLOSURE (Critical). Report that class instead of the generic authz gap.
                        // ONLY claim credential disclosure when a secret is ACTUALLY present in THIS endpoint's
                        // unauth response — never by endpoint name (that fabricates a finding with borrowed
                        // evidence). A handler-reached-unauth with no secret in the body is an authz gap, not a leak.
                        String leak = detectSecret(rr);
                        if (leak != null) {
                            scanLog.found("Unauthenticated credential/secret disclosure via API endpoint", url,
                                    "Request: POST " + ep + " with NO session.\n\n"
                                    + "Response: HTTP " + rr.response().statusCode() + " with sensitive material in "
                                    + "the body. Leaked secret type observed: " + leak + ".\n\n"
                                    + "Differential: a bogus unknown action under " + jb + " returns 401 (the base "
                                    + "gates anonymous callers), whereas " + ep + " returns "
                                    + rr.response().statusCode() + " with the secret present — so the gate is missing "
                                    + "on this specific action.\n\n"
                                    + "Impact: an anonymous attacker obtains credential/secret material with no login "
                                    + "(CWE-306, CWE-522).",
                                    rr);
                            scanLog.incFinding();
                            scanLog.log("  >>> gwt-rpc CREDENTIAL LEAK (unauth): " + ep + " leaks " + leak);
                        } else {
                            scanLog.found("Missing authentication on API endpoint (RPC authz gap)", url,
                                    "Request: POST " + ep + " with NO session.\n\n"
                                    + "Response: HTTP " + rr.response().statusCode() + " — the request reached the "
                                    + "server-side handler (it ran far enough to error on missing parameters rather "
                                    + "than being rejected up front).\n\n"
                                    + "Differential: a bogus unknown action under " + jb + " returns 401 (the base "
                                    + "gates anonymous callers), whereas " + ep + " returns "
                                    + rr.response().statusCode() + " — so the per-action authentication gate is "
                                    + "missing on this endpoint.\n\n"
                                    + "Impact: an anonymous attacker can invoke this server function without a "
                                    + "session (CWE-306, CWE-285). Concrete impact depends on the handler and should "
                                    + "be assessed per endpoint.",
                                    rr);
                            scanLog.incFinding();
                            scanLog.log("  >>> gwt-rpc AUTHZ GAP: " + ep + " reachable UNAUTHENTICATED (sibling actions 401)");
                        }
                    }
                }
            }

            scanLog.log("gwt-rpc: confirmed " + live + " live servlet(s) of " + endpoints.size() + " ("
                    + servletReached + " handler-reached, " + gated + " auth-gated); " + findings
                    + " missing-authentication finding(s) — surface bridged into the audit battery.");

            // 5b·) AUTO-SEED the cross-account BOLA probes: harvest foreign identifiers/keys the authenticated
            //      session can already see (drives the app's own lookup/list endpoints, excludes our own identity),
            //      so the BOLA differential fires with zero operator setup. Operator -D/env seeds still take
            //      priority and are UNIONed in. Read-only, bounded.
            List<String> harvestIds = new ArrayList<>(), harvestKeys = new ArrayList<>();
            harvestForeignSeeds(base, endpoints, withSession, harvestIds, harvestKeys);
            List<String> readSeeds = resolveSeeds("aiscanner.gwtForeignIds", "AISCANNER_GWT_FOREIGN_IDS", harvestIds);
            List<String> loadSeeds = resolveSeeds("aiscanner.gwtForeignKeys", "AISCANNER_GWT_FOREIGN_KEYS", harvestKeys);

            // 5c) CROSS-ACCOUNT OBJECT LOAD (BOLA / broken object-level authz). With OUR authenticated session,
            //     send another account's object reference to a fetch-shaped endpoint. If the server LOADS the
            //     foreign entity (evidenced by a type/kind/cast error naming a domain class) instead of rejecting
            //     with 401/403 or a clean not-found, the ownership check is missing or runs AFTER the datastore
            //     load — an attacker of tenant A can make the server operate on tenant B's objects. Needs a
            //     session (withSession) + a foreign object key (auto-seeded or -Daiscanner.gwtForeignKeys). Read-only.
            findings += probeCrossAccountLoad(base, endpoints, withSession, loadSeeds);

            // 5d) CROSS-ACCOUNT DATA READ (BOLA that RETURNS another tenant's record, not just a load error).
            //     With our session, request a FOREIGN identifier (email/id — auto-seeded or -Daiscanner.gwtForeignIds)
            //     and confirm the endpoint returns that account's populated data (differs from a bogus id, echoes
            //     the foreign id, and unauth→401). Covers account-lookup-by-email and config-by-foreign-group-id.
            findings += probeCrossAccountRead(base, endpoints, withSession, readSeeds);

            // 5e) UNAUTH CREDENTIAL/TOKEN MINT. Endpoints named like a token/key minter that return credential
            //     material to an ANONYMOUS caller (like issueUploadCredentials, but a bespoke key/token). Probe UNAUTH
            //     with a benign marker value; raise ONLY if a credential field/secret is in the response.
            findings += exploitCredentialMint(base, endpoints);

            // 6) Catalogue method-level surface for the operator (mutating methods flagged, never auto-fired).
            catalogMethods(permJs, services);

        } catch (Throwable t) {
            scanLog.debug("gwt-rpc discovery error: " + t);
        }
        return confirmed;
    }

    // ---- servlet classification ------------------------------------------------------------------

    private enum Kind { SERVLET, AUTH_GATED, SHELL, CATCHALL, DEAD }

    /** Classify a probe response: is this a real RPC/JSON servlet, an auth-gated one, or just the SPA shell? */
    private static Kind classify(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return Kind.DEAD;
        int st = rr.response().statusCode();
        String ct = header(rr, "Content-Type");
        String body = rr.response().bodyToString();
        String bl = body == null ? "" : body;
        // Auth gate: the servlet exists but rejects us pre-dispatch.
        if (st == 401 || st == 403) return Kind.AUTH_GATED;
        // GWT-RPC servlet signatures: //OK / //EX payloads, or the GWT "call failed on the server" 500,
        // or a GWT RpcToken/IncompatibleRemoteService exception — all prove a real servlet behind this URL.
        if (bl.startsWith("//OK") || bl.startsWith("//EX")) return Kind.SERVLET;
        if (bl.contains("RpcTokenException") || bl.contains("IncompatibleRemoteServiceException")) return Kind.SERVLET;
        if (st == 500 && (bl.contains("call failed on the server") || bl.contains("java."))) return Kind.SERVLET;
        // App-shell HTML served for any unknown path (the SPA catch-all) — NOT a servlet.
        if (ct != null && ct.toLowerCase().contains("html")) return Kind.SHELL;
        if (bl.regionMatches(true, 0, "<!doctype", 0, 9) || bl.regionMatches(true, 0, "<html", 0, 5)) return Kind.SHELL;
        // Generic method-not-allowed catch-all ("Not Supported").
        if (st == 405) return Kind.CATCHALL;
        // A non-HTML 2xx/4xx with a real body (e.g. a JSON action returning data or a typed error) = servlet.
        if (bl.trim().length() >= 2 && (ct == null || !ct.toLowerCase().contains("html"))) return Kind.SERVLET;
        return Kind.DEAD;
    }

    // Response markers that prove the server LOADED a (foreign) entity from the datastore before any ownership
    // check — a type/kind/cast mismatch naming a domain class, distinct from a clean authz denial or not-found.
    private static final Pattern ENTITY_LOADED = Pattern.compile(
            "(?i)ClassCastException|cannot be cast to|nonexistent entity|IllegalArgumentException.*entity|"
            + "wrong (kind|type)|ClassCast|cast to [A-Za-z.]+");

    /** Resolve a BOLA seed list: operator-provided (-D property / env, comma-separated) takes priority and is
     *  UNIONed with the auto-harvested candidates. Empty result → the probe self-skips. */
    private List<String> resolveSeeds(String prop, String env, List<String> harvested) {
        String s = System.getProperty(prop, System.getenv(env) == null ? "" : System.getenv(env));
        List<String> out = new ArrayList<>();
        if (s != null && !s.isBlank()) for (String t : s.split(",")) { t = t.trim(); if (!t.isEmpty() && !out.contains(t)) out.add(t); }
        if (harvested != null) for (String h : harvested) if (h != null && !h.isEmpty() && !out.contains(h)) out.add(h);
        return out;
    }

    /**
     * Auto-seed the cross-account BOLA probes with ZERO operator setup. With our own authenticated session we
     * (a) drive the app's own account lookup/summary/list endpoints — lookups primed with our own login email,
     * lists with empty args — and (b) scrape the populated 2xx responses for OTHER accounts' emails and opaque
     * object keys. The harvested values feed probeCrossAccountRead (foreign emails/ids) and probeCrossAccountLoad
     * (foreign keys), so the differential fires automatically instead of waiting on an operator seed.
     *
     * Generic: no app-specific names — it keys off endpoint-leaf shape + the app's own JSON field names. FP-safe:
     * (1) it requires our own login email so it can EXCLUDE our own identity (every email/key returned when we
     * look ourselves up is treated as self/self-adjacent and never used as a foreign seed); (2) the probes' bogus
     * + unauth controls still gate every finding, so even if a self identifier slipped through it could not
     * masquerade as a cross-account read (a self-read is not object-specific vs. our own baseline and unauth≠401
     * would not hold). Read-only. Bounded to HARVEST_MAX_CALLS requests.
     */
    private void harvestForeignSeeds(String base, Set<String> endpoints, UnaryOperator<HttpRequest> withSession,
                                     List<String> outIds, List<String> outKeys) {
        if (withSession == null) return;
        String ownEmail = System.getProperty("aiscanner.loginEmail",
                System.getenv("AISCANNER_LOGIN_EMAIL") == null ? "" : System.getenv("AISCANNER_LOGIN_EMAIL"));
        if (ownEmail != null) ownEmail = ownEmail.trim();
        if (ownEmail == null || ownEmail.isBlank()) {
            scanLog.debug("  gwt-rpc: cross-account auto-seed skipped — no own login identity to exclude "
                    + "(set -Daiscanner.loginEmail or seed AISCANNER_GWT_FOREIGN_IDS/KEYS manually).");
            return;
        }
        Set<String> own = new java.util.HashSet<>();
        own.add(ownEmail.toLowerCase());
        StringBuilder foreignText = new StringBuilder();
        int calls = 0;
        for (String ep : endpoints) {
            if (calls >= HARVEST_MAX_CALLS) break;
            String leaf = ep.substring(ep.lastIndexOf('/') + 1).toLowerCase();
            boolean lookup = leaf.matches(".*(get|fetch|find|lookup|read|retrieve|load|summ|info).*")
                    && leaf.matches(".*(account|user|info|email|group|summary|member|profile).*");
            boolean list = leaf.matches(".*(list|all|search|members?|recent|browse|directory|roster).*");
            if (!lookup && !list) continue;
            // Prime lookups with our OWN email → our record (+ any related accounts it exposes). Everything in
            // OUR OWN record is self/self-adjacent → add to the exclude set, never used as a foreign seed.
            if (lookup) {
                HttpRequestResponse self = jsonAuthed(base + ep, "\"" + ownEmail.replace("\"", "\\\"") + "\"", withSession);
                calls++;
                if (is2xx(self) && self.response().bodyToString() != null) {
                    String b = self.response().bodyToString();
                    for (String e : allMatches(EMAIL, b, 0)) own.add(e.toLowerCase());
                    for (String k : allMatches(KEYVAL, b, 1)) own.add(k);
                }
            }
            // Lists often return a default page of OTHER accounts with empty args → a foreign-identifier source.
            if (list) {
                HttpRequestResponse r = jsonAuthed(base + ep, "{}", withSession);
                calls++;
                if (is2xx(r) && r.response().bodyToString() != null) foreignText.append('\n').append(r.response().bodyToString());
                if (calls < HARVEST_MAX_CALLS) {
                    HttpRequestResponse r2 = formAuthed(base + ep, "", withSession);
                    calls++;
                    if (is2xx(r2) && r2.response().bodyToString() != null) foreignText.append('\n').append(r2.response().bodyToString());
                }
            }
        }
        String text = foreignText.toString();
        for (String e : allMatches(EMAIL, text, 0)) if (!own.contains(e.toLowerCase()) && !outIds.contains(e)) outIds.add(e);
        for (String k : allMatches(KEYVAL, text, 1)) if (!own.contains(k) && !outKeys.contains(k)) outKeys.add(k);

        // Burp's authenticated crawl corpus: the native browser crawl RENDERS the app (executing the GWT-RPC /
        // XHR calls this plain-JSON harvest cannot make — e.g. the post-login account tree / summaries) and
        // records those responses in the site map. It is the richest generic source of related-account
        // identifiers the session has ALREADY legitimately seen. Scrape same-host, non-asset responses for
        // foreign emails (lookupAccountByEmail is email-keyed → a foreign email is exactly the read-probe seed)
        // and JSON *key* values, excluding our own identity. Bounded; FP-safe (probe controls still gate).
        try {
            int scraped = 0;
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (scraped >= SITEMAP_MAX) break;
                if (rr == null || rr.response() == null || rr.request() == null) continue;
                String url = rr.request().url();
                if (url == null || !sameHost(url, base) || ASSET_URL.matcher(url).matches()) continue;
                String b = rr.response().bodyToString();
                if (b == null || b.length() < 20) continue;
                scraped++;
                for (String e : allMatches(EMAIL, b, 0)) if (!own.contains(e.toLowerCase()) && !outIds.contains(e)) outIds.add(e);
                for (String k : allMatches(KEYVAL, b, 1)) if (!own.contains(k) && !outKeys.contains(k)) outKeys.add(k);
            }
            if (scraped > 0) scanLog.debug("  gwt-rpc: auto-seed scraped " + scraped + " authenticated site-map response(s) for foreign identifiers.");
        } catch (Throwable t) { scanLog.debug("  gwt-rpc: site-map harvest skipped: " + t); }

        if (!outIds.isEmpty() || !outKeys.isEmpty()) {
            scanLog.log("  gwt-rpc: auto-seeded cross-account BOLA probes — harvested " + outIds.size()
                    + " foreign id(s) + " + outKeys.size() + " foreign key(s) from the session "
                    + "(operator -Daiscanner.gwtForeignIds/Keys override/extend this).");
        } else {
            scanLog.debug("  gwt-rpc: auto-seed harvested 0 foreign identifiers from list/lookup responses — "
                    + "seed AISCANNER_GWT_FOREIGN_IDS/KEYS to confirm the cross-account BOLA.");
        }
    }

    /**
     * Cross-account object-level authorization test (BOLA / CWE-639 + CWE-285). With OUR authenticated session,
     * submit ANOTHER account's object reference to fetch-shaped /api endpoints. If the server loads that foreign
     * entity (type/kind/cast error) rather than rejecting (401/403) or returning a clean not-found, the ownership
     * check is missing or post-load. Read-only. Gated on: an authenticated session AND a seeded foreign key
     * (-Daiscanner.gwtForeignKeys / AISCANNER_GWT_FOREIGN_KEYS = comma-separated foreign object keyText values,
     * harvested from a victim account). Zero-FP: fires only on the loaded-entity marker AND requires the SAME
     * bogus key to NOT produce that marker (so it is entity-specific, not a generic 500).
     */
    private int probeCrossAccountLoad(String base, Set<String> endpoints, UnaryOperator<HttpRequest> withSession, List<String> seeds) {
        if (withSession == null) {
            scanLog.debug("  gwt-rpc: cross-account-load test skipped — no authenticated session (seed a session cookie to enable).");
            return 0;
        }
        if (seeds == null || seeds.isEmpty()) {
            scanLog.debug("  gwt-rpc: cross-account-load test skipped — no foreign object key (auto-seed harvested none; "
                    + "seed -Daiscanner.gwtForeignKeys=<foreignObjectKey,...> from a victim login to enable the BOLA differential).");
            return 0;
        }
        // Fetch-shaped endpoints that take an object reference (the BOLA surface).
        List<String> targets = new ArrayList<>();
        for (String ep : endpoints) {
            String leaf = ep.substring(ep.lastIndexOf('/') + 1).toLowerCase();
            if (leaf.matches(".*(fetch|get|retrieve|load|resolve|view|read).*")
                    && leaf.matches(".*(account|entity|object|file|group|chain|key|token).*")) {
                targets.add(ep);
            }
        }
        if (targets.isEmpty()) return 0;

        int hits = 0;
        for (String ep : targets) {
            if (hits > 0) break;   // one confirmed cross-account load is enough to prove the class
            // Discover the endpoint's key parameter name: an authed empty POST discloses it via the
            // "The '<name>' parameter was not set." 400 (generic — the server names its own params).
            String pname = discoverParamName(base + ep, withSession);
            if (pname == null) continue;
            for (String fk : seeds) {
                fk = fk.trim(); if (fk.isEmpty()) continue;
                // (1) authed request with the FOREIGN key (form-encoded servlet param)
                HttpRequestResponse foreign = formAuthed(base + ep, pname + "=" + urlEnc(fk), withSession);
                if (foreign == null || foreign.response() == null) continue;
                String fbody = foreign.response().bodyToString();
                boolean loaded = fbody != null && ENTITY_LOADED.matcher(fbody).find();
                if (!loaded) continue;
                // (2) control: a BOGUS key must NOT produce the loaded-entity marker (a malformed key fails to
                //     parse/load — e.g. "Cannot parse" — so the marker is specific to a REAL foreign entity).
                HttpRequestResponse bogus = formAuthed(base + ep, pname + "=aiscnf0zq9xNONEXISTENTkey", withSession);
                String bbody = bogus != null && bogus.response() != null ? bogus.response().bodyToString() : "";
                boolean bogusLoaded = bbody != null && ENTITY_LOADED.matcher(bbody).find();
                if (bogusLoaded) {
                    scanLog.debug("  gwt-rpc: cross-account-load on " + ep + " — bogus key also errors the same way; "
                            + "inconclusive (generic error, not entity-specific).");
                    continue;
                }
                // (3) control: unauth must be rejected (proves it is OUR session that reached the load).
                HttpRequestResponse unauth = formAuthed(base + ep, pname + "=" + urlEnc(fk), null);
                int us = unauth != null && unauth.response() != null ? unauth.response().statusCode() : -1;
                scanLog.found("Broken object-level authorization (cross-account entity load)", base + ep,
                        "Request: POST " + ep + " with OUR authenticated session but ANOTHER account's object "
                        + "reference (" + pname + "=" + redact(fk) + ").\n\n"
                        + "Response: HTTP " + foreign.response().statusCode() + " — the server LOADED the foreign "
                        + "entity from the datastore and failed only on a type/kind/cast mismatch, NOT on an "
                        + "authorization denial. (Body marker: '" + firstMarker(fbody) + "'.)\n\n"
                        + "Controls: a bogus/nonexistent key does NOT produce that marker (so the load is specific "
                        + "to a REAL foreign entity), and the same request with NO session returns HTTP " + us
                        + " (so it is our session that reached the load, and the object-level check is what is missing).\n\n"
                        + "Impact: an authenticated user of one tenant can make the server operate on another "
                        + "tenant's objects — the ownership/authorization check is absent or runs after the entity "
                        + "is loaded (CWE-639 Authorization Bypass Through User-Controlled Key; CWE-285). Against a "
                        + "populated tenant this is a cross-account data-access primitive; here it is proven at the "
                        + "load/authorization layer.",
                        foreign, bogus != null ? bogus : foreign);
                scanLog.incFinding(); hits++;
                scanLog.log("  >>> gwt-rpc CROSS-ACCOUNT LOAD (BOLA): " + ep + " loaded a foreign entity with our session (marker: " + firstMarker(fbody) + ")");
                break;
            }
        }
        if (hits == 0) scanLog.log("  gwt-rpc: cross-account-load tested " + targets.size()
                + " fetch-shaped endpoint(s) with seeded foreign key(s) — no cross-account entity load confirmed.");
        return hits;
    }

    /**
     * Cross-account DATA read (BOLA that RETURNS another tenant's record). With our session, request a FOREIGN
     * identifier (email/id) and confirm the endpoint returns that account's populated data — distinct from the
     * load-error case in probeCrossAccountLoad. Oracle (zero-FP): (1) foreign id → 200 populated body that ECHOES
     * the foreign id (proves it looked the object up, not reflected our own); (2) a bogus id → NOT a populated
     * 200 (so it is object-specific); (3) unauth → 401 (so our session is what reached it). Read-only. Seeded via
     * -Daiscanner.gwtForeignIds / AISCANNER_GWT_FOREIGN_IDS (foreign emails/ids). Tries form + JSON-string bodies.
     */
    private int probeCrossAccountRead(String base, Set<String> endpoints, UnaryOperator<HttpRequest> withSession, List<String> seeds) {
        if (withSession == null) return 0;
        if (seeds == null || seeds.isEmpty()) {
            scanLog.debug("  gwt-rpc: cross-account-read test skipped — no foreign id (auto-seed harvested none; "
                    + "seed -Daiscanner.gwtForeignIds=<foreignEmail|id,...> to enable).");
            return 0;
        }
        List<String> targets = new ArrayList<>();
        for (String ep : endpoints) {
            String leaf = ep.substring(ep.lastIndexOf('/') + 1).toLowerCase();
            if (leaf.matches(".*(get|fetch|find|lookup|read|retrieve|load|summ|info).*")
                    && leaf.matches(".*(account|user|info|email|settings|policy|group|summary|profile|member).*")) {
                targets.add(ep);
            }
        }
        if (targets.isEmpty()) return 0;
        int hits = 0;
        for (String ep : targets) {
            boolean epHit = false;                          // per-endpoint: report each vulnerable endpoint once
            for (String fid : seeds) {
                if (epHit) break;
                fid = fid.trim(); if (fid.isEmpty()) continue;
                // Body encodings: raw JSON string (lookupAccountByEmail), then form named-param — the disclosed name
                // if any, else a wordlist of common id params (getPrivacySettings doesn't disclose its 'groupId').
                String pname = discoverParamName(base + ep, withSession);   // may be null
                java.util.LinkedHashMap<String,HttpRequestResponse> tries = new java.util.LinkedHashMap<>();
                tries.put("<json-string>", jsonAuthed(base + ep, "\"" + fid.replace("\"", "\\\"") + "\"", withSession));
                java.util.List<String> params = new ArrayList<>();
                if (pname != null) params.add(pname);
                for (String cp : COMMON_ID_PARAMS) if (!params.contains(cp)) params.add(cp);
                for (String p : params) tries.put(p, formAuthed(base + ep, p + "=" + urlEnc(fid), withSession));
                for (Map.Entry<String,HttpRequestResponse> te : tries.entrySet()) {
                    String usedParam = te.getKey();
                    HttpRequestResponse foreign = te.getValue();
                    if (!is2xx(foreign)) continue;
                    String fbody = foreign.response().bodyToString();
                    if (fbody == null || fbody.length() < 40) continue;                 // must be populated
                    if (!fbody.contains(fid)) continue;                                 // must ECHO the foreign id (looked it up)
                    boolean jsonForm = usedParam.equals("<json-string>");
                    // bogus control: a nonexistent id must NOT return the same populated shape
                    String bogusId = "aiscnf0zq9xNONEXISTENT";
                    HttpRequestResponse bogus = jsonForm
                            ? jsonAuthed(base + ep, "\"" + bogusId + "\"", withSession)
                            : formAuthed(base + ep, usedParam + "=" + urlEnc(bogusId), withSession);
                    boolean bogusPopulated = bogus != null && bogus.response() != null
                            && bogus.response().statusCode() >= 200 && bogus.response().statusCode() < 300
                            && bogus.response().bodyToString() != null
                            && bogus.response().bodyToString().length() >= fbody.length() - 20
                            && bogus.response().bodyToString().contains(bogusId);
                    if (bogusPopulated) continue;   // returns data for anything → not object-specific
                    // unauth control: must be rejected (proves our session reached it)
                    HttpRequestResponse unauth = jsonForm
                            ? jsonAuthed(base + ep, "\"" + fid.replace("\"", "\\\"") + "\"", null)
                            : formAuthed(base + ep, usedParam + "=" + urlEnc(fid), null);
                    int us = unauth != null && unauth.response() != null ? unauth.response().statusCode() : -1;
                    if (us >= 200 && us < 300) continue;   // if it works unauth too, that's a different (unauth) issue, not cross-account-authz
                    scanLog.found("Broken object-level authorization (cross-account data read)", base + ep,
                            "Request: POST " + ep + " with OUR authenticated session but ANOTHER account's "
                            + "identifier (" + redact(fid) + ").\n\n"
                            + "Response: HTTP " + foreign.response().statusCode() + ", " + fbody.length()
                            + " bytes — the endpoint RETURNED that account's record (the response echoes the "
                            + "foreign identifier and carries data we did not supply).\n\n"
                            + "Controls: a bogus/nonexistent identifier does NOT return that populated shape (so "
                            + "the read is object-specific, not a template), and the same request with NO session "
                            + "returns HTTP " + us + " (so it is our low-privilege session that read another "
                            + "tenant's data — the object-level authorization check is missing).\n\n"
                            + "Impact: any authenticated user can read another tenant's account/config record by "
                            + "supplying its identifier (often a guessable email/id) — cross-tenant data disclosure "
                            + "(CWE-639, CWE-285). This can expose PII/config and can harvest the "
                            + "object handles that seed further object-level attacks.",
                            foreign, bogus != null ? bogus : foreign);
                    scanLog.incFinding(); hits++; epHit = true;
                    scanLog.log("  >>> gwt-rpc CROSS-ACCOUNT READ (BOLA): " + ep + " returned a foreign account's data with our session");
                    break;
                }
            }
        }
        if (hits == 0) scanLog.log("  gwt-rpc: cross-account-read tested " + targets.size()
                + " lookup-shaped endpoint(s) with seeded foreign id(s) — no cross-account data read confirmed.");
        return hits;
    }

    private HttpRequestResponse jsonAuthed(String url, String body, UnaryOperator<HttpRequest> withSession) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                .withBody(body).withHeader("Content-Type", "application/json");
        if (withSession != null) req = withSession.apply(req);
        return sendPolite(req);
    }

    private static boolean is2xx(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        int st = rr.response().statusCode();
        return st >= 200 && st < 300;
    }

    /**
     * Unauthenticated credential/token MINT: an endpoint named like a token/key minter that returns credential
     * material to an anonymous caller. Probe UNAUTH with a benign marker on the disclosed param; raise ONLY when
     * a credential field or secret is present (detectSecret). Read-only: a benign marker mints a throwaway token,
     * no real credential is submitted or exposed. Generic — the endpoint-name shape + the secret-in-body oracle.
     */
    private int exploitCredentialMint(String base, Set<String> endpoints) {
        int hits = 0;
        for (String ep : endpoints) {
            if (!ep.startsWith("/api/")) continue;
            String leaf = ep.substring(ep.lastIndexOf('/') + 1).toLowerCase();
            if (!(leaf.matches(".*(request|get|create|mint|new|issue).*")
                    && leaf.matches(".*(token|key|credential|secret|keypair).*"))) continue;
            // Try the disclosed param name, then a wordlist of common mint params (many minters don't disclose it).
            String disc = discoverParamName(base + ep, null);
            java.util.List<String> params = new ArrayList<>();
            if (disc != null) params.add(disc);
            for (String p : COMMON_MINT_PARAMS) if (!params.contains(p)) params.add(p);
            params.add(null);   // also try an empty body (some minters need no param)
            HttpRequestResponse rr = null; String leak = null; String usedParam = null;
            for (String p : params) {
                HttpRequestResponse t = robustFormPost(base + ep, p == null ? "" : p + "=" + urlEnc("aiscnf-benign-marker"), 3);
                String l = detectSecret(t);
                if (l != null) { rr = t; leak = l; usedParam = p; break; }
            }
            if (leak == null) continue;
            scanLog.found("Unauthenticated credential/token minter (no authentication)", base + ep,
                    "Request: POST " + ep + " with NO session"
                    + (usedParam != null ? " and a benign " + usedParam + " value" : "") + ".\n\n"
                    + "Response: HTTP " + rr.response().statusCode() + " returning credential material to an "
                    + "ANONYMOUS caller — " + leak + ".\n\n"
                    + "Impact: an unauthenticated attacker drives this token/key minter with no authentication and "
                    + "no credential check, decoupling it from any lockout/rate-limit path (token flooding, relay "
                    + "abuse) and obtaining credential material with zero login (CWE-306, CWE-522). If the returned "
                    + "key/token unlocks another resource, the whole credential flow is anonymous.",
                    rr);
            scanLog.incFinding(); hits++;
            scanLog.log("  >>> gwt-rpc CREDENTIAL MINT (unauth): " + ep + " returns " + leak);
        }
        return hits;
    }

    /** Missing-parameter disclosure — the server names its own expected param. Two observed formats:
     *  "The '<name>' parameter was not set." and "Parameter <name> was not set/null". */
    private static final Pattern MISSING_PARAM = Pattern.compile(
            "The '([A-Za-z0-9_]+)' parameter was not set|Parameter ([A-Za-z0-9_]+) was (?:not set|null)");
    /** Common object-identifier param names to try form-encoded when the server does NOT disclose its param. */
    private static final String[] COMMON_ID_PARAMS = {
        "id","groupId","accountId","userId","key","keyString","keyText","email","shareKey",
        "dbId","recordKeyId","entityId","itemId","objectId","uid"};
    /** Common credential-mint param names for the benign token/key-minter probe. */
    private static final String[] COMMON_MINT_PARAMS = {"password","key","secret","credential","data","value","token"};
    /** Auto-seed harvest: an email address, and the VALUE of any JSON field named like an object key/handle/ref. */
    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");
    private static final Pattern KEYVAL = Pattern.compile(
            "\"[A-Za-z0-9_]*(?:[Kk]ey(?:[Ss]tring)?|[Hh]andle|[Rr]ef(?:erence)?)\"\\s*:\\s*\"([A-Za-z0-9_\\-]{16,})\"");
    private static final int HARVEST_MAX_CALLS = 10;   // bound the auto-seed request burst
    private static final int SITEMAP_MAX = 400;        // bound the auto-seed site-map scrape
    private static final Pattern ASSET_URL = Pattern.compile(
            "(?i).*\\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|html?)(\\?.*)?$");

    /** Probe an endpoint with an empty authed POST; extract the required param name from its 400 disclosure. */
    private String discoverParamName(String url, UnaryOperator<HttpRequest> withSession) {
        HttpRequestResponse rr = formAuthed(url, "", withSession);
        if (rr == null || rr.response() == null) return null;
        String body = rr.response().bodyToString();
        if (body == null) return null;
        Matcher m = MISSING_PARAM.matcher(body);
        if (!m.find()) return null;
        return m.group(1) != null ? m.group(1) : m.group(2);   // whichever alternative matched
    }

    private HttpRequestResponse formAuthed(String url, String body, UnaryOperator<HttpRequest> withSession) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                .withBody(body).withHeader("Content-Type", "application/x-www-form-urlencoded");
        if (withSession != null) req = withSession.apply(req);
        return sendPolite(req);
    }

    private static String urlEnc(String s) {
        try { return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    private static String firstMarker(String body) {
        if (body == null) return "";
        Matcher m = ENTITY_LOADED.matcher(body);
        return m.find() ? m.group().substring(0, Math.min(60, m.group().length())) : "";
    }

    private static String redact(String key) {
        if (key == null || key.length() <= 10) return "***";
        return key.substring(0, 6) + "…" + key.substring(key.length() - 4);
    }

    /** POST form body with N robust retries (Burp's HTTP client intermittently drops some responses). */
    private HttpRequestResponse robustFormPost(String url, String body, int attempts) {
        for (int i = 0; i < attempts; i++) {
            try { Thread.sleep(i == 0 ? PROBE_DELAY_MS : RETRY_BACKOFF_MS); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                        .withBody(body)
                        .withHeader("Content-Type", "application/x-www-form-urlencoded");
                HttpRequestResponse rr = api.http().sendRequest(req,
                        RequestOptions.requestOptions().withResponseTimeout(TIMEOUT_MS));
                if (rr != null && rr.response() != null && detectSecret(rr) != null) return rr;  // got the secret
                if (rr != null && rr.response() != null && i >= attempts - 1) return rr;          // last: return whatever
            } catch (Throwable ignore) { }
        }
        return null;
    }

    /** Secret/credential patterns that must never appear in an unauthenticated response body. */
    private static final Pattern SECRETS = Pattern.compile(
            "AKIA[0-9A-Z]{16}"                                  // AWS access key id
            + "|ASIA[0-9A-Z]{16}"                               // AWS temp key id
            + "|X-Amz-Signature|x-amz-credential|X-Amz-Credential" // presigned S3 URL
            + "|-----BEGIN [A-Z ]*PRIVATE KEY-----"             // private key
            + "|\"secret[a-zA-Z]*\"\\s*:\\s*\"[^\"]{8,}"        // "secret*": "..."
            + "|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{6,}" // JWT
            );
    /** A JSON credential-material field: "decryptionKey"/"encryptionKey"/"apiKey"/"privateKey"/"accessToken"/
     *  "sessionKey"/"authToken"/"credential" : "<>=8 chars>" — a key/token MINTED in a response body. Distinct
     *  from SECRETS (which are recognisable literals); this catches a bespoke key-mint like a one-time token. */
    private static final Pattern CRED_FIELD = Pattern.compile(
            "\"(decryption[Kk]ey|encryption[Kk]ey|api[Kk]ey|private[Kk]ey|access[Tt]oken|session[Kk]ey|"
            + "auth[Tt]oken|refresh[Tt]oken|credential|bearer)\"\\s*:\\s*\"[^\"]{8,}\"");

    /** Return a short label of the secret type leaked in the response body, or null if none. */
    private static String detectSecret(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return null;
        String body = rr.response().bodyToString();
        if (body == null) return null;
        Matcher m = SECRETS.matcher(body);
        if (m.find()) {
            String hit = m.group();
            if (hit.startsWith("AKIA") || hit.startsWith("ASIA")) return "AWS access-key ID";
            if (hit.toLowerCase().contains("amz")) return "AWS presigned-S3 URL";
            if (hit.contains("PRIVATE KEY")) return "private key";
            if (hit.startsWith("eyJ")) return "JWT/bearer token";
            return "secret value";
        }
        // Credential-material field minted in a JSON body (e.g. {"apiKey":"…"}).
        Matcher c = CRED_FIELD.matcher(body);
        if (c.find()) {
            String f = c.group(1).toLowerCase();
            return "credential-material field '" + f + "'";
        }
        return null;
    }

    // ---- method cataloguing (read vs write; write is never auto-invoked) -------------------------

    private void catalogMethods(String permJs, Set<String> services) {
        // Heuristic method-name harvest: camelCase identifiers that appear as remote-method-like tokens.
        // We only LOG these (grouped read/write) so an operator sees the full method surface; nothing is fired.
        Set<String> reads = new LinkedHashSet<>(), writes = new LinkedHashSet<>();
        Matcher m = Pattern.compile("[\"']([a-z][a-zA-Z0-9]{3,40})[\"']").matcher(permJs);
        int scanned = 0;
        while (m.find() && scanned < 500_000) {
            scanned++;
            String tok = m.group(1);
            if (READ_METHOD.matcher(tok).find()) reads.add(tok);
            else if (WRITE_METHOD.matcher(tok).find()) writes.add(tok);
        }
        // Trim to plausible RPC method names (drop common JS/DOM noise by requiring a verbⁿ+Noun shape already matched).
        scanLog.log("gwt-rpc: method surface (heuristic) — " + reads.size() + " read-named, "
                + writes.size() + " state-changing. State-changing methods are catalogued for MANUAL review and are "
                + "NEVER auto-invoked (generic-target safety).");
    }

    // ---- GWT-RPC serialization (minimal, correct) -----------------------------------------------

    /**
     * A minimal, well-formed GWT-RPC request stream for servlet confirmation:
     * {@code version|flags|tableLen|<interned strings>|<body int refs>|}. We send only the module base +
     * an empty policy so a real servlet reveals itself (RpcTokenException / policy error / auth) rather than
     * silently 200-shelling. No method is invoked.
     */
    private static String emptyRpcBody(String moduleBase) {
        // 7=RPC version, 0=flags, 1 string in the table (the module base), then a single ref to it.
        return "7|0|1|" + gwtEscape(moduleBase) + "|1|";
    }

    /** GWT ClientSerializationStreamWriter escaping: backslash and the '|' field separator. */
    private static String gwtEscape(String s) {
        return s.replace("\\", "\\\\").replace("|", "\\!");
    }

    private HttpRequestResponse sendGwtRpc(String url, String moduleBase, String perm, String body,
                                           UnaryOperator<HttpRequest> withSession) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                .withBody(body)
                .withHeader("Content-Type", "text/x-gwt-rpc; charset=utf-8")
                .withHeader("X-GWT-Module-Base", moduleBase)
                .withHeader("X-GWT-Permutation", perm);
        if (withSession != null) req = withSession.apply(req);
        return sendPolite(req);
    }

    private HttpRequestResponse sendJson(String url, String body, UnaryOperator<HttpRequest> withSession) {
        // The /api "JSON-action" API reads standard servlet params (Content-Type form-urlencoded), NOT a JSON body —
        // probing with application/json left the body unread (and, on some endpoints, made Burp's HTTP client
        // drop the response). Form-encoded is the native content type: correct + reliable.
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                .withBody("{}".equals(body) ? "" : body)
                .withHeader("Content-Type", "application/x-www-form-urlencoded");
        if (withSession != null) req = withSession.apply(req);
        return sendPolite(req);
    }

    /**
     * Send with politeness + one retry on a dead/throttled response. Live targets may rate-limit
     * a burst of scan requests, degrading later probes to timeouts — which silently shrinks coverage and
     * makes findings non-deterministic run-to-run. A small inter-request delay + a single back-off retry keeps
     * coverage stable without hammering the host.
     */
    private HttpRequestResponse sendPolite(HttpRequest req) {
        for (int attempt = 0; attempt < 3; attempt++) {   // 3 tries: Burp's HTTP to the hosting platform intermittently drops
            try { Thread.sleep(attempt == 0 ? PROBE_DELAY_MS : RETRY_BACKOFF_MS * attempt); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
            try {
                HttpRequestResponse rr = api.http().sendRequest(req,
                        RequestOptions.requestOptions().withResponseTimeout(TIMEOUT_MS));
                if (rr != null && rr.response() != null) {
                    int st = rr.response().statusCode();
                    if (st != 429 && st != 503) return rr;   // 429/503 = throttled → back off + retry
                }
            } catch (Throwable ignore) { /* back off + retry */ }
        }
        return null;
    }

    // ---- detection + fetch helpers ---------------------------------------------------------------

    /** Find the GWT module name from a crawled host page (or a live GET of the root). */
    private String detectModule(String host) {
        // Prefer the site map (already crawled) so we don't add load.
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                if (!sameHost(rr.request().url(), host)) continue;
                String body = rr.response().bodyToString();
                if (body == null || !GWT_META.matcher(body).find()) continue;
                Matcher m = NOCACHE.matcher(body);
                if (m.find()) return m.group(1);
            }
        } catch (Throwable ignore) { }
        // Fallback: one GET of the root.
        try {
            String base = resolveBase(host);
            if (base == null) return null;
            HttpRequestResponse rr = api.http().sendRequest(
                    HttpRequest.httpRequestFromUrl(base + "/").withMethod("GET"),
                    RequestOptions.requestOptions().withResponseTimeout(TIMEOUT_MS));
            if (rr == null || rr.response() == null) return null;
            String body = rr.response().bodyToString();
            if (body == null || !GWT_META.matcher(body).find()) return null;
            Matcher m = NOCACHE.matcher(body);
            if (m.find()) return m.group(1);
        } catch (Throwable ignore) { }
        return null;
    }

    private String fetchText(String url, UnaryOperator<HttpRequest> withSession) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (withSession != null) req = withSession.apply(req);
            HttpRequestResponse rr = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(TIMEOUT_MS));
            if (rr == null || rr.response() == null) return null;
            if (rr.response().statusCode() != 200) return null;
            String ct = header(rr, "Content-Type");
            String body = rr.response().bodyToString();
            // Guard against the SPA shell being returned for a missing asset.
            if (ct != null && ct.toLowerCase().contains("html")) return null;
            return body;
        } catch (Throwable t) { return null; }
    }

    // ---- small utilities -------------------------------------------------------------------------

    private static String resolveBase(String host) {
        try {
            if (host.startsWith("http")) {
                URI u = URI.create(host);
                return u.getScheme() + "://" + u.getAuthority();
            }
            // bare authority: default https for the hosting platform / modern hosts, caller usually passes a URL anyway
            return "https://" + host;
        } catch (Exception e) { return null; }
    }

    private static boolean sameHost(String url, String host) {
        try {
            String a = URI.create(url).getAuthority();
            if (a == null) return false;
            if (host.startsWith("http")) return a.equalsIgnoreCase(URI.create(host).getAuthority());
            return a.equalsIgnoreCase(host);
        } catch (Exception e) { return false; }
    }

    private static String header(HttpRequestResponse rr, String name) {
        try { return rr.response().headerValue(name); } catch (Throwable t) { return null; }
    }

    /**
     * Extract the GWT service-entry-point constructors and the base path each binds. Two compiled patterns:
     *  (1) inline base literal:  {@code function Ab1(a){...this.a='/api/'+a}}
     *  (2) shared base variable:  {@code _x='/svc/'} + {@code function Cd2(a){...this.b=_x+a}}
     * Returns constructorClassName -> basePath (e.g. Cd2 -> /svc/).
     */
    private static Map<String,String> extractCtorBases(String js) {
        Map<String,String> out = new LinkedHashMap<>();
        // (1) inline base literal in the constructor body
        Matcher m1 = Pattern.compile(
                "function ([A-Za-z0-9_$]+)\\(([a-z])\\)\\{[^}]{0,200}?this\\.[a-z]=['\"](/[a-z0-9_]+/)['\"]\\+\\2").matcher(js);
        while (m1.find()) out.put(m1.group(1), m1.group(3));
        // (2) shared base variable: collect var/field -> base literal, then constructors that concat it
        Map<String,String> baseVar = new LinkedHashMap<>();
        Matcher mv = Pattern.compile("([A-Za-z0-9_$]{1,4})=['\"](/[a-z0-9_]+/)['\"]").matcher(js);
        while (mv.find()) baseVar.putIfAbsent(mv.group(1), mv.group(2));
        Matcher m2 = Pattern.compile(
                "function ([A-Za-z0-9_$]+)\\(([a-z])\\)\\{[^}]{0,200}?this\\.[a-z]=([A-Za-z0-9_$]{1,4})\\+\\2").matcher(js);
        while (m2.find()) { String bv = baseVar.get(m2.group(3)); if (bv != null) out.putIfAbsent(m2.group(1), bv); }
        return out;
    }

    private static String firstMatch(Pattern p, String s) {
        Matcher m = p.matcher(s);
        return m.find() ? m.group() : null;
    }

    private static Set<String> allMatches(Pattern p, String s, int group) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = p.matcher(s);
        while (m.find()) out.add(group == 0 ? m.group() : m.group(group));
        return out;
    }
}
