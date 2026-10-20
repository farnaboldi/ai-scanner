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

    private static final int MAX_PERM_BYTES = 6_000_000;       // a permutation cache.js is ~2-3MB
    private static final int MAX_PERMUTATIONS = 6;             // bound how many permutations we fetch
    private static final int MAX_TOTAL_PERM_BYTES = 10_000_000; // bound the concatenated multi-perm blob
    private static final int MAX_LOGIN_ATTEMPTS = 20;           // bound the GWT auto-login live-POST search
    private static final int MAX_CONFIRM = 200;            // cap live confirmation requests
    private static final long TIMEOUT_MS = 12_000L;
    private static final long PROBE_DELAY_MS = 300L;       // politeness between probes (avoid target rate-limit)
    private static final long RETRY_BACKOFF_MS = 1500L;    // back-off before the single retry on a throttled/dead probe

    public GwtRpcDiscovery(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /**
     * Detect + map + live-confirm the GWT surface for {@code host}.
     * @param host        the target authority (host[:port]) or a base URL
     * @param withSession applies the captured session (cookie/bearer) to probe requests; may be null
     * @return live-confirmed servlet request/response pairs
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

            // 2) nocache bootstrap -> EVERY permutation strong-name it lists -> fetch each compiled permutation,
            //    merged into the UNION surface (see fetchGwtSurface: permutations are not guaranteed equivalent).
            GwtSurface surf = fetchGwtSurface(base, module, withSession);
            if (surf == null) return confirmed;
            String moduleBase = surf.moduleBase, perm = surf.perm, permJs = surf.allJs;
            Set<String> services = surf.services;
            Map<String,String> ctorBase = surf.ctorBase;
            Set<String> endpoints = surf.endpoints;

            scanLog.log("gwt-rpc: registry parsed — fetched " + surf.fetchedCount + " of " + surf.totalPerms
                    + " permutation(s) (union surface) — " + services.size() + " service interface(s), "
                    + endpoints.size() + " exact servlet endpoint(s) from " + ctorBase.size()
                    + " entry-point constructor(s). Native crawl saw 0.");
            for (String s : services) scanLog.debug("  gwt-rpc service: " + s);
            if (endpoints.isEmpty()) { scanLog.debug("  gwt-rpc: no entry-point constructors parsed."); return confirmed; }

            // 4) Live-confirm + AUTHZ-DIFFERENTIAL each REAL endpoint. One non-mutating probe never carries valid
            //    method args, so a mutating endpoint just rejects it ("too few tokens"/400/401) — no state change.
            //    For JSON/form action bases (non-GWT-RPC servlets) we also run the endpoint UNAUTHENTICATED and
            //    compare to the base's blanket unknown-action response: a specific action that reaches its handler
            //    with NO session (non-401 while the base 401s bogus actions) is a MISSING-AUTHENTICATION finding —
            //    the generalized "anonymous endpoint hands out credentials" leak, emitted automatically. GWT-RPC bases
            //    reject the empty body pre-auth ("too few tokens"), so their unauth response is not authz-conclusive
            //    here — those are only confirmed as servlets (real arg-level authz testing is GwtRpcProbe/v2).
            //    Which bases are GWT-RPC is learned from the servlets' own responses (isGwtRpcResponse), never
            //    from path names.
            // The differential is inherently UNAUTHENTICATED ("does this endpoint process an anonymous request?"),
            // so we probe each endpoint exactly ONCE with no session — one request per endpoint keeps coverage
            // stable under the target's rate-limit (an authed second probe per endpoint doubled the burst and
            // collapsed coverage). Per JSON base we learn the blanket unknown-action response once (cached).
            int tested = 0, live = 0, servletReached = 0, gated = 0, findings = 0;
            Map<String,Kind> jsonBaseBogus = new LinkedHashMap<>();
            Set<String> gwtRpcBases = new LinkedHashSet<>();   // bases whose servlets answered as GWT-RPC
            for (String ep : endpoints) {
                if (tested >= MAX_CONFIRM) break;
                tested++;
                String url = base + ep;
                String jb = baseOf(ep);   // e.g. /api/
                // A form probe answered with a GWT-RPC signature marks the whole base GWT-RPC: this endpoint is
                // re-confirmed with a well-formed GWT-RPC body, and later endpoints under that base go straight to
                // the GWT-RPC probe (only the first endpoint of a GWT-RPC base costs a second request).
                boolean gwtRpc = gwtRpcBases.contains(jb);
                HttpRequestResponse rr = gwtRpc
                        ? sendGwtRpc(url, moduleBase, perm, emptyRpcBody(moduleBase), null)   // unauth
                        : sendJson(url, "{}", null);                                          // unauth
                if (!gwtRpc && isGwtRpcResponse(rr)) {
                    gwtRpc = true;
                    gwtRpcBases.add(jb);
                    rr = sendGwtRpc(url, moduleBase, perm, emptyRpcBody(moduleBase), null);   // unauth
                }
                Kind k = classify(rr);
                if (k != Kind.SERVLET && k != Kind.AUTH_GATED) continue;   // drop dead/shell/405 only
                live++;
                confirmed.add(rr);
                if (k == Kind.SERVLET) servletReached++; else gated++;
                scanLog.log("  gwt-rpc endpoint: POST " + ep + " -> " + rr.response().statusCode() + " " + k);

                // AUTHZ DIFFERENTIAL (JSON endpoints only — the GWT-RPC empty body errors "too few tokens"
                // pre-auth, so its unauth response is not authz-conclusive; arg-level GWT-RPC authz = v3).
                // A specific action that REACHES ITS HANDLER unauthenticated, while the base gates unknown
                // actions (bogus -> 401/403), is a missing-authentication finding (the generalized
                // unauthenticated credential-leak class).
                if (!gwtRpc && k == Kind.SERVLET) {
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

            // 5b) AUTO-SEED the cross-account BOLA probes: harvest foreign identifiers/keys the authenticated
            //     session can already see (drives the app's own lookup/list endpoints, excludes our own identity),
            //     so the BOLA differential fires with zero operator setup. Operator -D/env seeds still take
            //     priority and are UNIONed in. Read-only, bounded.
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
            probeCrossAccountLoad(base, endpoints, withSession, loadSeeds);

            // 5d) CROSS-ACCOUNT DATA READ (BOLA that RETURNS another tenant's record, not just a load error).
            //     With our session, request a FOREIGN identifier (email/id — auto-seeded or -Daiscanner.gwtForeignIds)
            //     and confirm the endpoint returns that account's populated data (differs from a bogus id, echoes
            //     the foreign id, and unauth→401). Covers account-lookup-by-email and config-by-foreign-group-id.
            probeCrossAccountRead(base, endpoints, withSession, readSeeds);

            // 5e) UNAUTH CREDENTIAL/TOKEN MINT. Endpoints named like a token/key minter that return credential
            //     material to an ANONYMOUS caller (e.g. an endpoint that mints a key/token or presigned URL).
            //     Probe UNAUTH with a benign marker value; raise ONLY if a credential field/secret is in the response.
            exploitCredentialMint(base, endpoints, gwtRpcBases);

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

    /** True when the response carries a GWT-RPC servlet signature: an //OK or //EX payload, a GWT RPC exception,
     *  or GWT's generic "call failed on the server" failure (what a GWT-RPC servlet answers to a non-GWT-RPC
     *  body). This is GWT's own wire format, so it classifies a servlet without relying on its path name. */
    private static boolean isGwtRpcResponse(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String b = rr.response().bodyToString();
        if (b == null) return false;
        return b.startsWith("//OK") || b.startsWith("//EX")
                || b.contains("RpcTokenException") || b.contains("IncompatibleRemoteServiceException")
                || b.contains("call failed on the server");
    }

    /** The servlet base an endpoint sits under: its first path segment, e.g. /api/getItem -> /api/. */
    private static String baseOf(String ep) {
        return ep.substring(0, ep.indexOf('/', 1) + 1);
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
        // foreign emails (an email-keyed account lookup takes a foreign email directly as the read-probe seed)
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
     * submit ANOTHER account's object reference to fetch-shaped JSON endpoints. If the server loads that foreign
     * entity (type/kind/cast error) rather than rejecting (401/403) or returning a clean not-found, the ownership
     * check is missing or post-load. Read-only. Gated on: an authenticated session AND a seeded foreign key
     * (-Daiscanner.gwtForeignKeys / AISCANNER_GWT_FOREIGN_KEYS = comma-separated foreign object key values,
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
                    && leaf.matches(".*(account|entity|object|record|file|group|key|token).*")) {
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
                // Body encodings: raw JSON string, then form named-param — the disclosed name if any, else a
                // wordlist of common id params (some endpoints never disclose their param name).
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
                            + "(CWE-639, CWE-285). This can expose PII/configuration and harvest the "
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
     * Only JSON/form endpoints are probed: those under a base learned as GWT-RPC ({@code gwtRpcBases}) are skipped.
     */
    private int exploitCredentialMint(String base, Set<String> endpoints, Set<String> gwtRpcBases) {
        int hits = 0;
        for (String ep : endpoints) {
            if (gwtRpcBases.contains(baseOf(ep))) continue;
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
        "id","groupId","accountId","userId","key","email","dbId","entityId","objectId","uid"};
    /** Common credential-mint param names for the benign token/key-minter probe. */
    private static final String[] COMMON_MINT_PARAMS = {"password","key","secret","credential","data","value","token"};
    /** Auto-seed harvest: an email address, and the VALUE of any JSON field named like an object key/handle/ref. */
    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");
    private static final Pattern KEYVAL = Pattern.compile(
            "\"[A-Za-z0-9_]*(?:[Kk]ey|[Hh]andle|[Rr]ef(?:erence)?)\"\\s*:\\s*\"([A-Za-z0-9_\\-]{16,})\"");
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

    /** POST form body with N robust retries (some hosts intermittently drop responses). */
    private HttpRequestResponse robustFormPost(String url, String body, int attempts) {
        for (int i = 0; i < attempts; i++) {
            try { Thread.sleep(i == 0 ? PROBE_DELAY_MS : RETRY_BACKOFF_MS); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                        .withBody(body)
                        .withHeader("Content-Type", "application/x-www-form-urlencoded");
                HttpRequestResponse rr = com.ioactive.aiscanner.scan.SafeHttp.sendRequest(api, req,
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
     *  from SECRETS (which are recognisable literals); this catches a bespoke key/token mint. */
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
        // Many JSON-action servlets read standard servlet params (Content-Type form-urlencoded), NOT a JSON body —
        // probing with application/json left the body unread (and, on some endpoints, made Burp's HTTP client
        // drop the response). Form-encoded is the native content type: correct + reliable.
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                .withBody("{}".equals(body) ? "" : body)
                .withHeader("Content-Type", "application/x-www-form-urlencoded");
        if (withSession != null) req = withSession.apply(req);
        return sendPolite(req);
    }

    /**
     * Send with politeness + one retry on a dead/throttled response. Live targets may rate-limit a burst of
     * scan requests, degrading later probes to timeouts — which silently shrinks coverage and makes findings
     * non-deterministic run-to-run. A small inter-request delay + a single back-off retry keeps
     * coverage stable without hammering the host.
     */
    private HttpRequestResponse sendPolite(HttpRequest req) {
        for (int attempt = 0; attempt < 3; attempt++) {   // 3 tries: some hosts intermittently drop responses
            try { Thread.sleep(attempt == 0 ? PROBE_DELAY_MS : RETRY_BACKOFF_MS * attempt); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
            try {
                HttpRequestResponse rr = com.ioactive.aiscanner.scan.SafeHttp.sendRequest(api, req,
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
            HttpRequestResponse rr = com.ioactive.aiscanner.scan.SafeHttp.sendRequest(api, 
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
            HttpRequestResponse rr = com.ioactive.aiscanner.scan.SafeHttp.sendRequest(api, req, RequestOptions.requestOptions().withResponseTimeout(TIMEOUT_MS));
            if (rr == null || rr.response() == null) return null;
            if (rr.response().statusCode() != 200) return null;
            String ct = header(rr, "Content-Type");
            String body = rr.response().bodyToString();
            // Guard against the SPA shell being returned for a missing asset.
            if (ct != null && ct.toLowerCase().contains("html")) return null;
            return body;
        } catch (Throwable t) { return null; }
    }

    // ---- GWT-RPC autonomous login (operator-supplied credentials) --------------------------------
    //
    // Same trust boundary as AutonomousAuth's REST login strategies: this NEVER invents or guesses
    // credentials — it only fires when the operator already supplied email+password
    // (-Daiscanner.loginEmail/.loginPassword), and it only assembles the correctly-formed GWT-RPC wire
    // request for THOSE credentials. The one piece that looked like it needed guessing — which of the
    // ~30 embedded serialization-policy strong-names belongs to the login method — is resolved by
    // CALL-GRAPH TRACING, not by trying candidates against the live server:
    //
    //   (a) every RPC proxy constructor the GWT compiler emits has the stable shape
    //         function CTOR(){ ...; SUPER.call(this, BASEFN(), 'POLICY', TYPEARR) }
    //   (b) every RPC method-invocation helper has the stable shape
    //         function METHODFN(inst,arg1,...,argN,callback){ ...; new STREAMWRITER(inst,SVCVAR,'methodName'); ... }
    //       where `inst` is literally METHODFN's own first declared parameter;
    //   (c) METHODFN is invoked elsewhere as METHODFN(SINGLETON, realArgs..., cb) — SINGLETON is the
    //       module-level variable holding the one shared proxy instance for that service;
    //   (d) SINGLETON is lazily constructed exactly once: SINGLETON = new CTOR (CTOR from step a).
    //
    // Chasing (b)->(c)->(d)->(a) backward from a target method name deterministically resolves the one
    // correct policy for that exact method — pure static analysis of the already-downloaded permutation
    // JS, zero extra requests to the target, zero brute force.
    //
    // This generalizes to ANY GWT app's login (or any other RPC method) — nothing here names a specific
    // product, service, or method; only structural shape + a login-shaped NAME heuristic.

    /** Method-name shapes that plausibly mean "authenticate with a credential" — CONTAINS-match (methods
     *  are routinely named with a suffix/prefix around the verb, e.g. "userLogin", "doLogin",
     *  "authenticateUser"), not an exact match. Generic, not app-specific. */
    private static final Pattern LOGIN_METHOD_NAME = Pattern.compile("(?i)login|logon|signin|sign_in|authenticate");
    /** Service/class-name shapes that plausibly host a login method — used only to disambiguate when a
     *  method-name match alone is ambiguous across several declared service interfaces. */
    private static final Pattern LOGIN_SERVICE_NAME = Pattern.compile("(?i)login|auth|session|account");

    /** The parsed/fetched GWT client surface — shared between {@link #discover} and {@link #autoLogin} so
     *  the permutation-union fetch + registry extraction happens exactly once per call, in one place. */
    private static final class GwtSurface {
        final String moduleBase, perm, allJs;
        final Set<String> services, endpoints;
        final Map<String,String> ctorBase;
        final int fetchedCount, totalPerms;
        GwtSurface(String moduleBase, String perm, String allJs, Set<String> services, Set<String> endpoints,
                   Map<String,String> ctorBase, int fetchedCount, int totalPerms) {
            this.moduleBase = moduleBase; this.perm = perm; this.allJs = allJs;
            this.services = services; this.endpoints = endpoints; this.ctorBase = ctorBase;
            this.fetchedCount = fetchedCount; this.totalPerms = totalPerms;
        }
    }

    /**
     * Fetch EVERY permutation {@code nocache.js} lists and merge the UNION of their service registries.
     * GWT emits one permutation per deferred-binding axis (browser/locale/...); which one a real browser
     * loads is decided by runtime UA/locale sniffing this scanner doesn't replicate, and permutations are
     * NOT guaranteed equivalent — some permutations ship a reduced surface (an entire service registry,
     * e.g. login/account, missing) while a sibling permutation has the full app. Picking "the first one"
     * silently truncates discovery; the union is the only way to guarantee full coverage. Bounded
     * ({@link #MAX_PERMUTATIONS} fetches, {@link #MAX_TOTAL_PERM_BYTES} concatenated).
     */
    private GwtSurface fetchGwtSurface(String base, String module, UnaryOperator<HttpRequest> withSession) {
        String moduleBase = base + "/" + module + "/";
        String nocache = fetchText(moduleBase + module + ".nocache.js", withSession);
        if (nocache == null) { scanLog.debug("  gwt-rpc: nocache bootstrap unreadable."); return null; }
        List<String> perms = new ArrayList<>(allMatches(HEX32, nocache, 0));
        if (perms.isEmpty()) { scanLog.debug("  gwt-rpc: no permutation strong-name in nocache."); return null; }

        List<String> fetchedHashes = new ArrayList<>();
        Set<String> services = new LinkedHashSet<>();
        Map<String,String> ctorBase = new LinkedHashMap<>();
        Set<String> endpoints = new LinkedHashSet<>();
        StringBuilder allJs = new StringBuilder();
        for (String p : perms) {
            if (fetchedHashes.size() >= MAX_PERMUTATIONS) break;
            String js = fetchText(moduleBase + p + ".cache.js", withSession);
            if (js == null || js.length() < 10_000) continue;
            if (js.length() > MAX_PERM_BYTES) js = js.substring(0, MAX_PERM_BYTES);
            fetchedHashes.add(p);
            services.addAll(allMatches(SERVICE, js, 0));
            Map<String,String> cb = extractCtorBases(js);
            for (Map.Entry<String,String> e : cb.entrySet()) {
                ctorBase.putIfAbsent(e.getKey(), e.getValue());   // base paths are stable across permutations
                Matcher m = Pattern.compile("new " + Pattern.quote(e.getKey()) + "\\('([a-zA-Z0-9_/]+)'\\)").matcher(js);
                while (m.find()) endpoints.add(e.getValue() + m.group(1));
            }
            if (allJs.length() < MAX_TOTAL_PERM_BYTES) allJs.append(js).append('\n');
        }
        if (fetchedHashes.isEmpty()) { scanLog.debug("  gwt-rpc: no permutation fetched/parseable."); return null; }
        return new GwtSurface(moduleBase, fetchedHashes.get(0), allJs.toString(), services, endpoints, ctorBase,
                fetchedHashes.size(), perms.size());
    }

    /** One resolved GWT-RPC login candidate: method name, its serialization policy, and how many string
     *  arguments its invocation helper declares (proxy instance + N args + callback). */
    private static final class GwtLoginCandidate {
        final String methodName, policy; final int argCount;
        GwtLoginCandidate(String methodName, String policy, int argCount) {
            this.methodName = methodName; this.policy = policy; this.argCount = argCount;
        }
    }

    /**
     * Call-graph-resolve every login-shaped RPC method in {@code js} to its serialization policy + arg
     * count. Pure static analysis (see the block comment above for the 4-step trace). Returns candidates
     * in the order found; the caller tries each until one authenticates.
     */
    private static List<GwtLoginCandidate> findGwtLoginCandidates(String js) {
        List<GwtLoginCandidate> out = new ArrayList<>();
        Map<String,String> ctorPolicy = buildProxyCtorPolicyTable(js);
        if (ctorPolicy.isEmpty()) return out;

        // (b) RPC method-invocation call sites: new STREAMWRITER(instParam, svcVar, 'methodName')
        Matcher invM = Pattern.compile("new [A-Za-z0-9_$]+\\(([a-z][A-Za-z0-9_$]*),[A-Za-z0-9_$]+,'([A-Za-z0-9_.]+)'\\)").matcher(js);
        Set<String> seenMethods = new java.util.HashSet<>();
        while (invM.find()) {
            String instParam = invM.group(1), methodName = invM.group(2);
            if (!LOGIN_METHOD_NAME.matcher(methodName).find()) continue;
            if (!seenMethods.add(methodName)) continue;   // one candidate per distinct method name
            String fnName = enclosingFunctionWithFirstParam(js, invM.start(), instParam);
            if (fnName == null) continue;
            int argCount = declaredParamCount(js, fnName);
            if (argCount < 3) continue;   // need at least (instance, 1 real arg, callback)
            int realArgs = argCount - 2; // minus the proxy instance + trailing AsyncCallback

            // (c) find where fnName(...) is called; the first actual argument there is the proxy SINGLETON.
            Matcher callM = Pattern.compile("(?<![A-Za-z0-9_$.])" + Pattern.quote(fnName) + "\\(([A-Za-z0-9_$]+)").matcher(js);
            while (callM.find()) {
                int cs = callM.start();
                if (cs >= 9 && js.regionMatches(cs - 9, "function ", 0, 9)) continue;   // skip its own declaration
                String singleton = callM.group(1);
                // (d) resolve the singleton's one-time construction: SINGLETON=new CTOR
                Matcher initM = Pattern.compile(Pattern.quote(singleton) + "=new ([A-Za-z0-9_$]+)").matcher(js);
                if (initM.find()) {
                    String policy = ctorPolicy.get(initM.group(1));
                    if (policy != null) { out.add(new GwtLoginCandidate(methodName, policy, realArgs)); break; }
                }
            }
        }
        return out;
    }

    /** (a) Build the table of every RPC proxy constructor function -> its embedded serialization policy. */
    private static Map<String,String> buildProxyCtorPolicyTable(String js) {
        Map<String,String> table = new LinkedHashMap<>();
        Matcher m = Pattern.compile("[A-Za-z0-9_$]+\\.call\\(this,[A-Za-z0-9_$]+\\(\\),'([0-9A-F]{32})',[A-Za-z0-9_$]+\\)").matcher(js);
        while (m.find()) {
            String policy = m.group(1);
            String fn = nearestEnclosingZeroArgFunction(js, m.start());
            if (fn != null) table.putIfAbsent(fn, policy);
        }
        return table;
    }

    /** Nearest {@code function NAME(){...}} (zero-arg) declaration opening before {@code pos} — the proxy
     *  constructor shape (GWT proxy ctors always take no arguments). */
    private static String nearestEnclosingZeroArgFunction(String js, int pos) {
        int from = Math.max(0, pos - 300);
        Matcher m = Pattern.compile("function ([A-Za-z0-9_$]+)\\(\\)\\{").matcher(js.substring(from, pos));
        String last = null;
        while (m.find()) last = m.group(1);
        return last;
    }

    /** Nearest {@code function NAME(PARAM,...)} declaration opening before {@code pos} whose FIRST declared
     *  parameter is exactly {@code param} — ties an inner call site back to its enclosing helper function. */
    private static String enclosingFunctionWithFirstParam(String js, int pos, String param) {
        int from = Math.max(0, pos - 2000);
        Matcher m = Pattern.compile("function ([A-Za-z0-9_$]+)\\(" + Pattern.quote(param) + "[,)]").matcher(js.substring(from, pos));
        String last = null;
        while (m.find()) last = m.group(1);
        return last;
    }

    /** Declared parameter count of {@code function fnName(...)}; -1 if not found. */
    private static int declaredParamCount(String js, String fnName) {
        Matcher m = Pattern.compile("function " + Pattern.quote(fnName) + "\\(([^)]*)\\)").matcher(js);
        if (!m.find()) return -1;
        String params = m.group(1).trim();
        return params.isEmpty() ? 0 : params.split(",").length;
    }

    /**
     * Build a GWT-RPC wire body for a method taking {@code argCount} java.lang.String arguments, the
     * first two bound to {@code email}/{@code password} and any remaining args defaulted to "" (the
     * common trailing-optional-param convention on login methods). String-typed-args only — covers the
     * realistic login-method shape; a non-String-shaped login (rare) simply fails closed (no crash, no
     * corrupt request — the caller just gets no account-shaped response and moves on).
     */
    private static String buildGwtLoginBody(String moduleBase, String policy, String serviceFqn, String methodName,
                                             String email, String password, int argCount) {
        List<String> table = new ArrayList<>(List.of(moduleBase, policy, serviceFqn, methodName,
                "java.lang.String/2004016611", email, password));
        StringBuilder inv = new StringBuilder("1|2|3|4|").append(argCount).append('|');
        for (int i = 0; i < argCount; i++) inv.append("5|");           // every arg shares the one String-type entry
        inv.append("6|7|");                                             // email, password refs
        if (argCount > 2) {
            table.add("");                                              // one shared empty-string table entry
            int emptyRef = table.size();
            for (int i = 2; i < argCount; i++) inv.append(emptyRef).append('|');
        }
        StringBuilder body = new StringBuilder("7|0|").append(table.size()).append('|');
        for (String s : table) body.append(gwtEscape(s)).append('|');
        return body.append(inv).toString();
    }

    /**
     * Autonomous GWT-RPC login with OPERATOR-SUPPLIED credentials. Detects every login-shaped RPC method
     * via {@link #findGwtLoginCandidates}, pairs each with a declared service interface whose simple name
     * looks login/auth-shaped, and POSTs the assembled request — trying candidates in order until one
     * response contains the caller's own email (proof the server accepted the credential) and sets a
     * session cookie. Read-only from the scanner's perspective: it submits exactly the credential pair the
     * operator already gave it, nothing invented. Returns the raw {@code Set-Cookie} header on success, or
     * null (the caller falls back to an operator-supplied cookie, unchanged).
     */
    public String autoLogin(String host, String email, String password) {
        try {
            String base = resolveBase(host);
            if (base == null || email == null || email.isBlank() || password == null) return null;
            String module = detectModule(host);
            if (module == null) return null;

            GwtSurface surf = fetchGwtSurface(base, module, null);
            if (surf == null) return null;
            List<GwtLoginCandidate> candidates = findGwtLoginCandidates(surf.allJs);
            if (candidates.isEmpty()) {
                scanLog.debug("  gwt-rpc: auto-login found no login-shaped RPC method (call-graph trace empty).");
                return null;
            }

            // Servlet URL candidates: REAL entry-point-constructor-derived endpoints (the same authoritative
            // extraction discover() uses — no guessing) whose relpath looks login-shaped. NEVER fall back to
            // the full endpoint set (can be 100+ on a real app) — that turns this into an unbounded, impolite
            // sweep against a live target. No login-shaped relpath found = no guess; bail out cleanly instead.
            List<String> servletUrls = new ArrayList<>();
            for (String ep : surf.endpoints) if (LOGIN_METHOD_NAME.matcher(ep).find()) servletUrls.add(base + ep);
            if (servletUrls.isEmpty()) {
                scanLog.debug("  gwt-rpc: auto-login found login method candidate(s) but no login-shaped servlet "
                        + "endpoint among the " + surf.endpoints.size() + " discovered — not guessing further.");
                return null;
            }

            List<String> loginServices = new ArrayList<>();
            for (String s : surf.services) if (LOGIN_SERVICE_NAME.matcher(s.substring(s.lastIndexOf('.') + 1)).find()) loginServices.add(s);
            if (loginServices.isEmpty()) loginServices.addAll(surf.services);   // fall back to trying all known services

            // Bounded, polite search: URL outermost (the most promising/login-shaped servlet first — if it's
            // right, success lands within the first few attempts regardless of candidate/service count), a
            // small delay between live POSTs, and a hard cap on total requests so a target with many declared
            // services can never turn this into an unbounded sweep. MAX_LOGIN_ATTEMPTS bounds the worst case
            // to a couple dozen requests — once, for the whole scan, not per endpoint.
            int attempts = 0;
            AuthSessionGwt sess = new AuthSessionGwt(api);
            outer:
            for (String url : servletUrls) {
                for (GwtLoginCandidate c : candidates) {
                    for (String svcFqn : loginServices) {
                        if (attempts >= MAX_LOGIN_ATTEMPTS) {
                            scanLog.debug("  gwt-rpc: auto-login hit its " + MAX_LOGIN_ATTEMPTS + "-attempt cap "
                                    + "(" + servletUrls.size() + " login-shaped url(s) x " + candidates.size()
                                    + " method candidate(s) x " + loginServices.size() + " service(s) was too "
                                    + "large to exhaust) — bailing out, no further guessing.");
                            break outer;
                        }
                        attempts++;
                        String body = buildGwtLoginBody(surf.moduleBase, c.policy, svcFqn, c.methodName, email, password, c.argCount);
                        HttpRequestResponse rr = sess.postGwtRpc(url, surf.moduleBase, surf.perm, body);
                        try { Thread.sleep(PROBE_DELAY_MS); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break outer; }
                        if (rr == null || rr.response() == null) continue;
                        String rb = rr.response().bodyToString();
                        boolean hasCookie = rr.response().headers().stream()
                                .anyMatch(h -> h.name().equalsIgnoreCase("Set-Cookie") && h.value().contains("="));
                        if (rb != null && rb.contains(email) && hasCookie) {
                            scanLog.log("gwt-rpc: auto-login OK — " + svcFqn.substring(svcFqn.lastIndexOf('.') + 1)
                                    + "." + c.methodName + "() accepted the supplied credential (call-graph-resolved "
                                    + "policy, " + c.argCount + "-arg signature; servlet " + url.substring(base.length())
                                    + "; " + attempts + " attempt(s)).");
                            return sess.cookieHeader();
                        }
                    }
                }
            }
            scanLog.debug("  gwt-rpc: auto-login tried " + candidates.size() + " method candidate(s) x "
                    + loginServices.size() + " service(s) x " + servletUrls.size() + " servlet path(s) — none authenticated.");
            return null;
        } catch (Throwable t) { scanLog.debug("gwt-rpc auto-login error: " + t); return null; }
    }

    /** Minimal cookie-accumulating sender for the GWT-RPC login POST (mirrors AuthSession's jar-merge, kept
     *  local so GwtRpcDiscovery has no dependency on the scan.auth package). */
    private static final class AuthSessionGwt {
        private final MontoyaApi api;
        private final Map<String,String> jar = new LinkedHashMap<>();
        AuthSessionGwt(MontoyaApi api) { this.api = api; }
        String cookieHeader() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String,String> e : jar.entrySet()) { if (sb.length() > 0) sb.append("; "); sb.append(e.getKey()).append('=').append(e.getValue()); }
            return sb.toString();
        }
        HttpRequestResponse postGwtRpc(String url, String moduleBase, String perm, String body) {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                    .withBody(body)
                    .withHeader("Content-Type", "text/x-gwt-rpc; charset=utf-8")
                    .withHeader("X-GWT-Module-Base", moduleBase)
                    .withHeader("X-GWT-Permutation", perm);
            HttpRequestResponse rr;
            try {
                rr = com.ioactive.aiscanner.scan.SafeHttp.sendRequest(api, req, RequestOptions.requestOptions().withResponseTimeout(12_000L));
            } catch (Throwable t) { return null; }
            if (rr != null && rr.response() != null) {
                try { for (var c : rr.response().cookies()) if (c.name() != null && !c.name().isBlank()) jar.put(c.name(), c.value() == null ? "" : c.value()); }
                catch (Throwable ignore) { }
            }
            return rr;
        }
    }

    // ---- small utilities -------------------------------------------------------------------------

    private static String resolveBase(String host) {
        try {
            if (host.startsWith("http")) {
                URI u = URI.create(host);
                return u.getScheme() + "://" + u.getAuthority();
            }
            // bare authority: default https; the caller usually passes a URL anyway
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
     *  (1) inline base literal:  {@code function Ab1(a){...this.a='/rpc/'+a}}
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

    private static Set<String> allMatches(Pattern p, String s, int group) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = p.matcher(s);
        while (m.find()) out.add(group == 0 ? m.group() : m.group(group));
        return out;
    }
}
