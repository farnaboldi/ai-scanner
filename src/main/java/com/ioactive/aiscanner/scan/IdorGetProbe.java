package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.scan.sast.SourceFindings;
import com.ioactive.aiscanner.scan.sast.StaticHint;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Generic IDOR probe on id-bearing GET paths (no app-specific paths). For a captured
 * {@code GET /collection/<id>} it re-requests a NEIGHBORING id with our own session; if the server
 * returns a valid, DIFFERENT record, that's cross-tenant access (IDOR) — and its natural effect trips
 * "access another user's resource" challenges (e.g. viewing another basket). Read-only (GET only).
 */
public final class IdorGetProbe extends Probe {
    private static final Pattern NUM_TAIL = Pattern.compile("^(.*/)(\\d{1,7})$");
    /** A page-route tail (…/x.mvc, /x.lesson, /x.jsp, /x.php, /x.aspx, /x.action, …) is a ROUTE to a page, NOT an
     *  object reference. Treating one as an opaque object handle causes BOLA false positives on shared/public
     *  authenticated pages whose static content contains an example email (e.g. WebGoat lesson pages, all served
     *  identically to every logged-in user). Real object handles are numeric / hex / UUID / slugs — never a
     *  server-page extension. Data files (.pdf/.csv/…) are deliberately NOT excluded — those CAN be IDOR'd. */
    private static final Pattern PAGE_ROUTE = Pattern.compile("(?i)\\.(mvc|lesson|jsp|jspx|jsf|php|aspx?|html?|action|do|cgi|py|rb|pl)(?:$|[?#])");
    private static boolean isPageRoute(String url) { return url != null && PAGE_ROUTE.matcher(url).find(); }
    // OPAQUE (non-arithmetic) resource-key tail: /collection/<slug|username|email | ObjectId | UUID>. Neighbors
    // can't be computed for these, so candidate identities are sourced from the collection's OWN listing (generic,
    // not guessed). Covers a digit-leading 24-hex Mongo ObjectId and a UUID — which a letter-leading-only matcher
    // would miss (they match NEITHER the numeric nor the old string tail), making IDOR id-scheme-agnostic.
    private static final Pattern OPAQUE_TAIL = Pattern.compile(
            "^(https?://[^/]+/.+/)("
            + "[A-Za-z][A-Za-z0-9._@%-]{0,63}"                                                 // slug / username / email
            + "|[0-9a-fA-F]{24}"                                                               // Mongo ObjectId (24 hex)
            + "|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"   // UUID
            + ")$");
    // id-like string values in a collection-list JSON — the identities to try as the object key. Keys widened to
    // Mongo/NoSQL/UUID conventions (_id, $oid, objectId, uuid, guid, pk) so opaque ids are harvested, not just slugs.
    private static final Pattern LIST_ID  = Pattern.compile("(?i)\"(?:user(?:name)?|login|handle|slug|\\bid\\b|_id|\\$?oid|objectid|uuid|guid|pk|name|email|account)\"\\s*:\\s*\"([^\"\\n]{1,64})\"");
    // Per-user distinctive tokens used to CONFIRM a two-identity cross-user read: an email, or a long opaque id.
    private static final Pattern EMAIL_V = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern LONG_ID = Pattern.compile("\"([A-Za-z0-9]{12,64})\"");
    // A query param that names an OBJECT REFERENCE (report_id, order_id, user_id, id, videoId…) — the kind
    // that IDOR affects — as opposed to PAGINATION (which also carries numbers but is not an object ref).
    private static final Pattern ID_PARAM = Pattern.compile("(?i)(^id$|_id$|id$)");
    private static final Pattern PAGINATION = Pattern.compile("(?i)^(limit|offset|page|pageno|size|count|per_?page|start|skip|top|from|to)$");
    // Ownership / PII / private-object markers — require one in the returned records so we flag accessing
    // someone's PRIVATE object, not a public catalogue paged by a numeric key (keeps this FP-safe). Beyond
    // classic PII we accept unambiguous privacy/internal markers that never appear in a public catalogue:
    // privilege flags (is_admin/superuser/is_staff), ownership references (creator_id/author_id/owner_id) and
    // private financial fields (money_made/account_balance/salary) — generic, not app-specific field names.
    private static final Pattern TENANT_DATA = Pattern.compile("(?i)(\"?e-?mail\"?|\"?owner\"?|\"?user(name)?\"?|\\bvin\\b|first_?name|last_?name|address|phone|ssn|credit|is_?admin|\"admin\"|superuser|is_?staff|creator_?id|author_?id|owner_?id|money_?made|account_?balance|\\bsalary\\b)");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    // Static assets + API-spec documents are NOT per-user ownable objects — they are byte-identical for EVERY
    // authenticated caller by design, and specs embed EXAMPLE emails/owner fields. A slug-shaped filename like
    // openapi.json otherwise matches OPAQUE_TAIL and its example email matches TENANT_DATA → a bogus cross-user
    // "BOLA" (observed: GET /static/openapi.json flagged for two merchant identities). NOT a blanket .json ban
    // (real IDOR can live on a `.json` API route) — only asset DIRS, spec-named files, and spec-shaped bodies.
    private static final Pattern STATIC_OR_SPEC = Pattern.compile(
            "(?i)(^|/)(static|assets?|public|dist|build|_next|node_modules|vendor)(/|$)"     // asset directories
            + "|/(openapi|swagger|api-?docs)(\\.json|\\.ya?ml)?($|[/?#])"                    // API-spec docs by name
            + "|\\.(js|mjs|css|map|xml|txt|ico|wasm|woff2?|ttf|eot|svg|png|jpe?g|gif)($|[?#])"); // static file exts
    private static boolean isStaticOrSpec(String url, String body) {
        if (url != null && STATIC_OR_SPEC.matcher(url).find()) return true;
        if (body != null) {                                    // an OpenAPI/Swagger spec served off a plain path
            String head = body.length() > 400 ? body.substring(0, 400) : body;
            if (head.matches("(?s).*\"(openapi|swagger)\"\\s*:.*")) return true;
        }
        return false;
    }
    // Auth-flow pages are NOT ownable objects: an id-style tail like /Account/Login or /account/register must
    // never be treated as a per-tenant object, else the cross-identity read flags the SHARED public login page as
    // BOLA (observed: WebGoatCore /Account/Login). Skipped for every IDOR/BOLA branch.
    private static final Pattern AUTH_FLOW = Pattern.compile(
            "(?i)/(log-?in|log-?on|sign-?in|sign-?up|signup|signin|register|registration|log-?out|sign-?out|logout|signout)(/|$|\\.)");
    // Markers of a login / access-denied page returned to an UNAUTHENTICATED probe — proof the resource IS
    // access-controlled (so a login bounce is NOT mistaken for "public content"). MUST be tight: a bare
    // "Login"/"Sign in" word appears in the NAV BAR of essentially every page (incl. public ones), so matching it
    // wrongly marked a public /Product/Details catalogue as "protected" and defeated the FP gate. Require a real
    // login FORM (password input) or an explicit denial / "please log in to …" gate instead.
    private static final Pattern LOGIN_PAGE = Pattern.compile(
            "(?is)type\\s*=\\s*['\"]?password|\\b(unauthoriz|unauthorised|forbidden|access denied|not authori|"
            + "please (log|sign) ?in to|you must (log|sign) ?in|login required|authentication required)\\b");

    private SourceFindings sourceHints;   // optional SAST directives — only ADD coverage / provenance, never remove

    public IdorGetProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    /** Optional source-analysis directives: widen enumeration on source-flagged object-refs + tag provenance. */
    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    /** True if source analysis flagged an IDOR/object-ref at this url → enumerate a WIDER id set (additive). */
    private boolean idorHinted(String url) {
        return sourceHints != null && !sourceHints.isEmpty() && sourceHints.touches(url, "IDOR");
    }

    /** Provenance suffix for a confirmed finding when a matching source hint exists (else empty). */
    private String prov(String url) {
        if (sourceHints == null) return "";
        for (StaticHint h : sourceHints.all())
            if ("IDOR".equalsIgnoreCase(h.vulnClass) && (!h.hasEndpoint() || h.matchesUrl(url)))
                return "  " + h.provenance();
        return "";
    }

    public int probe(String host, String cookieHeader, String bearer) {
        return probe(host, cookieHeader, bearer, null, null, null);   // single-identity (backward-compatible)
    }

    public int probe(String host, String cookieHeader, String bearer, String cookieB, String bearerB) {
        return probe(host, cookieHeader, bearer, cookieB, bearerB, null);
    }

    /** @param cookieB,bearerB a SECOND distinct authenticated identity B (or null). When present, id-bearing objects
     *  identity A fetched are re-requested AS B (two-identity cross-user read).
     *  @param identityB B's OWN registered handle (or null). When present, the RIGOROUS test reads B's PROVABLY-OWN
     *  object {@code /root/{identityB}} AS A — B just registered it, so A receiving it is an unambiguous cross-user
     *  read that RULES OUT an intended public directory. */
    public int probe(String host, String cookieHeader, String bearer, String cookieB, String bearerB, String identityB) {
        int hits = 0;
        boolean haveB = (cookieB != null && !cookieB.isBlank()) || (bearerB != null && !bearerB.isBlank());
        Set<String> tried = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                if (!"GET".equals(req.method()) || rr.response() == null) continue;
                String url = req.url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                String base = url.split("\\?")[0];
                if (AUTH_FLOW.matcher(base).find()) continue;   // login/register/logout are not ownable objects
                // Static assets + API-spec docs (/static/…, openapi.json, swagger.json) are byte-identical for
                // EVERY authenticated caller by design and embed EXAMPLE emails/owner fields — a slug-shaped
                // filename matches OPAQUE_TAIL and the example email matches TENANT_DATA → a bogus cross-user
                // "BOLA" (observed: GET /static/openapi.json flagged for two merchant identities). Not ownable.
                if (isStaticOrSpec(base, rr.response().bodyToString())) continue;

                // (A00) RIGOROUS provably-owned cross-user read — runs BEFORE the A0 heuristic because it is the
                // STRONGEST (it rules out an intended public directory). For a string/handle-keyed endpoint, read B's
                // OWN object /root/{identityB} AS A: B just registered that account so the record is definitively B's.
                if (identityB != null && !identityB.isBlank()) {
                    java.util.regex.Matcher om = OPAQUE_TAIL.matcher(base);
                    if (om.matches() && !isPageRoute(base) && tried.add("rig:" + om.group(1))
                            && rigorousBOwnRead(om.group(1), identityB, cookieHeader, bearer, cookieB, bearerB, base)) {
                        hits++;
                        continue;   // definitive — skip the weaker heuristics for this url
                    }
                }

                // (A0) SECOND-IDENTITY cross-user read — the STRONGEST oracle. If THIS is an id-bearing private
                // object A fetched (numeric/ObjectId/UUID tail, A's body carries tenant data) and we hold a distinct
                // identity B, re-request the SAME url AS B. If B — a genuinely different registered user — receives
                // A's exact private record (matched by a per-user distinctive token), the endpoint enforces no
                // ownership check: a definitive cross-user read, no heuristic.
                if (haveB && !isPageRoute(base) && (NUM_TAIL.matcher(base).matches() || OPAQUE_TAIL.matcher(base).matches())
                        && tried.add("b:" + base)) {
                    String aBody = rr.response().bodyToString();
                    if (aBody != null && aBody.length() >= 20 && TENANT_DATA.matcher(aBody).find()) {
                        String token = distinctiveToken(aBody);
                        if (token != null) {
                            try {
                                HttpRequest g = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
                                if (cookieB != null && !cookieB.isBlank()) g = g.withHeader("Cookie", cookieB);
                                if (bearerB != null && !bearerB.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearerB);
                                HttpRequestResponse r = send(g);
                                if (r != null && r.response() != null && r.response().statusCode() == 200) {
                                    String bBody = r.response().bodyToString();
                                    if (bBody != null && bBody.contains(token) && !publiclyReadable(base)) {
                                        scanLog.found("Broken Object Level Authorization (BOLA)", base,
                                                "The SAME id-bearing object was returned to TWO DISTINCT authenticated identities — "
                                                + "identity A and a second, separately-registered user identity B — each receiving "
                                                + "the identical private record (matched the object's OWN owner identifier "
                                                + redact(token) + ", e.g. its email). Because the record self-identifies a specific "
                                                + "owner yet is readable by two different authenticated users (neither of whom is that "
                                                + "owner), the endpoint enforces NO per-object ownership check — Broken Object Level "
                                                + "Authorization (CWE-639). (If this endpoint is instead an intended public "
                                                + "authenticated directory, it is at minimum excessive exposure of another tenant's PII.) "
                                                + "Evidence: identity A's response, then identity B's response for the SAME object." + prov(base),
                                                rr, r);
                                        scanLog.incFinding();
                                        hits++;
                                        continue;   // strongest evidence for this url — skip the heuristic enumeration
                                    }
                                }
                            } catch (Throwable ignore) { }
                        }
                    }
                }

                // (B) QUERY-PARAM IDOR: an object-reference id in the query string (crАПI
                // mechanic_report?report_id=N → other users' reports). If sequential ids return DIFFERENT
                // valid records that carry ownership/PII, the endpoint serves arbitrary objects with no
                // ownership check. Gated to object-ref param names (not pagination) + tenant-data markers.
                if (req.hasParameters()) {
                    for (ParsedHttpParameter p : req.parameters()) {
                        if (p.type() != HttpParameterType.URL) continue;
                        if (!ID_PARAM.matcher(p.name()).find() || PAGINATION.matcher(p.name()).matches()) continue;
                        if (!tried.add("q:" + base + "?" + p.name())) continue;
                        Set<String> distinct = new LinkedHashSet<>();
                        boolean tenant = false;
                        HttpRequestResponse evidence = null;
                        long[] ids = idorHinted(base) ? new long[]{ 1, 2, 3, 4, 5 } : new long[]{ 1, 2, 3 };
                        for (long other : ids) {
                            try {
                                HttpRequest g = req.withUpdatedParameters(
                                        HttpParameter.parameter(p.name(), String.valueOf(other), HttpParameterType.URL));
                                if (cookieHeader != null && !cookieHeader.isBlank()) g = g.withHeader("Cookie", cookieHeader);
                                if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
                                HttpRequestResponse r = send(g);
                                if (r == null || r.response() == null || r.response().statusCode() != 200) continue;
                                String b = r.response().bodyToString();
                                if (b == null || b.length() < 40 || b.toLowerCase().contains("\"error\"")) continue;
                                // Require a STRUCTURED-DATA (JSON) response: a real object/record endpoint returns
                                // JSON. This excludes source-viewers / HTML pages that merely render different text
                                // per id (e.g. DVWA's source/info.php?id= viewer), which are not object references.
                                String t = b.trim();
                                if (!t.startsWith("{") && !t.startsWith("[")) continue;
                                distinct.add(b);
                                if (TENANT_DATA.matcher(b).find()) { tenant = true; if (evidence == null) evidence = r; }
                            } catch (Throwable ignore) { }
                        }
                        if (distinct.size() >= 2 && tenant) {
                            scanLog.found("Insecure Direct Object Reference (IDOR)", base,
                                    p.name() + "= enumerated → distinct tenant records returned (no ownership check)" + prov(base),
                                    evidence);
                            scanLog.incFinding();
                            hits++;
                        }
                    }
                }

                // (C) STRING-keyed BOLA: /collection/<identity> where the id is a username/slug/email (VAmPI
                // /users/v1/{username}, crAPI email-keyed). Numeric neighbors don't apply — SOURCE candidate
                // identities from the collection's own list response, then confirm cross-tenant access exactly
                // like the numeric branch (same TENANT_DATA gate ⇒ zero-FP). Gated to a record that itself
                // carries tenant data so we only enumerate real private-object endpoints.
                java.util.regex.Matcher sm = OPAQUE_TAIL.matcher(base);
                if (sm.matches() && !isPageRoute(base) && tried.add("str:" + base)) {
                    String selfBody = rr.response().bodyToString();
                    if (selfBody != null && selfBody.length() >= 20 && TENANT_DATA.matcher(selfBody).find()) {
                        String root = sm.group(1), self = sm.group(2);
                        for (String other : harvestIds(root, self, cookieHeader, bearer)) {
                            try {
                                HttpRequest g = HttpRequest.httpRequestFromUrl(root + other).withMethod("GET");
                                if (cookieHeader != null && !cookieHeader.isBlank()) g = g.withHeader("Cookie", cookieHeader);
                                if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
                                HttpRequestResponse r = send(g);
                                if (r == null || r.response() == null) continue;
                                String b = r.response().bodyToString();
                                if (r.response().statusCode() == 200 && b != null && b.length() > 20 && !b.equals(selfBody)
                                        && !b.toLowerCase().contains("error") && TENANT_DATA.matcher(b).find()
                                        && !publiclyReadable(base)) {
                                    scanLog.found("Insecure Direct Object Reference (IDOR)", base,
                                            "identity '" + self + "' → '" + other + "' returned another user's private "
                                            + "record using the SAME session — an object keyed by an enumerable identity "
                                            + "with no ownership check (BOLA, CWE-639). Candidate identities were sourced "
                                            + "from the collection's own listing." + prov(base),
                                            rr, r);
                                    scanLog.incFinding();
                                    hits++;
                                    break;
                                }
                            } catch (Throwable ignore) { }
                        }
                    }
                }

                java.util.regex.Matcher m = NUM_TAIL.matcher(base);
                if (!m.matches()) continue;                       // only /…/<numeric id>
                if (!tried.add(base)) continue;
                String origBody = rr.response().bodyToString();
                if (origBody == null || origBody.length() < 20) continue;
                long id = Long.parseLong(m.group(2));
                long[] neighbors = idorHinted(base)
                        ? new long[]{ id + 1, id - 1, id + 2, id - 2, 1, 2, 3 }   // source-flagged → probe wider
                        : new long[]{ id + 1, id - 1, 1, 2 };
                for (long other : neighbors) {
                    if (other <= 0 || other == id) continue;
                    String target = m.group(1) + other;
                    try {
                        HttpRequest g = HttpRequest.httpRequestFromUrl(target).withMethod("GET");
                        if (cookieHeader != null && !cookieHeader.isBlank()) g = g.withHeader("Cookie", cookieHeader);
                        if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
                        HttpRequestResponse r = send(g);
                        if (r == null || r.response() == null) continue;
                        String b = r.response().bodyToString();
                        // valid (200), non-trivial, DIFFERENT from our own record, AND carrying ownership/PII
                        // markers → another tenant's private object. The TENANT_DATA gate (same one the
                        // query-param branch uses) is essential: without it ANY numeric path segment whose
                        // output varies with the number trips a FP — e.g. /uptime/{flag} (a command arg, not
                        // an object id) returns different text per value but has no tenant data. Zero-FP.
                        if (r.response().statusCode() == 200 && b.length() > 20 && !b.equals(origBody)
                                && !b.toLowerCase().contains("error") && TENANT_DATA.matcher(b).find()
                                && !sameOwnerObject(origBody, b)   // neighbor owned by the SAME principal (your own object) → not IDOR
                                && !publiclyReadable(base)) {
                            scanLog.found("Insecure Direct Object Reference (IDOR)", base,
                                    "id " + id + " → " + other + " returned a different record with tenant/PII data "
                                    + "using the SAME session — evidence: your own object (id " + id + ") and another "
                                    + "tenant's object (id " + other + ") both accessible with your credential (no "
                                    + "ownership check). Attached: the cross-tenant request/response." + prov(base),
                                    rr, r);   // your record, then the other tenant's record fetched with your session
                            scanLog.incFinding();
                            hits++;
                            break;
                        }
                    } catch (Throwable ignore) { }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("IDOR probe error: " + t);
        }
        return hits;
    }

    /** Fetch the collection root's listing with our session and harvest candidate identities to try as the object
     *  key — the app's OWN published ids, never guessed (keeps it generic + FP-safe). Excludes the current id. */
    private java.util.List<String> harvestIds(String root, String self, String cookie, String bearer) {
        java.util.LinkedHashSet<String> ids = new java.util.LinkedHashSet<>();
        try {
            String listUrl = root.replaceAll("/+$", "");          // collection root (drop trailing slash)
            HttpRequest g = HttpRequest.httpRequestFromUrl(listUrl).withMethod("GET");
            if (cookie != null && !cookie.isBlank()) g = g.withHeader("Cookie", cookie);
            if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
            HttpRequestResponse r = send(g);
            if (r != null && r.response() != null && r.response().statusCode() == 200) {
                String body = r.response().bodyToString();
                if (body != null) {
                    java.util.regex.Matcher m = LIST_ID.matcher(body);
                    while (m.find() && ids.size() < 6) {
                        String v = m.group(1);
                        if (v != null && !v.equalsIgnoreCase(self) && v.matches("[A-Za-z0-9][A-Za-z0-9._@%-]{0,63}")) ids.add(v);
                    }
                }
            }
        } catch (Throwable ignore) { }
        return new java.util.ArrayList<>(ids);
    }

    /** A per-user distinctive token from a private object body — an email, else a long opaque id — used to confirm a
     *  two-identity cross-user read (B's response containing A's token ⇒ B received A's exact object). Null if none. */
    private String distinctiveToken(String body) {
        if (body == null) return null;
        java.util.regex.Matcher e = EMAIL_V.matcher(body);
        if (e.find()) return e.group();
        java.util.regex.Matcher l = LONG_ID.matcher(body);
        if (l.find()) return l.group(1);
        return null;
    }

    /** Redact a private token for the finding text (never leak the full private value). */
    private static String redact(String t) {
        if (t == null || t.isEmpty()) return "'…'";
        int at = t.indexOf('@');
        if (at > 0) return "'" + t.charAt(0) + "…@" + t.substring(at + 1) + "'";   // a…@example.com
        return "'" + t.substring(0, Math.min(2, t.length())) + "…' (" + t.length() + " chars)";
    }

    /** True when {@code url} returns real (non-login) content to an UNAUTHENTICATED client — i.e. a PUBLIC
     *  resource, so serving different ids to different users is NOT an access-control flaw. This is the gate that
     *  kills IDOR/BOLA false positives on public catalogues + description pages (VulnLab /vuln/{id} challenge
     *  pages whose prose merely contains words like "user"/"owner"/"address"; a public /Product/Details catalogue).
     *  CONSERVATIVE — returns false (⇒ KEEP the finding) on any error / non-2xx / empty body / login-or-deny page,
     *  so a genuinely access-controlled object is never suppressed. */
    // Owner-object comparison for the single-identity numeric tier: does the neighbor belong to the SAME principal
    // as the base record (the caller's OWN sequential object), rather than a different tenant? Compares only
    // OWNER-identifying fields (merchant_id/owner_id/user_id/account_id/tenant_id/*_email/*_name) — NOT the bare
    // id/email a "looked_up_by"/debug echo of the CALLER also carries. Every owner field present in BOTH holding
    // the SAME value → same owner → suppress; any owner field DIFFERS → genuine cross-tenant read → flag. Fixes
    // the FP where /payments/812 and /payments/813 are both the caller's own (merchant_id 53).
    private static final Pattern OWNER_KV = Pattern.compile(
            "(?i)\"((?:merchant|owner|user|account|tenant|creator|author|customer)_?(?:id|email|name|number))\"\\s*:\\s*\"?([^\",}\\s]{1,128})");
    private static java.util.Map<String, String> ownerKv(String body) {
        java.util.Map<String, String> m = new java.util.HashMap<>();
        java.util.regex.Matcher mm = OWNER_KV.matcher(body);
        while (mm.find()) {
            String k = mm.group(1).toLowerCase().replace("_", ""), v = mm.group(2);
            if (v != null && !v.isBlank() && !"null".equalsIgnoreCase(v)) m.putIfAbsent(k, v);
        }
        return m;
    }
    private static boolean sameOwnerObject(String a, String b) {
        if (a == null || b == null) return false;
        java.util.Map<String, String> oa = ownerKv(a), ob = ownerKv(b);
        boolean anyCommon = false;
        for (java.util.Map.Entry<String, String> e : oa.entrySet()) {
            String bv = ob.get(e.getKey());
            if (bv == null) continue;
            anyCommon = true;
            if (!bv.equalsIgnoreCase(e.getValue())) return false;   // an owner field differs → different principal
        }
        return anyCommon;   // shared owner field(s), all equal → same principal
    }

    private boolean publiclyReadable(String url) {
        try {
            HttpRequest bare = HttpRequest.httpRequestFromUrl(url).withMethod("GET");   // NO Cookie / Authorization
            HttpRequestResponse r = send(bare);
            if (r == null || r.response() == null) return false;
            int sc = r.response().statusCode();
            if (sc < 200 || sc >= 300) return false;               // unauth denied / redirected → access-controlled → real
            String b = r.response().bodyToString();
            if (b == null || b.length() < 20) return false;        // empty / stub → treat as protected
            return !LOGIN_PAGE.matcher(b).find();                  // login/deny page → protected; real content → PUBLIC
        } catch (Throwable t) { return false; }
    }

    /** RIGOROUS cross-user read: identity B's PROVABLY-OWN object ({@code root}+{@code identityB}) is read AS A. B just
     *  registered, so that record is definitively B's private data; A (a different user) receiving it — confirmed by
     *  A's response carrying B's unique handle — is an unambiguous BOLA that rules out an intended public directory. */
    private boolean rigorousBOwnRead(String root, String identityB, String cookieA, String bearerA,
                                     String cookieB, String bearerB, String reportUrl) {
        try {
            String bOwnUrl = root + identityB;
            // 1) B reads its OWN object — confirm it exists and is B's (200 + mentions B's handle).
            HttpRequestResponse asB = get(bOwnUrl, cookieB, bearerB);
            if (asB == null || asB.response() == null || asB.response().statusCode() != 200) return false;
            String bBody = asB.response().bodyToString();
            if (bBody == null || bBody.length() < 20 || !bBody.contains(identityB)) return false;
            // 2) A reads B's OWN object — if A gets B's record (carries B's unique handle) it is a definitive
            //    cross-user read. If the server returned A's OWN object instead, it would NOT contain B's handle.
            HttpRequestResponse asA = get(bOwnUrl, cookieA, bearerA);
            if (asA == null || asA.response() == null || asA.response().statusCode() != 200) return false;
            String aBody = asA.response().bodyToString();
            if (aBody == null || aBody.toLowerCase().contains("\"error\"") || !aBody.contains(identityB)) return false;
            scanLog.found("Broken Object Level Authorization (BOLA)", reportUrl,
                    "Identity A read identity B's PROVABLY-OWN object (" + root + redactId(identityB) + "): B had just "
                  + "registered that account, so the record is definitively B's private data, yet A — a DIFFERENT "
                  + "authenticated user — retrieved it in full (A's response carries B's unique handle). This rules out "
                  + "an intended public directory: it is an unambiguous cross-user object read with no per-object "
                  + "ownership check (BOLA, CWE-639). Evidence: B's own response for its object, then A's cross-user "
                  + "response for the SAME object." + prov(reportUrl),
                    asB, asA);
            scanLog.incFinding();
            return true;
        } catch (Throwable t) { scanLog.debug("rigorous BOLA read error: " + t); return false; }
    }

    private HttpRequestResponse get(String url, String cookie, String bearer) {
        try {
            HttpRequest g = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (cookie != null && !cookie.isBlank()) g = g.withHeader("Cookie", cookie);
            if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
            return send(g);
        } catch (Throwable t) { return null; }
    }

    private static String redactId(String id) {
        if (id == null || id.length() <= 5) return "{id}";
        return "{" + id.substring(0, 5) + "…}";
    }

    // hostOf(String) inherited from Probe.
}
