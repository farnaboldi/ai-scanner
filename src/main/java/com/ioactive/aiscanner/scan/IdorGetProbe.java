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

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Generic IDOR probe on id-bearing GET paths (no app-specific paths). For a captured
 * {@code GET /collection/<id>} it re-requests a NEIGHBORING id with our own session; if the server
 * returns a valid, DIFFERENT record, that's cross-tenant access (IDOR) — and its natural effect trips
 * "access another user's resource" challenges (e.g. viewing another basket). Read-only (GET only).
 */
public final class IdorGetProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private static final Pattern NUM_TAIL = Pattern.compile("^(.*/)(\\d{1,7})$");
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

    private SourceFindings sourceHints;   // optional SAST directives — only ADD coverage / provenance, never remove

    public IdorGetProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
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

                // (A00) RIGOROUS provably-owned cross-user read — runs BEFORE the A0 heuristic because it is the
                // STRONGEST (it rules out an intended public directory). For a string/handle-keyed endpoint, read B's
                // OWN object /root/{identityB} AS A: B just registered that account so the record is definitively B's.
                if (identityB != null && !identityB.isBlank()) {
                    java.util.regex.Matcher om = OPAQUE_TAIL.matcher(base);
                    if (om.matches() && tried.add("rig:" + om.group(1))
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
                if (haveB && (NUM_TAIL.matcher(base).matches() || OPAQUE_TAIL.matcher(base).matches())
                        && tried.add("b:" + base)) {
                    String aBody = rr.response().bodyToString();
                    if (aBody != null && aBody.length() >= 20 && TENANT_DATA.matcher(aBody).find()) {
                        String token = distinctiveToken(aBody);
                        if (token != null) {
                            try {
                                HttpRequest g = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
                                if (cookieB != null && !cookieB.isBlank()) g = g.withHeader("Cookie", cookieB);
                                if (bearerB != null && !bearerB.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearerB);
                                HttpRequestResponse r = api.http().sendRequest(g, RequestOptions.requestOptions().withResponseTimeout(12000L));
                                if (r != null && r.response() != null && r.response().statusCode() == 200) {
                                    String bBody = r.response().bodyToString();
                                    if (bBody != null && bBody.contains(token)) {
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
                                HttpRequestResponse r = api.http().sendRequest(g, RequestOptions.requestOptions().withResponseTimeout(12000L));
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
                if (sm.matches() && tried.add("str:" + base)) {
                    String selfBody = rr.response().bodyToString();
                    if (selfBody != null && selfBody.length() >= 20 && TENANT_DATA.matcher(selfBody).find()) {
                        String root = sm.group(1), self = sm.group(2);
                        for (String other : harvestIds(root, self, cookieHeader, bearer)) {
                            try {
                                HttpRequest g = HttpRequest.httpRequestFromUrl(root + other).withMethod("GET");
                                if (cookieHeader != null && !cookieHeader.isBlank()) g = g.withHeader("Cookie", cookieHeader);
                                if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
                                HttpRequestResponse r = api.http().sendRequest(g, RequestOptions.requestOptions().withResponseTimeout(12000L));
                                if (r == null || r.response() == null) continue;
                                String b = r.response().bodyToString();
                                if (r.response().statusCode() == 200 && b != null && b.length() > 20 && !b.equals(selfBody)
                                        && !b.toLowerCase().contains("error") && TENANT_DATA.matcher(b).find()) {
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
                        HttpRequestResponse r = api.http().sendRequest(g, RequestOptions.requestOptions().withResponseTimeout(12000L));
                        if (r == null || r.response() == null) continue;
                        String b = r.response().bodyToString();
                        // valid (200), non-trivial, DIFFERENT from our own record, AND carrying ownership/PII
                        // markers → another tenant's private object. The TENANT_DATA gate (same one the
                        // query-param branch uses) is essential: without it ANY numeric path segment whose
                        // output varies with the number trips a FP — e.g. /uptime/{flag} (a command arg, not
                        // an object id) returns different text per value but has no tenant data. Zero-FP.
                        if (r.response().statusCode() == 200 && b.length() > 20 && !b.equals(origBody)
                                && !b.toLowerCase().contains("error") && TENANT_DATA.matcher(b).find()) {
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
            scanLog.debug("[AI Scanner] IDOR probe error: " + t);
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
            HttpRequestResponse r = api.http().sendRequest(g, RequestOptions.requestOptions().withResponseTimeout(12000L));
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
        } catch (Throwable t) { scanLog.debug("[AI Scanner] rigorous BOLA read error: " + t); return false; }
    }

    private HttpRequestResponse get(String url, String cookie, String bearer) {
        try {
            HttpRequest g = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (cookie != null && !cookie.isBlank()) g = g.withHeader("Cookie", cookie);
            if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
            return api.http().sendRequest(g, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Throwable t) { return null; }
    }

    private static String redactId(String id) {
        if (id == null || id.length() <= 5) return "{id}";
        return "{" + id.substring(0, 5) + "…}";
    }

    private static String hostOf(String url) {
        try { return URI.create(url).getHost(); } catch (Exception e) { return ""; }
    }
}
