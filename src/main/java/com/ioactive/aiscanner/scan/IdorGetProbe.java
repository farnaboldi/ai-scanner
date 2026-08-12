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
        int hits = 0;
        Set<String> tried = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                if (!"GET".equals(req.method()) || rr.response() == null) continue;
                String url = req.url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                String base = url.split("\\?")[0];

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

    private static String hostOf(String url) {
        try { return URI.create(url).getHost(); } catch (Exception e) { return ""; }
    }
}
