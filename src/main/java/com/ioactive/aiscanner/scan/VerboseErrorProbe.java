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
import java.util.regex.Pattern;

/**
 * Generic verbose-error / stack-trace disclosure probe. ASP.NET (and most frameworks) return a full stack trace on
 * malformed input when custom errors are Off/RemoteOnly-broken — a systemic misconfiguration, not an endpoint-specific
 * bug. This probe surfaces it host-wide and zero-FP:
 * <ol>
 *   <li><b>Passive</b> — scan every in-scope site-map response for the strong {@link StackTraceOracle} markers
 *       (no extra traffic; catches whatever already leaked during crawl/audit/other probes).</li>
 *   <li><b>Active</b> — POST a deliberately-malformed JSON body ({@code {}}, i.e. missing required fields) to
 *       discovered page-method / service-method endpoints ({@code …/x.aspx/Method}, {@code …/x.asmx/Method},
 *       {@code …/x.ashx}) AND rest/JSON Web-API routes ({@code /rest|/api|/odata/…} or any endpoint that spoke
 *       {@code application/json}) — the shape that reliably trips a framework model-binding / validation error path
 *       — and confirm the same oracle, re-sent once. Clearly state-changing verbs (delete/transfer/…) are skipped
 *       so the fuzz stays non-destructive.</li>
 * </ol>
 * Fires ONCE per host (via {@link ScanLog#firstForHost}), listing every leaking endpoint in the evidence, so it never
 * near-dupes {@link SamlProbe}'s SAML-route finding. Non-destructive (a single malformed read per endpoint). Generic:
 * detection is by response shape and endpoint shape only — no vendor/app-specific paths.
 */
final class VerboseErrorProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    /** ASP.NET page-method / service-handler shapes whose error path a malformed JSON body reliably trips. */
    private static final Pattern PAGE_METHOD = Pattern.compile("(?i)\\.(aspx|asmx|ashx)/[a-z][\\w]*$");
    /** REST / Web-API path shapes (ASP.NET Web API, WCF, etc.) — the JSON layer page-methods miss. */
    private static final Pattern REST_API_PATH = Pattern.compile("(?i)(^|/)(rest|api|odata|services?)/");
    /** State-changing verbs to NEVER fuzz (non-destructive engagement): a malformed body could still trigger an
     *  irreversible action. Deliberately narrow — `{}` (missing required fields) fails validation before acting on
     *  reset/send/save/create endpoints, so those stay testable; only clearly-irreversible verbs are skipped. */
    private static final Pattern UNSAFE_PATH = Pattern.compile(
            "(?i)(delete|remove|purge|destroy|\\bdrop\\b|wipe|deactivate|disable|revoke|transfer|withdraw|payment|logout|signout|signoff)");
    private static final int MAX_ACTIVE = 60;    // cap active malformed sends per host (a big site map is bounded)
    private static final int MAX_EVIDENCE = 10;  // cap request/response tabs attached to the one host-wide issue

    VerboseErrorProbe(MontoyaApi api, ScanLog scanLog) { this.api = api; this.scanLog = scanLog; }

    /** Run once per host. Returns the finding count (0 or 1 — one systemic issue per host). */
    int probe(String host, UnaryOperator<HttpRequest> withSession) {
        Set<String> inScope = new LinkedHashSet<>();
        Set<String> fuzzTargets = new LinkedHashSet<>();   // page-method + rest/JSON-API endpoints to malform-fuzz
        Map<String, HttpRequestResponse> leaks = new LinkedHashMap<>();   // endpoint → evidence rr

        // (1) passive: existing site-map responses that already leak a stack trace; also classify fuzz targets
        //     (page-methods by URL shape, rest/JSON-API by /rest|/api path OR an application/json content-type).
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.request() == null) continue;
                String url = rr.request().url();
                if (!inScope(host, url)) continue;
                String key = stripQuery(url);
                inScope.add(key);
                if (!leaks.containsKey(key) && StackTraceOracle.hasStackTrace(rr)) leaks.put(key, rr);
                if (PAGE_METHOD.matcher(pathOf(key)).find() || isJsonApi(key, rr)) fuzzTargets.add(key);
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner]   verbose-error site-map scan error: " + t); }

        // (2) active: POST a malformed body ({} → missing required fields) to page-method + rest/JSON-API endpoints
        //     not already flagged, skipping clearly state-changing verbs (non-destructive). Fire on the strong
        //     oracle, re-confirmed. `{}` trips the framework's model-binding / parameter-validation error path.
        long restCount = fuzzTargets.stream().filter(u -> REST_API_PATH.matcher(pathOf(u)).find()).count();
        scanLog.log("[AI Scanner] verbose-error probe: " + fuzzTargets.size() + " malformed-body target(s) ("
                + restCount + " rest/API-path) + " + leaks.size() + " already-leaking from passive scan.");
        int sent = 0;
        for (String url : fuzzTargets) {
            if (sent >= MAX_ACTIVE) break;
            if (leaks.containsKey(url)) continue;
            if (UNSAFE_PATH.matcher(pathOf(url)).find()) { scanLog.debug("[AI Scanner]   verbose-error: skip state-changing endpoint " + url); continue; }
            sent++;
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                        .withUpdatedHeader("Content-Type", "application/json")
                        .withUpdatedHeader("X-Requested-With", "XMLHttpRequest")
                        .withBody("{}");
                HttpRequestResponse rr = send(withSession != null ? withSession.apply(req) : req);
                if (!StackTraceOracle.hasStackTrace(rr)) continue;
                HttpRequestResponse rr2 = send(withSession != null ? withSession.apply(req) : req);   // re-confirm (zero-FP)
                if (!StackTraceOracle.hasStackTrace(rr2)) continue;
                leaks.put(url, rr);
            } catch (Throwable ignore) { }
        }

        if (leaks.isEmpty()) {
            scanLog.log("[AI Scanner] verbose-error probe: no stack-trace disclosure found.");
            return 0;
        }
        // Rank leaking endpoints by disclosure severity (a DB-schema/SQL leak reveals far more than a bare framework
        // trace), stable within a tier, so the MOST DAMAGING artifact anchors the finding and is the first evidence
        // tab. Generic — the ranking is by response shape only, no app/vendor knowledge.
        List<String> endpoints = new ArrayList<>(leaks.keySet());
        endpoints.sort((a, b) -> Integer.compare(
                StackTraceOracle.disclosureSeverity(leaks.get(b)), StackTraceOracle.disclosureSeverity(leaks.get(a))));
        String primary = endpoints.get(0);
        // Systemic class — one issue per host. If SamlProbe already claimed it, just note the extra endpoints.
        if (!scanLog.firstForHost("Stack trace disclosure", primary)) {
            scanLog.log("[AI Scanner] verbose-error probe: stack-trace disclosure already reported for this host; "
                    + "also affected: " + preview(endpoints));
            return 0;
        }
        // Aggregate the CONCRETE artifacts each error disclosed (DB objects, internal paths, code frames, versions)
        // so the finding shows WHAT leaked, not just that something did — deduped + bounded across endpoints.
        Set<String> artifacts = new LinkedHashSet<>();
        boolean anyDb = false;
        for (String ep : endpoints) {
            artifacts.addAll(StackTraceOracle.leakedArtifacts(leaks.get(ep)));
            anyDb |= StackTraceOracle.leaksDbSchema(leaks.get(ep));
        }
        String detail = "The application returns a framework stack trace on malformed input, leaking exception types, "
                + "class/method names, framework version and internal paths (CWE-209). This is a host-wide verbose-error "
                + "misconfiguration (e.g. ASP.NET customErrors Off), reproducible across multiple endpoints and layers "
                + "(page-methods, ASMX, and rest/JSON Web-API routes) — not a single page."
                + (anyDb ? " At least one endpoint additionally leaks DATABASE SCHEMA / SQL error text (database, table "
                        + "and/or column names, and the data-access stack), which materially aids SQL-injection targeting "
                        + "and data-model reconnaissance." : "")
                + " Affected endpoint(s): " + preview(endpoints) + "."
                + (artifacts.isEmpty() ? "" : " Leaked artifacts observed: " + previewN(new ArrayList<>(artifacts), 14) + ".")
                + " Re-confirmed.";
        // Attach EVERY leaking request/response (most-severe first) so Burp shows one evidence tab per endpoint —
        // the SQL/DB-schema disclosure leads, not whichever endpoint the crawl happened to hit first.
        List<HttpRequestResponse> evidence = new ArrayList<>();
        for (String ep : endpoints) {
            if (evidence.size() >= MAX_EVIDENCE) break;
            HttpRequestResponse rr = leaks.get(ep);
            if (rr != null) evidence.add(rr);
        }
        scanLog.found("Stack trace disclosure", primary, detail, evidence.toArray(new HttpRequestResponse[0]));
        scanLog.incFinding();
        scanLog.log("[AI Scanner] verbose-error probe: stack-trace disclosure @ " + endpoints.size() + " endpoint(s)"
                + (anyDb ? " (incl. DB-schema leak)" : "") + "; " + evidence.size() + " evidence artifact(s) attached.");
        return 1;
    }

    // ------------------------------------------------------------------ helpers (mirror SamlProbe idioms)

    private HttpRequestResponse send(HttpRequest req) {
        try {
            return AiScanner.decompress(api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(15000L)));
        } catch (Throwable t) { return null; }
    }

    private boolean inScope(String host, String url) {
        try { if (!api.scope().isInScope(url)) return false; } catch (Throwable ignore) { }
        return host == null || host.equalsIgnoreCase(hostOf(url));
    }

    /** A rest/JSON-API endpoint: a /rest|/api|/odata|/services path segment, OR a request/response that
     *  advertised an application/json content-type (so we only fuzz things that actually speak JSON). */
    private static boolean isJsonApi(String url, HttpRequestResponse rr) {
        if (REST_API_PATH.matcher(pathOf(url)).find()) return true;
        try {
            if (rr.request() != null && ctHasJson(rr.request().headers())) return true;
            if (rr.response() != null && ctHasJson(rr.response().headers())) return true;
        } catch (Throwable ignore) { }
        return false;
    }
    private static boolean ctHasJson(java.util.List<burp.api.montoya.http.message.HttpHeader> headers) {
        if (headers == null) return false;
        for (burp.api.montoya.http.message.HttpHeader h : headers) {
            if ("Content-Type".equalsIgnoreCase(h.name()) && h.value() != null
                    && h.value().toLowerCase().contains("json")) return true;
        }
        return false;
    }

    private static String preview(List<String> endpoints) { return previewN(endpoints, 8); }
    private static String previewN(List<String> items, int cap) {
        int n = Math.min(items.size(), cap);
        String s = String.join(", ", items.subList(0, n));
        return items.size() > n ? s + " (+" + (items.size() - n) + " more)" : s;
    }
    private static String hostOf(String url) { try { return URI.create(url).getHost(); } catch (Exception e) { return null; } }
    private static String stripQuery(String url) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    private static String pathOf(String url) { try { String p = URI.create(url).getPath(); return p == null ? "" : p; } catch (Exception e) { return url; } }
}
