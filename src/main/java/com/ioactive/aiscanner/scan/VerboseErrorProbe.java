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
 *   <li><b>Active</b> — POST a deliberately-malformed JSON body ({@code {}}) to discovered page-method /
 *       service-method endpoints ({@code …/x.aspx/Method}, {@code …/x.asmx/Method}, {@code …/x.ashx}) — the shape
 *       that reliably trips a framework error path — and confirm the same oracle, re-sent once.</li>
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
    private static final int MAX_ACTIVE = 40;    // cap active malformed sends per host (a big site map is bounded)

    VerboseErrorProbe(MontoyaApi api, ScanLog scanLog) { this.api = api; this.scanLog = scanLog; }

    /** Run once per host. Returns the finding count (0 or 1 — one systemic issue per host). */
    int probe(String host, UnaryOperator<HttpRequest> withSession) {
        Set<String> inScope = new LinkedHashSet<>();
        Map<String, HttpRequestResponse> leaks = new LinkedHashMap<>();   // endpoint → evidence rr

        // (1) passive: existing site-map responses that already leak a stack trace.
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.request() == null) continue;
                String url = rr.request().url();
                if (!inScope(host, url)) continue;
                String key = stripQuery(url);
                inScope.add(key);
                if (!leaks.containsKey(key) && StackTraceOracle.hasStackTrace(rr)) leaks.put(key, rr);
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner]   verbose-error site-map scan error: " + t); }

        // (2) active: malformed POST to page-method-shaped endpoints not already flagged.
        int sent = 0;
        for (String url : inScope) {
            if (sent >= MAX_ACTIVE) break;
            if (leaks.containsKey(url)) continue;
            if (!PAGE_METHOD.matcher(pathOf(url)).find()) continue;
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
        List<String> endpoints = new ArrayList<>(leaks.keySet());
        String primary = endpoints.get(0);
        // Systemic class — one issue per host. If SamlProbe already claimed it, just note the extra endpoints.
        if (!scanLog.firstForHost("Stack trace disclosure", primary)) {
            scanLog.log("[AI Scanner] verbose-error probe: stack-trace disclosure already reported for this host; "
                    + "also affected: " + preview(endpoints));
            return 0;
        }
        String detail = "The application returns a framework stack trace on malformed input, leaking exception types, "
                + "class/method names, framework version and internal paths (CWE-209). This is a host-wide verbose-error "
                + "misconfiguration (e.g. ASP.NET customErrors Off), reproducible across multiple endpoints — not a "
                + "single page. Affected endpoint(s): " + preview(endpoints) + ". Re-confirmed.";
        scanLog.found("Stack trace disclosure", primary, detail, leaks.get(primary));
        scanLog.incFinding();
        scanLog.log("[AI Scanner] verbose-error probe: stack-trace disclosure @ " + endpoints.size() + " endpoint(s).");
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

    private static String preview(List<String> endpoints) {
        int n = Math.min(endpoints.size(), 8);
        String s = String.join(", ", endpoints.subList(0, n));
        return endpoints.size() > n ? s + " (+" + (endpoints.size() - n) + " more)" : s;
    }
    private static String hostOf(String url) { try { return URI.create(url).getHost(); } catch (Exception e) { return null; } }
    private static String stripQuery(String url) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    private static String pathOf(String url) { try { String p = URI.create(url).getPath(); return p == null ? "" : p; } catch (Exception e) { return url; } }
}
