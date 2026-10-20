package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The ONE door every request this extension sends goes through (every former {@code api.http().sendRequest(..)}
 * call site routes here). It enforces {@link WriteGuard#blocksDestructiveVerb}: a DELETE or PATCH (including a
 * method-override equivalent) is never put on the wire. A blocked send returns a request/response pair with no
 * response — the same shape Burp returns for a failed send, which every caller already treats as "no evidence".
 */
public final class SafeHttp {

    private static volatile ScanLog log;
    private static final Set<String> noted = ConcurrentHashMap.newKeySet();
    private static final AtomicInteger blocked = new AtomicInteger();
    private static final AtomicInteger droppedTargets = new AtomicInteger();

    private SafeHttp() { }

    public static void setLog(ScanLog scanLog) { log = scanLog; }

    public static HttpRequestResponse sendRequest(MontoyaApi api, HttpRequest req) {
        if (WriteGuard.blocksDestructiveVerb(req)) return refuse(req, "send");
        return api.http().sendRequest(req);
    }

    public static HttpRequestResponse sendRequest(MontoyaApi api, HttpRequest req, RequestOptions options) {
        if (WriteGuard.blocksDestructiveVerb(req)) return refuse(req, "send");
        return api.http().sendRequest(req, options);
    }

    /** Log a refused DELETE/PATCH once per method+path (and count every refusal). {@code where} names the path
     *  that tried it, e.g. "send" or "native audit". */
    public static void noteBlocked(HttpRequest req, String where) {
        blocked.incrementAndGet();
        String m = req == null ? "?" : WriteGuard.effectiveMethod(req);
        String path = req == null ? "?" : Net.stripQuery(req.url());
        if (!noted.add(where + " " + m + " " + path)) return;
        ScanLog l = log;
        if (l != null) l.log("[verb-guard] NOT sent (" + where + "): " + m + " " + path
                + " — DELETE/PATCH/MERGE are disabled (AISCANNER_ALLOW_DELETE_PATCH=1 applies to local lab hosts only).");
    }

    /** A DELETE/PATCH request dropped from the audit-target list. Not a send, so it is counted apart from refused
     *  sends, and logged at debug level once per method+path (every re-sighting of the same request is silent). */
    public static void noteDroppedTarget(HttpRequest req) {
        String m = req == null ? "?" : WriteGuard.effectiveMethod(req);
        String path = req == null ? "?" : Net.stripQuery(req.url());
        if (!noted.add("target " + m + " " + path)) return;
        droppedTargets.incrementAndGet();
        ScanLog l = log;
        if (l != null) l.debug("[verb-guard] not an audit target: " + m + " " + path);
    }

    /** The lab opt-in is set but this host is not a local/private lab host: say so once per host. */
    public static void noteOptInIgnored(String host) {
        if (!noted.add("optin-ignored " + host)) return;
        ScanLog l = log;
        if (l != null) l.log("[verb-guard] AISCANNER_ALLOW_DELETE_PATCH is set but IGNORED for " + host
                + " (only loopback/localhost/RFC1918 lab hosts qualify) — DELETE/PATCH stay blocked.");
    }

    /** Start-of-scan reset of the per-scan refusal log/counter, plus a banner when the lab opt-in is active. */
    public static void resetForScan() {
        noted.clear();
        blocked.set(0);
        droppedTargets.set(0);
        ScanLog l = log;
        if (l != null && WriteGuard.allowDeletePatch())
            l.log("[verb-guard] WARNING: AISCANNER_ALLOW_DELETE_PATCH is set — DELETE/PATCH/MERGE WILL be sent to "
                    + "local/private lab hosts (never to public hosts). Unset it before scanning a client target.");
    }

    /** End-of-scan line, or null when nothing was refused or dropped. {@code otherScans} = scans still running, whose
     *  refusals share these process-wide counters. */
    public static String summaryLine(int otherScans) {
        int n = blocked.get(), t = droppedTargets.get();
        if (n == 0 && t == 0) return null;
        long distinct = noted.stream().filter(k -> !k.startsWith("optin-ignored ") && !k.startsWith("target ")).count();
        return "[verb-guard] " + n + " DELETE/PATCH/MERGE send(s) refused (" + distinct + " distinct method+path), "
                + t + " request(s) kept out of the audit targets. Those checks did not run."
                + (otherScans > 0 ? " Counts are shared with " + otherScans + " concurrent scan(s)." : "");
    }

    private static HttpRequestResponse refuse(HttpRequest req, String where) {
        noteBlocked(req, where);
        try { return HttpRequestResponse.httpRequestResponse(req, null); } catch (Throwable t) { return null; }
    }
}
