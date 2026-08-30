package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;

/**
 * Base class for the deterministic HTTP probes. It centralizes the two things every probe needs — the Burp
 * {@link MontoyaApi} handle and the {@link ScanLog} sink — plus the small helpers that were previously
 * copy-pasted across ~40 probe classes (host/path extraction from a URL, a JSON-body test).
 *
 * <p>The reason this is a base class and not just a bag of statics is the <b>politeness delay</b>: a single
 * chokepoint ({@link #politeness()} / {@link #send(HttpRequest, long)}) so the ScanConfig "delay between
 * requests" knob set in Settings is honoured by every probe that routes its outbound sends through here.
 *
 * <p><b>Migration pattern.</b> A probe: (1) {@code extends Probe}; (2) calls {@code super(api, scanLog)} instead
 * of assigning its own {@code api}/{@code scanLog} fields (which are removed — they'd otherwise SHADOW the
 * inherited ones and stay null); (3) drops any identical private {@code hostOf}/{@code isJson}; (4) calls
 * {@link #politeness()} at the head of its send path (or sends via {@link #send(HttpRequest, long)}). All the
 * oracle / candidate / finding logic stays in the subclass — this class holds no detection policy.
 */
public abstract class Probe {

    protected final MontoyaApi api;
    protected final ScanLog scanLog;

    protected Probe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    // ---- politeness delay (wired from ScanConfig.delayMs by AiScanner at scan start) -------------------------
    // Static + volatile: parallel per-target scans share ONE ScanConfig instance (AiScannerExtension), so a
    // single process-wide value is consistent with that design; AiScanner sets it before each battery runs.
    private static volatile int politenessDelayMs = 0;

    /** Set the between-requests politeness delay (ms). Called by AiScanner from ScanConfig.delayMs at scan start. */
    public static void setPolitenessDelayMs(int ms) { politenessDelayMs = Math.max(0, ms); }

    /** The current politeness delay (ms); 0 = none. */
    public static int politenessDelayMs() { return politenessDelayMs; }

    // ---- centralized, Settings-configurable per-request timeout (ScanConfig.requestTimeoutMs) ----------------
    // Single source of truth for the default probe→target response timeout, replacing the ~40 hardcoded 12000L
    // literals that used to live in every probe. AiScanner pushes ScanConfig.requestTimeoutMs here at scan start,
    // exactly like the politeness delay, so the Settings field actually governs it.
    private static volatile long requestTimeoutMs = 12_000L;

    /** Set the default per-request response timeout (ms). Called by AiScanner from ScanConfig.requestTimeoutMs. */
    public static void setRequestTimeoutMs(long ms) { if (ms > 0) requestTimeoutMs = ms; }

    /** The configured default per-request response timeout (ms). Probes with a bespoke send() read this too, so
     *  the timeout value lives in ONE place even for the handful that can't use {@link #send(HttpRequest)}. */
    public static long requestTimeoutMs() { return requestTimeoutMs; }

    /** Sleep the configured politeness delay, if any. Call once before each outbound probe request. */
    protected static void politeness() {
        int d = politenessDelayMs;
        if (d <= 0) return;
        try { Thread.sleep(d); }
        catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
    }

    // ---- shared URL helpers (formerly ~24 byte-identical private copies) -------------------------------------

    /** {@code host[:port]} with the scheme's default port elided — the port-aware identity used for scope/dedup. */
    protected static String hostOf(String url) { return Net.authority(url); }

    /** URL path (no query), or the raw URL on parse failure. */
    protected static String pathOf(String url) {
        try { String p = URI.create(url).getPath(); return p == null ? "" : p; }
        catch (Exception e) { return url; }
    }

    /** True when the request body is JSON — by Content-Type, or by body shape when a replay lost the header. */
    protected static boolean isJson(HttpRequest req) {
        try {
            String b = req.bodyToString();
            if (b == null || b.isBlank()) return false;
            String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
            if (ct != null && ct.toLowerCase().contains("json")) return true;
            String t = b.trim();   // fall back to body SHAPE — captured/replayed reqs can lose the header
            return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
        } catch (Throwable t) { return false; }
    }

    /** Standard best-effort probe send: politeness + the single, Settings-configurable request timeout
     *  ({@link #requestTimeoutMs()}); returns null on any failure (the common probe contract). This is the ONE
     *  place the default per-request timeout lives — probes call {@code send(req)} instead of repeating
     *  {@code RequestOptions.requestOptions().withResponseTimeout(...)} at every call site. */
    protected HttpRequestResponse send(HttpRequest req) {
        return send(req, requestTimeoutMs);
    }

    /** Politeness + an EXPLICIT response timeout, for the few probes that genuinely need a non-default window
     *  (time-based injection that must outlast an injected sleep; slow LLM endpoints); null on any failure. */
    protected HttpRequestResponse send(HttpRequest req, long responseTimeoutMs) {
        politeness();
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(responseTimeoutMs)); }
        catch (Throwable t) { return null; }
    }
}
