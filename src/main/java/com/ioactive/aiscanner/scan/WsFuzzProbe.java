package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import com.ioactive.aiscanner.ui.ScanLog;
import com.ioactive.aiscanner.vulns.Signal;
import com.ioactive.aiscanner.vulns.VulnClass;
import com.ioactive.aiscanner.vulns.VulnClasses;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic injection fuzzing OVER WebSocket messages. Apps like OWASP Damn Vulnerable Web Sockets deliver
 * their entire injectable surface through a WebSocket (the HTTP page just serves JS that does
 * {@code new WebSocket("ws://…"); ws.send(userInput)}), so an HTTP active audit reaches NONE of it — the params
 * are WS frames, not query/body params. {@link WebSocketCswshProbe} confirms the CSWSH handshake flaw but never
 * sends messages; this probe sends them.
 *
 * <p><b>Reuse, not reinvention.</b> The payloads and verdicts are the SAME deterministic oracles used for HTTP
 * ({@link VulnClasses#all()} — SQLi/XSS/SSTI/traversal/command-injection): each {@link VulnClass} carries its own
 * {@code fallbackSeeds} (payloads) and an {@link com.ioactive.aiscanner.vulns.Oracle} that decides hit/miss from a
 * baseline vs a mutated response. We simply move the transport from HTTP request/response to WS send/receive:
 * open the socket, capture a benign BASELINE reply, then for each seed send it as a WS text frame, capture the
 * reply, and hand (baseline, reply, timing, payload) to the oracle. A hit is the same proof as over HTTP (canary
 * reflected unescaped, template arithmetic evaluated, {@code /etc/passwd} signature, SQL error, timing delay).</p>
 *
 * <p>Generic: WS endpoints come from {@code new WebSocket("ws://…")} URLs mined from crawled JS/HTML (no guessed
 * paths); every seed of every class is sent to every endpoint, so the endpoint whose handler is vulnerable fires
 * its own oracle regardless of the URL name. Uses only {@code burp.api.montoya.websocket} (no external deps).</p>
 */
public final class WsFuzzProbe extends Probe {

    // api + scanLog inherited from Probe
    private static final Pattern WS_URL = Pattern.compile("wss?://[^\\s\"'<>()\\\\{}]+", Pattern.CASE_INSENSITIVE);
    private static final int MAX_ENDPOINTS = 12;     // bound sockets opened
    private static final long RECV_TIMEOUT_MS = 2500;// wait for a reply to one frame
    private static final long DRAIN_MS = 150;        // collect any follow-up frames after the first

    // Per-socket receive buffer + latch (this probe fuzzes one socket at a time; the message handler appends here).
    private final StringBuilder rxBuf = new StringBuilder();
    private volatile CountDownLatch rxLatch;

    public WsFuzzProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    /** Discover WS endpoints (mined from JS/HTML) and fuzz each with the shared oracle seed set. Returns hit count. */
    public int probe(String base, UnaryOperator<HttpRequest> withSession) {
        UnaryOperator<HttpRequest> sess = withSession != null ? withSession : (r -> r);
        Set<String> wsUrls = discoverWsUrls(base);
        if (wsUrls.isEmpty()) { scanLog.debug("  ws-fuzz: no ws:// endpoints mined — nothing to fuzz"); return 0; }
        scanLog.debug("  ws-fuzz: " + wsUrls.size() + " WS endpoint(s) to fuzz: " + wsUrls);
        int hits = 0, n = 0;
        for (String wsUrl : wsUrls) {
            if (n++ >= MAX_ENDPOINTS) break;
            try { hits += fuzzEndpoint(wsUrl, sess); } catch (Throwable t) { scanLog.debug("  ws-fuzz " + wsUrl + " error: " + t); }
        }
        return hits;
    }

    /** WS URLs referenced by the app's own crawled JS/HTML ({@code new WebSocket("ws://…")}) on the target host. */
    private Set<String> discoverWsUrls(String base) {
        Set<String> out = new LinkedHashSet<>();
        String baseHost = bareHost(base);
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.response() == null) continue;
                String body;
                try { body = rr.response().bodyToString(); } catch (Throwable t) { continue; }
                if (body == null || !body.toLowerCase().contains("ws")) continue;
                Matcher m = WS_URL.matcher(body);
                while (m.find()) {
                    String wsUrl = trimTrailing(m.group());
                    String wsHost = bareHost(wsUrl.replaceFirst("(?i)^wss?://", "http://"));
                    if (wsHost == null) continue;
                    // stay on the target host (a WS legitimately runs on a different PORT than the HTTP surface)
                    if (baseHost != null && !wsHost.equalsIgnoreCase(baseHost)) continue;
                    out.add(wsUrl);
                    if (out.size() >= MAX_ENDPOINTS) return out;
                }
            }
        } catch (Throwable ignore) { }
        return out;
    }

    /** One opened + rx-handler-registered extension WebSocket, plus the upgrade response kept for finding evidence. */
    private static final class Conn {
        final ExtensionWebSocket ws; final HttpResponse upResp; final burp.api.montoya.core.Registration reg;
        Conn(ExtensionWebSocket ws, HttpResponse upResp, burp.api.montoya.core.Registration reg) {
            this.ws = ws; this.upResp = upResp; this.reg = reg;
        }
    }

    /** Open a fresh WS to {@code wsUrl} + register the rx handler; null if it does not upgrade. */
    private Conn open(String wsUrl, UnaryOperator<HttpRequest> sess, HttpRequest handshake) {
        ExtensionWebSocketCreation creation;
        try { creation = api.websockets().createWebSocket(sess.apply(handshake)); }
        catch (Throwable t) { scanLog.debug("  ws-fuzz " + wsUrl + " createWebSocket error: " + t); return null; }
        if (creation == null || creation.status() != ExtensionWebSocketCreationStatus.SUCCESS
                || creation.webSocket().isEmpty()) {
            scanLog.debug("  ws-fuzz " + wsUrl + " did not upgrade (status="
                    + (creation == null ? "null" : creation.status()) + ")");
            return null;
        }
        ExtensionWebSocket ws = creation.webSocket().get();
        burp.api.montoya.core.Registration reg = ws.registerMessageHandler(new ExtensionWebSocketMessageHandler() {
            @Override public void textMessageReceived(TextMessage m) {
                try { synchronized (rxBuf) { rxBuf.append(m.payload()).append('\n'); } } catch (Throwable ignore) { }
                CountDownLatch l = rxLatch; if (l != null) l.countDown();
            }
            @Override public void binaryMessageReceived(BinaryMessage m) { }
        });
        return new Conn(ws, creation.upgradeResponse().orElse(null), reg);
    }

    private void deregisterClose(Conn c) {
        if (c == null) return;
        try { if (c.reg != null) c.reg.deregister(); } catch (Throwable ignore) { }
        try { c.ws.close(); } catch (Throwable ignore) { }
    }

    private int fuzzEndpoint(String wsUrl, UnaryOperator<HttpRequest> sess) {
        HttpRequest handshake = synthesize(wsUrl);
        if (handshake == null) return 0;
        // Capture the benign BASELINE + upgrade response ONCE, then fuzz each seed on its OWN fresh socket. Real apps
        // CLOSE the socket on some payloads (DVWS /command-execution drops the connection on `;id`/`$(id)`/backticks),
        // and on a single SHARED socket that closer would poison every seed sent afterwards — hiding the seed that
        // actually fires (the pipe `|id`, which keeps `ping` alive to emit id output). Per-seed reconnect isolates it.
        Conn probe = open(wsUrl, sess, handshake);
        if (probe == null) return 0;
        HttpResponse upResp = probe.upResp;
        String baseline;
        try { baseline = sendRecv(probe.ws, "aiswsbaseline1"); } finally { deregisterClose(probe); }
        scanLog.debug("  ws-fuzz " + wsUrl + " baseline reply=" + snip(baseline));

        int hits = 0;
        for (VulnClass vc : VulnClasses.all()) {
            boolean fired = false;
            for (String seed : vc.fallbackSeeds) {
                if (seed == null || seed.isBlank()) continue;
                Conn c = open(wsUrl, sess, handshake);
                if (c == null) {   // (re)connect failed for this seed — a prior payload likely closed the listener
                    scanLog.debug("  ws-fuzz " + wsUrl + " [" + vc.id + "] no socket for seed " + trunc(seed)
                            + " (closed by a prior payload / server down?) — skipping");
                    continue;
                }
                long t0 = System.nanoTime();
                String reply;
                try { reply = sendRecv(c.ws, seed); } finally { deregisterClose(c); }
                long ms = (System.nanoTime() - t0) / 1_000_000L;
                Signal s;
                try { s = vc.oracle.detect(baseline, reply, ms, seed); } catch (Throwable t) { continue; }
                // Per-seed visibility: WHAT was sent, HOW LONG, WHAT came back, and the oracle VERDICT — so a miss is
                // diagnosable (empty reply? socket closed? oracle didn't match?) instead of a silent "not confirmed".
                scanLog.debug("  ws-fuzz " + wsUrl + " [" + vc.id + "] send=" + trunc(seed) + " " + ms + "ms reply="
                        + snip(reply) + " -> " + (s != null && s.hit ? "HIT" : "miss"));
                if (s != null && s.hit) {
                    scanLog.found(vc.id + " (WebSocket)", wsUrl,
                            "WS message insertion point: the frame " + trunc(seed) + " sent to " + wsUrl
                          + " produced " + s.evidence + " in the socket's reply — the same deterministic "
                          + vc.id + " oracle as over HTTP, proven over the WebSocket transport (input arrives as "
                          + "a WS frame, not an HTTP param, so a request-based audit never reaches it).",
                            true,   // forceRaise: Burp's native audit does not fuzz WS messages, so raise our own
                            upResp != null ? HttpRequestResponse.httpRequestResponse(handshake, upResp) : null);
                    scanLog.incFinding();
                    hits++; fired = true; break;   // one finding per (endpoint, class)
                }
            }
            if (fired) scanLog.debug("  ws-fuzz " + wsUrl + " → " + vc.id + " confirmed");
        }
        return hits;
    }

    /** Send one text frame and collect the reply within the receive window (first frame + a short drain for extras). */
    private String sendRecv(ExtensionWebSocket ws, String payload) {
        synchronized (rxBuf) { rxBuf.setLength(0); }
        rxLatch = new CountDownLatch(1);
        try { ws.sendTextMessage(payload); } catch (Throwable t) { return ""; }
        try { rxLatch.await(RECV_TIMEOUT_MS, TimeUnit.MILLISECONDS); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        try { Thread.sleep(DRAIN_MS); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        synchronized (rxBuf) { return rxBuf.toString(); }
    }

    /** ws://|wss:// URL → a standards-compliant upgrade GET (random Sec-WebSocket-Key). Mirrors WebSocketCswshProbe. */
    private HttpRequest synthesize(String wsUrl) {
        try {
            String httpUrl = wsUrl.replaceFirst("(?i)^ws://", "http://").replaceFirst("(?i)^wss://", "https://");
            byte[] k = new byte[16];
            new java.security.SecureRandom().nextBytes(k);
            return HttpRequest.httpRequestFromUrl(httpUrl).withMethod("GET")
                    .withAddedHeader("Upgrade", "websocket")
                    .withAddedHeader("Connection", "Upgrade")
                    .withAddedHeader("Sec-WebSocket-Version", "13")
                    .withAddedHeader("Sec-WebSocket-Key", java.util.Base64.getEncoder().encodeToString(k));
        } catch (Throwable t) { return null; }
    }

    private static String bareHost(String url) {
        try { return url == null ? null : java.net.URI.create(url).getHost(); } catch (Throwable t) { return null; }
    }
    private static String trimTrailing(String u) {
        int end = u.length();
        while (end > 0 && ".,;:)]}>\"'".indexOf(u.charAt(end - 1)) >= 0) end--;
        return u.substring(0, end);
    }
    private static String trunc(String s) { return s == null ? "(null)" : s.length() > 60 ? s.substring(0, 60) + "…" : s; }
    /** One-line reply snippet for DEBUG: collapse whitespace, cap at 140 chars (keep the full length for context). */
    private static String snip(String s) {
        if (s == null) return "(null)";
        String one = s.replaceAll("\\s+", " ").trim();
        return one.length() > 140 ? one.substring(0, 140) + "…(" + s.length() + "ch)" : one;
    }
}
