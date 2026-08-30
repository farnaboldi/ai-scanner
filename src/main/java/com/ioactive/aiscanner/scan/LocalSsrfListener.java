package com.ioactive.aiscanner.scan;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Lightweight HTTP listener for SSRF confirmation when Burp Collaborator is unavailable. It catches TWO
 * manifestations, both deterministic and zero-FP:
 * <ul>
 *   <li><b>Blind / OOB SSRF</b>: the target fetches a scanner-controlled URL pointing back here; the request
 *       arrives at the listener and the embedded tag is recorded ({@link #received(String)}).</li>
 *   <li><b>Reflected / returned-content SSRF</b>: the target fetches the URL and echoes the fetched body back in
 *       its OWN HTTP response (common for URL-preview / avatar-by-URL / import-from-URL features, sometimes
 *       base64-wrapped). The listener answers every callback with a unique {@link #canary()} string so the caller
 *       can look for that canary (raw or base64) in the app's response — see SsrfProbe.</li>
 * </ul>
 *
 * <p><b>Bind address.</b> Binds all interfaces (0.0.0.0), NOT loopback-only, on purpose: a containerised target
 * reaches the host via {@code host.docker.internal} (the bridge/gateway IP), so a 127.0.0.1-only socket would be
 * unreachable from inside the container and Docker SSRF would never confirm. Exposure is kept sound by prefixing
 * every payload path with a 128-bit {@link #nonce()} and serving a 128-bit {@link #canary()}: a stray/adversarial
 * LAN request can guess neither, so it can neither forge a callback hit nor a reflected match. Up only for the
 * brief poll window; auto-closed after.</p>
 */
public final class LocalSsrfListener implements AutoCloseable {

    private static final SecureRandom RNG = new SecureRandom();

    private final HttpServer server;
    private final int port;
    private final String nonce;
    private final String canary;
    private final byte[] canaryBytes;
    private final Set<String> hits = Collections.synchronizedSet(new LinkedHashSet<>());

    private LocalSsrfListener(HttpServer server, String nonce, String canary) {
        this.server = server;
        this.port   = server.getAddress().getPort();
        this.nonce  = nonce;
        this.canary = canary;
        this.canaryBytes = canary.getBytes(StandardCharsets.UTF_8);
        server.createContext("/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();          // e.g. /<nonce>/ssrf-3
                if (path != null) {
                    String p = path.startsWith("/") ? path.substring(1) : path;
                    if (p.startsWith(nonce + "/")) hits.add(p.substring(nonce.length() + 1));
                }
                // Answer with the canary body so a reflected-SSRF target echoes it back in its own response.
                exchange.sendResponseHeaders(200, canaryBytes.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(canaryBytes); }
            } catch (Throwable ignore) {
                try { exchange.close(); } catch (Throwable ignore2) { }
            }
        });
        server.start();
    }

    /** Start the listener on a random free port with a fresh unguessable nonce + canary. Null if binding fails. */
    public static LocalSsrfListener start() {
        try {
            HttpServer s = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 8);
            return new LocalSsrfListener(s, rand("n"), rand("AISSRF"));
        } catch (Throwable t) { return null; }
    }

    private static String rand(String prefix) {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        StringBuilder n = new StringBuilder(prefix);
        for (byte x : b) n.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return n.toString();
    }

    /** Port the listener bound to. */
    public int port() { return port; }

    /** Per-instance unguessable path prefix — callers build payloads as http://host:port/{nonce}/{tag}. */
    public String nonce() { return nonce; }

    /** Per-instance unguessable canary served in every callback body — used to detect reflected/returned SSRF. */
    public String canary() { return canary; }

    /** True if the given tag was received as an HTTP request path under this listener's nonce (blind SSRF). */
    public boolean received(String tag) { return hits.contains(tag); }

    /** All tags received so far. */
    public Set<String> received() { return Collections.unmodifiableSet(hits); }

    @Override public void close() {
        try { server.stop(0); } catch (Throwable ignore) { }
    }
}
