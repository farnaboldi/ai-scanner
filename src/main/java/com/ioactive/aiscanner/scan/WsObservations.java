package com.ioactive.aiscanner.scan;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Process-wide collector of the WebSocket UPGRADE handshakes Burp observes. Registered once at extension load via
 * {@code api.websockets().registerWebSocketCreatedHandler(...)}; every socket the crawl (or the proxied browser)
 * opens hands us its {@code upgradeRequest()}. {@link WebSocketCswshProbe} reads a snapshot so WS discovery is
 * generic — whatever endpoints the app actually opened — never a hardcoded/guessed path.
 */
public final class WsObservations {

    private static final List<HttpRequest> HANDSHAKES = Collections.synchronizedList(new ArrayList<>());
    private static final Set<String> SEEN = Collections.synchronizedSet(new HashSet<>());

    /** Record a WebSocket upgrade request (deduped by method+url). Null / malformed inputs are ignored. */
    public static void add(HttpRequest upgrade) {
        if (upgrade == null) return;
        String key;
        try { key = upgrade.method() + " " + upgrade.url(); } catch (Throwable t) { return; }
        if (SEEN.add(key)) HANDSHAKES.add(upgrade);
    }

    public static List<HttpRequest> snapshot() {
        synchronized (HANDSHAKES) { return new ArrayList<>(HANDSHAKES); }
    }

    public static int size() { return HANDSHAKES.size(); }

    private WsObservations() {}
}
