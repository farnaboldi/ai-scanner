package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic Cross-Site WebSocket Hijacking (CSWSH — CWE-1385 / CWE-346).
 *
 * <p>A WebSocket handshake is a plain HTTP GET carrying {@code Upgrade: websocket}. A browser attaches the target's
 * cookies to it AMBIENTLY, and the Same-Origin Policy / CORS do NOT apply to WebSockets — the only thing standing
 * between an attacker page and a victim's authenticated socket is the server validating the {@code Origin} header.
 * If it doesn't, any attacker-controlled page can open a socket to the server carrying the victim's cookie.</p>
 *
 * <p><b>Discovery (generic).</b> WebSockets are rarely reachable by an HTTP crawl (they open from client JS, often on
 * a different port than the HTTP surface). So we take the WS endpoints from two sources and normalise them:
 * <ul>
 *   <li>handshakes actually observed by Burp ({@link WsObservations} + proxy history + site map), and</li>
 *   <li>WS URLs MINED from crawled JS/HTML bodies ({@code new WebSocket("ws://…")}) — for which we SYNTHESISE a
 *       standards-compliant upgrade request (random {@code Sec-WebSocket-Key}). No guessed paths; only URLs the app
 *       itself references.</li>
 * </ul></p>
 *
 * <p><b>Oracle (handshake-level replay differential — NON-DESTRUCTIVE).</b> For each WS endpoint:
 * <ol>
 *   <li><b>Scope + cookie gate:</b> the WS host must be in the operator's authorised scope, and the (ambient) handshake
 *       must carry a {@code Cookie} — cross-origin browsers only attach cookies ambiently, so a socket with no ambient
 *       cookie has nothing to hijack.</li>
 *   <li><b>Baseline:</b> the endpoint must upgrade (HTTP 101, {@code SUCCESS}) with the app's own legitimate Origin —
 *       proving it is a live WS and the request is valid.</li>
 *   <li><b>Attack:</b> replay with a FOREIGN {@code Origin}. A still-successful upgrade DETERMINISTICALLY proves the
 *       server does not validate Origin (CWE-346); a hardened server rejects the foreign Origin.</li>
 * </ol>
 * We never send WS <i>messages</i> (that could mutate state, e.g. a change-password socket), so we confirm at the
 * handshake only: what is asserted is the missing Origin validation. CSWSH (CWE-1385) FOLLOWS <i>if</i> the socket is
 * authenticated by that ambient cookie — the finding text states this conditionally rather than claiming a proven
 * session hijack. Reported once per host:port. Uses only {@code burp.api.montoya.websocket} (no external deps).</p>
 */
public final class WebSocketCswshProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // Cross-origin sentinel: a scheme+host no legitimate app is served from, so it is ALWAYS off-origin to any
    // victim. This is an attack MARKER (like an XSS canary), not a computed oracle value.
    private static final String FOREIGN_ORIGIN = "https://cswsh-probe.attacker.example";
    private static final Pattern WS_URL = Pattern.compile("wss?://[^\\s\"'<>()\\\\{}]+", Pattern.CASE_INSENSITIVE);
    private static final int MAX_CANDIDATES = 25;

    public WebSocketCswshProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** A WS endpoint to test + the legitimate Origin to baseline it with (null ⇒ use the request's own Origin). */
    private static final class Candidate {
        final HttpRequest handshake; final String baselineOrigin;
        Candidate(HttpRequest h, String o) { handshake = h; baselineOrigin = o; }
    }

    /** Discover WS endpoints (observed + JS-mined) and test each. Returns the number of hosts confirmed vulnerable. */
    public int probe(UnaryOperator<HttpRequest> withSession) {
        List<Candidate> candidates = discover();
        scanLog.debug("CSWSH: " + candidates.size() + " WS endpoint(s) discovered (observed + JS-mined).");
        if (candidates.isEmpty()) return 0;
        Set<String> inScopeHosts = inScopeHosts();
        Set<String> reported = new HashSet<>();   // host:port keys already confirmed (dedup + return count)
        for (Candidate c : candidates) {
            try { test(c, withSession, reported, inScopeHosts); }
            catch (Throwable t) { scanLog.debug("CSWSH test error: " + t); }
        }
        return reported.size();
    }

    private List<Candidate> discover() {
        Map<String, Candidate> byKey = new LinkedHashMap<>();
        // 1) handshakes Burp actually observed (WsObservations from our crawl → trusted, no scope filter; a WS often
        //    runs on a different port than the HTTP surface so host+port scope would wrongly drop it).
        for (HttpRequest r : WsObservations.snapshot()) addObserved(byKey, r, false);
        try { for (var rr : api.proxy().history()) if (rr != null) addObserved(byKey, rr.finalRequest(), true); } catch (Throwable ignore) {}
        try { for (HttpRequestResponse rr : api.siteMap().requestResponses()) if (rr != null) addObserved(byKey, rr.request(), true); } catch (Throwable ignore) {}
        // 2) WS URLs mined from crawled JS/HTML bodies, synthesised into upgrade requests.
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (byKey.size() >= MAX_CANDIDATES) break;
                if (rr == null || rr.response() == null) continue;
                String body = safeBody(rr.response());
                if (body == null || !body.toLowerCase().contains("ws")) continue;
                String pageHost = hostOf(safeUrl(rr.request()));
                String pageOrigin = originOf(safeUrl(rr.request()));
                Matcher m = WS_URL.matcher(body);
                while (m.find() && byKey.size() < MAX_CANDIDATES) {
                    String wsUrl = trimTrailing(m.group());
                    String wsHost = hostOf(wsUrl);
                    if (wsHost == null || pageHost == null || !wsHost.equalsIgnoreCase(pageHost)) continue; // same-host only (stay in authorised scope)
                    String key = keyOf(wsUrl);
                    if (key == null || byKey.containsKey(key)) continue;   // dedup; prefer an already-observed handshake
                    HttpRequest synth = synthesize(wsUrl);
                    if (synth != null) byKey.put(key, new Candidate(synth, pageOrigin));
                }
            }
        } catch (Throwable ignore) {}
        return new ArrayList<>(byKey.values());
    }

    private void addObserved(Map<String, Candidate> byKey, HttpRequest r, boolean scopeCheck) {
        if (r == null || !isWsUpgrade(r)) return;
        String url = safeUrl(r);
        if (url == null) return;
        if (scopeCheck) { try { if (!api.scope().isInScope(url)) return; } catch (Throwable ignore) {} }
        String key = keyOf(url);
        if (key != null) byKey.putIfAbsent(key, new Candidate(r, null));   // baseline uses the request's own Origin
    }

    /** Build a standards-compliant upgrade request for a mined ws://|wss:// URL (random key — never hardcoded). */
    private HttpRequest synthesize(String wsUrl) {
        try {
            String httpUrl = wsUrl.replaceFirst("(?i)^ws://", "http://").replaceFirst("(?i)^wss://", "https://");
            byte[] k = new byte[16];
            new java.security.SecureRandom().nextBytes(k);
            String key = java.util.Base64.getEncoder().encodeToString(k);
            return HttpRequest.httpRequestFromUrl(httpUrl).withMethod("GET")
                    .withAddedHeader("Upgrade", "websocket")
                    .withAddedHeader("Connection", "Upgrade")
                    .withAddedHeader("Sec-WebSocket-Version", "13")
                    .withAddedHeader("Sec-WebSocket-Key", key);
        } catch (Throwable t) { return null; }
    }

    private void test(Candidate c, UnaryOperator<HttpRequest> withSession, Set<String> reported, Set<String> inScopeHosts) {
        HttpRequest hs = withSession.apply(c.handshake);
        String url = safeUrl(hs);
        if (url == null) return;
        String host = hostOf(url);
        // Authorised-scope gate: the WebSocket's HOST must appear in an in-scope request. A WS may legitimately run on
        // a DIFFERENT PORT than the HTTP surface (Burp's host+port scope would drop it), but we must NEVER open a
        // handshake to a host outside the operator's target scope (e.g. a third-party/CDN host the crawl merely touched).
        if (host == null || !inScopeHosts.contains(host.toLowerCase())) {
            scanLog.debug("CSWSH skip (host not in authorised scope): " + url); return;
        }
        String hostPort = hostPortOf(url);
        if (hostPort != null && reported.contains(hostPort)) return;   // one finding per host:port (distinct WS services differ)
        // A browser attaches AMBIENT cookies to a cross-origin WS handshake — harvest what the crawl actually sent to
        // this host (ambientCookieHeader). Without an ambient cookie there is nothing to hijack cross-site, so we skip.
        if (!hasCookie(hs)) {
            String jar = ambientCookieHeader(host);
            if (jar != null) hs = hs.withAddedHeader("Cookie", jar);
        }
        if (!hasCookie(hs)) { scanLog.debug("CSWSH skip (no ambient cookie): " + url); return; }

        // baseline: the endpoint must upgrade with the app's OWN (legitimate) Origin — the origin that legitimately
        // consumes this socket, which a correctly-configured server would allow-list.
        HttpRequest baseReq = c.baselineOrigin != null ? hs.withUpdatedHeader("Origin", c.baselineOrigin) : hs;
        ExtensionWebSocketCreation base = api.websockets().createWebSocket(baseReq);
        String baseStatus = base != null ? String.valueOf(base.status()) : "null";
        boolean baseOk = base != null && base.status() == ExtensionWebSocketCreationStatus.SUCCESS;
        closeQuietly(base);
        if (!baseOk) { scanLog.debug("CSWSH " + url + " baseline did not upgrade (status=" + baseStatus + ")"); return; }

        // attack: replay with a foreign Origin — a still-successful upgrade means Origin was never validated
        HttpRequest evil = hs.withUpdatedHeader("Origin", FOREIGN_ORIGIN);
        ExtensionWebSocketCreation attack = api.websockets().createWebSocket(evil);
        boolean cswsh = attack != null && attack.status() == ExtensionWebSocketCreationStatus.SUCCESS;
        HttpResponse upResp = attack != null ? attack.upgradeResponse().orElse(null) : null;
        closeQuietly(attack);
        scanLog.debug("CSWSH " + url + " baseline=SUCCESS foreignOrigin=" + (attack != null ? attack.status() : "null"));
        if (!cswsh) return;

        if (hostPort != null) reported.add(hostPort);
        // Honest framing: what is DETERMINISTICALLY proven is missing Origin validation (CWE-346). CSWSH (CWE-1385)
        // FOLLOWS *if* the socket is authenticated by that ambient cookie — which we do NOT assert, because confirming
        // it would require sending a WS message (potentially state-changing, e.g. a change-password socket).
        String detail = "The WebSocket endpoint " + url + " completed its upgrade handshake (HTTP 101) when replayed "
              + "with a foreign Origin (" + FOREIGN_ORIGIN + "); the server does NOT validate the Origin of WebSocket "
              + "upgrades (CWE-346), and the handshake carried an ambient session Cookie. Browsers attach cookies to "
              + "cross-origin WS handshakes automatically and no SOP/CORS applies to WebSockets, so IF this socket is "
              + "authenticated by that cookie, any attacker page can open it on a victim's behalf and read/drive their "
              + "session — Cross-Site WebSocket Hijacking (CWE-1385). Deterministic and non-destructive: the foreign-"
              + "Origin handshake upgrades exactly as the app's own Origin does (a server that validated Origin would "
              + "reject the foreign value); no WebSocket messages are sent, so whether the socket actually consumes the "
              + "cookie for authorisation is not asserted. Reported once per host:port.";
        if (upResp != null) scanLog.found("Cross-Site WebSocket Hijacking (CSWSH)", url, detail, true,
                                          HttpRequestResponse.httpRequestResponse(evil, upResp));
        else                scanLog.found("Cross-Site WebSocket Hijacking (CSWSH)", url, detail, true);
        scanLog.incFinding();
    }

    /** Hosts that appear in at least one IN-SCOPE site-map request — the authorised hosts a WS may live on (any port). */
    private Set<String> inScopeHosts() {
        Set<String> hosts = new HashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = safeUrl(rr == null ? null : rr.request());
                String hh = hostOf(u);
                if (hh == null) continue;
                try { if (api.scope().isInScope(u)) hosts.add(hh.toLowerCase()); } catch (Throwable ignore) {}
            }
        } catch (Throwable ignore) {}
        return hosts;
    }

    // ---- helpers ----------------------------------------------------------------------------------------------
    private boolean isWsUpgrade(HttpRequest r) {
        try { String up = r.headerValue("Upgrade"); return up != null && up.toLowerCase().contains("websocket"); }
        catch (Throwable t) { return false; }
    }
    private boolean hasCookie(HttpRequest r) {
        try { String c = r.headerValue("Cookie"); return c != null && !c.isBlank(); } catch (Throwable t) { return false; }
    }
    /** The ambient cookies a browser would attach to a handshake for {@code host}. Preference order: the Cookie header
     *  the crawl actually SENT to this host, else the Set-Cookie(s) the host issued, else Burp's cookie jar. (A
     *  headless scan often does not populate the cookie jar, so the site-map traffic is the reliable source.) */
    private String ambientCookieHeader(String host) {
        if (host == null) return null;
        String h = host.toLowerCase();
        java.util.List<HttpRequestResponse> map;
        try { map = api.siteMap().requestResponses(); } catch (Throwable t) { map = java.util.Collections.emptyList(); }
        // 1) a Cookie header the crawl sent to this host
        for (HttpRequestResponse rr : map) {
            HttpRequest r = rr == null ? null : rr.request();
            if (r == null || !h.equalsIgnoreCase(hostOf(safeUrl(r)))) continue;
            try { String c = r.headerValue("Cookie"); if (c != null && !c.isBlank()) return c; } catch (Throwable ignore) {}
        }
        // 2) Set-Cookie(s) the host issued (name=value only)
        StringBuilder sb = new StringBuilder();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (HttpRequestResponse rr : map) {
            if (rr == null || rr.response() == null || !h.equalsIgnoreCase(hostOf(safeUrl(rr.request())))) continue;
            try {
                for (burp.api.montoya.http.message.HttpHeader hd : rr.response().headers()) {
                    if (hd.name() == null || !hd.name().equalsIgnoreCase("Set-Cookie") || hd.value() == null) continue;
                    String nv = hd.value().split(";", 2)[0].trim();
                    int eq = nv.indexOf('=');
                    if (eq <= 0 || !seen.add(nv.substring(0, eq))) continue;
                    if (sb.length() > 0) sb.append("; ");
                    sb.append(nv);
                }
            } catch (Throwable ignore) {}
        }
        if (sb.length() > 0) return sb.toString();
        // 3) Burp's cookie jar (domain-scoped), if populated
        try {
            StringBuilder jb = new StringBuilder();
            for (burp.api.montoya.http.message.Cookie c : api.http().cookieJar().cookies()) {
                String d = c.domain();
                if (d == null || c.name() == null) continue;
                String dn = (d.startsWith(".") ? d.substring(1) : d).toLowerCase();
                if (!(h.equals(dn) || h.endsWith("." + dn))) continue;
                if (jb.length() > 0) jb.append("; ");
                jb.append(c.name()).append('=').append(c.value() == null ? "" : c.value());
            }
            if (jb.length() > 0) return jb.toString();
        } catch (Throwable ignore) {}
        return null;
    }
    private String safeUrl(HttpRequest r) { try { return r == null ? null : r.url(); } catch (Throwable t) { return null; } }
    private String safeBody(HttpResponse r) { try { return r.bodyToString(); } catch (Throwable t) { return null; } }
    private String trimTrailing(String u) {
        int end = u.length();
        while (end > 0 && ".,;:)]}>\"'".indexOf(u.charAt(end - 1)) >= 0) end--;
        return u.substring(0, end);
    }
    private String hostOf(String url) {
        try { return java.net.URI.create(url).getHost(); } catch (Throwable t) { return null; }
    }
    /** scheme://host[:port] of an HTTP(S)/WS(S) URL as a browser serialises an Origin (default ports 80/443 omitted). */
    private String originOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            String s = u.getScheme(); String h = u.getHost();
            if (s == null || h == null) return null;
            String scheme = s.equalsIgnoreCase("ws") ? "http" : s.equalsIgnoreCase("wss") ? "https" : s.toLowerCase();
            int port = u.getPort();
            boolean deflt = port < 0 || ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
            return scheme + "://" + h + (deflt ? "" : ":" + port);
        } catch (Throwable t) { return null; }
    }
    /** host:port key (default ports normalised) so distinct WS services on the same host dedupe/report separately. */
    private String hostPortOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            if (u.getHost() == null) return null;
            int port = u.getPort();
            return u.getHost().toLowerCase() + ":" + port;
        } catch (Throwable t) { return null; }
    }
    /** host:port/path normalised across ws/http so an observed handshake and a mined URL dedupe to one. */
    private String keyOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            String h = u.getHost(); if (h == null) return null;
            return h.toLowerCase() + ":" + u.getPort() + (u.getPath() == null ? "" : u.getPath());
        } catch (Throwable t) { return null; }
    }
    private void closeQuietly(ExtensionWebSocketCreation c) {
        try { if (c != null) c.webSocket().ifPresent(ws -> { try { ws.close(); } catch (Throwable ignore) {} }); }
        catch (Throwable ignore) {}
    }
}
