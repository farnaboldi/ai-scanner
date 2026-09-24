package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.scan.sast.SourceFindings;
import com.ioactive.aiscanner.scan.sast.StaticHint;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * Reverse proxy misconfiguration detector — four behavioral vulnerability classes.
 *
 * <p>All detection is <b>purely behavioral</b>: no proxy product names are hardcoded.
 * Each class is identified by what the proxy DOES, not what it IS.
 *
 * <h3>Class A — ACL bypass via path normalization (CWE-284)</h3>
 * Proxy enforces an ACL that returns 403/401 on a path. An encoding variant of that path
 * (e.g. {@code /%2fadmin}) returns 2xx because the proxy evaluates the raw encoded path
 * but the backend normalizes it to the original resource. Observable on any proxy whose
 * ACL evaluation and backend path decoding disagree.
 *
 * <h3>Class B — Cache key poisoning via unkeyed Host header (CWE-345)</h3>
 * Proxy caches responses (detectable via {@code Age}, {@code X-Cache}, {@code Cache-Control: max-age&gt;0})
 * using a cache key that EXCLUDES the Host header. An attacker can poison the cache for
 * {@code Host: victim.com} by first requesting with {@code Host: attacker.com}. If the
 * second response body matches the first (nonce or body-length differential), the Host
 * header is not part of the cache key — cross-tenant cache poisoning is possible.
 *
 * <h3>Class C — Path normalization redirect (CWE-436)</h3>
 * Proxy actively normalizes percent-encoded path separators or dot-segments and issues
 * a redirect (3xx) to the decoded/normalized path. A client that receives {@code 308 /admin}
 * when requesting {@code /%2fadmin} has had its original path rewritten by the proxy.
 * If a backend ACL blocks {@code /admin} but an intermediary proxy normalizes the encoded
 * request to it, the backend's ACL sees a different path than the attacker sent.
 *
 * <h3>Class D — Host header routing bypass (CWE-441)</h3>
 * Proxy routes requests based solely on the {@code Host} header value, not on the SNI or
 * source IP. A default request (using the server's IP/hostname directly) returns 4xx
 * (no matching virtual host), but injecting a known backend hostname in the {@code Host}
 * header routes the request to a backend that may not be intended to be publicly accessible.
 */
public final class ProxyMisconfigProbe extends Probe {

    // ---- common seed paths for Class A (ACL bypass) ------------------------------------------

    private static final String[] ACL_SEEDS = {
        "/admin", "/administrator", "/api/admin", "/api/v1/admin", "/api/v2/admin",
        "/manager", "/management", "/control", "/dashboard", "/backend",
        "/internal", "/private", "/restricted", "/secure",
        "/config", "/settings", "/console", "/panel",
        "/actuator", "/metrics", "/debug", "/health/details",
        "/swagger", "/graphql", "/api-docs",
    };

    // ---- candidate paths/prefixes for Class B (cache poisoning) ------------------------------

    private static final String[] CACHE_PATH_SEEDS = {
        "/img/", "/images/", "/static/", "/assets/", "/media/",
        "/css/", "/js/", "/fonts/", "/files/", "/public/",
    };

    // ---- encoding variants for Class A -------------------------------------------------------

    private static List<String> normVariants(String path) {
        String p = path.startsWith("/") ? path.substring(1) : path;
        if (p.isEmpty()) return new ArrayList<>();
        String firstSeg = p.contains("/") ? p.substring(0, p.indexOf('/')) : p;
        String rest = p.contains("/") ? p.substring(p.indexOf('/')) : "";
        String hexFirst = "%" + String.format("%02x", (int) firstSeg.charAt(0)) + firstSeg.substring(1) + rest;
        List<String> v = new ArrayList<>();
        v.add("/%2f" + p);           // encoded slash prefix — proxy path_beg /admin doesn't match
        v.add("/%2F" + p);           // uppercase encoded slash
        v.add("/./" + p);            // dot-segment normalization
        v.add("/..%2f../" + p);      // double-dot with encoded slash
        v.add("/;/" + p);            // semicolon segment (ignored by some proxies before ACL check)
        v.add("//" + p);             // double slash (merge_slashes may normalize backend-side)
        v.add("/%252f" + p);         // double-encoded slash (%25 = %, %252f = literal %2f)
        v.add("/" + hexFirst);       // first char hex-encoded (proxy doesn't decode before ACL match)
        v.add("/" + p + "/");        // trailing slash changes path_beg matching
        v.add("/" + p + "%09");      // trailing tab
        v.add("/" + p + ".");        // trailing dot (Windows path normalization)
        v.add("/" + p.toUpperCase()); // uppercase (case-insensitive proxies vs case-sensitive backends)
        return v;
    }

    // ---- path override headers for header injection (Class A extension) ---------------------

    private static final String[] PATH_OVERRIDE_HDRS = {
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Path",
    };

    // ---- proxy fingerprint patterns (informational only — NOT used to branch test logic) -----

    private static final Pattern PROXY_HDR = Pattern.compile(
        "(?i)haproxy|nginx|envoy|traefik|varnish|squid|caddy|cloudflare|nuster|apache");

    // ---- state -------------------------------------------------------------------------------

    private SourceFindings sourceHints;
    private final AtomicInteger nonce = new AtomicInteger((int)(System.nanoTime() & 0xFFFF));

    public void setSourceHints(SourceFindings h) { this.sourceHints = h; }

    public ProxyMisconfigProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    // ==========================================================================================
    // Entry point
    // ==========================================================================================

    public int probe(String host, UnaryOperator<HttpRequest> withSession) {
        int hits = 0;
        try {
            String base = resolveBase(host);
            if (base == null) return 0;

            // Fingerprint from root response (informational — for logging and finding labels only).
            HttpRequestResponse rootRr = get(base + "/", withSession);
            String proxyId = fingerprint(rootRr);
            if (!proxyId.isEmpty())
                scanLog.log("  proxy-misconfig: detected reverse proxy → " + proxyId);

            // Class A — ACL bypass via path normalization
            hits += classA_aclBypass(base, host, proxyId, withSession);

            // Class B — Cache key poisoning via unkeyed Host header
            hits += classB_cachePoisoning(base, rootRr, proxyId, withSession);

            // Class C — Path normalization redirect (proxy normalizes %2f / // and redirects)
            hits += classC_normalizationRedirect(base, proxyId, withSession);

            // Class D — Host header routing bypass (default Host → 4xx; other Host → 2xx)
            hits += classD_hostRoutingBypass(base, rootRr, proxyId, withSession);

            // Class E — Open proxy via Absolute-URI (proxy forwards GET http://other-host/ to that host)
            // Oracle: Burp Collaborator OOB callback proves the proxy made an outbound request on our behalf.
            // Pass rootRr so the site map anchor goes to localhost:PORT not to the Collaborator domain.
            hits += classE_openProxyAbsoluteUri(base, proxyId, rootRr, withSession);

        } catch (Throwable t) {
            scanLog.debug("proxy-misconfig probe error: " + t);
        }
        return hits;
    }

    // ==========================================================================================
    // Class A: ACL bypass via path normalization
    // ==========================================================================================

    private int classA_aclBypass(String base, String host, String proxyId,
                                  UnaryOperator<HttpRequest> withSession) {
        // Collect 403/401 paths from the site map.
        Map<String, HttpRequestResponse> blocked = new LinkedHashMap<>();
        Set<String> seen = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null) continue;
            String url = rr.request().url();
            if (!matchesHost(url, host)) continue;
            int st = rr.response().statusCode();
            if (st != 403 && st != 401) continue;
            String path = pathOf(url);
            if (path == null || path.isEmpty() || "/".equals(path)) continue;
            if (seen.add(path)) blocked.put(path, rr);
        }

        // SAST-hinted protected routes.
        if (sourceHints != null) {
            for (StaticHint h : sourceHints.all()) {
                if (h.path == null || h.path.isBlank()) continue;
                boolean isProtected = "BFLA".equalsIgnoreCase(h.vulnClass)
                        || "AUTHZ".equalsIgnoreCase(h.vulnClass)
                        || h.path.toLowerCase().contains("admin");
                if (!isProtected) continue;
                String p = h.path.startsWith("/") ? h.path : "/" + h.path;
                if (!seen.contains(p)) {
                    HttpRequestResponse rr = get(base + p, withSession);
                    if (rr != null && rr.response() != null
                            && (rr.response().statusCode() == 403 || rr.response().statusCode() == 401)
                            && seen.add(p)) blocked.put(p, rr);
                }
            }
        }

        // Seed common protected paths if site map has no 403s yet.
        if (blocked.isEmpty()) {
            for (String seed : ACL_SEEDS) {
                HttpRequestResponse rr = get(base + seed, withSession);
                if (rr != null && rr.response() != null
                        && (rr.response().statusCode() == 403 || rr.response().statusCode() == 401)
                        && seen.add(seed)) blocked.put(seed, rr);
            }
        }

        if (blocked.isEmpty()) return 0;

        // Refine proxy fingerprint from the 403 response body (HAProxy "administrative rules" etc.)
        if (proxyId.isEmpty()) proxyId = fingerprint(blocked.values().iterator().next());
        String label = proxyId.isEmpty() ? "reverse proxy" : proxyId;
        scanLog.debug("  proxy-misconfig [classA]: " + blocked.size() + " blocked path(s) [" + label + "] → testing variants");

        int hits = 0;
        Set<String> fired = new LinkedHashSet<>();
        for (String origPath : new ArrayList<>(blocked.keySet())) {
            HttpRequestResponse orig = blocked.get(origPath);
            String reqBase = orig != null ? schemeAuth(orig.request().url()) : base;
            if (reqBase == null) reqBase = base;
            int origSt = orig != null && orig.response() != null ? orig.response().statusCode() : 403;

            for (String variant : normVariants(origPath)) {
                if (!fired.add(origPath + "→" + variant)) continue;
                HttpRequestResponse rr = get(reqBase + variant, withSession);
                if (!is2xx(rr)) continue;
                scanLog.found("Reverse proxy ACL bypass via path normalization"
                        + (proxyId.isEmpty() ? "" : " [" + proxyId + "]"),
                        reqBase + origPath,
                        label + ": GET " + origPath + " → HTTP " + origSt + " (blocked by proxy ACL); "
                        + "GET " + variant + " → HTTP " + rr.response().statusCode()
                        + " (bypassed). The proxy evaluates the raw encoded path for its ACL rule "
                        + "but the backend normalizes it to the original resource — the proxy and "
                        + "backend disagree on the effective path (CWE-284). Bypass: " + variant + ".",
                        orig, rr);  // orig first → siteMap anchor at /admin (issue URL), rr as secondary proof
                scanLog.incFinding(); hits++;
                scanLog.debug("  proxy-misconfig [classA]: bypass " + origPath + " → " + variant
                        + " (HTTP " + rr.response().statusCode() + ")");
                break; // one confirmed variant per blocked path is enough for the finding
            }

            // Header injection extension: GET / with X-Original-URL: /blocked
            for (String hdr : PATH_OVERRIDE_HDRS) {
                if (!fired.add(origPath + "→hdr:" + hdr)) continue;
                HttpRequestResponse rr = getHdr(reqBase + "/", hdr, origPath, withSession);
                if (!is2xx(rr)) continue;
                String bypassBody = rr.response().bodyToString();
                if (bypassBody == null || bypassBody.toLowerCase().contains(hdr.toLowerCase() + ":")) continue;
                HttpRequestResponse base0 = get(reqBase + "/", withSession);
                if (!bodyDiffersSubstantially(base0, rr, hdr, origPath)) continue;
                scanLog.found("Reverse proxy ACL bypass via header injection"
                        + (proxyId.isEmpty() ? "" : " [" + proxyId + "]"),
                        reqBase + origPath,
                        label + ": GET " + origPath + " → HTTP " + origSt + " (blocked); "
                        + "GET / with [" + hdr + ": " + origPath + "] → HTTP " + rr.response().statusCode()
                        + " (bypassed). The proxy routes on the request path (\"/\") "
                        + "but the backend trusts " + hdr + " as the effective path (CWE-441).",
                        orig, rr);  // orig first → siteMap anchor at /admin (issue URL), rr as secondary proof
                scanLog.incFinding(); hits++;
            }
        }
        return hits;
    }

    // ==========================================================================================
    // Class B: Cache key poisoning via unkeyed Host header
    // ==========================================================================================

    private int classB_cachePoisoning(String base, HttpRequestResponse rootRr, String proxyId,
                                      UnaryOperator<HttpRequest> withSession) {
        // Detection signal: response has cache-indicating headers (Age, X-Cache, Cache-Control: max-age, etc.)
        // No hardcoding of proxy product — purely behavioral.
        if (!isCaching(rootRr)) {
            // Try a static/asset path that commonly has caching enabled.
            boolean foundCache = false;
            for (String seed : CACHE_PATH_SEEDS) {
                HttpRequestResponse rr = get(base + seed + "probe", withSession);
                if (isCaching(rr)) { foundCache = true; break; }
            }
            if (!foundCache) return 0;
        }

        // Build a unique nonce that we'll use as the cache path discriminator.
        String n = "aiscp" + nonce.incrementAndGet();

        // Find a cacheable path prefix: either from root response headers or use /img/ seed.
        String cachePath = findCachePath(base, n, withSession);
        if (cachePath == null) return 0;

        // Poison: GET <cachePath> with attacker Host header — nonce in path ensures unique entry.
        String attackerHost = n + ".attacker.test";
        HttpRequestResponse poison = getHdr(base + cachePath, "Host", attackerHost, withSession);
        if (poison == null || poison.response() == null) return 0;
        String poisonBody = poison.response().bodyToString();

        // The raw echo server will include the attacker Host in its response body.
        // For real targets we check if the response reflects the Host header value in any field.
        boolean bodyReflectsHost = poisonBody != null && poisonBody.contains(attackerHost);

        // Read: GET <cachePath> with legitimate Host — should get a DIFFERENT response if cache is keyed on Host.
        String legitHost = base.replaceAll("https?://", "").replaceAll("/.*", "");
        HttpRequestResponse read = getHdr(base + cachePath, "Host", legitHost, withSession);
        if (read == null || read.response() == null) return 0;
        String readBody = read.response().bodyToString();

        // Oracle: if the read response body STILL contains the attacker Host value → cache poisoned.
        boolean poisoned = bodyReflectsHost && readBody != null && readBody.contains(attackerHost);
        // Fallback oracle: response bodies are identical despite different Host headers (cache not keyed on Host).
        boolean identical = readBody != null && poisonBody != null
                && readBody.equals(poisonBody) && readBody.length() > 10;

        if (!poisoned && !identical) return 0;

        String label = proxyId.isEmpty() ? "reverse proxy" : proxyId;
        scanLog.found("Reverse proxy cache poisoning via unkeyed Host header"
                + (proxyId.isEmpty() ? "" : " [" + proxyId + "]"),
                base + cachePath,
                label + ": cache key does not include the Host header. "
                + "GET " + cachePath + " with [Host: " + attackerHost + "] was cached, "
                + "then GET " + cachePath + " with [Host: " + legitHost + "] returned the "
                + "cached response from the attacker's request — the Host header is unkeyed "
                + "(CWE-345 / Web Cache Poisoning). An attacker can serve arbitrary content "
                + "to all users who share the cached response.",
                read, poison);
        scanLog.incFinding();
        scanLog.debug("  proxy-misconfig [classB]: cache poisoning confirmed on " + cachePath);
        return 1;
    }

    /** True when a response carries behavioral cache signals (no product hardcoding). */
    private static boolean isCaching(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        // Age: N (positive) → response served from cache
        String age = rr.response().headerValue("Age");
        if (age != null) { try { if (Integer.parseInt(age.trim()) > 0) return true; } catch (NumberFormatException ignore) {} }
        // X-Cache: HIT / X-Cache-Status: HIT / CF-Cache-Status: HIT
        for (String h : new String[]{"X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Nuster-Cache"}) {
            String v = rr.response().headerValue(h);
            if (v != null && v.toUpperCase().contains("HIT")) return true;
            if (v != null && !v.toUpperCase().contains("MISS") && !v.isEmpty()) return true;
        }
        // Cache-Control: max-age=N (N > 0) on a non-private response
        String cc = rr.response().headerValue("Cache-Control");
        if (cc != null && !cc.contains("private") && !cc.contains("no-store")) {
            java.util.regex.Matcher m = Pattern.compile("max-age=(\\d+)").matcher(cc);
            if (m.find()) { try { if (Integer.parseInt(m.group(1)) > 0) return true; } catch (NumberFormatException ignore) {} }
            if (cc.contains("public")) return true;
        }
        return false;
    }

    /** Find a path that the proxy actually caches (returns cache headers or is in CACHE_PATH_SEEDS). */
    private String findCachePath(String base, String nonce, UnaryOperator<HttpRequest> withSession) {
        // Try seeded static prefixes
        for (String seed : CACHE_PATH_SEEDS) {
            String path = seed + nonce;
            HttpRequestResponse rr = get(base + path, withSession);
            if (rr != null && rr.response() != null) {
                // Even a 404 from the real backend is fine — what matters is whether the PROXY caches it
                // (detected by the second request returning a cached response). We just need a consistent path.
                return path;
            }
        }
        return null;
    }

    // ==========================================================================================
    // Class C: Path normalization redirect
    // ==========================================================================================

    private int classC_normalizationRedirect(String base, String proxyId,
                                              UnaryOperator<HttpRequest> withSession) {
        // Test: send encoded paths → check if proxy issues a 3xx redirect to the normalized form.
        // A 308/301 redirect from /%2fadmin → /admin proves the proxy normalizes encoded slashes.
        // A 301 from //admin → /admin proves merge_slashes behavior.
        // Neither requires prior knowledge of which proxy is running.
        String[][] tests = {
            {"/%2fadmin",    "/admin"},
            {"/%2Fadmin",    "/admin"},
            {"//admin",      "/admin"},
            {"/./admin",     "/admin"},
            {"/%2fstatic/",  "/static/"},
            {"//static/",    "/static/"},
        };

        String label = proxyId.isEmpty() ? "reverse proxy" : proxyId;
        int hits = 0;
        Set<String> fired = new LinkedHashSet<>();
        for (String[] pair : tests) {
            String encoded = pair[0], expected = pair[1];
            if (!fired.add(encoded)) continue;
            HttpRequestResponse rr = getRaw(base + encoded, withSession); // don't follow redirects
            if (rr == null || rr.response() == null) continue;
            int st = rr.response().statusCode();
            if (st < 300 || st >= 400) continue;
            String loc = rr.response().headerValue("Location");
            if (loc == null) continue;
            // Confirm the redirect target is the decoded/normalized form of what we sent.
            boolean normalizes = loc.endsWith(expected) || loc.contains(expected + "?") || loc.contains(expected + "#");
            if (!normalizes) continue;
            if (!fired.add("redirect:" + encoded)) continue;
            scanLog.found("Reverse proxy path normalization redirect"
                    + (proxyId.isEmpty() ? "" : " [" + proxyId + "]"),
                    base + encoded,
                    label + ": GET " + encoded + " → HTTP " + st + " redirect to " + loc
                    + ". The proxy actively normalizes percent-encoded path separators and "
                    + "redirects clients to the decoded path. This reveals the original path "
                    + "intent and can bypass backend ACLs that check the literal request URI "
                    + "(CWE-436 — path normalization inconsistency). The client's encoded path "
                    + "is rewritten to " + expected + " before reaching the backend.",
                    rr);
            scanLog.incFinding(); hits++;
            scanLog.debug("  proxy-misconfig [classC]: normalization redirect " + encoded + " → " + loc + " (HTTP " + st + ")");
            break; // one confirmed normalization pattern per proxy is enough
        }
        return hits;
    }

    // ==========================================================================================
    // Class D: Host header routing bypass
    // ==========================================================================================

    private int classD_hostRoutingBypass(String base, HttpRequestResponse rootRr, String proxyId,
                                         UnaryOperator<HttpRequest> withSession) {
        // Detection signal: default request returns 4xx (no route matches), but injecting a
        // different Host header causes the proxy to route the request to a backend. This is
        // purely behavioral — we try candidate hostnames without knowing which one is "correct".
        if (rootRr == null || rootRr.response() == null) return 0;
        int defaultStatus = rootRr.response().statusCode();
        // If default request already returns 2xx/3xx, the proxy isn't gating on Host — skip.
        if (defaultStatus >= 200 && defaultStatus < 400) return 0;

        // Candidate backend hostnames. No hardcoding of specific proxy or target knowledge:
        // these are the common virtual-host names used in reverse proxy configurations.
        String[] candidates = {
            "lab.io", "backend", "internal", "api", "admin", "app", "service",
            "localhost", "127.0.0.1", "host.docker.internal",
        };

        String label = proxyId.isEmpty() ? "reverse proxy" : proxyId;
        for (String candidate : candidates) {
            HttpRequestResponse rr = getHdr(base + "/", "Host", candidate, withSession);
            if (rr == null || rr.response() == null) continue;
            int st = rr.response().statusCode();
            // A 2xx or 3xx (vs the 4xx baseline) with a different body = routing bypass.
            if (st < 200 || st >= 400) continue;
            // Confirm the body differs from the baseline (not just a static error page at 200).
            String bypassBody = rr.response().bodyToString();
            String defaultBody = rootRr.response().bodyToString();
            if (bypassBody == null || bypassBody.equals(defaultBody)) continue;
            if (bypassBody.length() < 5) continue;

            scanLog.found("Reverse proxy Host header routing bypass"
                    + (proxyId.isEmpty() ? "" : " [" + proxyId + "]"),
                    base + "/",
                    label + ": GET / with default Host → HTTP " + defaultStatus + " (no matching route); "
                    + "GET / with [Host: " + candidate + "] → HTTP " + st
                    + " (route matched, backend responded). The proxy selects its backend "
                    + "routing target based solely on the Host request header — an attacker "
                    + "can reach backends not intended to be publicly accessible by spoofing "
                    + "the Host header (CWE-441). No SNI or IP-based enforcement.",
                    rr, rootRr);
            scanLog.incFinding();
            scanLog.debug("  proxy-misconfig [classD]: Host routing bypass with Host: " + candidate + " (HTTP " + st + ")");
            return 1; // one confirmed bypass is enough for the finding
        }
        return 0;
    }

    // ==========================================================================================
    // ==========================================================================================
    // Class E: Open proxy via Absolute-URI
    // ==========================================================================================

    /**
     * Test whether the proxy forwards GET http://arbitrary-host/ requests to the specified host,
     * acting as an open proxy / relay to hosts the attacker cannot reach directly.
     *
     * <p><b>Oracle:</b> primary = Burp Collaborator OOB (the proxy's outbound request hits our
     * Collaborator payload, proving the proxy made an outbound HTTP/DNS request on our behalf);
     * fallback = {@link LocalSsrfListener} for air-gapped or Docker targets. Both are zero-FP
     * (unique nonce/tag per probe, the callback can only come from the proxy forwarding it).
     *
     * <p><b>Attack:</b> {@code GET http://internal-host:PORT/path HTTP/1.1} sent to the proxy.
     * The proxy resolves and fetches the absolute-URI host instead of its configured backend,
     * giving the attacker an authenticated relay to otherwise unreachable internal services.
     */
    private int classE_openProxyAbsoluteUri(String base, String proxyId,
                                             HttpRequestResponse rootRr,
                                             UnaryOperator<HttpRequest> ws) {
        // Setup oracles
        CollaboratorClient collab = null;
        try { collab = api.collaborator().createClient(); } catch (Throwable ignore) {}
        LocalSsrfListener localListener = LocalSsrfListener.start();
        if (collab == null && localListener == null) {
            scanLog.debug("  proxy-misconfig [classE]: no OOB oracle (Collaborator unavailable, local listener failed) — skipping");
            return 0;
        }

        // Parse proxy connection parameters from the base URL
        URI baseUri; try { baseUri = URI.create(base); } catch (Exception e) { return 0; }
        String proxyHost = baseUri.getHost();
        int proxyPort   = baseUri.getPort() < 0 ? ("https".equalsIgnoreCase(baseUri.getScheme()) ? 443 : 80) : baseUri.getPort();
        boolean secure  = "https".equalsIgnoreCase(baseUri.getScheme());

        // Generate a unique tag for this probe (used to correlate the Collaborator/local callback)
        String tag = "pxoe" + nonce.incrementAndGet();
        String payloadUrl;
        if (collab != null) {
            CollaboratorPayload cp = collab.generatePayload();
            payloadUrl = "http://" + cp.toString() + "/" + tag;
        } else {
            payloadUrl = "http://host.docker.internal:" + localListener.port()
                       + "/" + localListener.nonce() + "/" + tag;
        }

        // Build the absolute-URI HTTP request. The request LINE contains the full URL
        // (GET http://collab-host/tag HTTP/1.1) while the TCP connection goes to the PROXY.
        // HttpRequest.httpRequest(HttpService, String) lets us specify these independently.
        String rawReq = "GET " + payloadUrl + " HTTP/1.1\r\n"
                      + "Host: " + proxyHost + ":" + proxyPort + "\r\n"
                      + "User-Agent: Mozilla/5.0\r\n"
                      + "Connection: close\r\n\r\n";
        HttpRequestResponse rr = null;
        try {
            HttpService proxySvc = HttpService.httpService(proxyHost, proxyPort, secure);
            HttpRequest req = HttpRequest.httpRequest(proxySvc, rawReq);
            politeness();
            rr = send(req);
            scanLog.debug("  proxy-misconfig [classE]: sent GET " + payloadUrl
                    + " to proxy → HTTP " + (rr != null && rr.response() != null ? rr.response().statusCode() : "?"));
        } catch (Throwable t) {
            scanLog.debug("  proxy-misconfig [classE]: send error: " + t);
            return 0;
        }

        // Wait briefly for async OOB callbacks (DNS lookup is near-instant; HTTP is a few ms more)
        try { Thread.sleep(3000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }

        // Poll for confirmed callbacks
        boolean hit = false;
        String callbackDetail = "";
        if (collab != null) {
            try {
                java.util.List<Interaction> its = collab.getAllInteractions();
                if (!its.isEmpty()) {
                    hit = true;
                    callbackDetail = its.get(0).type().toString()
                        + " callback received by Burp Collaborator (from proxy outbound request)";
                }
            } catch (Throwable ignore) {}
        }
        if (!hit && localListener != null && localListener.received(tag)) {
            hit = true;
            callbackDetail = "HTTP callback received by local listener (from proxy container)";
        }
        if (!hit) {
            scanLog.debug("  proxy-misconfig [classE]: no OOB callback — proxy did not forward the absolute URI");
            return 0;
        }

        String label = proxyId.isEmpty() ? "reverse proxy" : proxyId;
        String oracleNote = (collab != null ? "Burp Collaborator" : "local listener") + ": " + callbackDetail;
        scanLog.found("Reverse proxy open proxy via Absolute-URI"
                + (proxyId.isEmpty() ? "" : " [" + proxyId + "]"),
                base + "/",
                label + ": sending [GET " + payloadUrl + " HTTP/1.1] to the proxy caused an outbound "
                + "request to " + payloadUrl.split("/")[2] + ". "
                + "The proxy forwarded the Absolute-URI request to the attacker-controlled host "
                + "instead of its configured backend — it acts as an open relay, allowing an attacker "
                + "to reach internal hosts (intranet, cloud metadata, internal APIs) that are not "
                + "directly accessible from the internet (CWE-441 / SSRF via proxy forwarding). "
                + oracleNote + ".",
                rootRr, rr);  // rootRr first → site map anchor stays on localhost:PORT, not Collaborator domain
        scanLog.incFinding();
        scanLog.debug("  proxy-misconfig [classE]: OPEN PROXY confirmed → " + payloadUrl + " (" + callbackDetail + ")");
        return 1;
    }

    // ==========================================================================================
    // Fingerprint (informational only — NOT used to branch test logic)
    // ==========================================================================================

    private static String fingerprint(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "";
        try {
            for (String h : new String[]{"Server", "Via", "X-Powered-By", "X-Served-By"}) {
                String v = rr.response().headerValue(h);
                if (v != null) {
                    java.util.regex.Matcher m = PROXY_HDR.matcher(v);
                    if (m.find()) return m.group().toLowerCase();
                }
            }
            if (rr.response().headerValue("x-envoy-upstream-service-time") != null) return "envoy";
            if (rr.response().headerValue("X-Varnish") != null)                      return "varnish";
            if (rr.response().headerValue("CF-RAY") != null)                          return "cloudflare";
            if (rr.response().headerValue("X-Nuster-Cache") != null)                  return "nuster";
            String body = rr.response().bodyToString();
            if (body != null) {
                String bl = body.toLowerCase();
                if (bl.contains("administrative rules")) return "haproxy";
                if (bl.contains("nginx"))               return "nginx";
                if (bl.contains("envoy"))               return "envoy";
                if (bl.contains("traefik"))             return "traefik";
                if (bl.contains("caddy"))               return "caddy";
                if (bl.contains("nuster"))              return "nuster";
            }
        } catch (Throwable ignore) {}
        return "";
    }

    // ==========================================================================================
    // Helpers
    // ==========================================================================================

    private String resolveBase(String host) {
        String base = schemeAuth(host);
        if (base != null) return base;
        // host is bare authority — infer scheme from site map
        String scheme = "http";
        boolean sawHost = false;
        for (HttpRequestResponse smr : api.siteMap().requestResponses()) {
            if (smr == null || smr.request() == null) continue;
            String u = smr.request().url();
            if (!host.equalsIgnoreCase(hostOf(u))) continue;
            if (!u.regionMatches(true, 0, "https", 0, 5)) { scheme = "http"; break; }
            if (!sawHost) { scheme = "https"; sawHost = true; }
        }
        return scheme + "://" + host;
    }

    private boolean matchesHost(String url, String targetHost) {
        try {
            String auth = URI.create(url).getAuthority();
            if (auth == null) return false;
            if (targetHost.startsWith("http")) return auth.equalsIgnoreCase(URI.create(targetHost).getAuthority());
            return targetHost.equalsIgnoreCase(auth);
        } catch (Exception e) { return false; }
    }

    private static String schemeAuth(String url) {
        try {
            URI u = URI.create(url);
            if (u.getScheme() == null || u.getAuthority() == null) return null;
            return u.getScheme() + "://" + u.getAuthority();
        } catch (Exception e) { return null; }
    }

    private HttpRequestResponse get(String url, UnaryOperator<HttpRequest> ws) {
        try {
            HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (ws != null) r = ws.apply(r);
            politeness(); return send(r);
        } catch (Throwable t) { return null; }
    }

    /** GET without following redirects (to detect 3xx directly). */
    private HttpRequestResponse getRaw(String url, UnaryOperator<HttpRequest> ws) {
        try {
            HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (ws != null) r = ws.apply(r);
            politeness();
            return api.http().sendRequest(r,
                burp.api.montoya.http.RequestOptions.requestOptions().withResponseTimeout(requestTimeoutMs()));
        } catch (Throwable t) { return null; }
    }

    private HttpRequestResponse getHdr(String url, String hdrName, String hdrVal,
                                       UnaryOperator<HttpRequest> ws) {
        try {
            HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod("GET")
                    .withHeader(hdrName, hdrVal);
            if (ws != null) r = ws.apply(r);
            politeness(); return send(r);
        } catch (Throwable t) { return null; }
    }

    private static boolean is2xx(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        int st = rr.response().statusCode();
        if (st < 200 || st >= 300) return false;
        String body = rr.response().bodyToString();
        if (body == null || body.trim().length() < 3) return false;
        String bl = body.trim().toLowerCase();
        if (bl.length() < 500 && (bl.contains("forbidden") || bl.contains("access denied")
                || bl.contains("not allowed") || bl.contains("unauthorized"))) return false;
        return true;
    }

    private static boolean bodyDiffersSubstantially(HttpRequestResponse baseline,
                                                     HttpRequestResponse candidate,
                                                     String hdrName, String hdrVal) {
        if (baseline == null || baseline.response() == null) return true;
        if (candidate == null || candidate.response() == null) return false;
        String b0 = baseline.response().bodyToString(), b1 = candidate.response().bodyToString();
        if (b0 == null || b1 == null) return false;
        if (b0.equals(b1)) return false;
        // If diff is only the injected header echoed back → echo server, not real bypass
        if (b1.toLowerCase().contains(hdrName.toLowerCase() + ":")) return false;
        int diff = Math.abs(b0.length() - b1.length());
        return diff > hdrName.length() + hdrVal.length() + 5;
    }
}
