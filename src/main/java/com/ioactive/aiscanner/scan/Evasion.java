package com.ioactive.aiscanner.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WAF-evasion library. Two responsibilities:
 *
 * <p><b>1. Toggle.</b> Probes check {@link #enabled()} and, when true, ALSO send obfuscated payload
 * variants that slip common WAF signature rules (ModSecurity/OWASP CRS, Cloudflare OWASP, Akamai KSD).
 * Enabled manually via {@code -Daiscanner.wafEvasion=true} / {@code AISCANNER_WAF_EVASION=true} (the
 * Settings checkbox), OR automatically via {@link #autoEnable(String)} when {@link WafObserver} detects a
 * WAF fingerprint during the scan — so if Cloudflare or Akamai starts blocking, evasion kicks in without
 * the user having to toggle it first.
 *
 * <p><b>2. Transform library.</b> Static methods that produce semantics-preserving payload variants:
 * <ul>
 *   <li>SQL: inline comments, case-flip, double-nested comments (bypasses CRS paranoia level 1–2).</li>
 *   <li>NoSQL: Unicode-escape MongoDB operator {@code $}.</li>
 *   <li>XSS: covered by {@link EvasionXssProbe} (tag/handler obfuscation).</li>
 *   <li>HTTP headers: X-Forwarded-For / X-Real-IP / True-Client-IP spoofing to defeat IP-based
 *       rate-limit/geo-block rules; {@code X-Original-URL} / {@code X-Rewrite-URL} for path-override
 *       bypasses; {@code X-Custom-IP-Authorization} for misconfigured internal-IP allowlists.</li>
 *   <li>Path: double URL-encode, dot-segment insertion ({@code /./}), case-variation (IIS), null-byte
 *       extension (.php%00.jpg) — all normalized by the origin server, not by the WAF.</li>
 *   <li>Content-Type swap: send JSON as {@code text/plain} or rotate to {@code application/xml} to slip
 *       rules that only inspect typed bodies.</li>
 * </ul>
 *
 * <p>Every transform is semantics-preserving: the origin server decodes it to the original payload, so a
 * positive finding is still real. All are the same techniques a human tester uses in an authorized test.
 */
public final class Evasion {
    private Evasion() {}

    private static final AtomicBoolean autoFlag = new AtomicBoolean(false);
    private static volatile String autoReason = "";
    private static volatile String userAgentOverride = "";   // set by AISCANNER_USER_AGENT to match the CF-challenge-solving browser

    // Cloudflare-specific signals (used by autoEnable to log which WAF triggered)
    static final Pattern CF_FINGERPRINT = Pattern.compile(
            "(?i)(cf-ray|cf-mitigated|cloudflare|__cf_bm|cf_clearance|challenge-platform)", Pattern.CASE_INSENSITIVE);

    public static boolean enabled() {
        if (autoFlag.get()) return true;
        if (Boolean.getBoolean("aiscanner.wafEvasion")) return true;
        String e = System.getenv("AISCANNER_WAF_EVASION");
        return e != null && e.equalsIgnoreCase("true");
    }

    /**
     * Called by {@link WafObserver} the first time it detects a WAF fingerprint. Permanently enables
     * evasion for this JVM process so all subsequent probe calls benefit. {@code fingerprint} is the
     * signal string from WafObserver (e.g. {@code "cf-ray=abc123"}).
     */
    public static void autoEnable(String fingerprint) {
        if (autoFlag.compareAndSet(false, true)) {
            autoReason = fingerprint == null ? "WAF detected" : fingerprint;
        }
    }

    /** Returns the fingerprint string that triggered auto-enable, or "" if not auto-enabled. */
    public static String autoReason() { return autoReason; }

    /** Set a static User-Agent to send on every probe request (pair with cf_clearance — cookie is UA-bound). */
    public static void setUserAgent(String ua) { userAgentOverride = ua == null ? "" : ua; }
    public static String userAgent() { return userAgentOverride; }
    public static boolean hasUserAgent() { return !userAgentOverride.isEmpty(); }

    /**
     * Unicode-escape the leading '$' of Mongo operator keys in a JSON body: {@code "$ne"} → {@code "$ne"}.
     * A JSON parser decodes {@code $} back to '$', so the operator still reaches the query, but a WAF rule
     * matching a literal {@code "$op"} in the raw body no longer sees it (validated bypass of OWASP CRS 942290
     * and of naive custom rules). Only rewrites a '$' that immediately follows a quote (a key position).
     */
    public static String jsonDollarEscape(String jsonBody) {
        if (jsonBody == null) return null;
        return jsonBody.replaceAll("\"\\$", Matcher.quoteReplacement("\"\\u0024"));
    }

    /**
     * Obfuscated variants of a SQL-injection payload that are semantically identical but defeat common
     * signature matches: inline SQL comments between keywords, random case, and both combined. The server's
     * SQL parser ignores inline comments and is case-insensitive, so the injection still runs.
     */
    public static List<String> sqlVariants(String payload) {
        List<String> out = new ArrayList<>();
        if (payload == null || payload.isBlank()) return out;
        final String INLINE = "/" + "**" + "/";      // inline SQL comment, built to avoid a Javadoc terminator
        // inline comments replacing spaces (e.g. "OR 1=1" -> "OR<inline-comment>1=1")
        out.add(payload.replaceAll("\\s+", Matcher.quoteReplacement(INLINE)));
        // random-ish case flip of alpha keywords (OR → oR, UNION → UnIoN, SELECT → SeLeCt)
        out.add(caseFlip(payload));
        // both
        out.add(caseFlip(payload).replaceAll("\\s+", Matcher.quoteReplacement(INLINE)));
        return out;
    }

    /** Alternate the case of alphabetic characters — evades case-sensitive signature fragments. */
    public static String caseFlip(String s) {
        StringBuilder sb = new StringBuilder();
        boolean up = false;
        for (char c : s.toCharArray()) {
            if (Character.isLetter(c)) { sb.append(up ? Character.toUpperCase(c) : Character.toLowerCase(c)); up = !up; }
            else sb.append(c);
        }
        return sb.toString();
    }

    // ---- HTTP header evasion -----------------------------------------------------------

    /**
     * Headers that may override the client IP seen by WAF rate-limit / geo-block / internal-allowlist rules.
     * Some CDN configs trust these unconditionally (misconfiguration), letting us appear to come from
     * localhost or a private-range IP that bypasses IP-based rules. Return as "Name: value" strings ready
     * to add to a request.
     */
    public static List<String> ipSpoofHeaders(String spoofIp) {
        if (spoofIp == null || spoofIp.isBlank()) spoofIp = "127.0.0.1";
        List<String> h = new ArrayList<>();
        h.add("X-Forwarded-For: " + spoofIp);
        h.add("X-Real-IP: " + spoofIp);
        h.add("True-Client-IP: " + spoofIp);
        h.add("CF-Connecting-IP: " + spoofIp);     // Cloudflare passes this; origin apps may trust it
        h.add("X-Custom-IP-Authorization: " + spoofIp);
        h.add("X-Originating-IP: " + spoofIp);
        return h;
    }

    /**
     * Path-override headers that some reverse proxies / CDN configs honour, letting us reach a path
     * that an edge rule blocks while sending the HTTP request to a different (allowed) path. Both headers
     * are "Name: value" strings. The caller sends the request to {@code allowedPath} while the origin
     * (if misconfigured to trust the override) processes {@code targetPath}.
     */
    public static List<String> pathOverrideHeaders(String targetPath) {
        List<String> h = new ArrayList<>();
        h.add("X-Original-URL: " + targetPath);
        h.add("X-Rewrite-URL: " + targetPath);
        return h;
    }

    // ---- Path evasion ------------------------------------------------------------------

    /**
     * Path variants that some WAFs normalise differently from the origin server, letting the request
     * through the WAF while the origin still resolves to the target path.
     */
    public static List<String> pathVariants(String path) {
        List<String> v = new ArrayList<>();
        if (path == null || path.isBlank()) return v;
        // dot-segment: /admin/secret → /admin/./secret  (WAF may not normalise; Nginx/Apache do)
        v.add(path.replaceFirst("(/[^/]+)(/)", "$1/.$2"));
        // double slash: /admin/secret → //admin/secret
        v.add("/" + path.replaceFirst("^/+", ""));
        if (!v.get(1).equals(path)) v.set(1, v.get(1).replaceFirst("/", "//"));
        else v.set(1, "/" + path);
        // double URL-encode the first non-slash character (e.g. /a → /%2561)
        int first = path.indexOf('/');
        if (first >= 0 && first + 1 < path.length()) {
            char c = path.charAt(first + 1);
            String enc = String.format("%%%02X", (int) c);
            String doubleEnc = "%" + String.format("%02X", (int) '%') + enc.substring(1);
            v.add(path.substring(0, first + 1) + doubleEnc + path.substring(first + 2));
        }
        return v;
    }

    // ---- Content-Type evasion ----------------------------------------------------------

    /**
     * Alternative Content-Type values for a JSON body. Some WAFs inspect typed bodies (only parse JSON
     * when Content-Type is application/json); swapping to text/plain or application/xml causes them to
     * skip the body signature check while the origin app still processes the JSON or form data.
     */
    public static List<String> contentTypeVariants() {
        List<String> ct = new ArrayList<>();
        ct.add("text/plain");
        ct.add("application/x-www-form-urlencoded");
        ct.add("application/xml");
        ct.add("application/json; charset=utf-7");   // charset swap confuses some WAF parsers
        return ct;
    }

    // ---- Autonomous Cloudflare bypass ------------------------------------------------

    // Browser-realistic headers that Cloudflare's bot-detection expects to see from a real Chrome.
    // A Burp probe request is missing most of these → bot score rises → block. Injecting them
    // autonomously (no user config) makes probe traffic look like a browser-initiated fetch.
    private static final String[][] BROWSER_HEADERS = {
        { "Accept",                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" },
        { "Accept-Language",           "en-US,en;q=0.9" },
        { "Accept-Encoding",           "gzip, deflate, br" },
        { "Sec-CH-UA",                 "\"Chromium\";v=\"128\", \"Google Chrome\";v=\"128\", \"Not-A.Brand\";v=\"99\"" },
        { "Sec-CH-UA-Mobile",          "?0" },
        { "Sec-CH-UA-Platform",        "\"macOS\"" },
        { "Sec-Fetch-Dest",            "document" },
        { "Sec-Fetch-Mode",            "navigate" },
        { "Sec-Fetch-Site",            "none" },
        { "Sec-Fetch-User",            "?1" },
        { "Upgrade-Insecure-Requests", "1" },
    };

    // Default realistic Chrome UA — used when no AISCANNER_USER_AGENT is set and evasion is active.
    private static final String DEFAULT_BROWSER_UA =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

    /**
     * Autonomous Cloudflare bypass: reads {@code cf_clearance} + {@code __cf_bm} from Burp's cookie jar
     * for {@code domain} (populated when the user browses the site in Burp's embedded browser, which
     * executes JS and solves the challenge). Returns a ready-to-inject Cookie header string, or "" if
     * no CF cookies are present.
     */
    public static String extractCfClearance(burp.api.montoya.MontoyaApi api, String domain) {
        if (api == null || domain == null) return "";
        try {
            StringBuilder sb = new StringBuilder();
            for (burp.api.montoya.http.message.Cookie c : api.http().cookieJar().cookies()) {
                String name = c.name();
                if (!"cf_clearance".equals(name) && !"__cf_bm".equals(name)) continue;
                String cd = c.domain() == null ? "" : c.domain().replaceAll("^\\.", "");
                if (!domain.endsWith(cd) && !cd.endsWith(domain)) continue;
                if (sb.length() > 0) sb.append("; ");
                sb.append(name).append("=").append(c.value());
            }
            return sb.toString();
        } catch (Throwable ignore) { return ""; }
    }

    /**
     * Inject browser-realistic headers onto a probe request when evasion is active. Adds the Sec-CH-UA
     * suite, Accept family, and Sec-Fetch-* headers that Cloudflare's bot-detection expects from Chrome
     * but that Burp strips. Only adds headers not already present (never overwrites existing values).
     * Call this inside {@link Probe#send} alongside the IP-spoof injection.
     */
    public static burp.api.montoya.http.message.requests.HttpRequest injectBrowserHeaders(
            burp.api.montoya.http.message.requests.HttpRequest req) {
        for (String[] kv : BROWSER_HEADERS) {
            if (!req.hasHeader(kv[0])) req = req.withHeader(kv[0], kv[1]);
        }
        if (!req.hasHeader("User-Agent")) {
            String ua = userAgentOverride.isEmpty() ? DEFAULT_BROWSER_UA : userAgentOverride;
            req = req.withHeader("User-Agent", ua);
        }
        return req;
    }

    // ---- WAF detection (pure-Java, usable without Burp) --------------------------------

    /**
     * Detect a WAF/CDN signal from raw response headers + body (string form). Returns a short fingerprint
     * description or {@code null} if no WAF signal is found. Pure-Java — no Montoya types — so it can be
     * exercised in the standalone unit test ({@link EvasionTest}) without a running Burp.
     *
     * <p>Mirrors the logic in {@link WafObserver#wafSignal} but operates on plain strings so both code
     * paths can share coverage in tests.
     */
    public static String detectWaf(java.util.Map<String, String> responseHeaders, String responseBody) {
        if (responseHeaders != null) {
            for (java.util.Map.Entry<String, String> e : responseHeaders.entrySet()) {
                String k = e.getKey().toLowerCase();
                if (k.equals("cf-ray") || k.equals("cf-mitigated") || k.equals("x-amzn-waf-action")
                        || k.equals("x-sucuri-id") || k.equals("x-sucuri-block") || k.equals("x-datadome")
                        || k.equals("x-waf") || k.equals("x-waf-event") || k.equals("x-waf-action")
                        || k.equals("x-iinfo") || k.equals("x-sq-server")) {
                    return k + "=" + e.getValue();
                }
                if (k.equals("server") && e.getValue() != null
                        && WafObserver.WAF_SERVER.matcher(e.getValue()).find()) {
                    return "Server=" + e.getValue();
                }
            }
        }
        if (responseBody != null && !responseBody.isEmpty()) {
            String body = responseBody.length() > 4096 ? responseBody.substring(0, 4096) : responseBody;
            if (WafObserver.WAF_BODY.matcher(body).find()) return "block-page body";
        }
        return null;
    }
}
