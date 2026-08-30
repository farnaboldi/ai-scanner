package com.ioactive.aiscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import org.json.JSONObject;
import java.net.URI;
import java.util.Arrays;

/**
 * Shared URL/host helpers.
 *
 * <p>{@link #authority(String)} is PORT-AWARE (returns {@code host[:port]} with the scheme's default port elided),
 * so two targets that differ ONLY by port — e.g. two {@code localhost} apps scanned CONCURRENTLY in one Burp —
 * are DISTINCT hosts for every scope / dedup / site-map filter. This consolidates ~23 identical private
 * {@code hostOf()} copies, each of which used {@link URI#getHost()} and silently dropped the port; on a parallel
 * scan of {@code localhost:9500} + {@code localhost:1337} that made both indistinguishable, so each scan mined,
 * fuzzed, and attributed the OTHER target's requests. Making host identity carry the port fixes that in one place.
 *
 * <p>Default-port elision ({@code http:80 https:443 ws:80 wss:443} → no suffix) means production https targets are
 * unaffected (authority == bare hostname, exactly the old behaviour); only non-default dev ports gain a suffix,
 * which is precisely where the port distinguishes concurrent targets.
 */
public final class Net {
    private Net() {}

    /** {@code host[:port]} with the scheme's default port elided; {@code ""} on null / parse failure. */
    public static String authority(String url) {
        if (url == null) return "";
        try {
            URI u = URI.create(url);
            String h = u.getHost();
            if (h == null) return "";
            int port = u.getPort();
            return (port == -1 || port == defaultPort(u.getScheme())) ? h : h + ":" + port;
        } catch (Exception e) { return ""; }
    }

    /** The URL with any {@code ?query} stripped (consolidates ~15 identical private {@code stripQuery} copies). */
    public static String stripQuery(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        return q < 0 ? url : url.substring(0, q);
    }

    /**
     * Percent-encode the characters a strict server (Tomcat / Jetty / most Java stacks) rejects with 400 when they
     * appear RAW in a URL query value — chiefly the SPACE, plus the RFC-3986 "unwise"/delimiter set. Montoya places
     * a URL/form parameter value onto the wire literally (it does NOT auto-encode), so an injection payload with a
     * space (nearly every SQLi/blind/time payload) or an angle bracket (reflected-XSS) is dropped as a malformed
     * request BEFORE the app ever parses it — silently zeroing injection coverage on Java targets. We encode only
     * the wire-unsafe set and deliberately leave {@code & = % + '} untouched: those are query-structural or already
     * handled, and encoding them here would double-encode / change insertion semantics. Idempotent for the payloads
     * we send (they contain none of the encoded chars pre-encoded). Generic — no app or server fingerprint. */
    public static String encQuery(String v) {
        if (v == null || v.isEmpty()) return v;
        StringBuilder out = new StringBuilder(v.length() + 8);
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case ' ':  out.append("%20"); break;
                case '\n': out.append("%0A"); break;
                case '\r': out.append("%0D"); break;
                case '\t': out.append("%09"); break;
                case '"':  out.append("%22"); break;
                case '<':  out.append("%3C"); break;
                case '>':  out.append("%3E"); break;
                case '#':  out.append("%23"); break;
                case '{':  out.append("%7B"); break;
                case '}':  out.append("%7D"); break;
                case '|':  out.append("%7C"); break;
                case '\\': out.append("%5C"); break;
                case '^':  out.append("%5E"); break;
                case '`':  out.append("%60"); break;
                case '[':  out.append("%5B"); break;
                case ']':  out.append("%5D"); break;
                default:   out.append(c);
            }
        }
        return out.toString();
    }

    /** Bare hostname (no port) — for eTLD/registrable-domain and cookie-domain logic where the port is irrelevant. */
    public static String hostName(String url) {
        if (url == null) return "";
        try { String h = URI.create(url).getHost(); return h == null ? "" : h; } catch (Exception e) { return ""; }
    }

    /** Response SHAPE = status + sorted top-level JSON keys (value/order-insensitive), or a path-stripped token
     *  signature for non-JSON — so a real handler's response is distinguishable from a route-not-found without any
     *  framework-specific strings, and reorder/value noise can't move it. Consolidates the byte-identical private
     *  copies the access-control probes (BFLA / Unauth) used to compare a real response vs a 404 route-not-found.
     *  Pure + side-effect-free: the probes keep their own oracle/candidate/finding logic; only this signature is shared. */
    public static String shape(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "none";
        int st = rr.response().statusCode();
        String body = rr.response().bodyToString();
        if (body != null) {
            String t = body.trim();
            if (t.startsWith("{")) {
                try {
                    JSONObject o = new JSONObject(t);
                    String[] keys = o.keySet().toArray(new String[0]);
                    Arrays.sort(keys);
                    return st + ":keys:" + String.join(",", keys);
                } catch (Throwable ignore) { /* fall through */ }
            }
        }
        String norm = (body == null ? "" : body)
                .replaceAll("\\d+", "#")
                .replaceAll("(?i)[a-z0-9/_.-]{16,}", " ")   // drop long path/id-ish tokens (incl. the echoed URL)
                .replaceAll("\\s+", " ").trim();
        String[] toks = norm.split(" ");
        Arrays.sort(toks);
        return st + ":body:" + String.join(" ", toks);
    }

    private static int defaultPort(String scheme) {
        if (scheme == null) return -1;
        switch (scheme.toLowerCase()) {
            case "http": case "ws":  return 80;
            case "https": case "wss": return 443;
            default: return -1;
        }
    }
}
