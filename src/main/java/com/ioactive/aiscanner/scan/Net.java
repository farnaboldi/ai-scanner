package com.ioactive.aiscanner.scan;

import java.net.URI;

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

    /** Bare hostname (no port) — for eTLD/registrable-domain and cookie-domain logic where the port is irrelevant. */
    public static String hostName(String url) {
        if (url == null) return "";
        try { String h = URI.create(url).getHost(); return h == null ? "" : h; } catch (Exception e) { return ""; }
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
