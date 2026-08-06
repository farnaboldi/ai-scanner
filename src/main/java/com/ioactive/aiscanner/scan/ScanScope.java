package com.ioactive.aiscanner.scan;

import java.net.URI;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The set of hosts an AI Scanner scan has touched this session. Used to filter the global
 * audit-issue handler so we log only findings on hosts WE are scanning — not unrelated
 * background traffic Burp happens to audit (e.g. the browser's telemetry endpoints).
 */
public final class ScanScope {

    private final Set<String> hosts = ConcurrentHashMap.newKeySet();

    /** Canonicalize a host so all LOOPBACK aliases collapse to one — {@code localhost} ≡ {@code 127.0.0.1} ≡
     *  {@code 127.x.x.x} ≡ {@code ::1}. Otherwise a finding raised on one alias is dropped as "out of scope" just
     *  because the scan was seeded via another: e.g. an app whose configured site URL redirects a request from
     *  {@code localhost} to {@code 127.0.0.1} (WordPress WP_HOME) would file its login finding on 127.0.0.1 and it
     *  would never reach the dashboard even though it is the very host we are scanning. */
    private static String canon(String host) {
        if (host == null) return null;
        String h = host.toLowerCase().trim();
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);   // [::1] → ::1
        if (h.equals("localhost") || h.equals("::1") || h.equals("0:0:0:0:0:0:0:1")
                || h.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) return "localhost";
        return h;
    }

    public void add(String host) {
        if (host != null && !host.isBlank()) hosts.add(canon(host));
    }

    public boolean contains(String url) {
        try {
            String h = URI.create(url).getHost();
            return h != null && hosts.contains(canon(h));
        } catch (Exception e) {
            return false;
        }
    }

    /** Snapshot of the hosts scanned this session (sorted), for the Dashboard view. */
    public Set<String> hosts() {
        return new TreeSet<>(hosts);
    }
}
