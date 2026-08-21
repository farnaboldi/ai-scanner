package com.ioactive.aiscanner.scan;

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

    /** Canonicalize an AUTHORITY (host or host:port) so all LOOPBACK aliases collapse to one — {@code localhost} ≡
     *  {@code 127.0.0.1} ≡ {@code 127.x.x.x} ≡ {@code ::1} — WHILE PRESERVING THE PORT. Port-aware to stay consistent
     *  with {@link Net#authority} (which every {@code hostOf()} uses): the scan seeds/adds an authority WITH its port
     *  (e.g. {@code localhost:3000}), so {@link #contains} must compare the same port-aware key — otherwise a finding
     *  filed on {@code localhost:3000} is dropped as "out of scope" because a bare-host key ({@code localhost}) never
     *  matches, and NO finding reaches the dashboard. Two parallel same-host different-port targets stay isolated
     *  (localhost:3000 ≠ localhost:4000); loopback aliases on the SAME port still collapse (127.0.0.1:3000 ≡
     *  localhost:3000). */
    private static String canon(String authority) {
        if (authority == null) return null;
        String a = authority.toLowerCase().trim();
        String host = a, port = "";
        if (a.startsWith("[")) {                                  // bracketed IPv6: [::1]:3000
            int rb = a.indexOf(']');
            if (rb >= 0) { host = a.substring(1, rb); port = a.substring(rb + 1); }   // port keeps its leading ':'
        } else {
            int colon = a.indexOf(':');
            if (colon >= 0 && a.indexOf(':', colon + 1) < 0) {    // a SINGLE colon = host:port (multiple = raw IPv6)
                host = a.substring(0, colon); port = a.substring(colon);
            }
        }
        if (host.equals("localhost") || host.equals("::1") || host.equals("0:0:0:0:0:0:0:1")
                || host.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) host = "localhost";
        return host + port;
    }

    /** {@code host} is an AUTHORITY (host[:port]) as produced by {@code hostOf()} / {@link Net#authority} — canon'd
     *  directly (do NOT re-run Net.authority here: it expects a full URL and would blank a bare authority). */
    public void add(String host) {
        if (host != null && !host.isBlank()) hosts.add(canon(host));
    }

    public boolean contains(String url) {
        try {
            String a = Net.authority(url);
            return a != null && hosts.contains(canon(a));
        } catch (Exception e) {
            return false;
        }
    }

    /** Snapshot of the hosts scanned this session (sorted), for the Dashboard view. */
    public Set<String> hosts() {
        return new TreeSet<>(hosts);
    }
}
