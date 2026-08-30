package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Privilege-parity (broken function-level authorization) probe — fully generic, no app-specific paths.
 * Detects a self-defeating access-control inconsistency: the SAME resource is exposed under TWO sibling
 * routes, one gated behind a privileged segment and one NOT. When the privileged twin
 * (e.g. {@code /admin/all_users}) is DENIED to our session (401/403) but its unprivileged twin
 * (e.g. {@code /all_users}) returns real data (2xx) to that same session, the app leaks a privileged
 * resource through an ungated sibling — a missing function-level authorization check (CWE-285/OWASP-API5).
 *
 * <p>Direction: it starts from the DENIED privileged paths the authenticated crawl already recorded (a 401/403
 * PROVES the resource is meant to be privileged), derives the open twin by STRIPPING the privileged segment,
 * and confirms the twin returns data to the same session (site map first; one benign GET if not already seen).
 * Zero-FP by construction — the app itself establishes the {denied-privileged}⊕{open-with-data} differential.
 * The confirming request is a normal GET to a legitimate path (no attack signature), so it passes a WAF
 * unchanged and cannot crash a target the way an injection payload can.
 */
public final class PrivilegeParityProbe extends Probe {

    // api + scanLog inherited from Probe

    private static final Pattern PRIV_SEG = Pattern.compile("(?i)^(admin|administrator|manage|management|internal|superuser|staff)$");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public PrivilegeParityProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    public int probe(String host, String cookieHeader, String bearer) {
        int hits = 0;
        try {
            // Record, per in-scope GET path, the best status seen + a response we can cite as evidence.
            Map<String, Integer> statusByPath = new LinkedHashMap<>();
            Map<String, HttpRequestResponse> rrByPath = new LinkedHashMap<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !"GET".equalsIgnoreCase(rr.request().method())) continue;
                String url = rr.request().url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                String path = normPath(url);
                if (path == null) continue;
                int st = rr.response().statusCode();
                Integer prev = statusByPath.get(path);
                if (prev == null || (st >= 200 && st < 300 && !(prev >= 200 && prev < 300))) {
                    statusByPath.put(path, st);
                    rrByPath.put(path, rr);
                }
            }

            Set<String> fired = new LinkedHashSet<>();
            // Iterate the DENIED privileged paths (401/403 under a priv segment) → derive + confirm the open twin.
            for (Map.Entry<String, Integer> e : new LinkedHashMap<>(statusByPath).entrySet()) {
                String privPath = e.getKey();
                int privStatus = e.getValue();
                if (privStatus != 401 && privStatus != 403) continue;
                String openPath = stripPrivSegment(privPath);
                if (openPath == null || openPath.equals(privPath)) continue;
                if (!fired.add(openPath)) continue;

                // Confirm the open twin returns data to THIS session — site map first (crash-independent),
                // else one benign GET (a normal request to a legitimate path).
                HttpRequestResponse openRr = rrByPath.get(openPath);
                int openStatus = statusByPath.getOrDefault(openPath, -1);
                if (openStatus < 200 || openStatus >= 300 || openRr == null) {
                    // Build the open-twin URL from the privileged entry's OWN scheme://authority (preserves the
                    // port, e.g. localhost:8001) — never reconstruct from a bare host.
                    String base = schemeAuthority(rrByPath.get(privPath).request().url());
                    if (base == null) continue;
                    openRr = fetch(base + openPath, cookieHeader, bearer);
                    openStatus = (openRr != null && openRr.response() != null) ? openRr.response().statusCode() : -1;
                }
                if (openRr == null || openStatus < 200 || openStatus >= 300) continue;
                String body = openRr.response().bodyToString();
                if (body == null || body.trim().length() < 2) continue;
                String bl = body.trim().toLowerCase();
                if (bl.startsWith("<!doctype") || bl.startsWith("<html")) continue;   // an HTML page, not a data resource

                // FP guard (decisive): the open twin must ITSELF be access-controlled — denied to an
                // UNAUTHENTICATED caller (401/403, or a redirect to a login page). A truly PUBLIC endpoint
                // (e.g. /health, a public API) returns 2xx unauthenticated and is NOT a privilege downgrade —
                // this condition excludes it, so we only fire when the SAME resource is gated at two DIFFERENT
                // privilege levels (login vs admin), which is the real broken-authz case.
                String openUrl = openRr.request().url();
                HttpRequestResponse unauth = fetch(openUrl, null, null);
                int us = (unauth != null && unauth.response() != null) ? unauth.response().statusCode() : -1;
                boolean openIsGated = us == 401 || us == 403 || (us >= 300 && us < 400);
                if (!openIsGated) continue;

                scanLog.found("Broken function-level authorization (privilege-parity)", openRr.request().url(),
                        "A privileged resource is reachable through an UNGATED sibling route: the privileged twin "
                        + privPath + " is denied to this session (HTTP " + privStatus + "), but " + openPath
                        + " returns the resource with data (HTTP " + openStatus + ") to the SAME non-privileged "
                        + "session — a missing function-level authorization check (CWE-285 / OWASP-API5).",
                        openRr, rrByPath.get(privPath));
                scanLog.incFinding();
                hits++;
            }
        } catch (Throwable t) {
            scanLog.debug("privilege-parity probe error: " + t);
        }
        return hits;
    }

    /** Remove the FIRST privileged segment from a path: /admin/all_users -> /all_users ; /api/admin/x -> /api/x. */
    private static String stripPrivSegment(String path) {
        String p = path.startsWith("/") ? path.substring(1) : path;
        String[] segs = p.split("/");
        StringBuilder sb = new StringBuilder();
        boolean removed = false;
        for (String s : segs) {
            if (!removed && PRIV_SEG.matcher(s).matches()) { removed = true; continue; }
            sb.append('/').append(s);
        }
        if (!removed) return null;
        String out = sb.length() == 0 ? "/" : sb.toString();
        return out;
    }

    private HttpRequestResponse fetch(String url, String cookieHeader, String bearer) {
        try {
            HttpRequest g = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (cookieHeader != null && !cookieHeader.isBlank()) g = g.withHeader("Cookie", cookieHeader);
            if (bearer != null && !bearer.isBlank()) g = g.withHeader("Authorization", "Bearer " + bearer);
            return send(g);
        } catch (Throwable t) { return null; }
    }

    /** scheme://authority (host[:port]) of a URL — preserves the port so a rebuilt sibling URL hits the right service. */
    private static String schemeAuthority(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getAuthority(); }
        catch (Exception e) { return null; }
    }

    private static String normPath(String url) {
        try {
            String p = URI.create(url).getPath();
            if (p == null || p.isEmpty()) return "/";
            if (p.length() > 1 && p.endsWith("/")) p = p.substring(0, p.length() - 1);
            return p;
        } catch (Exception e) { return null; }
    }

    // hostOf(String) inherited from Probe.
}
