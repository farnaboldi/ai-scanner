package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.List;

/**
 * Missing security-response-header probe — fully generic (RFC / web-platform conventions, no app-specific
 * knowledge), PASSIVE and zero network cost: it reads only responses the scan already captured in the site
 * map and sends no requests of its own.
 *
 * <p>Checks the host's in-scope HTTPS HTML pages for FOUR hardening headers: Content-Security-Policy,
 * X-Content-Type-Options, Referrer-Policy, Permissions-Policy — bundled into ONE finding (LOW) naming exactly
 * which ones are absent, collapsing what would otherwise be up to four near-duplicate low-severity findings
 * per host (the same anti-flood pattern {@link CsrfProbe} uses for an app-wide CSRF gap).
 *
 * <p>Deliberately NOT checked here (both are already standard Burp-NATIVE passive-scanner issues — adding our
 * own copy would just duplicate the dashboard entry, not add coverage): Strict-Transport-Security ("Strict
 * transport security not enforced") and clickjacking / X-Frame-Options-CSP-frame-ancestors ("Frameable
 * response"). Burp's native passive scanner already raises "Strict transport security not enforced"
 * (LOW/CERTAIN) for a missing HSTS header. Before treating a header gap as uncovered by Burp, check BOTH log
 * channels {@link AiTriage} writes native issues to: the COUNTED one ({@code ">>> "}, FIRM/CERTAIN issues) and
 * the uncounted one ({@code " ·  "}, INFORMATION/TENTATIVE issues). Each native issue lands on only one of them.
 *
 * <p>Zero-FP by construction: a header is reported missing only when it is absent from EVERY in-scope,
 * same-host 2xx HTML response the scan actually captured — never guessed, never requested. A host that sets
 * a header on some pages but not others clears the check (out of scope for this v1 — it demonstrably knows
 * how to send the header; an inconsistency finding is a different class).
 */
public final class SecurityHeadersProbe extends Probe {

    public SecurityHeadersProbe(MontoyaApi api, ScanLog scanLog) { super(api, scanLog); }

    public int probe(String host) {
        try {
            List<HttpRequestResponse> htmlPages = new ArrayList<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || rr.request() == null) continue;
                String url = rr.request().url();
                if (!host.equalsIgnoreCase(hostOf(url))) continue;
                if (!url.toLowerCase().startsWith("https://")) continue;   // HSTS is an HTTPS-origin concern
                int st = rr.response().statusCode();
                if (st < 200 || st >= 300) continue;
                String ct = rr.response().headerValue("Content-Type");
                if (ct == null || !ct.toLowerCase().contains("text/html")) continue;
                htmlPages.add(rr);
                if (htmlPages.size() >= 25) break;   // a representative sample is enough; bounded for large sites
            }
            if (htmlPages.isEmpty()) return 0;   // nothing in-scope to check (no HTTPS HTML page captured)

            boolean csp = false, xcto = false, refpol = false, permpol = false;
            for (HttpRequestResponse rr : htmlPages) {
                if (has(rr, "Content-Security-Policy")) csp = true;
                if (has(rr, "X-Content-Type-Options")) xcto = true;
                if (has(rr, "Referrer-Policy")) refpol = true;
                if (has(rr, "Permissions-Policy")) permpol = true;
            }
            HttpRequestResponse sample = htmlPages.get(0);
            int hits = 0;

            List<String> missing = new ArrayList<>();
            if (!csp) missing.add("Content-Security-Policy");
            if (!xcto) missing.add("X-Content-Type-Options");
            if (!refpol) missing.add("Referrer-Policy");
            if (!permpol) missing.add("Permissions-Policy");
            if (!missing.isEmpty()) {
                scanLog.found("Missing recommended security headers", "https://" + host + "/",
                        "No HTML response from this host (checked " + htmlPages.size() + " page(s)) sets: "
                        + String.join(", ", missing) + ". These are defense-in-depth, browser-enforced controls: "
                        + "Content-Security-Policy constrains what scripts/resources a page may load or execute, "
                        + "limiting the blast radius of any injection; X-Content-Type-Options: nosniff stops the "
                        + "browser from MIME-sniffing a response into an executable content type; Referrer-Policy "
                        + "controls how much of this site's URLs (which may carry tokens/identifiers in the query "
                        + "string) leak to third-party destinations via the Referer header; Permissions-Policy "
                        + "disables powerful browser APIs (camera, geolocation, etc.) the app does not use. None of "
                        + "these is independently exploitable, but each is a standard layer currently missing.",
                        sample);
                scanLog.incFinding(); hits++;
            }
            return hits;
        } catch (Throwable t) {
            scanLog.debug("security-headers probe error: " + t);
            return 0;
        }
    }

    private static boolean has(HttpRequestResponse rr, String header) {
        try { return rr.response().hasHeader(header); } catch (Throwable t) { return false; }
    }
}
