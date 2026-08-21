package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Webhook / callback signature FAIL-OPEN probe — fully generic, no app-specific paths.
 *
 * <p>Inbound provider webhooks (payments, KYC, banking partners) must authenticate the caller by verifying an
 * HMAC signature over the body — they are unauthenticated by design (no user session), so the signature IS the
 * only auth. A common critical bug is a verifier that <b>fails open</b>: it returns "valid" when no secret is
 * configured, or never checks the signature header at all. An anonymous attacker can then forge provider events
 * (fake a deposit, flip a loan/KYB decision to approved/funded, mark a transfer settled).
 *
 * <p><b>Deterministic, zero-FP oracle (differential):</b> a correctly-implemented webhook verifier ALWAYS
 * rejects a request bearing a WRONG signature (401/403 / "invalid signature"). So we send the endpoint a POST
 * with a deliberately-bogus signature (and no session) — if it is ACCEPTED (2xx, and the body is not a
 * signature/authorization rejection), the signature is not being enforced. Confirmed by a second send with the
 * signature header entirely absent. Because the finding fires ONLY when the live server accepts a request whose
 * signature is provably invalid, it cannot be a false positive: a secure endpoint has no accepting branch for a
 * bad signature. Body is a minimal {@code {}} — non-destructive (no real event id/amount, so nothing is booked).
 *
 * <p>Candidates: webhook/callback-shaped paths already in the site map, PLUS a small synthesised set (common
 * webhook leaves appended to each distinct API path-prefix observed) so an UNLINKED provider webhook — never
 * referenced by the client the crawler sees — is still reached. Every candidate is live-probed; a 404/HTML/
 * signature-rejection simply doesn't fire.
 */
public final class WebhookAuthProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    /** A path that is (or claims to be) an inbound webhook/callback — where a signature MUST be enforced. */
    private static final Pattern WEBHOOK_PATH = Pattern.compile(
            "(?i).*/(web[_-]?hooks?|callbacks?|hooks?|ipn|inbound|notif(?:y|ications?)?/inbound|events?/inbound|"
          + "provider[_-]?events?|partner[_-]?events?)(/|$)");
    /** Common webhook leaf segments to synthesise under each observed API prefix. */
    private static final String[] LEAVES = {
            "webhook/", "webhooks/", "callback/", "callbacks/", "hook/", "hooks/", "ipn/", "inbound/", "events/", "notify/"
    };
    /** A response body that is itself a signature/authorization REJECTION — must NOT be treated as accepted. */
    private static final Pattern REJECTED = Pattern.compile(
            "(?i)(invalid|missing|bad|no).{0,20}sign|signature.{0,20}(invalid|mismatch|required|missing)|"
          + "unauthor|forbidden|permission denied|not allowed|401|403");
    private static final int MAX_CANDIDATES = 60;
    private static final String BOGUS_SIG = "00000000000000000000000000000000000000000000000000000000000000ff";

    public WebhookAuthProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public int probe(String host) {
        int hits = 0;
        try {
            Set<String> candidates = discoverCandidates(host);
            if (candidates.isEmpty()) { scanLog.debug("  webhook-auth: no webhook/callback candidates"); return 0; }
            scanLog.log("webhook-auth probe: testing " + candidates.size()
                    + " webhook/callback candidate(s) for signature fail-open.");
            Set<String> fired = new LinkedHashSet<>();
            for (String url : candidates) {
                // Primary: a POST bearing a WRONG signature, no session. A real verifier rejects it.
                HttpRequestResponse bad = post(url, true);
                if (!accepted(bad)) continue;                       // rejected/404/HTML → correct, or not a handler
                // Confirm: the same POST with NO signature header at all is also accepted (definitively fail-open).
                HttpRequestResponse none = post(url, false);
                if (!accepted(none)) continue;
                String key = Net.stripQuery(url);
                if (!fired.add(key)) continue;
                int st = bad.response().statusCode();
                scanLog.found("Webhook signature verification fail-open (unauthenticated forgery)", url,
                        "This webhook/callback endpoint ACCEPTED a POST bearing a deliberately-invalid signature "
                      + "AND a POST with no signature header at all (HTTP " + st + ", not a 401/403/signature "
                      + "rejection), with no session. Its signature verification is not enforced (fail-open) — an "
                      + "unauthenticated attacker can forge provider events (e.g. fake a deposit or flip a loan/KYC "
                      + "decision to approved/funded) (CWE-345/CWE-306). Deterministic: a correct verifier always "
                      + "rejects an invalid signature.", bad);
                scanLog.incFinding();
                hits++;
            }
        } catch (Throwable t) {
            scanLog.debug("webhook-auth probe error: " + t);
        }
        return hits;
    }

    /** Webhook-shaped URLs from the site map + synthesised leaves under each distinct API prefix. */
    private Set<String> discoverCandidates(String host) {
        Set<String> out = new LinkedHashSet<>();
        Set<String> prefixes = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            try {
                String url = rr.request().url();
                if (!host.equalsIgnoreCase(hostOf(url))) continue;
                String path = pathOf(url);
                if (WEBHOOK_PATH.matcher(path).matches()) out.add(base(url) + path);
                // record API path-prefixes (…/api/v1/<seg>/) to synthesise webhook leaves under
                java.util.regex.Matcher m = API_PREFIX.matcher(path);
                if (m.find()) prefixes.add(base(url) + m.group(1));
            } catch (Throwable ignore) { }
        }
        for (String pfx : prefixes) {
            for (String leaf : LEAVES) {
                if (out.size() >= MAX_CANDIDATES) break;
                out.add(pfx + leaf);
            }
        }
        return out;
    }

    // …/api/v?<n>/<segment>/ — the service prefix a provider webhook typically hangs off.
    private static final Pattern API_PREFIX = Pattern.compile("(?i)^(/api/(?:v\\d+/)?[a-z0-9_-]+/)");

    /** POST a minimal empty JSON body; optionally attach a deliberately-invalid signature header. No session. */
    private HttpRequestResponse post(String url, boolean withBadSig) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                    .withBody("{}").withHeader("Content-Type", "application/json").withHeader("Accept", "application/json");
            if (withBadSig) {
                req = req.withHeader("X-Signature", BOGUS_SIG)
                         .withHeader("X-Hub-Signature-256", "sha256=" + BOGUS_SIG)
                         .withHeader("X-Webhook-Signature", BOGUS_SIG);
            }
            return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Throwable t) { return null; }
    }

    /** Accepted == a 2xx that is NOT itself a signature/authorization rejection and is a handler (JSON) response. */
    private static boolean accepted(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        int st = rr.response().statusCode();
        if (st < 200 || st >= 300) return false;                    // 401/403/400/404/5xx → not accepted
        String body = rr.response().bodyToString();
        if (body == null) return true;
        String b = body.trim();
        if (REJECTED.matcher(b).find()) return false;               // 2xx but body says "invalid signature" → rejected
        // must look like an API handler answered (JSON), not a static/HTML catch-all page
        if (b.startsWith("<") || b.toLowerCase().contains("<!doctype")) return false;
        return b.startsWith("{") || b.startsWith("[") || b.isEmpty();
    }

    private static String base(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getAuthority(); } catch (Exception e) { return ""; }
    }
    private static String pathOf(String url) {
        try { String p = URI.create(url).getRawPath(); return p == null || p.isEmpty() ? "/" : p; }
        catch (Exception e) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    }
    private static String hostOf(String url) { return Net.authority(url); }
}
