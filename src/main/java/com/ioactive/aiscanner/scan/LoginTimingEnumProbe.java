package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Username / account enumeration on a login endpoint (CWE-204 / CWE-208).
 *
 * <p>A login that computes the (expensive) password hash ONLY for existing accounts, and short-circuits for
 * unknown usernames, leaks account existence through RESPONSE TIME even when the error message is identical
 * for both. (Typical signature: a wrong-password {@code POST} to the login endpoint takes ~1.5s for a real
 * account vs ~0.5s for a non-existent username, with the identical {@code 401} error.) A smaller class leaks
 * it directly through a DIFFERENT status/error body for existing vs non-existing usernames.
 *
 * <p><b>Oracle.</b> Take a captured login POST (it carries a KNOWN-valid username — the value the app itself
 * sent). Replay it with a deliberately-wrong password, N times, interleaved against the same request with a
 * clearly non-existent username (also wrong password). Both must FAIL (same non-2xx — we only compare among
 * failed logins). Then:
 * <ul>
 *   <li><b>content</b>: if the existing-user failure and the unknown-user failure differ in status code or
 *       error-body shape, that is a direct enumeration oracle.</li>
 *   <li><b>timing</b>: if the existing-user responses are UNIFORMLY slower — the fastest existing-user sample
 *       is still slower than the slowest unknown-user sample (zero overlap) AND the median gap is material —
 *       the password hash runs only for real accounts: a timing enumeration side-channel.</li>
 * </ul>
 * The zero-overlap + minimum-gap gates keep it FP-safe against ordinary jitter. Non-destructive: it only ever
 * sends WRONG-password login attempts (never the real one), capped at a handful per account.
 */
public final class LoginTimingEnumProbe extends Probe {

    private static final Pattern LOGINISH  = Pattern.compile("(?i)(login|signin|sign-in|logon|authenticate|/auth(/|$))");
    private static final Pattern PW_FIELD  = Pattern.compile("(?i)(^|[_-])(pass|passwd|password|pwd|passphrase)([_-]|$)");
    private static final Pattern USER_FIELD= Pattern.compile("(?i)(^|[_-])?(user|username|email|e-?mail|login|logon|account|userid|uid)([_-]|$)?");
    private static final Pattern EMAILY    = Pattern.compile("(?i)^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern SKIP      = Pattern.compile("(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\\?.*)?$");

    private static final int SAMPLES = 5;
    private static final long MIN_MEDIAN_GAP_MS = 150;   // existing-user median must exceed unknown-user median by this
    private static final double MIN_RATIO = 1.30;        // and by at least this factor

    public LoginTimingEnumProbe(MontoyaApi api, ScanLog scanLog) { super(api, scanLog); }

    private String sessCookie = "", sessBearer = "";

    /** @param cookie,bearer the scan's CURRENT session auth. Some apps (self-signed/short-lived bearer schemes)
     *  gate the login endpoint itself behind a token and reject a STALE captured one before the password hash —
     *  so the probe re-applies fresh session auth to each attempt, otherwise every request 401s fast and no
     *  timing differential can appear. Harmless when the login needs no pre-auth token. */
    public int probe(String host, String cookie, String bearer) {
        this.sessCookie = cookie == null ? "" : cookie;
        this.sessBearer = bearer == null ? "" : bearer;
        int hits = 0;
        try {
            // Group login POSTs by URL and, per URL, pick the request whose username field holds a REAL
            // (email-looking) value — the site map often also holds synthesized login requests with placeholder
            // usernames (value "username"), which carry no known-valid account and would never show a differential.
            java.util.LinkedHashMap<String, HttpRequest> best = new java.util.LinkedHashMap<>();
            java.util.Set<String> hasReal = new java.util.HashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                if (req == null || !"POST".equalsIgnoreCase(req.method())) continue;
                String url = req.url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                if (!LOGINISH.matcher(Net.stripQuery(url)).find()) continue;
                Creds c = extractCreds(req);
                if (c == null) continue;
                String key = Net.stripQuery(url);
                boolean real = EMAILY.matcher(c.knownUser).matches();
                if (real) { best.put(key, req); hasReal.add(key); }
                else if (!hasReal.contains(key)) best.putIfAbsent(key, req);
            }
            for (HttpRequest req : best.values()) {
                Creds c = extractCreds(req);
                if (c != null && oracle(req, c)) hits++;
            }
        } catch (Throwable t) {
            scanLog.debug("login-timing-enum probe error: " + t);
        }
        return hits;
    }

    /** The login request's field layout + a known-valid username (the captured value). */
    private static final class Creds {
        final List<String[]> fields = new ArrayList<>();   // {name, capturedValue}
        String userField, pwField, knownUser;
        boolean json;
    }

    private Creds extractCreds(HttpRequest req) {
        Creds c = new Creds();
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.type() != HttpParameterType.BODY && p.type() != HttpParameterType.URL) continue;
            c.fields.add(new String[]{ p.name(), p.value() == null ? "" : p.value() });
            if (PW_FIELD.matcher(p.name()).find()) c.pwField = p.name();
        }
        if (c.pwField == null && isJson(req)) {
            c.json = true;
            Matcher jf = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"").matcher(req.bodyToString());
            while (jf.find()) {
                c.fields.add(new String[]{ jf.group(1), jf.group(2) });
                if (PW_FIELD.matcher(jf.group(1)).find()) c.pwField = jf.group(1);
            }
        } else if (c.pwField != null) {
            c.json = isJson(req);
        }
        if (c.pwField == null) return null;
        // username field = the email-looking field, else the first user-ish field, else the first non-password field
        for (String[] f : c.fields) {
            if (f[0].equals(c.pwField)) continue;
            if (EMAILY.matcher(f[1]).matches()) { c.userField = f[0]; c.knownUser = f[1]; break; }
        }
        if (c.userField == null) for (String[] f : c.fields) {
            if (f[0].equals(c.pwField)) continue;
            if (USER_FIELD.matcher(f[0]).find() && !f[1].isBlank()) { c.userField = f[0]; c.knownUser = f[1]; break; }
        }
        if (c.userField == null || c.knownUser == null || c.knownUser.isBlank()) return null;
        return c;
    }

    private boolean oracle(HttpRequest req, Creds c) {
        String domain = c.knownUser.contains("@") ? c.knownUser.substring(c.knownUser.indexOf('@') + 1) : "example.com";
        String wrongPw = "aiscWrongPw_" + Integer.toHexString((int) (Math.random() * 0x7fffffff));
        String badUser = "aisc-nouser-" + Integer.toHexString((int) (Math.random() * 0x7fffffff)) + "@" + domain;

        List<Long> validMs = new ArrayList<>(), invalidMs = new ArrayList<>();
        int validStatus = -1, invalidStatus = -1;
        String validShape = null, invalidShape = null;
        HttpRequestResponse validEv = null, invalidEv = null;

        // Interleave to cancel slow drift; both carry a WRONG password so neither can succeed. Measure each
        // send's latency INLINE (one timer per request) — a shared holder would collapse both to one value.
        for (int i = 0; i < SAMPLES; i++) {
            long tv0 = System.nanoTime();
            HttpRequestResponse v = sendRebuilt(req, c, c.knownUser, wrongPw);
            long vt = (System.nanoTime() - tv0) / 1_000_000L;
            long tn0 = System.nanoTime();
            HttpRequestResponse n = sendRebuilt(req, c, badUser, wrongPw);
            long nt = (System.nanoTime() - tn0) / 1_000_000L;
            if (v == null || v.response() == null || n == null || n.response() == null) return false;
            validMs.add(vt); invalidMs.add(nt);
            if (validStatus < 0) { validStatus = v.response().statusCode(); validShape = Net.shape(v); validEv = v; }
            if (invalidStatus < 0) { invalidStatus = n.response().statusCode(); invalidShape = Net.shape(n); invalidEv = n; }
            // if the KNOWN-valid credential ever actually logs in (2xx), the captured pw wasn't wrong — bail (no destructive state)
            if (v.response().statusCode() / 100 == 2) return false;
        }

        // CONTENT oracle: existing vs non-existing username yield a different failure (status or body shape).
        if (!validShape.equals(invalidShape)) {
            scanLog.found("Username enumeration (login response differential)", Net.stripQuery(req.url()),
                    "A wrong-password login reveals whether the account exists: the existing-user failure (" + validStatus
                    + ", " + validShape + ") differs from the unknown-user failure (" + invalidStatus + ", " + invalidShape
                    + "). Same wrong password both times; only the username differs. Return an identical, generic failure "
                    + "(same status, body and timing) for valid and invalid usernames (CWE-204).", validEv, invalidEv);
            scanLog.incFinding();
            return true;
        }

        // TIMING oracle: existing-user responses uniformly slower (zero overlap) by a material margin.
        Collections.sort(validMs); Collections.sort(invalidMs);
        long vMed = validMs.get(validMs.size() / 2), nMed = invalidMs.get(invalidMs.size() / 2);
        long vMin = validMs.get(0), nMax = invalidMs.get(invalidMs.size() - 1);
        boolean zeroOverlap = vMin > nMax;
        boolean materialGap = (vMed - nMed) >= MIN_MEDIAN_GAP_MS && vMed >= nMed * MIN_RATIO;
        if (zeroOverlap && materialGap) {
            scanLog.found("Username enumeration (login timing side-channel)", Net.stripQuery(req.url()),
                    "A wrong-password login against an EXISTING account is uniformly slower than against a non-existent "
                    + "username (same " + validStatus + " error both ways): existing-user median " + vMed + "ms (min " + vMin
                    + "ms), unknown-user median " + nMed + "ms (max " + nMax + "ms) over " + SAMPLES + " interleaved samples, "
                    + "zero overlap. The password hash runs only for real accounts, so response time discloses account "
                    + "existence (CWE-208). Make the failure path constant-time — hash a dummy password for unknown users — "
                    + "and add rate-limiting so enumeration cannot be scaled.", validEv, invalidEv);
            scanLog.incFinding();
            return true;
        }
        scanLog.log("login-timing-enum: no enumeration at " + Net.stripQuery(req.url()) + " — user='" + c.knownUser
                + "' existing-median " + vMed + "ms (min " + vMin + ") vs unknown-median " + nMed + "ms (max " + nMax
                + "), status " + validStatus + "/" + invalidStatus + " (need zero-overlap + ≥" + MIN_MEDIAN_GAP_MS + "ms gap).");
        return false;
    }

    /** Send the login request with username/password swapped and the scan's current session auth applied. */
    private HttpRequestResponse sendRebuilt(HttpRequest req, Creds c, String user, String pw) {
        try {
            HttpRequest r = rebuild(req, c, user, pw);
            // Re-apply the scan's CURRENT session auth, overriding any stale captured token (see probe()).
            if (!sessBearer.isBlank()) { try { r = r.withRemovedHeader("Authorization"); } catch (Throwable ignore) {} r = r.withHeader("Authorization", "Bearer " + sessBearer); }
            if (!sessCookie.isBlank()) { try { r = r.withRemovedHeader("Cookie"); } catch (Throwable ignore) {} r = r.withHeader("Cookie", sessCookie); }
            return send(r);
        } catch (Throwable t) { return null; }
    }

    /** Rebuild the login body with the username + password fields replaced (JSON or form), other fields kept. */
    private HttpRequest rebuild(HttpRequest req, Creds c, String user, String pw) {
        if (c.json) {
            StringBuilder sb = new StringBuilder("{");
            for (int i = 0; i < c.fields.size(); i++) {
                if (i > 0) sb.append(',');
                String n = c.fields.get(i)[0];
                String val = n.equals(c.pwField) ? pw : n.equals(c.userField) ? user : c.fields.get(i)[1];
                sb.append('"').append(esc(n)).append("\":\"").append(esc(val)).append('"');
            }
            return req.withBody(sb.append('}').toString());
        }
        HttpRequest r = req;
        for (String[] f : c.fields) {
            String val = f[0].equals(c.pwField) ? pw : f[0].equals(c.userField) ? user : null;
            if (val == null) continue;
            try {
                r = r.withUpdatedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(
                        f[0], val, burp.api.montoya.http.message.params.HttpParameterType.BODY));
            } catch (Throwable ignore) { }
        }
        return r;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
