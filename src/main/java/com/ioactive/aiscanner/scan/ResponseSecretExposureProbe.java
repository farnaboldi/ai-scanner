package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Response-side secret-disclosure probe — fully generic, no app-specific paths. Reads the site map for
 * in-scope 2xx JSON responses and FIRES only on a self-defeating disclosure: the server returns, in the
 * SAME response, both a CHALLENGE field (captcha/question/puzzle/quiz/challenge) AND its ANSWER field
 * (answer/solution/expected…) with a non-empty scalar value. Handing the client the solution to the server's
 * own challenge (CWE-345 / insufficient verification) is indefensible, so the oracle is zero-FP by
 * construction — it never fires on a lone {@code token}/{@code password} field (those are legitimately
 * returned to their owner), only on the challenge+answer pairing.
 *
 * <p>Deterministic and read-only: it inspects responses already fetched during the crawl/discovery — it
 * sends no new requests. Recurses one level into arrays/objects so a challenge nested in a wrapper object
 * (or a list of challenges) is still caught, but requires the pair to be SIBLINGS in the same object.
 */
public final class ResponseSecretExposureProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // The answer/solution to a challenge. NOT generic secrets (token/password) — those have legitimate
    // owner-scoped uses and would FP; only a field literally naming the *solution* is self-defeating.
    private static final Pattern ANSWER_KEY = Pattern.compile(
            "(?i)^(answer|solution|correct(_?answer)?|expected(_?answer|_?value)?|the_?answer)$");
    // A VERIFICATION challenge sibling — specifically a captcha/puzzle the client must SOLVE. NOT generic
    // "question": a business Q&A (FAQ, a credit-assessment cockpit with question/answer/status, a survey) also
    // has question+answer siblings and is NOT a security control — including "question" here fires on all of
    // them (false positive). Kept to captcha/challenge/puzzle/riddle, which denote an actual solve-me control.
    private static final Pattern CHALLENGE_KEY = Pattern.compile(
            "(?i)^(captcha|challenge|puzzle|riddle)$");
    // A real captcha/OTP answer is a SHORT solution token (e.g. "7", "9*1-2", "AB3D9"), not a prose sentence.
    // Reject a multi-word phrase like "No active facility" so an assessment/FAQ answer can't trip the oracle.
    private static boolean looksLikeSolution(String v) {
        if (v == null) return false;
        String s = v.trim();
        if (s.isEmpty() || s.length() > 16) return false;          // solutions are short
        return s.chars().filter(c -> c == ' ').count() <= 1;       // at most one space (not a sentence)
    }
    // A field whose NAME denotes a cleartext secret that a server should NEVER echo back to a client
    // (a stored password, a private key, a national id…). NOT "token"/"apikey" — those are legitimately
    // returned by auth endpoints to their owner; a stored PASSWORD in a response is indefensible either way.
    private static final Pattern SECRET_KEY = Pattern.compile(
            "(?i)^(password|passwd|pwd|user_?password|secret|private_?key|ssn|social_?security|credit_?card|card_?number|cvv)$");
    private static final Pattern MASKED = Pattern.compile("^[*x•.\\s-]{3,}$");   // ****, xxxx, •••• → already masked
    // A JWT anywhere in a response body — its payload is base64url and UNENCRYPTED, so a secret embedded in it
    // is disclosed to anyone holding the token.
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{6,}\\.eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public ResponseSecretExposureProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public int probe(String host) {
        int hits = 0;
        Set<String> fired = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                String url = rr.request().url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                int st = rr.response().statusCode();
                if (st < 200 || st >= 300) continue;
                String body = rr.response().bodyToString();
                if (body == null) continue;
                String t = body.trim();
                if (!t.startsWith("{") && !t.startsWith("[")) continue;
                String key = Net.stripQuery(url);
                if (fired.contains(key)) continue;
                Object root;
                try { root = t.startsWith("{") ? new JSONObject(t) : new JSONArray(t); }
                catch (Throwable ignore) { continue; }

                String[] leak = new String[1];
                scan(root, leak);
                if (leak[0] != null) {
                    fired.add(key);
                    scanLog.found("Server discloses the answer to its own challenge", url,
                            "The 2xx JSON response returns a challenge together with its answer (" + leak[0]
                            + "). A client that should have to SOLVE the challenge is handed the solution — the "
                            + "verification is worthless (CWE-345). Deterministic: challenge+answer siblings present.",
                            rr);
                    scanLog.incFinding();
                    hits++;
                }

                // Sensitive-data exposure: a cleartext password/secret field echoed in the response body.
                String[] secret = new String[1];
                scanSecret(root, secret);
                if (secret[0] != null) {
                    fired.add(key);
                    scanLog.found("Sensitive data exposure — cleartext secret in response", url,
                            "The 2xx JSON response returns a cleartext secret field (" + secret[0] + "). Storing/"
                            + "returning a password or secret in plaintext is broken (CWE-312/CWE-359). Deterministic: "
                            + "a secret-named field with a non-empty, non-masked value.",
                            rr);
                    scanLog.incFinding();
                    hits++;
                }

                // Sensitive-data exposure via JWT payload: a JWT in the body whose base64url (unencrypted)
                // payload embeds a cleartext secret is a disclosure to anyone holding the token.
                if (!fired.contains(key)) {
                    String jwtLeak = scanJwtSecrets(body);
                    if (jwtLeak != null) {
                        fired.add(key);
                        scanLog.found("Sensitive data exposure — secret embedded in JWT payload", url,
                                "A JWT in the 2xx response embeds a cleartext secret in its base64url (unencrypted) "
                                + "payload (" + jwtLeak + "). Anyone holding the token can decode and read it "
                                + "(CWE-312/CWE-522). Deterministic: the decoded JWT payload carries a secret-named "
                                + "field with a real value.", rr);
                        scanLog.incFinding();
                        hits++;
                    }
                }
            }
        } catch (Throwable e) {
            scanLog.debug("[AI Scanner] response-secret probe error: " + e);
        }
        return hits;
    }

    /** Recurse; set leak[0] to a short "challenge=…, answer=…" description on the first object that holds
     *  both a challenge key and a non-empty answer key as SIBLINGS. */
    private static void scan(Object node, String[] leak) {
        if (leak[0] != null) return;
        if (node instanceof JSONObject) {
            JSONObject o = (JSONObject) node;
            String answerKey = null, answerVal = null, challengeKey = null, challengeVal = null;
            for (String k : o.keySet()) {
                Object v = o.get(k);
                if (ANSWER_KEY.matcher(k).matches() && isNonEmptyScalar(v) && looksLikeSolution(String.valueOf(v))) { answerKey = k; answerVal = String.valueOf(v); }
                else if (CHALLENGE_KEY.matcher(k).matches() && isNonEmptyScalar(v)) { challengeKey = k; challengeVal = String.valueOf(v); }
            }
            if (answerKey != null && challengeKey != null) {
                leak[0] = challengeKey + "=\"" + trunc(challengeVal) + "\", " + answerKey + "=\"" + trunc(answerVal) + "\"";
                return;
            }
            for (String k : o.keySet()) { scan(o.get(k), leak); if (leak[0] != null) return; }
        } else if (node instanceof JSONArray) {
            JSONArray a = (JSONArray) node;
            for (int i = 0; i < a.length(); i++) { scan(a.get(i), leak); if (leak[0] != null) return; }
        }
    }

    /** Recurse; set leak[0] to "field=value" for the first secret-named field with a real cleartext value. */
    private static void scanSecret(Object node, String[] leak) {
        if (leak[0] != null) return;
        if (node instanceof JSONObject) {
            JSONObject o = (JSONObject) node;
            for (String k : o.keySet()) {
                Object v = o.get(k);
                if (SECRET_KEY.matcher(k).matches() && isNonEmptyScalar(v)) {
                    String s = String.valueOf(v).trim();
                    // FP guard: an i18n/labels map returns the field's own display LABEL as the value
                    // (key "password" -> value "Password"). A stored secret is never literally its own field
                    // name/label, so skip when the value equals (or is the titlecase of) the key — BUT only in a
                    // pure label map. In a real DATA record (has a numeric id, an email-address value, a URL as a
                    // sibling), a value that coincidentally equals its key is a genuine secret (e.g. a user whose
                    // password literally is "password"), so we do NOT suppress it there.
                    boolean isLabel = s.equalsIgnoreCase(k) || s.equalsIgnoreCase(k.replace("_", " "))
                            || s.replace(" ", "").equalsIgnoreCase(k.replace("_", ""));
                    if (isLabel && looksLikeDataRecord(o)) isLabel = false;
                    if (!isLabel && s.length() >= 3 && s.length() <= 200 && !MASKED.matcher(s).matches()
                            && !s.equalsIgnoreCase("null") && !s.equalsIgnoreCase("none")) {
                        leak[0] = k + "=\"" + trunc(s) + "\"";
                        return;
                    }
                }
            }
            for (String k : o.keySet()) { scanSecret(o.get(k), leak); if (leak[0] != null) return; }
        } else if (node instanceof JSONArray) {
            JSONArray a = (JSONArray) node;
            for (int i = 0; i < a.length(); i++) { scanSecret(a.get(i), leak); if (leak[0] != null) return; }
        }
    }

    /** Decode any JWT in the body and run the cleartext-secret detector over its (unencrypted) payload. */
    private static String scanJwtSecrets(String body) {
        if (body == null) return null;
        java.util.regex.Matcher m = JWT.matcher(body);
        while (m.find()) {
            String[] parts = m.group().split("\\.");
            if (parts.length < 2) continue;
            try {
                String s = parts[1];
                while (s.length() % 4 != 0) s += "=";
                String payload = new String(java.util.Base64.getUrlDecoder().decode(s),
                        java.nio.charset.StandardCharsets.UTF_8);
                if (!payload.trim().startsWith("{")) continue;
                JSONObject o = new JSONObject(payload);
                String[] leak = new String[1];
                scanSecret(o, leak);
                if (leak[0] != null) return leak[0] + " (in JWT payload)";
            } catch (Throwable ignore) { }
        }
        return null;
    }

    private static final Pattern EMAIL_VALUE = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    /** True if the object carries real record DATA (a numeric field, an email-address value, or a URL) — i.e.
     *  it is NOT a pure i18n/labels map. Used to un-suppress a secret whose value coincidentally equals its key. */
    private static boolean looksLikeDataRecord(JSONObject o) {
        for (String k : o.keySet()) {
            Object v = o.opt(k);
            if (v instanceof Number) return true;
            if (v instanceof String) {
                String s = ((String) v).trim();
                if (EMAIL_VALUE.matcher(s).matches()) return true;
                if (s.startsWith("http://") || s.startsWith("https://")) return true;
            }
        }
        return false;
    }

    private static boolean isNonEmptyScalar(Object v) {
        if (v == null || v == JSONObject.NULL) return false;
        if (v instanceof JSONObject || v instanceof JSONArray) return false;
        return !String.valueOf(v).trim().isEmpty();
    }

    private static String trunc(String s) { return s == null ? "" : (s.length() <= 40 ? s : s.substring(0, 40) + "…"); }
    private static String hostOf(String url) { return Net.authority(url); }
}
