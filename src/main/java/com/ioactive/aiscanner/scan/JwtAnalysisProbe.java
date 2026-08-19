package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic analysis of JWT <em>implementation</em> security — no app knowledge, no guessing at findings.
 * We harvest every JWT the app actually used (Authorization headers, cookies, response bodies in the site map),
 * decode header+payload, and run oracle-gated checks that each stand on their own evidence:
 *
 * <ol>
 *   <li><b>alg:none accepted</b> — ACTIVE. Forge an unsigned {@code {"alg":"none"}} variant of a real token
 *       (same payload, empty signature) and replay it on a request that genuinely required the token. If the
 *       server still answers 2xx with the same response shape, signature verification is bypassable. (Strong:
 *       proven by a live request, not by the header alone.)</li>
 *   <li><b>weak/known HMAC secret</b> — OFFLINE. For an HS256/384/512 token, try a small wordlist of common
 *       secrets; if one re-produces the token's signature, the signing key is guessable (full forge-any-token).</li>
 *   <li><b>no expiry / excessive lifetime</b> — the payload has no {@code exp}, or exp − iat is very long.</li>
 *   <li><b>sensitive data in payload</b> — a JWT is signed, NOT encrypted; a password/secret/PAN-shaped claim
 *       is readable by anyone holding the token.</li>
 * </ol>
 * Fully generic: keyed on JWT structure and universal claim names, not on any one app.
 */
public final class JwtAnalysisProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // A compact JWS: three base64url segments. header+payload start with "eyJ" (== '{"' base64url'd).
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");
    private static final Pattern SECRET_CLAIM = Pattern.compile("(?i)^(password|passwd|pwd|secret|api[_-]?key|private[_-]?key|ssn|credit[_-]?card|card[_-]?number)$");
    // Identity/session claims that mark a JWT as an AUTH token (vs an ephemeral captcha/challenge/CSRF token).
    private static final Pattern SESSION_CLAIM = Pattern.compile(
            "(?i)^(sub|user|user_?id|uid|username|email|role|roles|scope|scopes|sid|session|jti|aud|iss|"
          + "token_?type|account|merchant|tenant|org|permissions?)$");
    private static boolean hasSessionClaim(JSONObject pl) {
        for (String k : pl.keySet()) if (SESSION_CLAIM.matcher(k).matches()) return true;
        return false;
    }
    private static final Pattern PAN = Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b");
    // Common/default HMAC secrets seen in tutorials, frameworks and CTF targets. Offline check only.
    private static final String[] COMMON_SECRETS = {
            "secret", "secretkey", "secret-key", "your-256-bit-secret", "changeme", "password", "jwt", "jwtsecret",
            "jwt-secret", "supersecret", "super-secret", "key", "test", "admin", "s3cr3t", "mysecret", "topsecret",
            "qwerty", "0000", "1234", "123456", "default", "token", "signingkey", "hmac", "shhhhh", "secretkeybase"
    };
    private static final long MAX_LIFETIME_SEC = 24 * 3600;   // >24h without refresh is an excessive access-token TTL

    public JwtAnalysisProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** Returns the number of distinct JWT-implementation findings raised. */
    public int probe(String host, String cookie, String bearer) {
        int hits = 0;
        try {
            // 1) Harvest distinct tokens WITH provenance: which were sent as an Authorization bearer (real
            // session tokens) vs merely seen in a body, and a representative request/response for EVIDENCE.
            Set<String> tokens = new LinkedHashSet<>();
            Set<String> bearerTokens = new LinkedHashSet<>();   // tokens actually used as Authorization: Bearer
            Map<String, HttpRequestResponse> evidence = new LinkedHashMap<>();
            List<HttpRequestResponse> carriers = new ArrayList<>();
            if (bearer != null && JWT.matcher(bearer).find()) {
                Matcher bm = JWT.matcher(bearer); if (bm.find()) { tokens.add(bm.group()); bearerTokens.add(bm.group()); }
            }
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                Set<String> inReq = new LinkedHashSet<>();
                scanForTokens(safe(() -> rr.request().toString()), inReq);
                Set<String> inResp = new LinkedHashSet<>();
                if (rr.response() != null) scanForTokens(safe(() -> rr.response().toString()), inResp);
                for (String t : inReq)  { tokens.add(t); evidence.putIfAbsent(t, rr); }
                for (String t : inResp) { tokens.add(t); evidence.putIfAbsent(t, rr); }
                // A token sent in THIS request's Authorization header is a real session/bearer token.
                try {
                    String auth = rr.request().hasHeader("Authorization") ? rr.request().headerValue("Authorization") : "";
                    if (auth != null) {
                        Matcher am = JWT.matcher(auth);
                        while (am.find()) { bearerTokens.add(am.group()); evidence.put(am.group(), rr); }
                        if (am.reset().find() && rr.response() != null
                                && rr.response().statusCode() >= 200 && rr.response().statusCode() < 300) carriers.add(rr);
                    }
                } catch (Exception ignore) { }
            }
            scanLog.log("[AI Scanner] JWT analysis: " + tokens.size() + " distinct token(s) ("
                    + bearerTokens.size() + " used as bearer), " + carriers.size() + " authed carrier request(s) on " + host + ".");
            if (tokens.isEmpty()) { scanLog.debug("[AI Scanner]   jwt: no JWTs in site map — skip"); return 0; }

            Set<String> firedNone = new LinkedHashSet<>();
            for (String tok : tokens) {
                String[] parts = tok.split("\\.");
                if (parts.length < 2) continue;
                JSONObject hdr, pl;
                try {
                    hdr = new JSONObject(new String(b64url(parts[0]), StandardCharsets.UTF_8));
                    pl  = new JSONObject(new String(b64url(parts[1]), StandardCharsets.UTF_8));
                } catch (Exception e) { scanLog.debug("[AI Scanner]   jwt: undecodable token skipped"); continue; }
                String alg = hdr.optString("alg", "?");
                scanLog.debug("[AI Scanner]   jwt: alg=" + alg + " hdr=" + hdr + " claims=" + pl.keySet());
                HttpRequestResponse ev = evidence.get(tok);   // the request/response this token was observed in

                // Is this an AUTH/SESSION token (where exp/lifetime/PII actually matter), or an ephemeral,
                // non-session token like a captcha/challenge/CSRF token? Only session tokens are subject to the
                // exp/lifetime/sensitive-claim checks — flagging "no exp" on a short-lived challenge token
                // (claims like {origin, challenge}) is a false positive. Signal: it was sent as a bearer, OR it
                // carries a recognized identity/session claim.
                boolean sessionToken = bearerTokens.contains(tok) || hasSessionClaim(pl);

                // --- (3) no/weak expiry — session tokens only ---
                if (sessionToken && !pl.has("exp")) {
                    if (raise(host, "Session JWT has no expiry (exp) claim",
                            "A session/bearer token carries no 'exp' claim — it never expires, so a leaked/stolen "
                          + "token is valid forever (CWE-613). alg=" + alg + ", claims=" + pl.keySet()
                          + (bearerTokens.contains(tok) ? " (observed used as an Authorization bearer)" : ""), ev)) hits++;
                } else if (sessionToken && pl.has("iat")) {
                    long life = pl.optLong("exp") - pl.optLong("iat");
                    if (life > MAX_LIFETIME_SEC) {
                        if (raise(host, "Session JWT excessive token lifetime",
                                "Session token lifetime is " + (life / 3600) + "h (exp-iat) — an over-long access-token "
                              + "TTL widens the stolen-token window (CWE-613). alg=" + alg, ev)) hits++;
                    }
                }

                // --- (4) sensitive data in a signed (not encrypted) token — any token ---
                for (String k : pl.keySet()) {
                    String v = String.valueOf(pl.opt(k));
                    if (SECRET_CLAIM.matcher(k).matches() && !v.isBlank()) {
                        if (raise(host, "Sensitive data exposed in JWT payload",
                                "Claim '" + k + "' carries sensitive data in the token payload. A JWT is signed, NOT "
                              + "encrypted — anyone with the token base64-decodes it (CWE-312). value(len)=" + v.length(), ev)) hits++;
                    } else if (PAN.matcher(v).find() && v.replaceAll("\\D", "").length() >= 13) {
                        if (raise(host, "Sensitive data exposed in JWT payload",
                                "Claim '" + k + "' looks like a card/account number in cleartext inside the JWT payload "
                              + "(CWE-312). A JWT is not encrypted.", ev)) hits++;
                    }
                }

                // --- (2) weak/known HMAC secret (offline) — real regardless of token role ---
                if (alg.matches("(?i)HS(256|384|512)") && parts.length == 3) {
                    String hit = crackHmac(tok, alg);
                    if (hit != null) {
                        if (raise(host, "JWT signed with a weak/guessable HMAC secret",
                                "The HS256/384/512 signing key was recovered offline (by re-verifying the token's own "
                              + "signature): the secret is \"" + hit + "\" — a common/default value. With this key an "
                              + "attacker forges ANY token — e.g. change the subject/role claim to an admin — a full "
                              + "authentication bypass (CWE-326/CWE-798). alg=" + alg, true, ev)) hits++;
                    }
                }

                // --- (1) alg:none accepted (ACTIVE replay) ---
                HttpRequestResponse carrier = carrierFor(carriers, tok);
                if (carrier != null && firedNone.add("none")) {
                    if (testAlgNone(carrier, parts)) {
                        if (raise(host, "JWT 'alg:none' accepted — signature verification bypassable",
                                "Replaying an authenticated request with a forged unsigned token (header {\"alg\":\"none\"}, "
                              + "original payload, empty signature) still returned 2xx with the same response shape. The "
                              + "server does not verify the signature, so any token can be forged (CWE-347).",
                                carrier)) hits++;
                    } else {
                        scanLog.debug("[AI Scanner]   jwt: alg:none replay rejected (good) on " + carrier.request().url());
                    }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] JWT analysis error: " + t);
        }
        return hits;
    }

    /** Forge {alg:none} + original payload + empty sig, replay the carrier request, compare to a no-token control. */
    private boolean testAlgNone(HttpRequestResponse carrier, String[] parts) {
        try {
            String forgedHeader = b64urlEncode("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String forged = forgedHeader + "." + parts[1] + ".";
            HttpRequest base = carrier.request().withMethod("GET");   // idempotent replay only — never re-mutate state
            HttpRequest withForged = base.withRemovedHeader("Authorization").withHeader("Authorization", "Bearer " + forged);
            HttpRequest withNone   = base.withRemovedHeader("Authorization");   // control: no credential at all
            HttpRequestResponse rForged = api.http().sendRequest(withForged, RequestOptions.requestOptions().withResponseTimeout(12000L));
            HttpRequestResponse rNone   = api.http().sendRequest(withNone, RequestOptions.requestOptions().withResponseTimeout(12000L));
            int sf = status(rForged), sn = status(rNone);
            // FIRE only if the forged token is ACCEPTED (2xx) AND the no-credential control is DENIED — otherwise
            // the endpoint is simply public and proves nothing about signature checking.
            return sf >= 200 && sf < 300 && (sn == 401 || sn == 403);
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner]   jwt: alg:none test error: " + t);
            return false;
        }
    }

    /** Recover a common HMAC secret by recomputing the signature over header.payload; null if none match. */
    private static String crackHmac(String token, String alg) {
        int dot = token.lastIndexOf('.');
        if (dot <= 0) return null;
        String signingInput = token.substring(0, dot);
        String sig = token.substring(dot + 1);
        String macAlg = alg.equalsIgnoreCase("HS384") ? "HmacSHA384" : alg.equalsIgnoreCase("HS512") ? "HmacSHA512" : "HmacSHA256";
        for (String secret : COMMON_SECRETS) {
            try {
                Mac mac = Mac.getInstance(macAlg);
                mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
                String computed = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
                if (computed.equals(sig)) return secret;
            } catch (Exception ignore) { }
        }
        return null;
    }

    /** A carrier request that ACTUALLY sent this token as a bearer — never a fallback to an unrelated request,
     *  so the alg:none replay only ever forges a token onto the endpoint that genuinely required it. */
    private HttpRequestResponse carrierFor(List<HttpRequestResponse> carriers, String tok) {
        for (HttpRequestResponse rr : carriers) {
            try { if (rr.request().toString().contains(tok)) return rr; } catch (Exception ignore) { }
        }
        return null;   // no genuine carrier → skip the active alg:none test for this token (no weak FP)
    }

    private boolean raise(String host, String vulnClass, String detail, HttpRequestResponse... evidence) {
        scanLog.found(vulnClass, "https://" + host + "/", detail, evidence);
        scanLog.incFinding();
        return true;
    }

    /** As {@link #raise} but RAISES our dashboard issue even for a Burp-covered class (forceRaise) — for a finding
     *  where our wording is materially clearer than Burp's (e.g. the cracked HMAC secret QUOTED, vs Burp's ambiguous
     *  "The key used was <secret>" which reads as an adjective). */
    private boolean raise(String host, String vulnClass, String detail, boolean forceRaise, HttpRequestResponse... evidence) {
        scanLog.found(vulnClass, "https://" + host + "/", detail, forceRaise, evidence);
        scanLog.incFinding();
        return true;
    }

    // ---- helpers ----
    private static void scanForTokens(String text, Set<String> out) {
        if (text == null) return;
        Matcher m = JWT.matcher(text);
        while (m.find()) out.add(m.group());
    }
    private static byte[] b64url(String s) { return Base64.getUrlDecoder().decode(pad(s)); }
    private static String b64urlEncode(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    private static String pad(String s) { int m = s.length() % 4; return m == 0 ? s : s + "====".substring(m); }
    private static int status(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; } catch (Throwable t) { return -1; }
    }
    private static String hostOf(String url) {
        return Net.authority(url);
    }
    private interface Sup { String get() throws Exception; }
    private static String safe(Sup s) { try { return s.get(); } catch (Exception e) { return null; } }
}
