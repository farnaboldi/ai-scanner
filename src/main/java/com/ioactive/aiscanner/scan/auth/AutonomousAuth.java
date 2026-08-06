package com.ioactive.aiscanner.scan.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.scan.SessionStore;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONObject;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Autonomous, <em>generic</em> authentication capabilities — NO per-app fingerprinting and NO
 * hardcoded URLs. Given only the target's base URL, these behave the way a human user would: look at
 * the page, and act on the affordances actually present.
 *
 * <ul>
 *   <li>{@link #manualImport} — explicit user-supplied session ({@code -Daiscanner.cookie/.bearer}),
 *       the only non-autonomous path (a human handing over their cookies), never a fingerprint.</li>
 *   <li>{@link #registerThenLogin} — when no default creds work: find a registration form by SHAPE
 *       (a form with two password fields, reached directly or via a "register/sign-up" link), fill it
 *       with a generic account, ADAPT to whatever length constraint the form's own validation error
 *       states, submit, then log in with those creds. Verified by a generic session oracle.</li>
 *   <li>securitySelector/applySecurity — post-auth, scan the authenticated surface for a "security/difficulty"
 *       &lt;select&gt; (choose its lowest option) and any "create/reset database"-type submit button,
 *       and submit those forms. This lowers a benchmark app's difficulty + primes its data store
 *       purely from affordances the app exposes — no knowledge that it is DVWA.</li>
 * </ul>
 *
 * Every URL, field name, option, and constraint comes from the app's own markup; this class contains
 * no target-specific paths or app identification.
 */
public final class AutonomousAuth {

    private final MontoyaApi api;
    private final SessionStore session;
    private final ScanLog scanLog;
    private final String host;
    private final String seedUrl;
    private AiEngine engine;   // optional — when set, enables model-driven OTP/verification extraction

    // ---- generic DOM patterns (shape/keyword, not app-specific strings) ----
    private static final Pattern FORM        = Pattern.compile("(?is)<form\\b.*?</form>");
    private static final Pattern TAG         = Pattern.compile("(?is)<(input|select|button|textarea)\\b[^>]*>");
    private static final Pattern PW_INPUT    = Pattern.compile("(?is)<input\\b[^>]*type\\s*=\\s*['\"]?password");
    private static final Pattern A_LINK      = Pattern.compile("(?is)<a\\b[^>]*\\bhref\\s*=\\s*['\"]?([^'\" >]+)['\"]?[^>]*>(.*?)</a>");
    private static final Pattern REGISTER    = Pattern.compile("(?i)regist|sign.?up|new.?user|create.?account|create.?an?.?account");
    private static final Pattern USER_FIELD  = Pattern.compile("(?i).*(user|email|login|usuario|account|name).*|^log$");   // ^log$ = WordPress's username field
    private static final Pattern SEC_SELECT  = Pattern.compile("(?i).*(security|seclev|difficulty|level|mode).*");
    private static final Pattern LOW_OPTION  = Pattern.compile("(?i)^(low|easy|insecure|none|off|no|disabled?)$");
    private static final Pattern RESET_BTN   = Pattern.compile("(?i)(create|reset|initiali[sz]e|setup|install).{0,25}(database|db|data|schema|table|app)");
    private static final Pattern LOGOUT      = Pattern.compile("(?i)(logout|log-out|log_off|sign.?out)");
    // "between 6 and 10", "6 to 10 characters", "at least 6", "minimum of 6", "max 10 characters"
    private static final Pattern RANGE       = Pattern.compile("(?i)between\\s+(\\d{1,3})\\s+and\\s+(\\d{1,3})|(\\d{1,3})\\s*(?:to|-|–)\\s*(\\d{1,3})\\s*char");
    private static final Pattern MIN_LEN     = Pattern.compile("(?i)(?:at least|minimum(?: of)?|min(?:imum)?|>=?)\\s+(\\d{1,3})");
    private static final Pattern MAX_LEN     = Pattern.compile("(?i)(?:at most|maximum(?: of)?|max(?:imum)?|no more than|<=?)\\s+(\\d{1,3})");

    public AutonomousAuth(MontoyaApi api, SessionStore session, ScanLog scanLog, String host, String seedUrl) {
        this.api = api;
        this.session = session;
        this.scanLog = scanLog;
        this.host = host;
        this.seedUrl = seedUrl == null ? "" : seedUrl;
    }

    /** Give the auth flow the model, enabling generic LLM-driven OTP/verification extraction (fluent). */
    public AutonomousAuth withEngine(AiEngine e) { this.engine = e; return this; }

    // ================================================================= manual import
    /** Explicit user-provided session (NOT fingerprinting): -Daiscanner.cookie / -Daiscanner.bearer /
     *  -Daiscanner.signingKey. The signing key is REQUIRED for HMAC-signed APIs (a bearer alone gets "invalid
     *  signature"); capture it from the browser's authenticated session alongside the bearer. */
    public boolean manualImport() {
        String cookie = arg("aiscanner.cookie", "AISCANNER_COOKIE");
        String bearer = arg("aiscanner.bearer", "AISCANNER_BEARER");
        String signKey = arg("aiscanner.signingKey", "AISCANNER_SIGNING_KEY");
        if (cookie == null && bearer == null) return false;
        if (cookie != null) { session.set(cookie); scanLog.log("[AI Scanner] manual session: cookie imported (" + cookie.length() + " chars)."); }
        if (bearer != null) { session.setBearer(bearer); scanLog.log("[AI Scanner] manual session: bearer imported."); }
        if (signKey != null) { session.setSigningKey(signKey); scanLog.log("[AI Scanner] manual session: request-signing key imported."); }
        return session.authenticated();
    }

    // ================================================================= register-then-login
    /**
     * Sign up like a user, then log in. Generic: locate a registration form by shape (2 password
     * fields), reached directly or via a register/sign-up link; fill + adapt to the form's stated
     * length constraint; submit; then log in with the chosen creds. Publishes the session on success.
     */
    public boolean registerThenLogin() {
        AuthSession s = new AuthSession(api, host);
        String[] found = findRegistrationForm(s);        // {formBlock, pageUrl}
        if (found == null) { scanLog.debug("[AI Scanner] register: no registration form on the surface."); return false; }
        String form = found[0], pageUrl = found[1];
        scanLog.phase("Registering an account (generic — no default creds worked)");

        String user = arg("aiscanner.reg.user", "AISCANNER_REG_USER"); if (user == null) user = "aiscbot";
        String pass = arg("aiscanner.reg.pass", "AISCANNER_REG_PASS"); if (pass == null) pass = "aiscpass";
        // If the register form has an EMAIL field, apps validate the format — use an email-format username.
        // The SAME value flows to login (buildBody puts `user` into the login's user/email field too), so
        // register and login stay consistent. Non-email forms (e.g. WebGoat's username) keep the plain name.
        if (hasEmailField(form) && !user.contains("@")) user = user + "@example.com";
        String action = resolveAction(form, pageUrl);

        HttpRequestResponse resp = null;
        for (int attempt = 0; attempt < 4; attempt++) {
            resp = s.postForm(action, buildBody(form, user, pass, /*forLogin*/false, null));
            String body = bodyOf(resp);
            boolean rerendered = PW_INPUT.matcher(body).find();       // still showing a password form → likely rejected
            int[] range = parseLengthConstraint(body);
            if (range != null && rerendered) {
                String nu = fitLength(user, range[0], range[1]);
                String np = fitLength(pass, range[0], range[1]);
                if (nu.equals(user) && np.equals(pass)) break;         // can't improve → stop
                user = nu; pass = np;
                scanLog.log("[AI Scanner] register: form requires " + range[0] + "-" + range[1]
                        + " chars → retrying as " + user + "/" + pass);
                continue;
            }
            break;   // 302 / no re-rendered form / no parseable constraint
        }

        // Registration may AUTO-LOGIN the new account (WebGoat does) — if the session is already
        // authenticated we're in; the register redirect's FINAL url is the app's real authenticated
        // entry (the raw seed may 404 for a logged-in user), so record it as the landing.
        if (verifyAuthenticated(s)) {
            s.publishTo(session, urlOf(resp, seedUrl), pageUrl, user, pass);
            scanLog.log("[AI Scanner] registered + authenticated as " + user + " (auto-login on signup).");
            return true;
        }
        boolean ok = loginWith(s, user, pass);
        if (ok) scanLog.log("[AI Scanner] registered + authenticated as " + user + " (generic register-then-login).");
        else scanLog.log("[AI Scanner] register: could not authenticate after signup.");
        return ok;
    }

    /** JWT anywhere in a response body (crAPI {"token":"eyJ…"}, Juice {"authentication":{"token":"eyJ…"}}). */
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{6,}\\.eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}");
    // A per-request signing key handed back alongside the access token (e.g. "signing_key":"…"). Generic key
    // names so it works across apps; value is any non-trivial secret string (hex/base64/opaque).
    private static final Pattern SIGNING_KEY = Pattern.compile(
            "(?i)\"(signing_?key|sign_?key|request_?signing_?key|hmac_?key|secret_?key)\"\\s*:\\s*\"([^\"]{8,})\"");

    /** Extract a request-signing key from a JSON auth-response body and store it on the session (no-op if absent). */
    private void captureSigningKey(String body) {
        if (body == null) return;
        Matcher m = SIGNING_KEY.matcher(body);
        if (m.find()) session.setSigningKey(m.group(2));
    }

    /**
     * API-first (JSON) register-then-login — lets the pure-Java BUILT-IN path authenticate an SPA whose
     * auth is a JSON API (no HTML form) WITHOUT the browser driver (the BApp-compliant path). Given
     * candidate JSON login endpoints (from EndpointDiscovery), derive each one's signup sibling, register a
     * UNIQUE account, log in, and capture the JWT the login response returns. Generic: a superset JSON body
     * (lenient parsers ignore extra fields), a JWT recognised by SHAPE, unique nonce-based creds — no
     * app-specific field or endpoint names.
     */
    public boolean apiRegisterThenLogin(List<HttpRequest> loginCandidates) {
        // Augment with login endpoints OBSERVED in the site map (any same-host request that looks like a login,
        // incl. a SIBLING ORIGIN the SPA calls — e.g. seed :3001 but the real login is the API's :8080/login).
        // The JS-mining candidates are built on the SEED origin, so a cross-port/subdomain API login is otherwise
        // never tried. Origin-aware + generic.
        loginCandidates = mergeCandidates(loginCandidates, siteMapLoginCandidates());
        if (loginCandidates == null || loginCandidates.isEmpty()) return false;
        // Prefer a DISPOSABLE, readable mailbox so an email-verification / OTP step can be completed
        // autonomously; fall back to a throwaway @example.com for apps that don't verify email (or that
        // block disposable domains). Both are generic — only the mailbox address changes.
        // Try each configured disposable provider (mailinator, then mail.tm) — if one never delivers/reads the
        // OTP (throttled or its domain is blocked by the target), re-run the whole sign-up with the next one.
        List<DisposableMailbox> boxes;
        try { boxes = DisposableMailbox.mintAll(api); } catch (Throwable t) { boxes = java.util.Collections.emptyList(); }
        for (DisposableMailbox box : boxes) {
            scanLog.log("[AI Scanner] API auth: trying disposable mailbox provider '" + box.providerName() + "' (" + box.address() + ")");
            if (attemptApiRegister(loginCandidates, box.address(), box)) return true;
            if (session.authenticated()) return true;   // captured mid-attempt (e.g. signup returned a token)
        }
        if (attemptApiRegister(loginCandidates, null, null)) return true;   // no-verify apps: throwaway @example.com
        scanLog.debug("[AI Scanner] API auth: no JSON login endpoint returned a token.");
        return false;
    }

    /**
     * Log in with OPERATOR-SUPPLIED credentials (env {@code AISCANNER_LOGIN_EMAIL}/{@code AISCANNER_LOGIN_PASSWORD}
     * or {@code -Daiscanner.loginEmail}/{@code -Daiscanner.loginPassword}). For prod/staging where autonomous
     * sign-up is blocked (e.g. disposable-email domains rejected). POSTs a superset JSON login body to each
     * discovered login endpoint and captures the JWT / signing-key / session cookie. No-op when no creds are set.
     * Generic — superset body ({email,username,password}); no app-specific field or endpoint names.
     */
    public boolean loginWithProvidedCreds(List<HttpRequest> loginCandidates) {
        String email = arg("aiscanner.loginEmail", "AISCANNER_LOGIN_EMAIL");
        String pass  = arg("aiscanner.loginPassword", "AISCANNER_LOGIN_PASSWORD");
        if (email == null || pass == null) return false;
        if (loginCandidates == null || loginCandidates.isEmpty()) {
            scanLog.log("[AI Scanner] API auth: operator credentials set but no login endpoint discovered.");
            return false;
        }
        String login = "{\"email\":\"" + esc(email) + "\",\"username\":\"" + esc(email)
                + "\",\"password\":\"" + esc(pass) + "\"}";
        scanLog.log("[AI Scanner] API auth: trying operator-supplied credentials (" + email + ") on "
                + loginCandidates.size() + " login endpoint(s).");
        Set<String> tried = new LinkedHashSet<>();
        for (HttpRequest cand : loginCandidates) {
            String loginUrl = cand.url();
            if (loginUrl == null || !tried.add(loginUrl)) continue;
            try {
                AuthSession s = new AuthSession(api, host);
                if (captureLoginToken(s, loginUrl, login, "(operator creds)")) return true;
            } catch (Throwable ignore) { }
        }
        scanLog.log("[AI Scanner] API auth: operator-supplied credentials did not authenticate (bad creds, MFA, or WAF).");
        return false;
    }

    /** Minimal JSON string escape for a single value built into a hand-assembled body. */
    private static String esc(String v) { return v == null ? "" : v.replace("\\", "\\\\").replace("\"", "\\\""); }

    /** One register+login sweep with a given email (null → a throwaway @example.com). With a {@code box},
     *  an emailed verification code / magic-link is completed between register and login. Generic —
     *  endpoints are derived from the discovered login URL; field names are common conventions. */
    private boolean attemptApiRegister(List<HttpRequest> loginCandidates, String emailOverride, DisposableMailbox box) {
        long nonce = Math.abs(System.nanoTime());
        String tag = "aisc" + Long.toString(nonce, 36);
        String email = emailOverride != null ? emailOverride : tag + "@example.com";
        String number = "9" + String.format("%09d", nonce % 1_000_000_000L);   // 10-digit unique phone
        String pass = "Aisc!" + (nonce % 100000) + "Zx";                        // meets common strength rules
        String signup = "{\"name\":\"" + tag + "\",\"username\":\"" + tag + "\",\"email\":\"" + email
                + "\",\"number\":\"" + number + "\",\"phone\":\"" + number + "\",\"password\":\"" + pass
                + "\",\"passwordConfirm\":\"" + pass + "\",\"repeatPassword\":\"" + pass + "\"}";
        // Carry the registered NAME (tag) as well as the email: form-login apps often key on the account's
        // name/handle (Spring usernameParameter), not its email — the form-encoded fallback tries each.
        String login = "{\"email\":\"" + email + "\",\"username\":\"" + email + "\",\"name\":\"" + tag
                + "\",\"password\":\"" + pass + "\"}";
        if (box != null) scanLog.log("[AI Scanner] API sign-up using disposable mailbox " + email);

        Set<String> tried = new LinkedHashSet<>();
        for (HttpRequest cand : loginCandidates) {
            String loginUrl = cand.url();
            if (loginUrl == null || !tried.add(loginUrl)) continue;
            for (String signupUrl : registrationTargets(loginUrl)) {
                try {
                    AuthSession s = new AuthSession(api, host);
                    HttpRequestResponse sr = registerSend(signupUrl, signup); // register (initial body; POST or PUT)
                    // Diagnostic: show what the signup endpoint actually returns (skip plain 404 siblings) so a
                    // failed sign-up is debuggable — status + a body snippet reveals validation errors / 429 / etc.
                    int sc0 = sr != null && sr.response() != null ? sr.response().statusCode() : -1;
                    if (sc0 != 404 && sc0 != -1) {
                        String sb0 = bodyOf(sr);
                        scanLog.log("[AI Scanner] signup " + signupUrl + " → HTTP " + sc0 + " | "
                                + (sb0 == null ? "" : sb0.substring(0, Math.min(160, sb0.length())).replaceAll("\\s+", " ")));
                    }
                    // ADAPTIVE: the app's own 400/422 validation errors reveal its required fields — fill them
                    // (business name, license #, phone, region, …) and retry, so sign-up works on app-specific
                    // schemas. DETERMINISTIC field-name heuristics first (reliable), LLM only as a fallback, and
                    // ALWAYS force our disposable email + password so the OTP reaches the mailbox. Generic, bounded.
                    for (int round = 0; round < 4; round++) {
                        int code = sr != null && sr.response() != null ? sr.response().statusCode() : -1;
                        if (code != 400 && code != 422) break;
                        String rbody = bodyOf(sr);
                        if (rbody == null || !rbody.toLowerCase().matches("(?s).*(required|invalid|valid|must|field).*")) break;
                        String filled = mergeRequiredFields(signup, rbody, email, pass);   // deterministic
                        if ((filled == null || filled.equals(signup)) && engine != null)   // fallback to the model
                            filled = forceIdentity(engine.fillRegistration(signup, rbody, email, pass), email, pass);
                        if (filled == null || filled.isBlank() || filled.equals(signup)) break;
                        scanLog.log("[AI Scanner] sign-up: completed required fields from the app's validation errors, retrying…");
                        signup = filled;
                        sr = registerSend(signupUrl, signup);
                    }
                    boolean signupOk = sr != null && sr.response() != null && sr.response().statusCode() < 400;
                    if (captureLoginToken(s, loginUrl, login, signupUrl)) return true;   // maybe no verify needed
                    // Only wait for an emailed code if the signup endpoint actually ACCEPTED the request
                    // (2xx/3xx) — else a 404/405 sibling would make us block on the inbox for nothing.
                    if (box != null && signupOk) {
                        completeEmailVerification(s, box, signupUrl, email);   // captures the token from verify, if any
                        if (session.authenticated()) return true;             // OTP-first flow: verify IS the auth
                        if (captureLoginToken(s, loginUrl, login, signupUrl)) return true;   // else a separate login
                        // Accepted but couldn't finalize: STOP. Re-POSTing signup on the next sibling "resends" a
                        // fresh code and invalidates the one we just used (a self-inflicted OTP race). One shot.
                        return false;
                    }
                } catch (Throwable ignore) { }
            }
        }
        return false;
    }

    /** Login URLs that already proved they are NOT a login handler (404/405/501) — never re-POSTed. This kills
     *  the dup storm where synthesized `<app>/accounts/{login,signin,authenticate}` candidates (all nginx 405)
     *  were POSTed once per signup-sibling × credential set. Populated in captureLoginToken. */
    private final Set<String> deadLoginUrls = new LinkedHashSet<>();

    /** POST the login body; capture a JWT (or a 2xx + session cookie) as the authenticated session. */
    private boolean captureLoginToken(AuthSession s, String loginUrl, String login, String signupUrl) {
        if (deadLoginUrls.contains(loginUrl)) return false;   // proven not a login handler — don't re-POST
        HttpRequestResponse r = s.postJson(loginUrl, login);
        String body = bodyOf(r);
        Matcher jm = JWT.matcher(body == null ? "" : body);
        if (jm.find()) {
            session.setBearer(jm.group());
            captureSigningKey(body);
            s.publishTo(session, seedUrl, null, null, null);                    // carry any auth cookies too
            scanLog.log("[AI Scanner] API auth: registered + logged in via " + loginUrl
                    + " (signup " + signupUrl + ") → JWT bearer captured."
                    + (session.hasSigningKey() ? " [+ request-signing key]" : ""));
            return true;
        }
        if (r != null && r.response() != null && r.response().statusCode() < 400 && !s.cookieHeader().isBlank()) {
            // A real JSON login answers with JSON (token/user) or a redirect. A GUESSED url like /login on a CMS
            // returns an HTML PAGE + a benign cookie (e.g. WordPress's wordpress_test_cookie) — that is NOT auth.
            // Require a JSON/redirect response with no re-rendered password form, so a stray 200+cookie can't be
            // mistaken for a successful login (which would stop us from trying the REAL login endpoint).
            String ct = r.response().headerValue("Content-Type");
            boolean jsonResp = (ct != null && ct.toLowerCase().contains("json")) || (body != null && body.trim().startsWith("{"));
            boolean redirected = r.response().statusCode() >= 300;
            boolean stillLoginForm = body != null && PW_INPUT.matcher(body).find();
            if ((jsonResp || redirected) && !stillLoginForm) {
                s.publishTo(session, seedUrl, null, null, null);
                if (session.has()) {
                    scanLog.log("[AI Scanner] API auth: registered + logged in via " + loginUrl + " → session cookie captured.");
                    return true;
                }
            }
        }
        int code = r != null && r.response() != null ? r.response().statusCode() : -1;
        // Not a login handler (404/405/501, incl. nginx "Method Not Allowed") → remember it so we don't POST it
        // again for every signup-sibling / credential set, and log once concisely instead of storming the log.
        if (code == 404 || code == 405 || code == 501) {
            deadLoginUrls.add(loginUrl);
            scanLog.debug("[AI Scanner]   login " + loginUrl + " → HTTP " + code + " — not a login handler; skipping further attempts.");
            return false;
        }
        // FORM-ENCODED login fallback: Spring Security formLogin and classic server apps take
        // username/password as application/x-www-form-urlencoded and answer 2xx (+ a session cookie) —
        // NOT JSON, NOT a JWT — so the JSON attempt above yields nothing. Retry the same creds form-encoded.
        // Generic: derives values from the JSON creds we already built. Guard against a redirect back to the
        // login page (formLogin's failure path): a body still showing a password input = not authenticated.
        try {
            JSONObject lj = new JSONObject(login);
            String p = lj.optString("password", "");
            s.get(loginUrl);   // prime any pre-login cookie/token the server sets on GET (WordPress wordpress_test_cookie, …)
            LinkedHashSet<String> ids = new LinkedHashSet<>();   // identity candidates: form-login apps key on
            for (String k : new String[]{ "username", "name", "email", "user", "login" }) {   // any of these
                String v = lj.optString(k, "");
                if (!v.isBlank()) ids.add(v);
            }
            if (!p.isBlank()) {
                for (String u : ids) {
                    // Set every common identity field to this candidate so the app's chosen param name matches,
                    // whichever it is (Spring usernameParameter, user/email/login, or WordPress log/pwd). One per candidate.
                    String form = "username=" + enc(u) + "&user=" + enc(u) + "&email=" + enc(u)
                            + "&login=" + enc(u) + "&log=" + enc(u)
                            + "&password=" + enc(p) + "&pwd=" + enc(p) + "&wp-submit=Log+In";
                    HttpRequestResponse fr = s.postForm(loginUrl, form);
                    int fc = code(fr);
                    String fb = bodyOf(fr);
                    boolean backOnLogin = fb != null && PW_INPUT.matcher(fb).find();   // failure → login page re-rendered
                    if (fc >= 200 && fc < 400 && !backOnLogin && !s.cookieHeader().isBlank()) {
                        s.publishTo(session, seedUrl, null, null, null);
                        if (session.has()) {
                            scanLog.log("[AI Scanner] API auth: logged in via " + loginUrl
                                    + " (form-encoded) → session cookie captured.");
                            return true;
                        }
                    }
                }
            }
        } catch (Throwable ignore) { }
        scanLog.log("[AI Scanner] login " + loginUrl + " → HTTP " + code + " (no token/cookie) | "
                + (body == null ? "" : body.substring(0, Math.min(140, body.length())).replaceAll("\\s+", " ")));
        return false;
    }

    /** Wait for the sign-up email, let the model read the OTP code / magic-link out of it, and submit it:
     *  GET the link, or POST the code to a derived verify endpoint under common field names. Generic. */
    private boolean completeEmailVerification(AuthSession s, DisposableMailbox box, String signupUrl, String email) {
        String mail = box.awaitMessage(60);
        if (mail == null || mail.isBlank()) return false;
        String value = engine != null ? engine.extractVerificationCode(mail) : regexVerification(mail);
        if (value == null || value.isBlank()) return false;
        if (value.startsWith("http")) {
            scanLog.log("[AI Scanner] sign-up: confirming account via emailed link…");
            s.get(value);
            return true;
        }
        scanLog.log("[AI Scanner] sign-up: submitting emailed verification code " + value + " …");
        for (String vurl : verifySiblings(signupUrl)) {
            for (String field : new String[]{ "otp", "code", "token", "verificationCode", "verification_code", "pin" }) {
                HttpRequestResponse r = s.postJson(vurl, "{\"email\":\"" + email + "\",\"" + field + "\":\"" + value + "\"}");
                int code = r != null && r.response() != null ? r.response().statusCode() : -1;
                if (code == 404 || code == -1) continue;                    // wrong endpoint/field — skip quietly
                String vb = bodyOf(r);
                scanLog.log("[AI Scanner]   verify " + vurl + " {" + field + "} → HTTP " + code + " | "
                        + (vb == null ? "" : vb.substring(0, Math.min(120, vb.length())).replaceAll("\\s+", " ")));
                if (code < 400) {
                    // OTP-first flow: the verify response ITSELF returns the session (a JWT/access token or a
                    // Set-Cookie) — capture it here instead of doing a separate password-login (which this flow
                    // doesn't support and would 401). Generic — any token/cookie the app hands back on verify.
                    Matcher jm = JWT.matcher(vb == null ? "" : vb);
                    if (jm.find()) {
                        session.setBearer(jm.group());
                        captureSigningKey(vb);
                        s.publishTo(session, seedUrl, null, null, null);
                        scanLog.log("[AI Scanner] sign-up: email verified → JWT captured from verify response — authenticated."
                                + (session.hasSigningKey() ? " [+ request-signing key]" : ""));
                    } else if (!s.cookieHeader().isBlank()) {
                        s.publishTo(session, seedUrl, null, null, null);
                        if (session.has()) scanLog.log("[AI Scanner] sign-up: email verified → session cookie captured — authenticated.");
                    }
                    return true;
                }
            }
        }
        return false;
    }

    /** Verify endpoints derived from the signup URL (swap its leaf for common verify verbs; slash-aware). */
    private static List<String> verifySiblings(String signupUrl) {
        return leafSiblings(signupUrl, new String[]{ "verify", "verify-email", "verifyEmail", "confirm", "activate", "otp", "verify-otp", "code", "verify-code" });
    }

    /** Fallback (no model): pull a verification URL or a 4–8 digit code out of the raw email text. */
    private static String regexVerification(String mail) {
        Matcher u = Pattern.compile("https?://[^\\s\"'<>]*(?:verif|confirm|activate|token)[^\\s\"'<>]*").matcher(mail);
        if (u.find()) return u.group();
        Matcher c = Pattern.compile("\\b([0-9]{4,8})\\b").matcher(mail);
        if (c.find()) return c.group(1);
        return "";
    }

    /** Fill the app's required/invalid fields (from its validation-error JSON) with generic, field-NAME-based
     *  values, ALWAYS forcing our disposable email + password (so the OTP reaches the mailbox). Deterministic —
     *  no model, no app schema; handles {"data":{f:[..]}} / {"errors":{..}} / {"detail":{..}} / flat {f:[..]}. */
    private static String mergeRequiredFields(String body, String errorJson, String email, String pass) {
        try {
            JSONObject cur = (body != null && body.trim().startsWith("{")) ? new JSONObject(body) : new JSONObject();
            JSONObject errs = new JSONObject(errorJson == null ? "{}" : errorJson);
            JSONObject fields = errs.optJSONObject("data");
            if (fields == null) fields = errs.optJSONObject("errors");
            if (fields == null) fields = errs.optJSONObject("detail");
            if (fields == null) fields = errs;                                  // flat {field:[msgs]}
            for (String f : fields.keySet()) {
                if (f.equalsIgnoreCase("message") || f.equalsIgnoreCase("success") || f.equalsIgnoreCase("status")) continue;
                // If the error enumerates valid values ("Must be one of: DUBAI, …"), pick one — even if a value
                // was already set (a wrong enum guess must be corrected). Otherwise fill blank/missing by name.
                String enumVal = firstEnumOption(fieldErrText(fields.opt(f)));
                if (enumVal != null) { cur.put(f, enumVal); continue; }
                Object existing = cur.opt(f);
                if (existing == null || (existing instanceof String && ((String) existing).isBlank()))
                    cur.put(f, valueForField(f, email, pass));
            }
            return forceIdentity(cur.toString(), email, pass);
        } catch (Throwable t) { return body; }
    }

    /** Overwrite any email/password field with our disposable identity — never let a fill change them
     *  (the OTP must go to OUR mailbox, and login must use OUR password). */
    private static String forceIdentity(String body, String email, String pass) {
        if (body == null || !body.trim().startsWith("{")) return body;
        try {
            JSONObject o = new JSONObject(body);
            for (String k : new ArrayList<>(o.keySet())) {
                String n = k.toLowerCase();
                if (n.equals("email") || n.endsWith("email")) o.put(k, email);
                else if (n.matches("(?i).*(password|pwd|passwd).*")) o.put(k, pass);
            }
            if (!o.has("email")) o.put("email", email);
            return o.toString();
        } catch (Throwable t) { return body; }
    }

    /** Join a field's validation-error messages into one string (handles a JSON array or a scalar). */
    private static String fieldErrText(Object v) {
        if (v == null) return "";
        if (v instanceof org.json.JSONArray) {
            StringBuilder sb = new StringBuilder();
            org.json.JSONArray a = (org.json.JSONArray) v;
            for (int i = 0; i < a.length(); i++) sb.append(a.optString(i, "")).append(' ');
            return sb.toString();
        }
        return v.toString();
    }

    /** If a validation message enumerates allowed values ("must be one of: A, B, C" / "valid choices are …"),
     *  return the FIRST option — a guaranteed-valid value. Generic; null when no enumeration is present. */
    private static String firstEnumOption(String errText) {
        if (errText == null || errText.isBlank()) return null;
        Matcher m = Pattern.compile("(?is)(?:one of|choices?\\s*(?:are|:)|valid (?:choices|options|values)[^:]*:|must be)\\s*:?\\s*\\[?([A-Za-z0-9_.,'\"|/\\- ]+?)[\\].]?\\s*$")
                .matcher(errText.trim());
        if (!m.find()) {
            m = Pattern.compile("(?is)one of:?\\s*([A-Za-z0-9_.,'\"|/\\- ]+)").matcher(errText);
            if (!m.find()) return null;
        }
        for (String tok : m.group(1).split("\\s*(?:,|\\||\\bor\\b)\\s*")) {
            String t = tok.trim().replaceAll("^['\"]+|['\".]+$", "").trim();
            if (t.matches("[A-Za-z0-9_.\\-]+")) return t;
        }
        return null;
    }

    /** A plausible, generic value for a signup field, chosen by its NAME (not app knowledge). */
    private static Object valueForField(String f, String email, String pass) {
        String n = f.toLowerCase();
        if (n.matches("(?i).*(agree|terms|accept|consent|newsletter|subscribe|^is_|^has_).*")) return Boolean.TRUE;
        if (n.contains("email")) return email;
        if (n.matches("(?i).*(password|pwd|passwd|pass).*")) return pass;
        if (n.matches("(?i).*(first_?name|fname|given_?name).*")) return "Test";
        if (n.matches("(?i).*(last_?name|lname|surname|family_?name).*")) return "User";
        if (n.matches("(?i).*(full_?name|display_?name|^name$|contact_?name).*")) return "Test User";
        if (n.contains("user")) return "aiscan" + (Math.abs(System.nanoTime()) % 100000);
        if (n.matches("(?i).*(company|business|organi[sz]ation|org|store|shop|brand|merchant|entity).*")) return "Test Trading LLC";
        if (n.matches("(?i).*(licen[sc]e|registration|reg_?no|trade_?license|permit|tax|vat|trn|crn|ein).*")) return String.valueOf(100000 + Math.abs(System.nanoTime()) % 900000);
        if (n.matches("(?i).*(phone|mobile|tel|contact|whatsapp|msisdn|number).*")) return "9" + String.format("%09d", Math.abs(System.nanoTime()) % 1_000_000_000L);
        if (n.matches("(?i).*(emirate|city|region|province|town|district|area|state).*")) return "Dubai";
        if (n.matches("(?i).*(country|nationality).*")) return "AE";
        if (n.matches("(?i).*(address|street|building|location|addr).*")) return "123 Test Street";
        if (n.matches("(?i).*(zip|postal|pin_?code|postcode).*")) return "00000";
        if (n.matches("(?i).*(dob|birth|_date|date_).*")) return "1990-01-01";
        if (n.matches("(?i).*(url|website|site|domain).*")) return "https://example.com";
        if (n.matches("(?i).*(currency).*")) return "AED";
        if (n.matches("(?i).*(gender|sex).*")) return "other";
        if (n.matches("(?i).*(age|quantity|count|amount|size|qty).*")) return 1;
        return "test";
    }

    /** Signup URLs derived from a login endpoint (swap the login-verb leaf for a signup verb). */
    private static List<String> signupSiblings(String loginUrl) {
        return leafSiblings(loginUrl, new String[]{ "signup", "register", "sign-up", "signUp", "registration" });
    }

    /** Identity-resource leaf nouns: a REST app often has NO /register alias and instead creates accounts
     *  by writing the user resource itself (PUT /rest/user). Generic, app-independent noun set. */
    private static final Pattern USER_RESOURCE =
            Pattern.compile("(?i)users?|accounts?|customers?|members?|register|signup|sign-up|registration");

    /** Where to try registration: the login URL's signup siblings (/signup,/register,…) PLUS any discovered
     *  same-host user/account RESOURCE already in the site map. Covers REST apps whose account creation is a
     *  create on the user resource (e.g. PUT /rest/user) with no /register sibling — which a login-sibling-only
     *  derivation misses. Deduped, capped, zero hardcoding (matched by conventional identity nouns). */
    private List<String> registrationTargets(String loginUrl) {
        LinkedHashSet<String> out = new LinkedHashSet<>(signupSiblings(loginUrl));
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (out.size() >= 24) break;
                String u = rr.request().url();
                if (u == null) continue;
                String h, path;
                try { URI uri = URI.create(u); h = uri.getHost(); path = uri.getPath(); }
                catch (Exception e) { continue; }
                if (h == null || !host.equalsIgnoreCase(h) || path == null || path.isEmpty()) continue;
                String leaf = path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
                int slash = leaf.lastIndexOf('/');
                String last = slash >= 0 ? leaf.substring(slash + 1) : leaf;
                if (USER_RESOURCE.matcher(last).matches()) {
                    int q = u.indexOf('?');
                    out.add(q < 0 ? u : u.substring(0, q));
                }
            }
            // Origin-aware SYNTHESIS: a REST app's account-create endpoint is often never SUBMITTED during a
            // crawl (the SPA only PUT/POSTs it on a real register-form submit), so it's absent from the site map
            // above. Append conventional identity leaves to each OBSERVED API base (scheme://host:port + a
            // /rest|/api[/vN]/ prefix, incl. a sibling origin) so e.g. an observed http://host:8080/rest/ yields
            // http://host:8080/rest/user to register against. Generic nouns, deduped, capped.
            Set<String> apiBases = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (out.size() >= 40) break;
                String u = rr.request() != null ? rr.request().url() : null;
                if (u == null || !host.equalsIgnoreCase(hostOfUrl(u))) continue;
                Matcher m = API_BASE_URL.matcher(u);
                if (m.find()) apiBases.add(m.group(1));
            }
            for (String b : apiBases) {
                String base = b.endsWith("/") ? b : b + "/";
                for (String leaf : new String[]{ "user", "users", "account", "accounts", "register", "signup", "customer", "member" }) {
                    if (out.size() >= 40) break;
                    out.add(base + leaf);
                }
            }
        } catch (Throwable ignore) { }
        return new ArrayList<>(out);
    }

    /** scheme://host[:port] up to and including a /rest or /api[/vN] segment — the app's API mount point. */
    private static final Pattern API_BASE_URL = Pattern.compile(
            "(?i)(https?://[^/]+(?:/[^/?#]+)*?/(?:rest|api)(?:/v\\d+)?/)");

    /** Login endpoints to try, sourced from OBSERVED traffic — robust to run-to-run crawl/LLM variance that can
     *  surface zero login candidates even when the app plainly has one. Two sources: (1) any same-host request
     *  whose path already looks like an auth leaf; (2) SYNTHESIS — append conventional login leaves to each
     *  distinct same-host ORIGIN the crawl touched (incl. a sibling API origin, e.g. :8080), so a form-login the
     *  crawler never SUBMITTED is still tried. Generic, deduped, capped. */
    private List<HttpRequest> siteMapLoginCandidates() {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        LinkedHashSet<String> origins = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = rr.request() != null ? rr.request().url() : null;
                if (u == null || !host.equalsIgnoreCase(hostOfUrl(u))) continue;
                try { URI uri = URI.create(u); origins.add(uri.getScheme() + "://" + uri.getAuthority()); }
                catch (Exception ignore) { }
                String path = pathOfUrl(u).toLowerCase().replaceAll("/+$", "");
                if (path.endsWith("/login") || path.endsWith("/signin") || path.endsWith("/authenticate")
                        || path.endsWith("/session") || path.endsWith("/auth")) {
                    int q = u.indexOf('?');
                    urls.add(q < 0 ? u : u.substring(0, q));
                }
            }
            for (String o : origins)
                for (String leaf : new String[]{ "/login", "/signin", "/authenticate", "/api/login", "/rest/login", "/auth/login" }) {
                    if (urls.size() >= 30) break;
                    urls.add(o + leaf);
                }
        } catch (Throwable ignore) { }
        List<HttpRequest> out = new ArrayList<>();
        for (String u : urls) { try { out.add(HttpRequest.httpRequestFromUrl(u).withMethod("POST")); } catch (Exception ignore) { } }
        return out;
    }

    /** Merge candidate lists, de-duplicating by URL and preserving order (passed candidates first). */
    private static List<HttpRequest> mergeCandidates(List<HttpRequest> a, List<HttpRequest> b) {
        LinkedHashMap<String, HttpRequest> byUrl = new LinkedHashMap<>();
        if (a != null) for (HttpRequest r : a) if (r != null && r.url() != null) byUrl.putIfAbsent(r.url(), r);
        if (b != null) for (HttpRequest r : b) if (r != null && r.url() != null) byUrl.putIfAbsent(r.url(), r);
        return new ArrayList<>(byUrl.values());
    }

    private static String hostOfUrl(String url) { try { return URI.create(url).getHost(); } catch (Exception e) { return ""; } }
    private static String pathOfUrl(String url) { try { String p = URI.create(url).getPath(); return p == null ? "" : p; } catch (Exception e) { return ""; } }

    /** Register at {@code url} trying the common resource-create methods: POST first (typical signup), then
     *  PUT (RESTful resource create — javulna createUser, DRF, etc.). Returns the response that a real handler
     *  produced: a 2xx/3xx acceptance, or a 400/422 validation error the caller's adaptive field-fill can act
     *  on. Only escalates to PUT when POST looks like a wrong-method/forbidden non-handler, so POST-only signup
     *  apps see exactly one request. Generic. */
    private HttpRequestResponse registerSend(String url, String body) {
        // FRESH session per method: a failed POST (e.g. 403 from an auth-required endpoint that shares the path)
        // sets a tracked session cookie that, carried onto the PUT, can itself trigger a 403 so the create never
        // lands. Isolating each attempt keeps the RESTful PUT create clean. (Verified against a Spring app whose
        // POST /rest/user needs auth but PUT /rest/user is permitAll.)
        HttpRequestResponse post = new AuthSession(api, host).postJson(url, body);
        int pc = code(post);
        if (pc >= 200 && pc < 400) return post;              // POST create accepted
        if (pc == 400 || pc == 422) return post;             // POST IS the handler — let adaptive fill drive it
        HttpRequestResponse put = new AuthSession(api, host).putJson(url, body);  // POST wrong-method/forbidden → RESTful PUT create
        int uc = code(put);
        if (uc >= 200 && uc < 400) return put;
        if (uc == 400 || uc == 422) return put;
        return (pc == 404 || pc == -1) ? put : post;         // neither accepted — return the more informative
    }

    private static int code(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().statusCode() : -1;
    }

    /** Sibling URLs of an auth endpoint: strip a TRAILING SLASH to find the real leaf, swap it for each verb,
     *  and emit BOTH the trailing-slash and no-slash forms (frameworks like DRF/Django enforce APPEND_SLASH).
     *  Fixes the bug where "/login/" (trailing slash) yielded nested "/login/signup" instead of "/signup/". */
    private static List<String> leafSiblings(String url, String[] verbs) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        int q = url.indexOf('?');
        String base = q < 0 ? url : url.substring(0, q);
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);   // strip trailing slash → real leaf
        int slash = base.lastIndexOf('/');
        if (slash < 0) return new ArrayList<>(out);
        String prefix = base.substring(0, slash + 1);
        String leaf = base.substring(slash + 1);
        for (String verb : verbs) {
            if (leaf.equalsIgnoreCase(verb)) continue;
            out.add(prefix + verb + "/");    // trailing-slash form first (DRF/Django default)
            out.add(prefix + verb);          // then the no-slash form
        }
        return new ArrayList<>(out);
    }

    /** Find a login form (one password field), submit the given creds, verify + publish on success. */
    private boolean loginWith(AuthSession s, String user, String pass) {
        String[] lf = findLoginForm(s);                  // {formBlock, pageUrl}
        if (lf == null) return false;
        String form = lf[0], pageUrl = lf[1];
        String action = resolveAction(form, pageUrl);
        HttpRequestResponse resp = s.postForm(action, buildBody(form, user, pass, /*forLogin*/true, null));
        if (!verifyAuthenticated(s)) return false;
        s.publishTo(session, urlOf(resp, pageUrl), pageUrl, user, pass);   // login redirect's final url = real entry
        return true;
    }

    // ================================================================= weaken + init posture
    /**
     * Submit any "create/reset database" form on the authenticated surface (once), so an app whose
     * data store must be initialized is primed. Generic — driven by the button's visible text.
     */
    public int initDataStores() {
        AuthSession s = new AuthSession(api, host);
        s.seedFrom(session);
        int inited = 0;
        for (String url : pagesWithResetButton()) {
            HttpRequestResponse rr = s.get(url);                 // fresh → current CSRF token
            String form = firstFormWithResetButton(bodyOf(rr));
            if (form == null) continue;
            String action = resolveAction(form, urlOf(rr, url));
            s.postForm(action, buildBody(form, null, null, false, null));   // reset button included by buildBody
            inited++;
            scanLog.log("[AI Scanner] posture: submitted create/reset-data form via " + action);
        }
        if (inited > 0) s.publishTo(session, session.landingUrl(), null, null, null);
        return inited;
    }

    /** {pageUrl, selectName} of the first "security/difficulty" selector on the surface, else null. */
    public String[] securitySelector() {
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null || !sameHost(rr.request().url())) continue;
            for (String form : allForms(safeBody(rr))) {
                String[] sel = findSecuritySelect(form);
                if (sel != null) return new String[]{stripFragment(rr.request().url()), sel[0]};
            }
        }
        return null;
    }

    /** Every option value a named selector offers (fresh fetch, DOM order preserved, de-duplicated). */
    public List<String> optionValues(String pageUrl, String selectName) {
        List<String> out = new ArrayList<>();
        AuthSession s = new AuthSession(api, host);
        s.seedFrom(session);
        String form = firstFormWithSecuritySelect(bodyOf(s.get(pageUrl)));
        if (form == null) return out;
        Matcher sm = Pattern.compile("(?is)<select\\b[^>]*\\bname\\s*=\\s*['\"]?" + Pattern.quote(selectName)
                + "['\"]?[^>]*>(.*?)</select>").matcher(form);
        if (sm.find()) {
            Matcher om = Pattern.compile("(?is)<option\\b([^>]*)>([^<]*)").matcher(sm.group(1));
            while (om.find()) {
                String v = attr("<option " + om.group(1) + ">", "value");
                String t = om.group(2) == null ? "" : om.group(2).trim();
                String val = (v == null || v.isBlank()) ? t : v;
                if (!val.isBlank() && !out.contains(val)) out.add(val);
            }
        }
        return out;
    }

    /** Set a security selector to a specific option value (fresh CSRF token); publishes the new cookie. */
    public boolean applySecurity(String pageUrl, String selectName, String value) {
        AuthSession s = new AuthSession(api, host);
        s.seedFrom(session);
        HttpRequestResponse rr = s.get(pageUrl);
        String form = firstFormWithSecuritySelect(bodyOf(rr));
        if (form == null) return false;
        String action = resolveAction(form, urlOf(rr, pageUrl));
        s.postForm(action, buildBody(form, null, null, false, new String[]{selectName, value}));
        s.publishTo(session, session.landingUrl(), null, null, null);
        scanLog.log("[AI Scanner] posture: set '" + selectName + "'=" + value + " via " + action);
        return true;
    }

    private Set<String> pagesWithResetButton() {
        Set<String> pages = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null || !sameHost(rr.request().url())) continue;
            String body = safeBody(rr);
            if (body.isEmpty()) continue;
            for (String form : allForms(body)) {
                if (hasResetButton(form)) { pages.add(stripFragment(rr.request().url())); break; }
            }
        }
        return pages;
    }

    // ================================================================= form location
    private String[] findRegistrationForm(AuthSession s) {
        HttpRequestResponse r0 = s.get(seedUrl);
        String b0 = bodyOf(r0);
        String base0 = urlOf(r0, seedUrl);
        String direct = firstFormWith(b0, 2);
        if (direct != null) return new String[]{direct, base0};
        String link = firstLinkMatching(b0, REGISTER);
        if (link != null) {
            String url = resolve(base0, link);
            HttpRequestResponse r1 = s.get(url);
            String rb = bodyOf(r1);
            String f1 = firstFormWith(rb, 2);
            // Minimal register forms have a SINGLE password field (email + password, no confirm) — e.g. Pixi.
            // Safe to accept a 1-password form HERE because we arrived via a register/sign-up link, so it's
            // the registration form, not the login form.
            if (f1 == null) f1 = firstFormWith(rb, 1);
            if (f1 != null) return new String[]{f1, urlOf(r1, url)};
        }
        return null;
    }

    private String[] findLoginForm(AuthSession s) {
        HttpRequestResponse r0 = s.get(seedUrl);
        String b0 = bodyOf(r0);
        String base0 = urlOf(r0, seedUrl);
        String f = firstFormWith(b0, 1);
        if (f != null) return new String[]{f, base0};
        // follow a login-ish link if the seed didn't render the form directly
        String link = firstLinkMatching(b0, Pattern.compile("(?i)log.?in|sign.?in|signin"));
        if (link != null) {
            String url = resolve(base0, link);
            HttpRequestResponse r1 = s.get(url);
            String f1 = firstFormWith(bodyOf(r1), 1);
            if (f1 != null) return new String[]{f1, urlOf(r1, url)};
        }
        return null;
    }

    /**
     * Generic session oracle: fetch the seed authenticated and decide we're in iff it is NOT a login
     * page (no password form, URL isn't a login path) AND a logout affordance is visible (or, failing
     * that, we at least hold a session cookie). The HTTP status is deliberately NOT gated on 200 — some
     * apps 404 the bare context path once logged in (e.g. WebGoat's /WebGoat/ → 404 with a logout nav),
     * which is still a clear "authenticated" signal.
     */
    private boolean verifyAuthenticated(AuthSession s) {
        // Retry through transient flakiness (a freshly-started app can bounce the first few requests to
        // login/error before it is fully warmed up); a real auth failure just fails all attempts.
        for (int attempt = 0; attempt < 3; attempt++) {
            HttpRequestResponse rr = s.get(seedUrl);
            if (rr != null && rr.response() != null) {
                String url = urlOf(rr, seedUrl).toLowerCase();
                String b = bodyOf(rr);
                boolean onLogin = url.matches("(?i).*(login|signin|sign-in).*") || PW_INPUT.matcher(b).find();
                boolean logout = LOGOUT.matcher(b).find();
                if (!onLogin && (logout || !s.cookieHeader().isBlank())) return true;
            }
            try { Thread.sleep(2000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        return false;
    }

    // ================================================================= form body building
    /**
     * Build an x-www-form-urlencoded body for a form. Rules (generic): password inputs → pass; the
     * user-ish text field → user; hidden inputs preserved; checkboxes checked (value or "on"); a
     * &lt;select&gt; → its first option, unless {@code forceSelect}={name,value} overrides one; submit
     * buttons included only when there is no separate primary action (register/login skip them, but a
     * reset form needs its submit name=value, so we include submit inputs whose value looks like a
     * data-reset action). For login we set only user+pass and drop extra password fields.
     */
    private String buildBody(String form, String user, String pass, boolean forLogin, String[] forceSelect) {
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        int pwSeen = 0;
        Matcher m = TAG.matcher(form);
        while (m.find()) {
            String tag = m.group();
            String tagName = m.group(1).toLowerCase();
            String name = attr(tag, "name");
            if (name == null || name.isBlank()) continue;
            String type = lower(attr(tag, "type"));
            String value = attr(tag, "value");

            if (tagName.equals("select")) {
                String chosen = (forceSelect != null && forceSelect[0].equalsIgnoreCase(name))
                        ? forceSelect[1] : firstOptionValue(form, name);
                if (chosen != null) fields.put(name, chosen);
                continue;
            }
            if (tagName.equals("button")) {                       // submit-like
                if (forceSelect != null || RESET_BTN.matcher(value == null ? "" : value).find() || RESET_BTN.matcher(stripTags(tag)).find())
                    fields.put(name, value == null ? "" : value);
                continue;
            }
            // <input ...>
            switch (type == null ? "text" : type) {
                case "password":
                    if (forLogin && pwSeen >= 1) break;           // login: only the first password field
                    fields.put(name, pass == null ? "" : pass);
                    pwSeen++;
                    break;
                case "hidden":
                    fields.put(name, value == null ? "" : value);
                    break;
                case "checkbox":
                case "radio":
                    fields.put(name, value == null || value.isBlank() ? "on" : value);
                    break;
                case "submit":
                case "image":
                case "button":
                case "reset":
                    // Include a submit's name=value when it TRIGGERS the action: a data-reset submit
                    // (RESET_BTN), OR a forced-select config submit. Many apps gate the change on
                    // isset($_POST[submitName]) — e.g. DVWA's seclev_submit: without it the security
                    // level never changes and the whole audit silently runs at the default (impossible).
                    if (forceSelect != null || RESET_BTN.matcher(value == null ? "" : value).find())
                        fields.put(name, value == null ? "" : value);
                    break;
                default:  // text / email / tel / number / etc.
                    if (user != null && USER_FIELD.matcher(name).matches() && !fields.containsValue(user))
                        fields.put(name, user);
                    else
                        fields.put(name, value == null ? "" : value);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(enc(e.getKey())).append('=').append(enc(e.getValue()));
        }
        return sb.toString();
    }

    // ================================================================= small generic helpers
    private static List<String> allForms(String html) {
        List<String> out = new ArrayList<>();
        Matcher m = FORM.matcher(html);
        while (m.find()) out.add(m.group());
        return out;
    }

    /** First form whose count of password inputs equals {@code pwCount} (1=login, 2=register). */
    /** True if a form has an email input (type=email, or a name containing email/mail). */
    private static boolean hasEmailField(String form) {
        Matcher m = TAG.matcher(form);
        while (m.find()) {
            String tag = m.group();
            if (!"input".equalsIgnoreCase(m.group(1))) continue;
            String type = lower(attr(tag, "type"));
            String name = lower(attr(tag, "name"));
            if ("email".equals(type)) return true;
            if (name != null && (name.contains("email") || name.contains("mail"))) return true;
        }
        return false;
    }

    private static String firstFormWith(String html, int pwCount) {
        for (String f : allForms(html)) if (countMatches(PW_INPUT, f) == pwCount) return f;
        // fall back: >=pwCount (registration may add a 3rd hidden password-strength field, etc.)
        for (String f : allForms(html)) if (countMatches(PW_INPUT, f) >= pwCount) return f;
        return null;
    }

    private static String firstFormWithSecuritySelect(String html) {
        for (String f : allForms(html)) if (findSecuritySelect(f) != null) return f;
        return null;
    }

    private static String firstFormWithResetButton(String html) {
        for (String f : allForms(html)) if (hasResetButton(f)) return f;
        return null;
    }

    /** Returns {selectName, lowestOptionValue} if the form has a security/difficulty selector, else null. */
    private static String[] findSecuritySelect(String form) {
        Matcher sm = Pattern.compile("(?is)<select\\b[^>]*\\bname\\s*=\\s*['\"]?([^'\" >]+)['\"]?[^>]*>(.*?)</select>").matcher(form);
        while (sm.find()) {
            String name = sm.group(1);
            if (!SEC_SELECT.matcher(name).matches()) continue;
            String block = sm.group(2);
            String lowest = null, first = null;
            Matcher om = Pattern.compile("(?is)<option\\b([^>]*)>([^<]*)").matcher(block);
            while (om.find()) {
                String val = attr("<option " + om.group(1) + ">", "value");   // prefer the value attribute
                String text = om.group(2) == null ? "" : om.group(2).trim();
                if (val == null || val.isBlank()) val = text;
                if (first == null) first = val;
                if (LOW_OPTION.matcher(val.trim()).matches() || LOW_OPTION.matcher(text).matches()) { lowest = val; break; }
            }
            String chosen = lowest != null ? lowest : first;
            if (chosen != null) return new String[]{name, chosen};
        }
        return null;
    }

    private static boolean hasResetButton(String form) {
        Matcher m = Pattern.compile("(?is)<(input|button)\\b[^>]*>(?:([^<]*)</button>)?").matcher(form);
        while (m.find()) {
            String tag = m.group();
            String type = lower(attr(tag, "type"));
            boolean submitLike = "submit".equals(type) || "image".equals(type) || tag.toLowerCase().startsWith("<button");
            if (!submitLike) continue;
            String v = attr(tag, "value");
            String text = m.group(2);
            if ((v != null && RESET_BTN.matcher(v).find()) || (text != null && RESET_BTN.matcher(text).find())) return true;
        }
        return false;
    }

    private static String firstOptionValue(String form, String selectName) {
        Matcher sm = Pattern.compile("(?is)<select\\b[^>]*\\bname\\s*=\\s*['\"]?" + Pattern.quote(selectName)
                + "['\"]?[^>]*>(.*?)</select>").matcher(form);
        if (sm.find()) {
            Matcher om = Pattern.compile("(?is)<option\\b([^>]*)>([^<]*)").matcher(sm.group(1));
            if (om.find()) {
                String v = attr("<option " + om.group(1) + ">", "value");
                return (v == null || v.isBlank()) ? (om.group(2) == null ? "" : om.group(2).trim()) : v;
            }
        }
        return null;
    }

    private String firstLinkMatching(String html, Pattern textOrHref) {
        Matcher m = A_LINK.matcher(html);
        while (m.find()) {
            String href = m.group(1);
            String text = stripTags(m.group(2));
            if (href == null || href.isBlank() || href.startsWith("#") || href.startsWith("javascript:")) continue;
            if (textOrHref.matcher(text).find() || textOrHref.matcher(href).find()) return href;
        }
        return null;
    }

    private int[] parseLengthConstraint(String body) {
        Matcher r = RANGE.matcher(body);
        if (r.find()) {
            if (r.group(1) != null) return new int[]{Integer.parseInt(r.group(1)), Integer.parseInt(r.group(2))};
            return new int[]{Integer.parseInt(r.group(3)), Integer.parseInt(r.group(4))};
        }
        int min = -1, max = -1;
        Matcher mn = MIN_LEN.matcher(body); if (mn.find()) min = Integer.parseInt(mn.group(1));
        Matcher mx = MAX_LEN.matcher(body); if (mx.find()) max = Integer.parseInt(mx.group(1));
        if (min < 0 && max < 0) return null;
        return new int[]{min < 0 ? 1 : min, max < 0 ? Math.max(min, 12) : max};
    }

    /** Return {@code base} adjusted to satisfy a [min,max] length (pad with digits / truncate). */
    private static String fitLength(String base, int min, int max) {
        if (min < 0) min = 1;
        if (max < min) max = min;
        String v = base;
        if (v.length() > max) v = v.substring(0, max);
        StringBuilder sb = new StringBuilder(v);
        int d = 0;
        while (sb.length() < min) sb.append((char) ('0' + (d++ % 10)));
        return sb.toString();
    }

    // ---- attribute / url utilities ----
    private String resolveAction(String form, String pageUrl) {
        String tag = form.substring(0, form.indexOf('>') + 1);
        String action = attr(tag, "action");
        try {
            if (action == null || action.isBlank() || action.equals("#")) return stripFragment(pageUrl);
            return stripFragment(URI.create(pageUrl).resolve(action).toString());
        } catch (Exception e) {
            return stripFragment(pageUrl);
        }
    }

    private String resolve(String base, String ref) {
        try { return URI.create(base).resolve(ref).toString(); } catch (Exception e) { return ref; }
    }

    private static String attr(String tag, String name) {
        Matcher m = Pattern.compile("(?is)\\b" + Pattern.quote(name) + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").matcher(tag);
        if (!m.find()) return null;
        if (m.group(2) != null) return m.group(2);
        if (m.group(3) != null) return m.group(3);
        return m.group(4);
    }

    private static int countMatches(Pattern p, String s) {
        Matcher m = p.matcher(s); int n = 0; while (m.find()) n++; return n;
    }

    private static String stripTags(String s) { return s == null ? "" : s.replaceAll("(?is)<[^>]*>", "").trim(); }
    private static String lower(String s) { return s == null ? null : s.toLowerCase(); }
    private static String enc(String v) { return URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8); }
    private static String stripFragment(String u) { int i = u == null ? -1 : u.indexOf('#'); return i < 0 ? u : u.substring(0, i); }
    private boolean sameHost(String url) { try { return host.equalsIgnoreCase(URI.create(url).getHost()); } catch (Exception e) { return false; } }

    private static String bodyOf(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : ""; } catch (Exception e) { return ""; }
    }
    private static String safeBody(HttpRequestResponse rr) { return bodyOf(rr); }
    private static String urlOf(HttpRequestResponse rr, String fallback) {
        try { return rr != null && rr.request() != null ? rr.request().url() : fallback; } catch (Exception e) { return fallback; }
    }

    private static String arg(String prop, String env) {
        String v = System.getProperty(prop);
        if (v == null || v.isBlank()) v = System.getenv(env);
        return (v == null || v.isBlank()) ? null : v.trim();
    }
}
