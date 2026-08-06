package com.ioactive.aiscanner.scan;

/**
 * Holds a captured authenticated session (a Cookie header value) so our attack
 * requests can be sent authenticated after a successful default-credentials login.
 */
public final class SessionStore {
    private volatile String cookieHeader = "";
    private volatile String landingUrl = "";   // where the app sent us right after a successful login

    public boolean has() { return !cookieHeader.isBlank(); }
    public String cookieHeader() { return cookieHeader; }
    public void set(String c) { this.cookieHeader = c == null ? "" : c.trim(); }

    // Bearer/JWT captured from a token-based (SPA/API) login → attached as Authorization on attacks.
    private volatile String bearer = "";
    public boolean hasBearer() { return !bearer.isBlank(); }
    public String bearer() { return bearer; }
    public void setBearer(String t) { this.bearer = t == null ? "" : t.trim(); }

    // Per-request HMAC signing key captured alongside the bearer from a token-based login/verify response
    // (e.g. `data.signing_key`). When present, the app gates its protected API behind a request signature
    // (X-Signature/X-Timestamp) computed with this key — see RequestSigner. Without it, a valid bearer alone
    // gets "Missing request signature" and the deep authenticated surface stays closed.
    private volatile String signingKey = "";
    public boolean hasSigningKey() { return !signingKey.isBlank(); }
    public String signingKey() { return signingKey; }
    public void setSigningKey(String k) { this.signingKey = k == null ? "" : k.trim(); }

    /** Authenticated by either mechanism (cookie session or bearer token). */
    public boolean authenticated() { return has() || hasBearer(); }

    /** Absolute URL the login redirected to — the seed for the authenticated re-crawl. "" if unknown. */
    public String landingUrl() { return landingUrl; }
    public void setLandingUrl(String u) { this.landingUrl = u == null ? "" : u.trim(); }

    // Winning login, remembered so we can re-authenticate if Burp's crawl logs us out mid-scan.
    private volatile String loginPageUrl = "", loginUser = "", loginPass = "";
    public void rememberLogin(String pageUrl, String user, String pass) {
        this.loginPageUrl = pageUrl == null ? "" : pageUrl;
        this.loginUser = user == null ? "" : user;
        this.loginPass = pass == null ? "" : pass;
    }
    public boolean canReauth() { return !loginPageUrl.isBlank(); }
    public String loginPageUrl() { return loginPageUrl; }
    public String loginUser() { return loginUser; }
    public String loginPass() { return loginPass; }

    /** Clear ALL captured session state — call between targets in a batch run so one host's auth (cookie/
     *  bearer/login) never bleeds into the next scan. */
    public void reset() {
        cookieHeader = ""; landingUrl = ""; bearer = ""; signingKey = "";
        loginPageUrl = ""; loginUser = ""; loginPass = "";
    }
}
