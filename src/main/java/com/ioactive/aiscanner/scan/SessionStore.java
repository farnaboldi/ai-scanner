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
    public void set(String c) {
        String incoming = c == null ? "" : c.trim();
        // DON'T DOWNGRADE a real session: if we already hold a genuine session cookie (a NON-CSRF cookie, e.g.
        // sessionid) and the incoming value has none (a later/weaker auth pass that only re-grabbed csrftoken),
        // keep the good one. A successful form-login captured sessionid; a subsequent pass must not clobber it back
        // to csrftoken-only, which would silently de-authenticate the whole scan.
        boolean downgrade = !incoming.isEmpty() && hasRealSessionCookie(this.cookieHeader) && !hasRealSessionCookie(incoming);
        if (downgrade) return;
        this.cookieHeader = incoming;
        // Propagate the captured session to Burp's cookie jar too, so the NATIVE crawler + active audit send it —
        // not only our own withSessionCookie() requests. Without this, auth-gated pages come back as empty 302s to
        // the native crawl (labs behind login never get discovered) and POSTs 403 (missing session/CSRF cookie).
        if (!cookieHeader.isEmpty() && onCookieUpdate != null) {
            try { onCookieUpdate.accept(cookieHeader); } catch (Throwable ignore) { }
        }
    }
    /** True when the header carries a cookie that ISN'T a CSRF/anti-forgery token — i.e. a genuine session cookie. */
    private static boolean hasRealSessionCookie(String header) {
        if (header == null) return false;
        for (String kv : header.split(";")) {
            int eq = kv.indexOf('=');
            String name = (eq > 0 ? kv.substring(0, eq) : kv).trim();
            if (!name.isEmpty() && !com.ioactive.aiscanner.scan.AuthenticatedExplorer.isCsrfParam(name)) return true;
        }
        return false;
    }
    /** Sink invoked whenever the cookie session is (re)captured — wired to push the cookies into Burp's cookie jar. */
    private volatile java.util.function.Consumer<String> onCookieUpdate;
    public void setOnCookieUpdate(java.util.function.Consumer<String> s) { this.onCookieUpdate = s; }

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

    /** True when we hold a GENUINE authenticated session — a bearer, OR a cookie that isn't merely a CSRF token.
     *  {@link #has()} is true even for a csrftoken-only "session" (set on unauth GETs), which isn't real auth. */
    public boolean hasRealSession() { return hasBearer() || hasRealSessionCookie(this.cookieHeader); }

    // Set when the session was PROVIDED by the operator (adopted from the request you right-clicked, or a launch
    // -Daiscanner.cookie/.bearer) rather than obtained by our own login. Suppresses ALL auto-registration — the
    // second-identity minting + its disposable-mailbox signup — because when you hand us a session for a real
    // target we must NOT go create accounts on it.
    private volatile boolean adopted;
    public boolean adopted() { return adopted; }
    public void setAdopted(boolean v) { this.adopted = v; }

    // ---- SECOND identity B (a distinct registered user) — enables TRUE cross-user access-control differentials
    // (BOLA/BFLA/mass-assignment/GraphQL-authz): "A reads/writes B's exact object" instead of a single-session
    // distinctness+PII heuristic. Populated by a second registration pass; empty when only one identity was minted.
    private volatile String cookieHeaderB = "", bearerB = "", signingKeyB = "";
    /** This session's OWN registered handle (username/email tag from auto-registration) — lets a probe target the
     *  identity's PROVABLY-OWN object (e.g. /users/{ownIdentity}) for a rigorous cross-user test. "" if unknown. */
    private volatile String ownIdentity = "";
    public void setOwnIdentity(String v) { this.ownIdentity = v == null ? "" : v.trim(); }
    public String ownIdentity() { return ownIdentity; }
    /** True when a STATE-CHANGING request (method + path) would mutate THIS authenticated identity's OWN account —
     *  its own handle appears as a path segment (e.g. POST /users/{ownIdentity} or its email local-part). The single
     *  source of truth consulted by every request-sending phase (native audit, discovery form-exercise, probes) so
     *  none of them reset/change/delete the very credentials we logged in with — self-mutation drops the session and
     *  bounces every later authenticated request to /login. The SAME verbs against OTHER identities are allowed (those
     *  are legitimate cross-user IDOR/BOLA writes). Generic — keyed on the captured own identity, no app-specific path. */
    public boolean mutatesOwnAccount(String method, String path) {
        if (!authenticated() || ownIdentity == null || method == null || path == null) return false;
        String own = ownIdentity.trim();
        if (own.length() < 3) return false;                          // too short → avoid a spurious substring match
        String m = method.toUpperCase();
        if (m.equals("GET") || m.equals("HEAD") || m.equals("OPTIONS")) return false;
        String seg = own.contains("@") ? own.substring(0, own.indexOf('@')) : own;   // email → local-part is the usual path token
        String alt = (seg.length() >= 3 && !seg.equalsIgnoreCase(own)) ? "|" + java.util.regex.Pattern.quote(seg) : "";
        return java.util.regex.Pattern.compile("(?i)/(" + java.util.regex.Pattern.quote(own) + alt + ")(/|$)")
                .matcher(path).find();
    }
    /** Identity B's own registered handle (copied from B's session by {@link #setSecondary}). "" if unknown. */
    private volatile String identityB = "";
    public String identityB() { return identityB; }
    public boolean hasIdentityB() { return !identityB.isBlank(); }
    /** True once a second, DISTINCT authenticated identity is available. */
    public boolean hasSecondIdentity() { return !cookieHeaderB.isBlank() || !bearerB.isBlank(); }
    public String cookieHeaderB() { return cookieHeaderB; }
    public String bearerB() { return bearerB; }
    public boolean hasBearerB() { return !bearerB.isBlank(); }
    public String signingKeyB() { return signingKeyB; }
    public boolean hasSigningKeyB() { return !signingKeyB.isBlank(); }
    /** Adopt a second identity from a separate SessionStore that a second auth pass authenticated. No-op if that
     *  store isn't authenticated or duplicates identity A (same cookie AND same bearer ⇒ not a distinct user). */
    public void setSecondary(SessionStore other) {
        if (other == null || !other.authenticated()) return;
        boolean sameCookie = other.cookieHeader().equals(cookieHeader);
        boolean sameBearer = other.bearer().equals(bearer);
        if (sameCookie && sameBearer) return;   // not actually a different identity
        this.cookieHeaderB = other.cookieHeader();
        this.bearerB = other.bearer();
        this.signingKeyB = other.signingKey();
        this.identityB = other.ownIdentity();   // B's provably-own handle → target /coll/{identityB} in the rigorous BOLA test
    }

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
        cookieHeader = ""; landingUrl = ""; bearer = ""; signingKey = ""; adopted = false;
        loginPageUrl = ""; loginUser = ""; loginPass = "";
        cookieHeaderB = ""; bearerB = ""; signingKeyB = ""; ownIdentity = ""; identityB = "";
    }
}
