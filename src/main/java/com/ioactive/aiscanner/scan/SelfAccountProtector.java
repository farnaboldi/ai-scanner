package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Scanner-wide SESSION SELF-PRESERVATION guard. Deliberately-vulnerable apps routinely expose the logged-in user's
 * OWN account as a mass-assignable / deletable endpoint (e.g. {@code POST /users/{me}} → change password/email/
 * username, {@code DELETE /users/{me}}). Any phase that exercises it with synthetic values — Burp's native audit,
 * our endpoint-discovery LIVE form-exercise, or any probe — silently RESETS or DELETES the very credentials we
 * logged in with, after which every later authenticated request bounces to {@code /login} and the deep surface
 * (BOLA, OAuth flow, authenticated XSS…) is missed. Per-phase guards are whack-a-mole; a single Montoya
 * {@link HttpHandler} sees ALL outgoing traffic, so it is the one reliable chokepoint.
 *
 * <p>A STATE-CHANGING request whose path carries OUR OWN identity (per {@link SessionStore#mutatesOwnAccount}) is
 * neutralized to a harmless {@code GET} (a read, not a write) so nothing can lock us out. Requests to OTHER
 * identities are untouched — those are legitimate cross-user IDOR/BOLA writes we WANT to test. The login / re-auth
 * itself (POST /login, /authenticate, …) never carries the own identity in its path, so it is never neutralized.
 * Generic — keyed on the captured own identity, no app-specific path or field.
 */
public final class SelfAccountProtector implements HttpHandler {

    // All authenticated identities to protect. A single-target scan registers one; a PARALLEL run adds one per target
    // (each has its own ownIdentity). A request is neutralized if it mutates ANY of them — the check is keyed on the
    // identity in the PATH, so only the session whose own handle actually appears in the path can match.
    private final java.util.Set<SessionStore> sessions = new java.util.concurrent.CopyOnWriteArraySet<>();
    private final ScanLog scanLog;
    private final AtomicInteger neutralized = new AtomicInteger();

    public SelfAccountProtector(MontoyaApi api, SessionStore session, ScanLog scanLog) {
        if (session != null) this.sessions.add(session);
        this.scanLog = scanLog;
        api.http().registerHttpHandler(this);
    }

    /** Register an additional identity to protect (a parallel target's own session). */
    public void addSession(SessionStore s) { if (s != null) sessions.add(s); }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            for (SessionStore session : sessions) {
                if (session.mutatesOwnAccount(req.method(), req.pathWithoutQuery())) {
                    int n = neutralized.incrementAndGet();
                    if (n <= 12) scanLog.debug("  self-account protector: neutralized " + req.method()
                            + " " + req.pathWithoutQuery() + " → GET (protects our own login)");
                    return RequestToBeSentAction.continueWith(req.withMethod("GET").withBody(""));
                }
            }
        } catch (Throwable ignore) { /* never break traffic over a guard error */ }
        return RequestToBeSentAction.continueWith(req);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        return ResponseReceivedAction.continueWith(resp);   // observe only
    }
}
