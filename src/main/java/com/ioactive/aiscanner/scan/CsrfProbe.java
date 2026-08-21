package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * Cross-Site Request Forgery probe — generic, no app-specific paths, CONFIRMED by replay (not a guess).
 * CSRF is exploitable only for a request a cross-site page can actually forge, so the oracle is tightly scoped:
 * a state-changing {@code POST} that is (1) FORM-encoded (application/x-www-form-urlencoded / multipart /
 * text-plain — JSON/XML need a CORS preflight a form can't send), (2) COOKIE-authenticated (carries a session
 * cookie, NOT an Authorization/bearer header — bearer auth is not CSRF-able), (3) not an auth endpoint, and (4)
 * whose session cookie is NOT SameSite=Strict/Lax (a browser would refuse to send it cross-site otherwise).
 *
 * <p>It then FORGES the request the way a cross-site attacker would: keep the victim's session cookie, but strip
 * any anti-CSRF token parameter and every header a simple form can't set (Origin, Referer, X-*, Sec-Fetch-*,
 * X-CSRF-Token). If the server STILL accepts it, there is no server-side CSRF defense (no token enforced, Origin
 * not checked) → CWE-352. A CSRF-protected server answers the forged request with 401/403 / a login redirect /
 * a token error, so it never fires there. Zero-FP: the acceptance of a genuinely-forgeable request IS the proof.
 * Intrusive by nature (it re-issues the state-changing action) — for authorized targets.
 */
public final class CsrfProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    private static final Pattern CSRF_TOKEN = Pattern.compile(
            "(?i)(csrf|xsrf|authenticity_?token|__requestverificationtoken|anti.?forgery|request.?verification|nonce|_token$|(^|_)token$)");
    private static final Pattern SESSION_COOKIE = Pattern.compile(
            "(?i)(jsessionid|phpsessid|asp\\.net_sessionid|connect\\.sid|session|sess|sid|auth|csrftoken)");
    private static final Pattern FORM_CT = Pattern.compile(
            "(?i)(application/x-www-form-urlencoded|multipart/form-data|text/plain)");
    private static final Pattern AUTHY = Pattern.compile(
            "(?i).*/(login|log-?in|signin|sign-?in|logout|log-?out|signout|sign-?out|authenticate|register|sign-?up|sso|oauth)(\\b|/|\\.|$).*");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    // headers a cross-site attacker CANNOT set on a simple form request → strip them to simulate the forgery.
    private static final Pattern STRIP_HDR = Pattern.compile(
            "(?i)^(origin|referer|sec-fetch-.*|x-.*|x-requested-with|x-csrf-token|x-xsrf-token)$");

    public CsrfProbe(MontoyaApi api, ScanLog scanLog) { this.api = api; this.scanLog = scanLog; }

    /** {@code sessionApplier}: the SAME live-session accessor every other authed probe uses (attaches the current
     *  session cookie/bearer to a request). Applying it fresh per forge — instead of a cookie string snapshotted
     *  once at phase start — is what makes authenticated, state-changing endpoints actually reachable at forge time
     *  (a snapshot can go stale between phases). {@code formTargets}: state-changing form requests discovered this
     *  scan (e.g. the derived /bank/* POSTs), tested DIRECTLY — independent of Burp's async audit having sent them
     *  into the site map yet — so the finding emits promptly even on a high-latency target. The site map is also
     *  scanned for any POSTs already sent (superset); results are de-duplicated by URL. */
    public int probe(String host, UnaryOperator<HttpRequest> sessionApplier, List<HttpRequest> formTargets) {
        int hits = 0;
        if (sessionApplier == null) return 0;
        // need a live COOKIE session to demonstrate a browser-forgeable request
        HttpRequest liveProbe = sessionApplier.apply(HttpRequest.httpRequestFromUrl("http://" + host + "/").withMethod("GET"));
        if (!hasHeader(liveProbe, "Cookie")) return 0;
        try {
            boolean sameSiteProtected = sessionCookieSameSiteProtected(host);
            Set<String> fired = new LinkedHashSet<>();
            java.util.LinkedHashMap<String, String> whyBy = new java.util.LinkedHashMap<>();
            java.util.LinkedHashMap<String, HttpRequestResponse> evBy = new java.util.LinkedHashMap<>();
            if (formTargets != null)
                for (HttpRequest t : formTargets) tryCsrf(host, t, sessionApplier, sameSiteProtected, fired, whyBy, evBy);
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                tryCsrf(host, rr.request(), sessionApplier, sameSiteProtected, fired, whyBy, evBy);
            }
            hits = emitCsrf(host, whyBy, evBy);
        } catch (Throwable t) {
            scanLog.debug("CSRF probe error: " + t);
        }
        return hits;
    }

    private static final int CSRF_CAP = 5;   // above this many CSRF-able endpoints it's an app-wide gap, not N bugs

    /** Emit CSRF findings, collapsing a FLOOD into one systemic finding. Apps that ship no anti-CSRF framework
     *  (WebGoat by design, many bearer-less MPAs) make EVERY cookie-auth POST forgeable — reporting N of them is
     *  noise. Below the cap, emit each (genuine handful); above it, emit ONE "no app-wide anti-CSRF protection". */
    private int emitCsrf(String host, java.util.Map<String, String> whyBy, java.util.Map<String, HttpRequestResponse> evBy) {
        int n = whyBy.size();
        if (n == 0) return 0;
        if (n <= CSRF_CAP) {
            for (java.util.Map.Entry<String, String> e : whyBy.entrySet()) {
                scanLog.found("Cross-Site Request Forgery (CSRF)", e.getKey(), e.getValue()
                        + " (CWE-352). Confirmed by replaying a forged request (token stripped, Origin/Referer/X-* removed) that still succeeded.",
                        evBy.get(e.getKey()));
                scanLog.incFinding();
            }
            return n;
        }
        java.util.List<String> keys = new ArrayList<>(whyBy.keySet());
        String examples = String.join(", ", keys.subList(0, Math.min(5, keys.size())));
        HttpRequestResponse ev = evBy.values().iterator().next();
        scanLog.found("Cross-Site Request Forgery (CSRF) — no app-wide anti-CSRF protection", "http://" + host + "/",
                n + " cookie-authenticated, state-changing endpoints accept a cross-site-forged request (token stripped, "
                + "Origin/Referer removed): the application enforces no anti-CSRF tokens app-wide (CWE-352). Reported as ONE "
                + "systemic finding, not " + n + " — examples: " + examples + " …", ev);
        scanLog.incFinding();
        return 1;
    }

    /** Full CSRF test on ONE request: filter to a forgeable cookie-auth form POST, apply the LIVE session, then
     *  FORGE it the way a cross-site page would — keep the session cookie, but strip the anti-CSRF token param(s),
     *  every header a simple form can't set (Origin/Referer/X-* and Sec-Fetch), AND any Authorization (a form can't set
     *  it, so a bearer-only endpoint is not CSRF-able). If the server still accepts it, the action is cross-site-
     *  forgeable (CWE-352). The forgery being accepted IS the proof (zero-FP). De-dups by URL via {@code fired}. */
    private boolean tryCsrf(String host, HttpRequest req, UnaryOperator<HttpRequest> sessionApplier, boolean sameSiteProtected,
                            Set<String> fired, java.util.Map<String, String> whyBy, java.util.Map<String, HttpRequestResponse> evBy) {
        if (req == null || !"POST".equalsIgnoreCase(req.method())) return false;
        String url = req.url();
        if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches() || AUTHY.matcher(url).find()) return false;
        String key = Net.stripQuery(url);
        if (fired.contains(key)) return false;

        // cookie-authenticated, NOT header/bearer-authenticated (bearer auth is not CSRF-able)
        if (hasHeader(req, "Authorization")) return false;

        // form content-type (forgeable); JSON/XML are CORS-preflight-protected
        String ctl = ctLower(req);
        if (ctl.contains("json") || ctl.contains("xml")) return false;
        boolean form = FORM_CT.matcher(ctl).find();
        String body = req.bodyToString();
        if (!form && ctl.isBlank() && body != null && body.matches("(?s)[^={}\\[\\]\\s]+=[^&]*(&[^=&]+=[^&]*)*")) form = true;
        if (!form) return false;

        // SameSite guard: a Strict/Lax session cookie is not sent cross-site → not exploitable
        if (sameSiteProtected) return false;

        // Apply the LIVE session (fresh cookie), then FORGE.
        HttpRequest forged = sessionApplier.apply(req);
        if (!hasHeader(forged, "Cookie")) return false;              // no live cookie session → can't forge
        List<HttpParameter> tokens = new ArrayList<>();
        for (ParsedHttpParameter p : req.parameters()) {
            if ((p.type() == HttpParameterType.BODY || p.type() == HttpParameterType.URL)
                    && CSRF_TOKEN.matcher(p.name()).find())
                tokens.add(HttpParameter.parameter(p.name(), p.value(), p.type()));
        }
        boolean hadToken = !tokens.isEmpty();
        if (hadToken) forged = forged.withRemovedParameters(tokens.toArray(new HttpParameter[0]));
        if (hasHeader(forged, "Authorization")) forged = forged.withRemovedHeader("Authorization");
        for (HttpHeader h : req.headers()) {
            if (STRIP_HDR.matcher(h.name()).matches() || CSRF_TOKEN.matcher(h.name()).find())
                forged = forged.withRemovedHeader(h.name());
        }

        HttpRequestResponse forgedRr = send(forged);
        scanLog.debug("CSRF candidate POST " + key + " → forged HTTP " + status(forgedRr)
                + (forgedRr != null && forgedRr.response() != null && forgedRr.response().hasHeader("Location")
                        ? " loc=" + forgedRr.response().headerValue("Location") : "")
                + " accepted=" + forgedAccepted(forgedRr));
        if (!forgedAccepted(forgedRr)) return false;                 // server rejected the forgery → protected

        fired.add(key);
        String why = hadToken
                ? "the POST carries an anti-CSRF token, but the server STILL accepts it with the token removed "
                  + "and no Origin/Referer — the token is not enforced"
                : "a cookie-authenticated, state-changing POST has NO anti-CSRF token and the server accepts it "
                  + "with no Origin/Referer — a cross-site page can forge the action";
        whyBy.put(key, why);        // collect; emitCsrf() decides per-URL vs one systemic finding (anti-flood)
        evBy.put(key, forgedRr);
        return true;
    }

    /** Accepted = the forged (tokenless, Origin-less) request was processed: 2xx, or a redirect NOT to login/error,
     *  and no auth/CSRF rejection in the body. A CSRF-protected server answers 401/403 / login-redirect / token error. */
    private static boolean forgedAccepted(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        int st = rr.response().statusCode();
        if (st == 401 || st == 403 || st >= 500) return false;
        String bl = rr.response().bodyToString();
        bl = bl == null ? "" : bl.toLowerCase();
        if (bl.contains("csrf") || bl.contains("forbidden") || bl.contains("invalid token")
                || bl.contains("access denied") || bl.contains("not authorized") || bl.contains("please log in")
                // the forged (wrong-content-type / token-stripped) request was REJECTED, not processed — a framework
                // validation/error envelope is NOT a forged action, so it must not count as "accepted".
                || bl.contains("invalid web service call") || bl.contains("missing value for parameter")
                || bl.contains("an error has occurred") || bl.contains("exceptionmessage") || bl.contains("\"stacktrace\"")) return false;
        // An EMPTY 2xx body is NOT proof of a processed action: an endpoint that only accepts a specific content-type
        // (e.g. a JSON page-method) silently IGNORES a form-encoded, browser-forgeable body and answers an empty 200.
        // A genuinely forged state change returns evidence — a rendered page / JSON result / success redirect. Require
        // non-empty content so an ignored-request 200 can't be mistaken for a CSRF (keeps the oracle zero-FP).
        if (st >= 200 && st < 300) return !bl.isBlank();
        if (st >= 300 && st < 400) {
            String loc = rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : "";
            return loc == null || !loc.toLowerCase().matches("(?s).*(login|signin|error|denied|unauthor).*");
        }
        return false;
    }

    /** True if a session-looking cookie is set SameSite=Strict/Lax anywhere in the site map (browser blocks the
     *  cross-site send → CSRF not exploitable). Conservative: any such Set-Cookie suppresses the finding. */
    private boolean sessionCookieSameSiteProtected(String host) {
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                for (HttpHeader h : rr.response().headers()) {
                    if (!"set-cookie".equalsIgnoreCase(h.name())) continue;
                    String v = h.value() == null ? "" : h.value();
                    String name = v.split("=", 2)[0].trim();
                    String lv = v.toLowerCase();
                    if (SESSION_COOKIE.matcher(name).find()
                            && (lv.contains("samesite=strict") || lv.contains("samesite=lax"))) return true;
                }
            }
        } catch (Throwable ignore) { }
        return false;
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)); }
        catch (Throwable t) { return null; }
    }
    private static boolean hasHeader(HttpRequest r, String n) { try { return r.hasHeader(n); } catch (Throwable t) { return false; } }
    private static String headerValue(HttpRequest r, String n) { try { return r.hasHeader(n) ? r.headerValue(n) : null; } catch (Throwable t) { return null; } }
    private static String ctLower(HttpRequest r) { String c = headerValue(r, "Content-Type"); return c == null ? "" : c.toLowerCase(); }
    private static int status(HttpRequestResponse rr) { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; }
    private static String hostOf(String u) { return Net.authority(u); }
}
