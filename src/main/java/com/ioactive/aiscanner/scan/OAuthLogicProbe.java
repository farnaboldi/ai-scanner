package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OAuth 2.0 authorization-server LOGIC probe. Standard injection probes miss protocol-logic flaws; this one
 * drives the actual authorization flow and checks it deterministically.
 *
 * <p><b>redirect_uri validation (CWE-601 + authorization-code/token leak).</b> A conformant authorization server
 * MUST reject a {@code redirect_uri} that is not pre-registered for the client. We drive the flow with an
 * OFF-ORIGIN sentinel redirect_uri that we choose (not the target, not any registered value); if the server ends
 * up delivering the {@code code=}/{@code access_token=} to THAT host, the redirect_uri is unvalidated — proven,
 * zero-FP, because the secret lands on a host the attacker picked. Handles both the immediate-302 form and the
 * consent-page form (extract transaction_id → POST the decision → follow to the leaked redirect).
 *
 * <p>Fully generic: the authorize endpoint, client_id, scope and response_type are all harvested from the app's
 * own observed OAuth request in the site map — no app-specific paths or values.
 */
public final class OAuthLogicProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    public OAuthLogicProbe(MontoyaApi api, ScanLog scanLog) { this.api = api; this.scanLog = scanLog; }

    // An authorization endpoint: path contains "authorize" (but not the consent-decision sub-path).
    private static final Pattern AUTHZ_PATH = Pattern.compile("(?i)/(oauth2?/)?authorize(/|$|\\?)");
    // Consent form bits.
    private static final Pattern FORM_ACTION = Pattern.compile("(?is)<form\\b[^>]*\\baction\\s*=\\s*['\"]([^'\"]*)['\"]");
    private static final Pattern HIDDEN = Pattern.compile("(?is)<input\\b[^>]*\\bname\\s*=\\s*['\"]([^'\"]+)['\"][^>]*\\bvalue\\s*=\\s*['\"]([^'\"]*)['\"]");
    // A leaked credential in the redirect (authorization code or implicit-flow token).
    private static final Pattern LEAK = Pattern.compile("(?i)[?&#](code|access_token|id_token|token)=");

    /** @return number of confirmed OAuth-logic findings. */
    public int probe(String host, UnaryOperator<HttpRequest> sess) {
        int hits = 0;
        try {
            for (String authzUrl : discoverAuthorizeRequests(host, sess)) {
                if (checkRedirectUriValidation(authzUrl, sess)) hits++;
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner] oauth-logic: " + t); }
        if (hits == 0) scanLog.log("[AI Scanner] OAuth-logic probe: 0 authorization-server flaw(s).");
        return hits;
    }

    // client_id in a URL query (client_id=x) OR a JSON/JS blob ("clientID": "x") — bridge any quotes/space around =/:
    private static final Pattern CLIENT_ID = Pattern.compile("(?i)client_?id[\"'\\s]*[=:][\"'\\s]*([A-Za-z0-9._-]{2,64})");
    // A client secret rendered in a response body (e.g. an authenticated /clients registry page that leaks it).
    private static final Pattern CLIENT_SECRET = Pattern.compile("(?i)client_?secret[\"'\\s]*[=:][\"'\\s]*([^\\s\"',}]{2,120})");
    // Well-known OAuth client-registry paths a logged-in user might list (browser-like active harvest of client_id).
    private static final String[] CLIENT_REGISTRY_PATHS = { "/clients", "/oauth/clients", "/oauth2/clients", "/api/clients" };

    /** Authorize-endpoint request URLs to drive. Primary: real OAuth authorize requests observed in the site map
     *  (they carry the client's own client_id/scope). Otherwise SYNTHESIZE one using a client_id we HARVEST like a
     *  browser would — from the URL, request body AND response body of anything crawled (a client's authorize link,
     *  an authenticated client-registry page such as /clients, an OpenID config blob), or, failing that, by actively
     *  fetching the well-known client-registry paths WITH the session (a logged-in user can usually list the OAuth
     *  clients). A client_id may also be supplied by the operator (-Daiscanner.oauthClientId / AISCANNER_OAUTH_CLIENT_ID)
     *  — it is public and usually known to the tester, same rationale as operator-supplied login creds. */
    private Set<String> discoverAuthorizeRequests(String host, UnaryOperator<HttpRequest> sess) {
        Set<String> out = new LinkedHashSet<>();
        Set<String> authzEndpoints = new LinkedHashSet<>();
        Set<String> clientIds = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.request() == null) continue;
            String u = rr.request().url();
            if (u == null || !sameHost(u, host)) continue;
            if (AUTHZ_PATH.matcher(u).find() && !u.toLowerCase().contains("/decision")) {
                if (u.contains("client_id=") || u.contains("response_type=")) out.add(u);   // real flow → replay as-is
                else authzEndpoints.add(u.split("[?#]")[0]);                                 // bare endpoint → maybe synth
            }
            // harvest client_id like a browser: from the URL, the request body, AND the response body — a client's
            // authorize link, an authenticated client-registry page (/clients), or an OpenID config blob all carry it.
            harvestClientIds(u, clientIds);
            harvestClientIds(reqBody(rr), clientIds);
            harvestClientIds(respBody(rr), clientIds);
        }
        String opCid = arg("aiscanner.oauthClientId", "AISCANNER_OAUTH_CLIENT_ID");
        if (opCid != null) clientIds.add(opCid);

        // Browser-like ACTIVE harvest: if nothing crawled surfaced a client_id, fetch the well-known client-registry
        // pages WITH the session. Many authorization servers let a logged-in user LIST the registered OAuth clients
        // (the same page a human would open). Generic convention, not app-specific; no-ops when unauthenticated (302).
        scanLog.debug("[AI Scanner] oauth-logic: passive client_id harvest = " + clientIds.size() + " from site map");
        if (clientIds.isEmpty()) {
            String origin = originOf(host);
            if (origin != null) for (String p : CLIENT_REGISTRY_PATHS) {
                // Force a SINGLE Accept: application/json (httpRequestFromUrl may already carry Accept: */*, and a
                // second added header makes Express res.format serve the HTML page — where client_id isn't key:value).
                HttpRequest req = HttpRequest.httpRequestFromUrl(origin + p).withMethod("GET")
                        .withRemovedHeader("Accept").withAddedHeader("Accept", "application/json");
                HttpRequestResponse rr = send(sess, req);
                int sc = (rr != null && rr.response() != null) ? rr.response().statusCode() : -1;
                String body = respBody(rr);
                scanLog.debug("[AI Scanner] oauth-logic: registry GET " + origin + p + " → HTTP " + sc
                        + " cookie=" + sess.apply(req).hasHeader("Cookie") + " body[" + (body == null ? 0 : body.length())
                        + "]=" + (body == null ? "" : body.replaceAll("\\s+", " ").substring(0, Math.min(90, body.length()))));
                if (sc != 200) continue;
                int before = clientIds.size();
                harvestClientIds(body, clientIds);
                if (clientIds.size() > before) {
                    scanLog.debug("[AI Scanner] oauth-logic: harvested " + (clientIds.size() - before)
                            + " client_id(s) from authenticated " + p);
                    // The registry is reachable by a logged-in (non-admin) user AND returns client secrets in
                    // cleartext → OAuth client-credential disclosure + broken access control. Deterministic.
                    if (body != null && CLIENT_SECRET.matcher(body).find()) {
                        scanLog.found("OAuth client credentials exposed via client-registry endpoint", origin + p,
                                "an authenticated user can GET " + p + " and read registered OAuth clients' "
                                + "client_secret in cleartext (broken access control + secret disclosure)", rr);
                        scanLog.incFinding();
                    }
                }
            }
        }

        // If we have a client_id but never crawled an authorize endpoint (the auth server doesn't self-link its
        // /authorize — only clients do), actively add the WELL-KNOWN authorize paths so we can still drive the flow.
        if (!clientIds.isEmpty()) {
            String origin = originOf(host);
            if (origin != null) for (String p : new String[]{ "/authorize", "/oauth/authorize", "/oauth2/authorize", "/dialog/authorize" })
                authzEndpoints.add(origin + p);
        }
        // synthesize an authorize request per (endpoint × client_id) when we have no real one to replay
        if (out.isEmpty() && !authzEndpoints.isEmpty() && !clientIds.isEmpty()) {
            // A NON-EMPTY scope: an empty scope= makes some servers 500 while parsing/rendering the consent dialog
            // (observed on dvoauth). "openid profile" is the universal OIDC default; servers that don't validate
            // scope accept it and render the grant dialog we then drive.
            for (String ep : authzEndpoints) for (String cid : clientIds) {
                out.add(ep + "?response_type=code&client_id=" + enc(cid) + "&scope=" + enc("openid profile")
                        + "&state=aisc&redirect_uri=");
                if (out.size() >= 12) break;
            }
        }
        scanLog.debug("[AI Scanner] oauth-logic: " + out.size() + " authorize target(s) ("
                + authzEndpoints.size() + " endpoint(s), " + clientIds.size() + " client_id(s))");
        return out;
    }

    /** Harvest OAuth client_id values from any text blob (URL, request body, response body). Bounded: caps the set
     *  and the bytes scanned so a huge JS bundle or site map can't blow up cost. Over-harvested junk is harmless —
     *  a bogus client_id just yields no consent page and no finding. */
    private static void harvestClientIds(String blob, Set<String> out) {
        if (blob == null || blob.isEmpty() || out.size() >= 25) return;
        String s = blob.length() > 524288 ? blob.substring(0, 524288) : blob;
        Matcher m = CLIENT_ID.matcher(s);
        while (m.find() && out.size() < 25) out.add(m.group(1));
    }
    private static String reqBody(HttpRequestResponse rr) {
        try { return rr.request() != null ? rr.request().bodyToString() : null; } catch (Exception e) { return null; }
    }
    private static String respBody(HttpRequestResponse rr) {
        try { return rr.response() != null ? rr.response().bodyToString() : null; } catch (Exception e) { return null; }
    }

    /** scheme://authority (WITH port) for the target host, from any observed same-host request. Must keep the port —
     *  synthesizing "http://localhost/authorize" (dropping :3005) sends to :80 and the whole probe silently no-ops. */
    private String originOf(String host) {
        String bareHost = host.split(":")[0];
        String portless = null;
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.request() == null) continue;
            try {
                URI u = URI.create(rr.request().url());
                if (u.getHost() == null || !u.getHost().equalsIgnoreCase(bareHost) || u.getAuthority() == null) continue;
                String o = u.getScheme() + "://" + u.getAuthority();
                if (u.getAuthority().indexOf(':') >= 0) return o;   // authority carries an explicit port → definitive
                if (portless == null) portless = o;                  // a :80/:443 request → keep only as last resort
            } catch (Exception ignore) {}
        }
        if (host.indexOf(':') >= 0) return "http://" + host;         // the host we were given already carries the port
        return portless != null ? portless : "http://" + host;       // last resort — keeps whatever we were given
    }

    private static String arg(String prop, String env) {
        String v = System.getProperty(prop);
        if (v == null || v.isBlank()) v = System.getenv(env);
        return (v == null || v.isBlank()) ? null : v.trim();
    }

    /** Drive the authorize flow with an off-origin sentinel redirect_uri; a leaked code/token to it = unvalidated. */
    private boolean checkRedirectUriValidation(String authzUrl, UnaryOperator<HttpRequest> sess) {
        // A host the attacker controls — off-origin, not the target, not any registered redirect. If the code lands
        // here the redirect_uri was not validated. Deterministic (we pick the host, we look for it in the redirect).
        String sentinelHost = "ais-oauth-redir-probe.example";
        String sentinel = "http://" + sentinelHost + "/cb";
        String url = replaceParam(authzUrl, "redirect_uri", sentinel);
        url = replaceParam(url, "state", "aischeckstate");   // set a known state so we can tell code-in-redirect apart
        scanLog.debug("[AI Scanner] oauth-logic: driving " + url);

        HttpRequest getReq = sess.apply(HttpRequest.httpRequestFromUrl(url).withMethod("GET"));
        scanLog.debug("[AI Scanner] oauth-logic: cookie sent = ["
                + (getReq.hasHeader("Cookie") ? getReq.headerValue("Cookie") : "NONE") + "]");
        HttpRequestResponse rr = send(sess, HttpRequest.httpRequestFromUrl(url).withMethod("GET"));
        if (rr == null || rr.response() == null) return false;
        scanLog.debug("[AI Scanner] oauth-logic: GET " + url + " → HTTP " + rr.response().statusCode()
                + " loc=" + (rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : "-")
                + " consent=" + (safeBody(rr) != null && safeBody(rr).toLowerCase().contains("decision")));

        // (a) immediate redirect straight to the sentinel host (implicit/relaxed servers).
        if (locationLeaksTo(rr, sentinelHost)) {
            scanLog.found("OAuth redirect_uri not validated (authorization-code/token leak)", authzUrl,
                    "redirect_uri=" + sentinel + " → server 302'd the response to the attacker-chosen host", rr);
            scanLog.incFinding();
            return true;
        }

        // (b) consent page → approve the grant, then check the post-consent redirect.
        String body = safeBody(rr);
        if (body == null || !body.toLowerCase().contains("decision")) return false;
        Matcher am = FORM_ACTION.matcher(body);
        if (!am.find()) return false;
        String action;
        try { action = URI.create(rr.request().url()).resolve(am.group(1)).toString(); } catch (Exception e) { return false; }

        StringBuilder form = new StringBuilder();
        Matcher hm = HIDDEN.matcher(body);   // carry transaction_id + scope + any hidden fields (approve = omit 'cancel')
        while (hm.find()) {
            String n = hm.group(1);
            if (n.equalsIgnoreCase("cancel")) continue;
            if (form.length() > 0) form.append('&');
            form.append(enc(n)).append('=').append(enc(hm.group(2)));
        }
        if (form.length() == 0) return false;

        HttpRequestResponse dec = send(sess, HttpRequest.httpRequestFromUrl(action).withMethod("POST")
                .withAddedHeader("Content-Type", "application/x-www-form-urlencoded").withBody(form.toString()));
        scanLog.debug("[AI Scanner] oauth-logic: decision POST " + action + " body=[" + form + "] → HTTP "
                + (dec != null && dec.response() != null ? dec.response().statusCode() : -1)
                + " loc=" + (dec != null && dec.response() != null && dec.response().hasHeader("Location") ? dec.response().headerValue("Location") : "-"));
        if (dec != null && dec.response() != null && locationLeaksTo(dec, sentinelHost)) {
            scanLog.found("OAuth redirect_uri not validated (authorization-code/token leak)", authzUrl,
                    "authorized grant redirected the code/token to the attacker-chosen redirect_uri (" + sentinel + ")",
                    rr, dec);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    /** True when the response's Location header sends a code/token to the sentinel host. */
    private static boolean locationLeaksTo(HttpRequestResponse rr, String sentinelHost) {
        try {
            if (rr.response().statusCode() < 300 || rr.response().statusCode() >= 400) return false;
            String loc = rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : null;
            if (loc == null) return false;
            String h = URI.create(loc).getHost();
            return sentinelHost.equalsIgnoreCase(h) && LEAK.matcher(loc).find();
        } catch (Exception e) { return false; }
    }

    private HttpRequestResponse send(UnaryOperator<HttpRequest> sess, HttpRequest req) {
        try {
            return AiScanner.decompress(api.http().sendRequest(sess.apply(req),
                    RequestOptions.requestOptions().withResponseTimeout(12000L)));
        } catch (Throwable t) { scanLog.debug("[AI Scanner] oauth-logic send failed: " + t); return null; }
    }

    /** Replace (or append) a query parameter's value in a URL. */
    private static String replaceParam(String url, String name, String value) {
        String enc = enc(value);
        Pattern p = Pattern.compile("([?&]" + Pattern.quote(name) + "=)[^&#]*");
        Matcher m = p.matcher(url);
        if (m.find()) return m.replaceAll("$1" + Matcher.quoteReplacement(enc));
        return url + (url.contains("?") ? "&" : "?") + name + "=" + enc;
    }

    private static boolean sameHost(String url, String host) {
        try { return host.equalsIgnoreCase(Net.authority(url)); } catch (Exception e) { return false; }
    }
    private static String safeBody(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : null; } catch (Exception e) { return null; }
    }
    private static String enc(String v) {
        try { return java.net.URLEncoder.encode(v, "UTF-8"); } catch (Exception e) { return v == null ? "" : v; }
    }
}
