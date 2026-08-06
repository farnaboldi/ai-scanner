package com.ioactive.aiscanner.scan.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.scan.SessionStore;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Generic HTTP working-session for the autonomous auth flow: an accumulating cookie jar + tiny
 * redirect-following GET/POST helpers that merge {@code Set-Cookie} at each hop. No app knowledge —
 * only transport mechanism. {@link #seedFrom} loads an already-captured session; {@link #publishTo}
 * pushes the jar back into the shared {@link SessionStore} + Burp's cookie jar.
 */
public final class AuthSession {

    private final MontoyaApi api;
    private final String host;
    private final LinkedHashMap<String, String> jar = new LinkedHashMap<>();
    private static final int MAX_REDIRECTS = 6;

    public AuthSession(MontoyaApi api, String host) {
        this.api = api;
        this.host = host;
    }

    /** Preload the jar from an existing session cookie header (so requests are already authenticated). */
    public void seedFrom(SessionStore session) {
        if (session == null || !session.has()) return;
        for (String part : session.cookieHeader().split(";")) {
            String s = part.trim();
            int eq = s.indexOf('=');
            if (eq > 0) jar.put(s.substring(0, eq).trim(), s.substring(eq + 1).trim());
        }
    }

    public String cookieHeader() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : jar.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    public HttpRequestResponse get(String url) {
        return send(HttpRequest.httpRequestFromUrl(url).withMethod("GET"));
    }

    public HttpRequestResponse postForm(String url, String formBody) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(formBody == null ? "" : formBody);
        return send(req);
    }

    /** JSON POST (API-first SPA auth: signup/login endpoints that consume a JSON body). Same
     *  cookie-jar + redirect handling as postForm. */
    public HttpRequestResponse postJson(String url, String jsonBody) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/json")
                .withBody(jsonBody == null ? "" : jsonBody);
        return send(req);
    }

    /** JSON PUT — many REST APIs expose account creation as a resource create/replace on the user
     *  resource itself (PUT /rest/user, DRF, etc.) with no POST /register alias. Same jar/redirect
     *  handling as {@link #postJson}. Generic: the caller decides which URL is a registration target. */
    public HttpRequestResponse putJson(String url, String jsonBody) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("PUT")
                .withAddedHeader("Content-Type", "application/json")
                .withBody(jsonBody == null ? "" : jsonBody);
        return send(req);
    }

    /** Stamp browser-like headers (UA / Origin / Referer / sec-fetch) so edge WAFs that block non-browser
     *  clients don't 403 our authentication requests — matches how a real login from the SPA looks. Generic:
     *  Origin/Referer are derived from the request's own scheme+host; never overwrites a header already set. */
    private static HttpRequest browserize(HttpRequest req) {
        String origin = "";
        // getAuthority() keeps the PORT (getHost() drops it) — an Origin without the port (http://localhost)
        // reads as :80, so a request to :8080 looks cross-origin to the server's CORS filter and is rejected
        // ("Invalid CORS request"). Same-origin Origin (host:port matches the target) passes the CORS check.
        try { URI u = URI.create(req.url()); origin = u.getScheme() + "://" + u.getAuthority(); } catch (Exception ignore) { }
        if (!req.hasHeader("User-Agent")) req = req.withHeader("User-Agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
        if (!req.hasHeader("Accept")) req = req.withHeader("Accept", "application/json, text/plain, */*");
        if (!req.hasHeader("Accept-Language")) req = req.withHeader("Accept-Language", "en-US,en;q=0.9");
        if (!origin.isEmpty()) {
            if (!req.hasHeader("Origin")) req = req.withHeader("Origin", origin);
            if (!req.hasHeader("Referer")) req = req.withHeader("Referer", origin + "/");
        }
        if (!req.hasHeader("Sec-Fetch-Site")) req = req.withHeader("Sec-Fetch-Site", "same-origin");
        if (!req.hasHeader("Sec-Fetch-Mode")) req = req.withHeader("Sec-Fetch-Mode", "cors");
        return req;
    }

    private HttpRequestResponse send(HttpRequest initial) {
        HttpRequest req = initial;
        HttpRequestResponse rr = null;
        String current = req.url();
        int rlRetries = 0;
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            try {
                if (!cookieHeader().isBlank()) req = req.withHeader("Cookie", cookieHeader());
                req = browserize(req);   // browser-like headers so UA/behavior WAFs don't 403 our auth requests
                rr = api.http().sendRequest(req, RequestOptions.requestOptions());
            } catch (Throwable t) {
                return rr;
            }
            if (rr == null || rr.response() == null) return rr;
            mergeCookies(rr);
            int st = rr.response().statusCode();
            // Rate-limited: back off (honoring Retry-After) and retry the SAME request a few times, so a
            // transient 429 doesn't sink a legitimate auth request (signup/verify/login). Generic, bounded.
            if (st == 429 && rlRetries < 3) {
                long wait = retryAfterMs(rr, rlRetries);
                try { Thread.sleep(wait); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return rr; }
                rlRetries++; hop--;   // this attempt doesn't consume a redirect hop
                continue;
            }
            if (st < 300 || st >= 400) return rr;
            String loc = safeHeader(rr, "Location");
            if (loc == null || loc.isBlank()) return rr;
            try {
                current = URI.create(current).resolve(loc).toString();
            } catch (Exception e) {
                return rr;
            }
            req = HttpRequest.httpRequestFromUrl(current).withMethod("GET");
        }
        return rr;
    }

    /** Backoff for a 429: honor a numeric Retry-After (capped), else 2s→5s→10s. */
    private static long retryAfterMs(HttpRequestResponse rr, int attempt) {
        try {
            String ra = safeHeader(rr, "Retry-After");
            if (ra != null && ra.trim().matches("\\d+")) return Math.min(30_000L, Long.parseLong(ra.trim()) * 1000L);
        } catch (Exception ignore) { }
        long[] backoff = { 2000L, 5000L, 10_000L };
        return backoff[Math.min(attempt, backoff.length - 1)];
    }

    private void mergeCookies(HttpRequestResponse rr) {
        try {
            for (Cookie c : rr.response().cookies()) {
                if (c.name() != null && !c.name().isBlank()) jar.put(c.name(), c.value() == null ? "" : c.value());
            }
        } catch (Throwable ignore) {
        }
    }

    /** Publish the jar into the shared session + Burp's cookie jar; optionally record landing/login. */
    public void publishTo(SessionStore session, String landingUrl, String loginPageUrl, String user, String pass) {
        String header = cookieHeader();
        if (!header.isBlank()) {
            session.set(header);
            for (Map.Entry<String, String> e : jar.entrySet()) {
                try {
                    api.http().cookieJar().setCookie(e.getKey(), e.getValue(), "/", host, ZonedDateTime.now().plusDays(1));
                } catch (Exception ignore) {
                }
            }
        }
        if (landingUrl != null && !landingUrl.isBlank()) session.setLandingUrl(landingUrl);
        if (loginPageUrl != null && !loginPageUrl.isBlank()) session.rememberLogin(loginPageUrl, user, pass);
    }

    static String safeHeader(HttpRequestResponse rr, String name) {
        try {
            return rr.response().headerValue(name);
        } catch (Exception e) {
            return null;
        }
    }
}
