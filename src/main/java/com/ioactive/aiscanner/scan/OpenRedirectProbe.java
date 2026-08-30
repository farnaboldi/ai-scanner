package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic open-redirect oracle — fully generic. Substitutes a distinctive canary host into every
 * parameter and fires ONLY when the app hands control to that canary: a {@code Location} response
 * header pointing at it (server-side 3xx redirect), or a client-side redirect to it (meta-refresh /
 * {@code location=}). The canary is an invented host that cannot occur naturally, so a match is
 * definitive; nothing about the payload or the oracle is target-specific.
 */
public final class OpenRedirectProbe extends Probe {

    // api + scanLog inherited from Probe

    private static final String CANARY = "aisc-redirect-canary.example";
    // Generic redirect payloads: absolute, scheme-relative, malformed-scheme, backslash and
    // encoded-slash bypasses — the shapes parsers mishandle when building a redirect target.
    private static final String[] PAYLOADS = {
            "https://" + CANARY + "/",
            "http://" + CANARY + "/",
            "//" + CANARY + "/",
            "https:/" + CANARY + "/",
            "/\\" + CANARY + "/",
            "https://" + CANARY + "%2f..",
    };
    // A CLIENT-SIDE redirect is a meta-refresh URL or a JS location assignment — NOT a bare <a href> link. The
    // extracted target is then host-checked (targetsCanaryHost), so the canary reflected inside a same-origin
    // link (phpMyAdmin echoes ?route=<canary> into <a href> + error text) or an ordinary <a> is NOT a redirect.
    private static final Pattern META_REFRESH = Pattern.compile(
            "(?is)http-equiv\\s*=\\s*['\"]?refresh['\"]?[^>]*?\\burl\\s*=\\s*['\"]?([^'\"<>\\s]+)");
    private static final Pattern JS_LOCATION = Pattern.compile(
            "(?is)\\b(?:window\\.)?location\\b(?:\\s*\\.\\s*(?:href|replace|assign))?\\s*(?:=|\\()\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    // Redirects live in redirect-ish params — target only those (by name, or a URL/path-looking value)
    // to keep the probe light and low-noise. Generic heuristic, no app-specific names.
    private static final Pattern REDIRECT_NAME = Pattern.compile(
            "(?i).*(redirect|return|returnurl|next|dest|destination|goto|continue|url|uri|link|target|forward|callback|success|cancel|back|out|redir|ref|referer|referrer|location).*");

    public OpenRedirectProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                if (!redirecty(p)) continue;   // only params that plausibly carry a redirect target
                for (String payload : PAYLOADS) {
                    HttpRequest m = req.withUpdatedParameters(HttpParameter.parameter(p.name(), payload, p.type()));
                    HttpRequestResponse rr = send(m);   // keep the proving pair (canary in request → Location→canary in response)
                    if (redirectsToCanary(rr)) {
                        scanLog.found("Open redirect", req.url(),
                                p.name() + " (" + p.type() + ") → " + payload, rr);   // attach request/response evidence
                        scanLog.incFinding();
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("open-redirect probe error: " + t);
        }
        return false;
    }

    private boolean redirectsToCanary(HttpRequestResponse r) {
        if (r == null || r.response() == null) return false;
        try {
            int st = r.response().statusCode();
            String loc = r.response().headerValue("Location");
            if (st >= 300 && st < 400 && targetsCanaryHost(loc)) return true;   // server-side redirect to the canary HOST
            return clientRedirectsToCanary(r.response().bodyToString());        // client-side (meta-refresh / JS)
        } catch (Throwable t) {
            return false;
        }
    }

    /** A genuine client-side redirect to the canary HOST: a meta-refresh {@code url=} or a JS {@code location}
     *  assignment whose target host is the canary. A plain {@code <a href>} or the canary reflected in a
     *  same-origin link / error text is NOT a redirect (that flooded phpMyAdmin's ?route= with false positives). */
    private static boolean clientRedirectsToCanary(String body) {
        if (body == null || body.isEmpty()) return false;
        Matcher m = META_REFRESH.matcher(body);
        while (m.find()) if (targetsCanaryHost(m.group(1))) return true;
        m = JS_LOCATION.matcher(body);
        while (m.find()) if (targetsCanaryHost(m.group(1))) return true;
        return false;
    }

    /**
     * True ONLY when the redirect target's HOST is the canary (external) — not when the canary merely appears
     * inside a SAME-ORIGIN path. A {@code Location: /aisc-redirect-canary.example/} (single leading slash) is a
     * LOCAL path: the app neutralized the payload (e.g. WordPress strips the backslash of a {@code /\host} bypass),
     * so it is NOT an open redirect. Browsers resolve backslashes as forward slashes, so {@code //host},
     * {@code /\host}, {@code \/host} and {@code http(s):/host} all navigate to the external host and DO count.
     */
    private static boolean targetsCanaryHost(String loc) {
        if (loc == null) return false;
        String n = loc.trim().replace('\\', '/');                 // browser-equivalent: backslash → forward slash
        String afterScheme = n.replaceFirst("(?i)^https?:", "");  // drop a leading http:/https: scheme
        String canary = Pattern.quote(CANARY);
        return afterScheme.matches("(?i)^/{2,}" + canary + "([/:?#].*)?$")   // //canary…  (protocol-relative / host)
            || n.matches("(?i)^https?:/+" + canary + "([/:?#].*)?$");        // http(s):/canary…  (malformed-scheme)
    }

    // send(HttpRequest) inherited from Probe (politeness + configured request timeout).

    /** A parameter plausibly carries a redirect target: redirect-ish name, or a URL/path-looking value. */
    private static boolean redirecty(ParsedHttpParameter p) {
        if (REDIRECT_NAME.matcher(p.name()).matches()) return true;
        String v = p.value();
        return v != null && (v.startsWith("http") || v.startsWith("//") || v.startsWith("/")
                || v.contains("://") || v.matches("(?i).*\\.(html?|php|aspx?|jsp).*"));
    }
}
