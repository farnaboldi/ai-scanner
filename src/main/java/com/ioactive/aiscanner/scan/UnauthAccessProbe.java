package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONObject;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Unauthenticated-access (broken/missing authentication) probe — fully generic, no app-specific paths.
 * For each endpoint the scanner reached AS AN AUTHENTICATED USER — a site-map request that CARRIED a
 * credential (Authorization bearer or session Cookie) and returned a 2xx JSON body — re-send the IDENTICAL
 * request with the credential STRIPPED. FIRE iff the credential-less response is ALSO 2xx AND its shape
 * (status + sorted JSON keys, value/order-insensitive) matches the authenticated one: a protected data
 * endpoint served the same data to an anonymous caller, so authentication is not enforced.
 *
 * <p>Deterministic, non-destructive (GET/HEAD only), and zero-FP by construction:
 * <ul>
 *   <li>only endpoints whose ORIGINAL request carried a credential are considered — a public endpoint never
 *       carried one, so it cannot fire (a public endpoint is not a finding);</li>
 *   <li>requires a non-trivial JSON body (len &gt; 40, no {@code "error"}) so an empty 200/OK cannot fire;</li>
 *   <li>shape match proves it is the SAME resource, not a generic landing page / redirect.</li>
 * </ul>
 * Depends on the site-map bridge: discovered authenticated endpoints must be in the site map to be seen.
 */
public final class UnauthAccessProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // Never treat STATIC or dev-server assets as "protected endpoints": they are legitimately public and
    // identical for every user, so authed==unauthed is expected, not a vuln (e.g. CRA's /manifest.json, a
    // webpack-dev-server /sockjs-node/info, build files under /static/). Excludes them by dev-server path,
    // by well-known static-config filename, by /static/ prefix (also catches extensionless mined phantoms
    // like /static/js/Microsoft.XMLHTTP), and by static file extension.
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io|sockjs-node)(\\b.*)?$"
            + "|.*/(manifest\\.json|asset-manifest\\.json|service-worker\\.js|robots\\.txt|browserconfig\\.xml|favicon\\.ico)$"
            + "|.*/static/.*"
            + "|.*\\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf|webmanifest)(\\?.*)?$");

    public UnauthAccessProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public int probe(String host) {
        int hits = 0;
        Set<String> tried = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                HttpRequest req = rr.request();
                String url = req.url();
                if (!host.equalsIgnoreCase(hostOf(url))) continue;
                if (SKIP.matcher(url).matches()) continue;
                if (AuthenticatedExplorer.SESSION_RESET.matcher(url).matches()) continue;   // never re-hit login/logout
                String method = req.method();
                if (!"GET".equals(method) && !"HEAD".equals(method)) continue;              // non-destructive only
                // the authenticated request must have CARRIED a credential (else it's a public endpoint)
                if (!req.hasHeader("Authorization") && !req.hasHeader("Cookie")) continue;
                // authed baseline must be a real 2xx JSON payload
                int baseSt = rr.response().statusCode();
                if (baseSt < 200 || baseSt >= 300) continue;
                String baseBody = rr.response().bodyToString();
                if (baseBody == null) continue;
                String bt = baseBody.trim();
                if (bt.length() < 40 || bt.toLowerCase().contains("\"error\"")) continue;
                if (!bt.startsWith("{") && !bt.startsWith("[")) continue;                   // JSON data endpoint
                // "authed==unauthed" alone does NOT mean broken access control — most APIs have legitimately
                // PUBLIC endpoints (product catalog, languages, captcha, search) that return the same data to
                // everyone. Only treat it as a protected-data exposure when the response actually carries
                // PII/secret DATA (email, token, secret, card, address, …) — that is what should require auth.
                if (!carriesSensitiveData(bt)) continue;
                if (!tried.add(method + " " + stripQuery(url))) continue;

                // re-send the SAME request WITHOUT any credential
                HttpRequest anon = HttpRequest.httpRequestFromUrl(url).withMethod(method);
                HttpRequestResponse ar = api.http().sendRequest(
                        anon, RequestOptions.requestOptions());
                if (ar == null || ar.response() == null) continue;
                int anonSt = ar.response().statusCode();
                if (anonSt < 200 || anonSt >= 300) continue;                                // properly denied → correct
                if (shape(rr).equals(shape(ar))) {
                    scanLog.found("Unauthenticated access to a protected endpoint", url,
                            method + " returned PII/secret DATA with NO credential (authed=" + baseSt
                                    + ", no-auth=" + anonSt + ", identical response shape; response carries "
                                    + "sensitive fields such as email/token/secret). Sensitive data served to the "
                                    + "anonymous public — broken access control / data exposure.", ar);
                    scanLog.incFinding();
                    hits++;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] unauth-access probe error: " + t);
        }
        return hits;
    }

    // A response carries protected DATA (should require auth) if it has a PII/secret field name or an
    // email-format value. Public catalog/game data (product name/price/image, language, captcha, challenge
    // text) has none of these, so it is NOT flagged — killing the "every public endpoint" false-positive flood.
    private static final Pattern SENSITIVE_KEY = Pattern.compile(
            "(?i)\"(e-?mail|password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|api[_-]?key|apikey"
            + "|ssn|social[_-]?security|credit[_-]?card|card[_-]?number|cardnumber|cvv|iban|account[_-]?number"
            + "|phone|mobile|street|address|postal|zipcode|passport|salary|totp|otp[_-]?secret)\"\\s*:");
    private static final Pattern EMAIL_VALUE = Pattern.compile("[A-Za-z0-9._%+*-]{1,64}@[A-Za-z0-9.-]{2,}\\.[A-Za-z]{2,}");

    private static boolean carriesSensitiveData(String body) {
        if (body == null) return false;
        return SENSITIVE_KEY.matcher(body).find() || EMAIL_VALUE.matcher(body).find();
    }

    /** status + sorted top-level JSON keys (value/order-insensitive), or a path-stripped token signature for
     *  non-JSON — same shape function BflaProbe uses so reorder/value noise can't move it. */
    private static String shape(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "none";
        int st = rr.response().statusCode();
        String body = rr.response().bodyToString();
        if (body != null) {
            String t = body.trim();
            if (t.startsWith("{")) {
                try {
                    JSONObject o = new JSONObject(t);
                    String[] keys = o.keySet().toArray(new String[0]);
                    Arrays.sort(keys);
                    return st + ":keys:" + String.join(",", keys);
                } catch (Throwable ignore) { /* fall through */ }
            }
        }
        String norm = (body == null ? "" : body)
                .replaceAll("\\d+", "#")
                .replaceAll("(?i)[a-z0-9/_.-]{16,}", " ")
                .replaceAll("\\s+", " ").trim();
        String[] toks = norm.split(" ");
        Arrays.sort(toks);
        return st + ":body:" + String.join(" ", toks);
    }

    private static String stripQuery(String url) {
        int q = url.indexOf('?');
        return q < 0 ? url : url.substring(0, q);
    }

    private static String hostOf(String url) {
        try { return URI.create(url).getHost(); } catch (Exception e) { return ""; }
    }
}
