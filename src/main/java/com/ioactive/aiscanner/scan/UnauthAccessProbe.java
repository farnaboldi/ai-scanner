package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONObject;

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
                // CRITICAL: our scanner attaches the session credential to EVERY request, so "carried a
                // credential" no longer proves the endpoint is private, and authed==anon==identical actually
                // proves the endpoint is PUBLIC (the credential was irrelevant). So we do NOT claim generic
                // "broken access control" here. We fire ONLY when the anonymous response leaks an actual SECRET
                // VALUE (token/key/password-hash/2FA-secret/JWT with real entropy) — a genuine data exposure to
                // the public. Field NAMES and plain emails are NOT enough (public reviews/feedback/catalog carry
                // those) — that heuristic caused a false-positive flood; requiring a secret VALUE is zero-FP.
                if (!carriesSecretValue(bt)) continue;
                if (!tried.add(method + " " + Net.stripQuery(url))) continue;

                // re-send the SAME request WITHOUT any credential
                HttpRequest anon = HttpRequest.httpRequestFromUrl(url).withMethod(method);
                HttpRequestResponse ar = api.http().sendRequest(
                        anon, RequestOptions.requestOptions().withResponseTimeout(12000L));
                if (ar == null || ar.response() == null) continue;
                int anonSt = ar.response().statusCode();
                if (anonSt < 200 || anonSt >= 300) continue;                                // properly denied → correct
                if (shape(rr).equals(shape(ar))) {
                    // Pinpoint WHICH secret + WHERE: name+redact it in the detail and HIGHLIGHT its bytes in the
                    // response (a Burp response Marker) so the analyst sees it in a big body (e.g. /openapi.json).
                    Secret sec = findSecret(ar.response().bodyToString());
                    HttpRequestResponse ev = ar;
                    String leaked = "";
                    if (sec != null) {
                        leaked = " Leaked secret — field \"" + sec.field + "\"=" + redact(sec.value) + " (highlighted in the response).";
                        try {
                            int off = ar.response().bodyOffset();
                            ev = ar.withResponseMarkers(burp.api.montoya.core.Marker.marker(off + sec.start, off + sec.end));
                        } catch (Throwable ignore) { }
                    }
                    scanLog.found("Secret value served to an unauthenticated caller", url,
                            method + " returned a SECRET VALUE (token/key/password-hash/2FA-secret/JWT) with NO "
                                    + "credential (authed=" + baseSt + ", no-auth=" + anonSt + ", identical response "
                                    + "shape) — a secret is exposed to the anonymous public (sensitive-data exposure, "
                                    + "CWE-200/CWE-312). Deterministic: a high-entropy secret value present in the "
                                    + "credential-less response." + leaked, ev);
                    scanLog.incFinding();
                    hits++;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("unauth-access probe error: " + t);
        }
        return hits;
    }

    // Fire ONLY on an actual SECRET VALUE in the response: a secret-named field whose value is long and
    // high-entropy (token/api-key/password-hash/2FA-secret), or a JWT. Field names or plain email addresses
    // are deliberately NOT triggers — public reviews/feedback/catalog legitimately contain those, and using
    // them caused a false-positive flood. Requiring a real secret value keeps genuine exposures and is zero-FP.
    private static final Pattern SECRET_VALUE = Pattern.compile(
            "(?i)\"(password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret"
            + "|api[_-]?key|apikey|totp|otp[_-]?secret|private[_-]?key|session[_-]?id)\"\\s*:\\s*\"([^\"]{16,})\"");
    private static final Pattern JWT_VALUE = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}");

    private static boolean carriesSecretValue(String body) {
        return findSecret(body) != null;
    }

    /** The leaked secret + its position in the body (field name, value, and [start,end) offsets), or null. */
    private static final class Secret {
        final String field, value; final int start, end;
        Secret(String field, String value, int start, int end) { this.field = field; this.value = value; this.start = start; this.end = end; }
    }
    private static Secret findSecret(String body) {
        if (body == null) return null;
        java.util.regex.Matcher m = SECRET_VALUE.matcher(body);
        while (m.find()) if (looksHighEntropy(m.group(2))) return new Secret(m.group(1), m.group(2), m.start(2), m.end(2));
        java.util.regex.Matcher j = JWT_VALUE.matcher(body);
        if (j.find()) return new Secret("JWT", j.group(), j.start(), j.end());
        return null;
    }

    /** Redact a secret for the finding text: keep enough to identify it, never print the whole value. */
    private static String redact(String v) {
        if (v == null || v.isEmpty()) return "\"\"";
        if (v.length() <= 12) return "\"" + v.charAt(0) + "…\" (" + v.length() + " chars, redacted)";
        return "\"" + v.substring(0, 6) + "…" + v.substring(v.length() - 4) + "\" (" + v.length() + " chars, redacted)";
    }

    // A genuine secret value: >= 16 chars AND either long hex, or mixed letters+digits with no spaces
    // (rejects human-readable sentences / placeholder text that happens to sit in a secret-named field).
    private static boolean looksHighEntropy(String v) {
        if (v == null || v.length() < 16) return false;
        if (v.matches("[0-9a-fA-F]{16,}")) return true;
        boolean d = false, a = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (Character.isDigit(c)) d = true; else if (Character.isLetter(c)) a = true;
        }
        return d && a && !v.contains(" ");
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


    private static String hostOf(String url) { return Net.authority(url); }
}
