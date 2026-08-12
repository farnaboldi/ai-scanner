package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic <b>path-traversal</b> oracle driven by <b>path reflection</b> — generic, no app-specific
 * filenames, and it needs NO {@code /etc/passwd} readback (the classic content oracle misses handlers that
 * force a suffix like {@code <value>.yaml} or parse the file instead of echoing it).
 *
 * <p>Two deterministic steps:
 * <ol>
 *   <li><b>Reflection</b>: replace the parameter value with a unique token; if the response echoes that token
 *       INSIDE an absolute filesystem path (e.g. {@code /app/configs/scenarios/&lt;token&gt;.yaml} in a "not
 *       found" error), the parameter is concatenated into a server file path. The leaked path also hands us the
 *       immediate parent directory name.</li>
 *   <li><b>Up-and-back equivalence</b>: with the app's own valid value, {@code ../&lt;leaked-dir&gt;/&lt;value&gt;}
 *       must behave like the baseline (the {@code ..} navigates up and back to the same real file) while a junk
 *       directory {@code ../&lt;token&gt;/&lt;value&gt;} must NOT — proving {@code ..} is resolved on the
 *       filesystem, not treated as an opaque key. An opaque-key handler 404s on both.</li>
 * </ol>
 * The pair (reflected-into-a-path AND up-and-back-via-a-real-dir works but via-a-junk-dir doesn't) is
 * unforgeable by a non-traversal endpoint → zero-FP. Injects URL/BODY params and JSON string fields, matching
 * how {@link BlindSqliProbe} reaches a JSON API's insertion points.
 */
public final class PathReflectionProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    private static final Pattern SKIP = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    private static final Pattern JSON_STR = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    public PathReflectionProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;

            // URL/BODY params.
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                String orig = p.value() == null ? "" : p.value();
                if (orig.isEmpty()) continue;                          // need a valid baseline to compare against
                if (run(req, v -> req.withUpdatedParameters(HttpParameter.parameter(p.name(), v, p.type())),
                        p.name() + " (" + p.type() + ")", orig)) return true;
            }
            // JSON body string fields (Montoya doesn't parse these into parameters()).
            String body = req.bodyToString();
            if (body != null && body.trim().startsWith("{")) {
                Set<String> keys = new LinkedHashSet<>();
                Matcher m = JSON_STR.matcher(body);
                while (m.find()) keys.add(m.group(1));
                for (String key : keys) {
                    String cur = currentJsonValue(body, key);
                    if (cur == null || cur.isEmpty()) continue;
                    if (run(req, v -> req.withBody(setJsonString(body, key, v)), key + " (JSON)", cur)) return true;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] path-reflection probe error: " + t);
        }
        return false;
    }

    private boolean run(HttpRequest req, Function<String, HttpRequest> build, String label, String orig) {
        HttpRequestResponse base = send(build.apply(orig));
        if (base == null || base.response() == null) return false;
        int baseClass = base.response().statusCode() / 100;
        if (baseClass != 2) return false;                              // baseline must be a working value

        String token = "AISCPT" + Long.toHexString(System.nanoTime()).toUpperCase();
        HttpRequestResponse refl = send(build.apply(token));
        if (refl == null || refl.response() == null) return false;
        String path = reflectedPath(refl.response().bodyToString(), token);
        if (path == null) return false;                                // value not reflected into a filesystem path
        String dir = parentDir(path, token);
        if (dir == null || dir.isEmpty()) return false;

        // up-and-back through the REAL leaked directory vs a junk directory.
        HttpRequestResponse up  = send(build.apply("../" + dir + "/" + orig));
        HttpRequestResponse ctl = send(build.apply("../" + token + "/" + orig));
        if (up == null || up.response() == null || ctl == null || ctl.response() == null) return false;
        int upClass = up.response().statusCode() / 100, ctlClass = ctl.response().statusCode() / 100;

        if (upClass == 2 && ctlClass != 2) {
            scanLog.found("Path traversal", pathOnly(req.url()),
                    "param " + label + ": the value is concatenated into a server file path (reflected as '"
                            + path + "'); '../" + dir + "/" + orig + "' resolves like the baseline while "
                            + "'../<nonexistent>/" + orig + "' does not — unescaped ../ traverses the filesystem "
                            + "(CWE-22), so arbitrary files under that root are reachable", up);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    /** The absolute path (starting with '/') in the body that contains the token, or null. */
    private static String reflectedPath(String body, String token) {
        if (body == null) return null;
        Matcher m = Pattern.compile("(/[^\\s\"'<>]*?" + Pattern.quote(token) + "[^\\s\"'<>]*)").matcher(body);
        return m.find() ? m.group(1) : null;
    }

    /** The directory segment immediately preceding the token in a '/'-delimited path. */
    private static String parentDir(String path, String token) {
        String[] seg = path.split("/");
        for (int i = 0; i < seg.length; i++) {
            if (seg[i].contains(token)) return i > 0 ? seg[i - 1] : null;
        }
        return null;
    }

    private static String pathOnly(String url) {
        int q = url == null ? -1 : url.indexOf('?');
        return q < 0 ? url : url.substring(0, q);
    }

    private static String setJsonString(String body, String key, String val) {
        return body.replaceFirst("(\"" + Pattern.quote(key) + "\"\\s*:\\s*\")(?:[^\"\\\\]|\\\\.)*(\")",
                "$1" + Matcher.quoteReplacement(val.replace("\\", "\\\\").replace("\"", "\\\"")) + "$2");
    }

    private static String currentJsonValue(String body, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
        return m.find() ? m.group(1).replace("\\\"", "\"").replace("\\\\", "\\") : null;
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)); }
        catch (Throwable t) { return null; }
    }
}
