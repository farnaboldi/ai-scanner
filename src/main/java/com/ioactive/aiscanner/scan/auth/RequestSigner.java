package com.ioactive.aiscanner.scan.auth;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reproduces a SPA's client-side request-signing scheme so our authenticated probes get past a
 * signature gate ("Missing request signature"). Reverse-engineered generically from the app's own JS:
 *
 * <pre>
 *   timestamp = floor(now_ms / 1000)                       // epoch seconds (client applies a server-time
 *                                                          //   skew offset that defaults to 0)
 *   bodyHash  = sha256_hex(rawBody)                        // sha256("") for a bodyless GET
 *   canonical = "{timestamp}:{METHOD}:{path}:{bodyHash}"   // path = URL path only, NO query string
 *   canonical += ":{requestId}"                            // appended when an X-Request-ID is sent
 *   signature = hmac_sha256_hex(signingKey, canonical)
 * </pre>
 *
 * Headers set on the request: {@code X-Signature}, {@code X-Timestamp}, {@code X-Request-ID}. The signing
 * key is the {@code signing_key} the server hands back next to the access token at auth time.
 *
 * <p>Only the canonical-string layout is app-specific; everything else (HMAC-SHA256, hex, sha256 body hash)
 * is a universal idiom. If a target differs, this is the single place to adjust.
 */
public final class RequestSigner {

    private final String signingKey;

    public RequestSigner(String signingKey) {
        this.signingKey = signingKey == null ? "" : signingKey;
    }

    public boolean usable() { return !signingKey.isBlank(); }

    /** Return a copy of {@code req} with the X-Signature/X-Timestamp/X-Request-ID headers added. */
    public HttpRequest sign(HttpRequest req) {
        if (!usable() || req == null) return req;
        try {
            String rawPath = pathOf(req.url());
            String path = normalizePath(rawPath);
            // The server canonicalizes the path with a trailing slash (Django APPEND_SLASH) BEFORE computing the
            // expected signature — PROVEN by a discriminator test: signing the slash path validates even when the
            // request is SENT without it, and signing the no-slash path fails even when sent with it. So (1) sign
            // the slash-normalized path and (2) rewrite the request to that path, so sent == signed == the path
            // the server validates. Idempotent when the path already ends in "/".
            if (!path.equals(rawPath)) {
                String q = queryOf(req.url());
                req = req.withPath(q.isEmpty() ? path : path + "?" + q);
            }
            String method = req.method();
            String body = req.body() == null ? "" : req.bodyToString();
            // Multipart uploads are signed with an EMPTY body hash on this scheme — the client streams the file
            // and does NOT hash its bytes (verified against the live API: signing sha256(rawMultipart) → "invalid
            // signature"; sha256("") → accepted). JSON/form bodies ARE hashed. Keep the real body on the request.
            String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
            boolean multipart = ct != null && ct.toLowerCase().contains("multipart/form-data");
            String ts = Long.toString(System.currentTimeMillis() / 1000L);
            String reqId = UUID.randomUUID().toString();
            String bodyHash = sha256Hex(multipart ? "" : body);
            String canonical = ts + ":" + method + ":" + path + ":" + bodyHash + ":" + reqId;
            String sig = hmacSha256Hex(signingKey, canonical);
            return req.withHeader("X-Signature", sig)
                      .withHeader("X-Timestamp", ts)
                      .withHeader("X-Request-ID", reqId);
        } catch (Throwable t) {
            return req;   // never break a request over a signing failure — degrade to unsigned
        }
    }

    /** Slash-normalize a path the way the server does before signing: append a trailing "/" to an extensionless
     *  path (a collection/API route). A path whose last segment has a file extension (…/x.js) is left as-is. */
    // A STATIC-ASSET extension on the last path segment — those are NOT slash-normalized by the server. A bare
    // dot (e.g. an API route /api/2.0/orders or /api/v1/user.profile) is NOT an asset, so it still gets a slash.
    private static final java.util.regex.Pattern ASSET_EXT = java.util.regex.Pattern.compile(
            "(?i)\\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|map|json|xml|pdf|mp4|webp|txt|wasm|csv|xlsx?)$");
    static String normalizePath(String path) {
        if (path == null || path.isEmpty()) return "/";
        if (path.endsWith("/")) return path;
        int lastSeg = path.lastIndexOf('/');
        String last = lastSeg >= 0 ? path.substring(lastSeg + 1) : path;
        return ASSET_EXT.matcher(last).find() ? path : path + "/";   // real asset ext → leave; else append slash
    }

    static String queryOf(String url) {
        try { String q = URI.create(url).getRawQuery(); return q == null ? "" : q; }
        catch (Exception e) { int i = url.indexOf('?'); return i < 0 ? "" : url.substring(i + 1); }
    }

    /** Standalone header computation (for a raw proof/probe that isn't built as an HttpRequest). */
    public String[] headers(String method, String url, String body) {
        String ts = Long.toString(System.currentTimeMillis() / 1000L);
        String reqId = UUID.randomUUID().toString();
        String canonical = ts + ":" + method + ":" + normalizePath(pathOf(url)) + ":" + sha256Hex(body == null ? "" : body) + ":" + reqId;
        return new String[]{ hmacSha256Hex(signingKey, canonical), ts, reqId };   // X-Signature, X-Timestamp, X-Request-ID
    }

    static String pathOf(String url) {
        try {
            String p = URI.create(url).getRawPath();
            return (p == null || p.isEmpty()) ? "/" : p;   // path only — the scheme signs the query-less path
        } catch (Exception e) {
            int q = url.indexOf('?');
            return q < 0 ? url : url.substring(0, q);
        }
    }

    static String sha256Hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return hex(d);
        } catch (Exception e) { return ""; }
    }

    static String hmacSha256Hex(String key, String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return hex(mac.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { return ""; }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) { sb.append(Character.forDigit((x >> 4) & 0xF, 16)); sb.append(Character.forDigit(x & 0xF, 16)); }
        return sb.toString();
    }
}
