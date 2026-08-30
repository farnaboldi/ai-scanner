package com.ioactive.aiscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Compact, LLM-friendly description of the request being attacked and the single
 * insertion point under test — the context a request-blind generator throws away,
 * and the whole point of "request-aware" generation.
 */
public final class RequestContext {

    private final String forLlm;

    private RequestContext(String forLlm) { this.forLlm = forLlm; }

    public String forLlm() { return forLlm; }

    /**
     * OBSERVE compaction for the flow-engine: the last request + its response, token-bounded. Status,
     * Location and Set-Cookie are surfaced explicitly because the body-only oracle can't see them — that
     * is how the planner reads create→consume 302s and token flows.
     */
    public static RequestContext of(HttpRequestResponse rr) {
        HttpRequest req = rr.request();
        StringBuilder sb = new StringBuilder();
        sb.append("Request: ").append(req.method()).append(' ').append(req.url()).append('\n');
        String ct = header(req, "Content-Type");
        if (!ct.isBlank()) sb.append("Content-Type: ").append(ct).append('\n');
        String reqBody = req.bodyToString();
        if (reqBody != null && !reqBody.isBlank())
            sb.append("Request body: ").append(truncate(reqBody, 600)).append('\n');
        if (rr.response() != null) {
            var resp = rr.response();
            sb.append("Response status: ").append(resp.statusCode()).append('\n');
            if (resp.hasHeader("Location")) sb.append("Response Location: ").append(resp.headerValue("Location")).append('\n');
            if (resp.hasHeader("Set-Cookie")) sb.append("Set-Cookie: present\n");
            String respBody = resp.bodyToString();
            sb.append("--- response body (truncated) ---\n").append(truncate(respBody, 1200));
            // Auto-decode base64 fields so the planner can act on embedded credentials / nested responses.
            // Generic: any JSON field ending in _base64 that decodes to valid UTF-8 is surfaced decoded.
            decodeBase64Fields(respBody, sb);
        }
        return new RequestContext(sb.toString());
    }

    private static String header(HttpRequest req, String name) {
        try {
            return req.hasHeader(name) ? req.headerValue(name) : "";
        } catch (Exception e) {
            return "";
        }
    }

    static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…[truncated]";
    }

    private static final java.util.regex.Pattern BASE64_FIELD = java.util.regex.Pattern.compile(
            "\"(\\w+_base64|\\w+Base64)\"\\s*:\\s*\"([A-Za-z0-9+/=]{20,4096})\"");

    /** Decode any *_base64 JSON fields in the response body and append them — so the planner sees the
     *  decoded content (e.g. embedded credentials from an SSRF response) without needing to decode itself. */
    private static void decodeBase64Fields(String body, StringBuilder sb) {
        if (body == null || body.isEmpty()) return;
        java.util.regex.Matcher m = BASE64_FIELD.matcher(body);
        boolean any = false;
        while (m.find()) {
            try {
                byte[] decoded = java.util.Base64.getDecoder().decode(m.group(2));
                String text = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
                if (text.indexOf('\0') >= 0) continue;   // binary — skip
                if (!any) { sb.append("\n[Auto-decoded base64 fields]\n"); any = true; }
                sb.append(m.group(1)).append(" → ").append(truncate(text, 300)).append('\n');
            } catch (Exception ignore) { }
        }
    }
}
