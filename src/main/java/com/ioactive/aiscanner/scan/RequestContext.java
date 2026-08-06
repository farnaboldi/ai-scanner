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
            sb.append("--- response body (truncated) ---\n").append(truncate(resp.bodyToString(), 1200));
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
}
