package com.ioactive.aiscanner.scan.flow;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The LLM's proposed next request (PLAN step). Parsed tolerantly from ONE JSON object; materialized
 * into a Montoya request; carries a signature for anti-loop dedup. Nothing here decides a verdict —
 * every materialized request is live-probed and then handed to a deterministic oracle.
 */
public record PlannedRequest(String method, String url, String body,
                             Map<String, String> headers, String intent,
                             String vulnClassHint, String extractHint) {

    /** Tolerant parse of one JSON object (already sliced by LocalAiEngine.firstJsonObject). null on junk. */
    public static PlannedRequest parse(String rawJson) {
        if (rawJson == null || rawJson.isBlank()) return null;
        try {
            JSONObject o = new JSONObject(rawJson);
            String url = o.optString("url", "").trim();
            if (url.isEmpty() || !url.startsWith("http")) return null;   // must be an absolute URL
            String method = o.optString("method", "GET").trim().toUpperCase();
            Map<String, String> h = new LinkedHashMap<>();
            JSONObject hj = o.optJSONObject("headers");
            if (hj != null) for (String k : hj.keySet()) h.put(k, hj.optString(k, ""));
            return new PlannedRequest(method, url, o.optString("body", ""), h,
                    o.optString("intent", ""), o.optString("vulnClassHint", ""), o.optString("extractHint", ""));
        } catch (Exception e) {
            return null;
        }
    }

    /** Materialize into a Montoya request; the session (Cookie/Bearer) is attached by the caller. */
    public HttpRequest toHttpRequest() {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        boolean hasCt = false;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            r = r.withHeader(e.getKey(), e.getValue());
            if (e.getKey().equalsIgnoreCase("content-type")) hasCt = true;
        }
        if (body != null && !body.isEmpty()) {
            // A state-changing body needs a Content-Type or JSON/form APIs won't parse it — the create /
            // mass-assignment payload would 400 and the whole chain would look "not live" and be dropped.
            if (!hasCt && (method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))) {
                String t = body.trim();
                r = r.withHeader("Content-Type",
                        (t.startsWith("{") || t.startsWith("[")) ? "application/json"
                                                                 : "application/x-www-form-urlencoded");
            }
            r = r.withBody(body);
        }
        return r;
    }

    /** Anti-loop signature: method + url + body hash (mirrors AiScanner.addTarget's key style). */
    public String signature() {
        return method + " " + url + "#" + Integer.toHexString((body == null ? "" : body).hashCode());
    }
}
