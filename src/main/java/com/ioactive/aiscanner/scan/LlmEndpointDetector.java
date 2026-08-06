package com.ioactive.aiscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.regex.Pattern;

/**
 * Identifies, GENERICALLY, whether an HTTP endpoint is LLM-backed — the prerequisite for the LLM-fuzz probe
 * (fire adversarial payloads at a model, have the local LLM judge the responses). Keyed on the universal shape
 * of chat/completion/agent APIs, NOT on any app's paths or field names verbatim, so a URL never being called
 * "/chat" is irrelevant.
 *
 * <p>Detection is two-layer; this class does the PASSIVE (structural) layer over an observed request/response.
 * The active behavioral confirmation (send an instruction-following probe, require a natural-language reply that
 * varies by prompt) is driven by the caller (which knows how to send to the specific endpoint) using
 * {@link #extractReply} to read the model's text back.
 *
 * <p>The strongest single tell is <b>token accounting</b> in the response ({@code prompt_tokens},
 * {@code total_output_tokens}, {@code usage}, cost fields): an endpoint that reports token usage is almost
 * certainly a model. Others: an assistant-text field, the OpenAI {@code choices[].message.content} shape, an
 * async run/turn status pair, SSE streaming, or a request carrying {@code messages:[{role,content}]} or a
 * free-text field beside {@code temperature}/{@code max_tokens}/{@code model}/{@code stream}.
 */
public final class LlmEndpointDetector {

    private LlmEndpointDetector() {}

    // Response fields that carry model output text (the reply we read back for behavioral checks + fuzzing).
    private static final String[] REPLY_KEYS = {
            "assistant_message", "message", "content", "reply", "completion", "answer", "text", "output", "response"
    };
    // Request fields that carry the user's free-text prompt (the insertion point we fuzz).
    private static final String[] PROMPT_KEYS = { "message", "prompt", "input", "query", "text", "content", "question" };
    // Token-accounting / model-config keys — a near-certain LLM tell wherever they appear (req or resp).
    private static final Pattern TOKEN_ACCT = Pattern.compile(
            "(?i)\\b(prompt_tokens|completion_tokens|total_tokens|input_tokens|output_tokens|total_input_tokens|"
          + "total_output_tokens|total_cost(?:_micros)?|usage|max_tokens|temperature|top_p|(?<![a-z])model(?![a-z]))\\b");
    // Async agent/run/turn status shape.
    private static final Pattern RUN_TURN = Pattern.compile("(?i)\\b(turn_id|run_id|assistant_message|stop_reason)\\b");

    /**
     * Structural (passive) verdict from an observed request/response. True when the shape matches a chat/
     * completion/agent API. Deliberately conservative — behavioral confirmation is expected before fuzzing.
     */
    public static boolean looksLlm(HttpRequestResponse rr) {
        if (rr == null) return false;
        try {
            HttpRequest req = rr.request();
            String reqBody = safeBody(req);
            String ct = rr.response() != null && rr.response().hasHeader("Content-Type")
                    ? rr.response().headerValue("Content-Type") : "";
            String respBody = rr.response() != null ? rr.response().bodyToString() : "";

            // Streaming completions.
            if (ct != null && ct.toLowerCase().contains("text/event-stream")) return true;

            // Token-accounting / async-agent shape anywhere is a strong tell.
            if (TOKEN_ACCT.matcher(respBody).find() && (hasReplyField(respBody) || RUN_TURN.matcher(respBody).find())) return true;
            if (RUN_TURN.matcher(respBody).find()) return true;

            // OpenAI-style request or response.
            if (looksOpenAiRequest(reqBody)) return true;
            if (hasChoicesMessage(respBody)) return true;

            // A request that carries a free-text prompt beside model config.
            if (promptField(reqBody) != null && TOKEN_ACCT.matcher(reqBody).find()) return true;

            // Generic chat/agent shape: a request free-text prompt field + a response reply field carrying
            // SUBSTANTIAL text. This covers model APIs that DON'T report token usage and use compound field names
            // (user_input → final_response), which the segment-aware matchers handle. Intentionally permissive —
            // the caller's behavioral confirmation (instruction-following / prose variation) is the real gate, so a
            // non-LLM echo endpoint that slips through here is rejected there before any payload fires.
            if (promptField(reqBody) != null) {
                String reply = extractReply(respBody);
                if (reply != null && reply.length() >= 12 && respBody != null && respBody.length() > 40) return true;
            }

            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    /** The free-text prompt field name in a JSON request body (the fuzz insertion point), or null. */
    public static String promptField(String jsonBody) {
        if (jsonBody == null || jsonBody.isBlank()) return null;
        try {
            JSONObject o = new JSONObject(jsonBody);
            String k = matchingStringKey(o, PROMPT_KEYS);        // segment-aware: user_input, message_text, …
            if (k != null) return k;
            // OpenAI messages[].content — signal caller to target the last user message's content.
            if (o.optJSONArray("messages") != null) return "messages";
        } catch (JSONException ignore) { }
        return null;
    }

    /** Extract the model's reply text from a response body (assistant_message / choices / common fields). */
    public static String extractReply(String body) {
        if (body == null || body.isBlank()) return null;
        try {
            JSONObject o = new JSONObject(body);
            JSONObject data = o.optJSONObject("data");
            JSONObject scope = data != null ? data : o;
            String k = matchingStringKey(scope, REPLY_KEYS);     // segment-aware: final_response, output_text, …
            if (k != null) return scope.optString(k);
            // OpenAI: choices[0].message.content
            JSONArray choices = scope.optJSONArray("choices");
            if (choices != null && choices.length() > 0) {
                JSONObject c0 = choices.optJSONObject(0);
                if (c0 != null) {
                    JSONObject msg = c0.optJSONObject("message");
                    if (msg != null) { String v = msg.optString("content", null); if (v != null && !v.isBlank()) return v; }
                    String delta = c0.optString("text", null);
                    if (delta != null && !delta.isBlank()) return delta;
                }
            }
        } catch (JSONException ignore) { }
        return null;
    }

    private static boolean hasReplyField(String body) {
        if (body == null) return false;
        try {
            JSONObject o = new JSONObject(body);
            JSONObject scope = o.optJSONObject("data"); if (scope == null) scope = o;
            return matchingStringKey(scope, REPLY_KEYS) != null;
        } catch (JSONException ignore) { }
        return false;
    }

    /**
     * The first STRING-valued key in the object whose name matches one of {@code tokens}, in token-priority order.
     * Matching is SEGMENT-aware: the key is split on camelCase/snake/dash boundaries, so a compound name like
     * {@code user_input} / {@code finalResponse} matches the base token ({@code input} / {@code response}) while a
     * word that merely CONTAINS the token as a substring ({@code context} ⊅ {@code text}, {@code valid} ⊅ {@code id})
     * does not. This is what lets detection work on real-world APIs that never use the bare OpenAI field names.
     */
    private static String matchingStringKey(JSONObject o, String[] tokens) {
        for (String t : tokens)
            for (String k : o.keySet()) {
                Object v = o.opt(k);
                if (v instanceof String && !((String) v).isBlank() && keySegments(k).contains(t)) return k;
            }
        return null;
    }

    /** A key split into lowercase segments (camelCase + snake/dash/dot/space boundaries), plus the whole key. */
    private static java.util.Set<String> keySegments(String key) {
        java.util.Set<String> segs = new java.util.HashSet<>();
        if (key == null) return segs;
        String n = key.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase();
        for (String s : n.split("[_.\\- ]")) if (!s.isEmpty()) segs.add(s);
        segs.add(n);
        return segs;
    }

    private static boolean hasChoicesMessage(String body) {
        if (body == null) return false;
        try {
            JSONObject o = new JSONObject(body);
            JSONObject scope = o.optJSONObject("data"); if (scope == null) scope = o;
            JSONArray ch = scope.optJSONArray("choices");
            return ch != null && ch.length() > 0 && ch.optJSONObject(0) != null
                    && (ch.optJSONObject(0).has("message") || ch.optJSONObject(0).has("text"));
        } catch (JSONException ignore) { return false; }
    }

    private static boolean looksOpenAiRequest(String body) {
        if (body == null || body.isBlank()) return false;
        try {
            JSONObject o = new JSONObject(body);
            JSONArray msgs = o.optJSONArray("messages");
            if (msgs != null && msgs.length() > 0) {
                JSONObject m0 = msgs.optJSONObject(0);
                if (m0 != null && m0.has("role") && m0.has("content")) return true;
            }
            // {prompt|input, ...model-config}
            for (String k : PROMPT_KEYS) if (o.has(k)) {
                if (o.has("model") || o.has("max_tokens") || o.has("temperature") || o.has("stream")) return true;
            }
        } catch (JSONException ignore) { }
        return false;
    }

    private static String safeBody(HttpRequest req) {
        try { return req.bodyToString(); } catch (Throwable t) { return ""; }
    }
}
