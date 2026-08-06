package com.ioactive.aiscanner.engine;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * OpenAI-compatible chat/completions engine (vLLM, llama.cpp, Ollama /v1,
 * LM Studio, OpenAI, ...). Handles Qwen "thinking" models: optionally sends
 * {@code chat_template_kwargs.enable_thinking=false} and tolerates a null
 * {@code content} by falling back to {@code reasoning}/{@code reasoning_content}.
 *
 * <p>All the higher-level tasks live in {@link PromptAiEngine}; this class only supplies transport + chat().
 */
public final class LocalAiEngine extends PromptAiEngine {

    private static final String THINK_REGEX = "(?s)<think>.*?</think>";

    private final EngineConfig cfg;
    private final LlmHttp http;
    private final Consumer<String> logger;

    public LocalAiEngine(EngineConfig cfg, LlmHttp http, Consumer<String> logger) {
        this.cfg = cfg;
        this.http = http;
        this.logger = logger != null ? logger : s -> { };
    }

    @Override public String name() { return "Local (OpenAI-compatible)"; }

    @Override public boolean isConfigured() { return cfg.isConfigured(); }

    /** A self-hosted LLM the user explicitly selected: if it's unreachable, ABORT rather than degrade silently. */
    @Override public boolean requiresReachableEndpoint() { return true; }

    @Override
    public String chat(String systemPrompt, String userPrompt) {
        setLastError("");
        if (cfg.baseUrl.isBlank()) { setLastError("Engine not configured (base URL missing)."); return ""; }
        try {
            JSONArray messages = new JSONArray();
            if (systemPrompt != null && !systemPrompt.isEmpty()) {
                messages.put(new JSONObject().put("role", "system").put("content", systemPrompt));
            }
            messages.put(new JSONObject().put("role", "user").put("content", userPrompt == null ? "" : userPrompt));

            JSONObject body = new JSONObject();
            if (!cfg.model.isBlank()) body.put("model", cfg.model);
            body.put("messages", messages);
            body.put("max_tokens", cfg.maxTokens);
            body.put("temperature", cfg.temperature);
            body.put("stream", false);
            if (cfg.disableThinking) {
                body.put("chat_template_kwargs", new JSONObject().put("enable_thinking", false));
            }

            List<String> headers = new ArrayList<>();
            if (!cfg.apiKey.isBlank()) headers.add("Authorization: Bearer " + cfg.apiKey);

            if (cfg.verbose) {   // log the OUTGOING prompt too (not just the response), so the query is debuggable
                String u = (userPrompt == null ? "" : userPrompt).replaceAll("\\s+", " ").trim();
                if (u.length() > 300) u = u.substring(0, 300) + "…";
                logger.accept("[AI Scanner] LLM → " + u);
            }
            String raw = http.postJson(cfg.chatCompletionsUrl(), body.toString(), headers);
            String content = extractContent(raw);
            if (cfg.verbose) {
                String c = content.replaceAll("\\s+", " ").trim();
                if (c.length() > 160) c = c.substring(0, 160) + "…";
                logger.accept("[AI Scanner] LLM ← " + c);
            }
            return content;
        } catch (Exception e) {
            setLastError(e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage())
                    + "  (URL: " + cfg.chatCompletionsUrl() + ")");
            logger.accept("[AI Scanner] LLM call failed: " + lastError());
            return "";
        }
    }

    /** Extract choices[0].message.content, tolerating thinking models (null content). */
    static String extractContent(String responseBody) {
        JSONObject root = new JSONObject(responseBody);
        JSONObject message = root.getJSONArray("choices").getJSONObject(0).getJSONObject("message");
        String content = message.optString("content", "");
        if (content.isEmpty()) {
            if (!message.isNull("reasoning")) content = message.optString("reasoning", "");
            else if (!message.isNull("reasoning_content")) content = message.optString("reasoning_content", "");
        }
        return content.replaceAll(THINK_REGEX, "").trim();
    }
}
