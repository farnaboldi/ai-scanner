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

    // Per-call seed sequence. Two purposes at once: (1) every request is UNIQUE → it can't hit a prompt/response
    // cache (server or Burp-transport), so a repeated N-round discovery pass actually re-samples instead of
    // returning a cached/empty reply; (2) the sequence is DETERMINISTIC (1,2,3… in a fixed call order, reset per
    // scan) → two scans send the same seeds → identical results, so temp>0 becomes REPRODUCIBLE across runs while
    // still diverse ACROSS rounds within a run (round 2's calls get later seeds than round 1 → fresh samples).
    // llama-server honors `seed` (verified: same seed → identical output, different seed → different). At temp=0
    // the seed is irrelevant to the greedy output, so determinism there is unchanged.
    private static final java.util.concurrent.atomic.AtomicLong SEED_SEQ = new java.util.concurrent.atomic.AtomicLong();
    /** Reset the per-call seed sequence at scan start so the seeds (and thus temp>0 output) are reproducible per scan. */
    public static void resetSeed() { SEED_SEQ.set(0); }


    private final EngineConfig cfg;
    private final LlmHttp http;
    private final Consumer<String> logger;

    public LocalAiEngine(EngineConfig cfg, LlmHttp http, Consumer<String> logger) {
        this.cfg = cfg;
        this.http = http;
        this.logger = logger != null ? logger : s -> { };
    }

    @Override public String name() { return "Local (OpenAI-compatible)"; }

    @Override public String paramSummary() {
        return "Local LLM model=" + (cfg.model == null || cfg.model.isBlank() ? "(default)" : cfg.model)
                + " temperature=" + cfg.temperature + " maxTokens=" + cfg.maxTokens;
    }

    @Override public boolean isConfigured() { return cfg.isConfigured(); }

    /** A self-hosted LLM the user explicitly selected: if it's unreachable, ABORT rather than degrade silently. */
    @Override public boolean requiresReachableEndpoint() { return true; }

    /** Reachability probe that SURFACES the real error (the default swallows it) — so a failed api.http() health
     *  check tells us why (connection vs HTTP status vs empty reply), not just "reachable=false". */
    @Override
    public boolean testConnection() {
        try {
            String r = chat("", "reply with the single word OK");
            if (r == null || r.isBlank()) {
                logger.accept("[AI Scanner] LLM health check: empty reply (lastError=" + lastError() + ")");
                return false;
            }
            return true;
        } catch (Throwable t) {
            logger.accept("[AI Scanner] LLM health check FAILED: " + t);
            return false;
        }
    }

    @Override
    public String chat(String systemPrompt, String userPrompt) { return chat(systemPrompt, userPrompt, ""); }

    @Override
    public String chat(String systemPrompt, String userPrompt, String label) {
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
            long seed = SEED_SEQ.incrementAndGet();
            body.put("seed", seed);   // unique per call → cache-proof + reproducible (see SEED_SEQ)
            if (cfg.disableThinking) {
                body.put("chat_template_kwargs", new JSONObject().put("enable_thinking", false));
            }

            List<String> headers = new ArrayList<>();
            if (!cfg.apiKey.isBlank()) headers.add("Authorization: Bearer " + cfg.apiKey);

            if (LogLevel.trace()) {   // TRACE: dump the OUTGOING prompt body (deepest detail)
                String u = (userPrompt == null ? "" : userPrompt).replaceAll("\\s+", " ").trim();
                if (u.length() > 300) u = u.substring(0, 300) + "…";
                logger.accept("[AI Scanner] LLM → " + u);
            }
            long t0 = System.currentTimeMillis();
            String raw;
            try {
                raw = http.postJson(cfg.chatCompletionsUrl(), body.toString(), headers);
            } catch (Exception transport) {
                // Transport failure (hard-deadline hit / HTTP 0 / connection reset under load) — retry ONCE with a
                // fresh seed so a single blip doesn't silently drop a discovery/payload call. If the retry also
                // fails it propagates to the outer catch and we return "" as before.
                body.put("seed", SEED_SEQ.incrementAndGet());
                raw = http.postJson(cfg.chatCompletionsUrl(), body.toString(), headers);
            }
            String content = extractContent(raw);
            // Retry ONCE on an empty reply. Thinking models (qwen/vLLM) intermittently return empty content even with
            // enable_thinking=false (~1-in-4 observed) — a blank payload silently degrades fuzzing to a no-op. A fresh
            // seed + a small temperature bump breaks the degenerate sample; the SAME exact request returns good content
            // on retry. Only when we asked for a real answer (non-empty prompt) and got nothing back.
            if (content.isBlank() && raw != null && !raw.isEmpty() && userPrompt != null && !userPrompt.isBlank()) {
                body.put("seed", SEED_SEQ.incrementAndGet());
                body.put("temperature", Math.min(1.0, cfg.temperature + 0.3));
                String raw2 = http.postJson(cfg.chatCompletionsUrl(), body.toString(), headers);
                String c2 = extractContent(raw2);
                if (!c2.isBlank()) { raw = raw2; content = c2; }
            }
            LlmTiming.record(System.currentTimeMillis() - t0);   // benchmark speed column: time WAITING on the model
            // Targeted per-call DEBUG (metadata only — NOT the request/response bodies, which are noise): seed +
            // sizes, so an empty/degenerate reply (the "round 2 parsed 0" mystery) is visible as resp=0 (transport
            // returned nothing) vs resp=NNN content=0 (a real reply we failed to parse). On with -Daiscanner.debug.
            if (LogLevel.debug()) logger.accept("[AI Scanner] llm-call "
                    + (label == null || label.isBlank() ? "" : "<" + label + "> ") + "seed=" + seed
                    + " req=" + (userPrompt == null ? 0 : userPrompt.length()) + "ch"
                    + " -> resp=" + (raw == null ? 0 : raw.length()) + "ch content=" + content.length() + "ch"
                    + (raw == null || raw.isEmpty() ? "  [EMPTY TRANSPORT REPLY]" : ""));
            if (LogLevel.trace()) {   // TRACE: dump the full response body (so a parse-to-0 reply can be read)
                String c = content.replaceAll("\\s+", " ").trim();
                if (c.length() > 800) c = c.substring(0, 800) + "…";
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
