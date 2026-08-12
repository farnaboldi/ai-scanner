package com.ioactive.aiscanner.engine;

/**
 * Connection + sampling configuration for an {@link AiEngine}.
 * Immutable; rebuilt from the settings UI whenever the user changes something.
 */
public final class EngineConfig {

    /** Which AI backend powers targeting/triage. */
    public enum Provider {
        /** Burp's built-in AI ({@code api.ai()}) — App-Store preferred; uses the user's own Burp AI. */
        BURP_AI,
        /** A user-run OpenAI-compatible server (vLLM / llama.cpp / Ollama / LM Studio / OpenAI). */
        LOCAL_LLM,
        /** Deterministic-only: NO LLM at all — auth + probes + native audit run, LLM discovery/triage skipped.
         *  The benchmark "no-ai" baseline, and a live A/B toggle vs the LLM providers. getEngine() returns null. */
        NO_AI
    }

    public final Provider provider;
    public final String baseUrl;        // e.g. http://127.0.0.1:8000/v1  (LOCAL_LLM only)
    public final String model;          // model name; may be blank if the server infers a default (vLLM)
    public final String apiKey;         // Bearer token; blank = no Authorization header
    public final double temperature;    // applied by BOTH providers
    public final int maxTokens;         // LOCAL_LLM only
    public final boolean disableThinking; // send chat_template_kwargs.enable_thinking=false (Qwen/vLLM)
    public final int timeoutSeconds;    // LOCAL_LLM only
    // NOTE: log verbosity is NOT here anymore — it's a single global {@link LogLevel} (INFO/DEBUG/TRACE), selected
    // from Settings + CLI, independent of the engine connection config.

    public EngineConfig(Provider provider, String baseUrl, String model, String apiKey, double temperature,
                        int maxTokens, boolean disableThinking, int timeoutSeconds) {
        this.provider = provider == null ? Provider.LOCAL_LLM : provider;
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim();
        this.model = model == null ? "" : model.trim();
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.temperature = temperature;
        this.maxTokens = maxTokens <= 0 ? 512 : maxTokens;
        this.disableThinking = disableThinking;
        this.timeoutSeconds = timeoutSeconds <= 0 ? 120 : timeoutSeconds;
    }

    /** Back-compat constructor — a LOCAL_LLM (OpenAI-compatible) engine (used by the launcher override). */
    public EngineConfig(String baseUrl, String model, String apiKey, double temperature,
                        int maxTokens, boolean disableThinking, int timeoutSeconds) {
        this(Provider.LOCAL_LLM, baseUrl, model, apiKey, temperature, maxTokens, disableThinking, timeoutSeconds);
    }

    /** The chat-completions URL, tolerating base URLs with or without a trailing slash / suffix. */
    public String chatCompletionsUrl() {
        String b = baseUrl;
        while (b.endsWith("/")) b = b.substring(0, b.length() - 1);
        if (b.endsWith("/chat/completions")) return b;
        return b + "/chat/completions";
    }

    /** Burp AI needs no local endpoint; a local engine needs a base URL. (Actual Burp-AI availability is
     *  {@code api.ai().isEnabled()}, checked by the engine at call time.) */
    public boolean isConfigured() {
        return provider == Provider.BURP_AI || !baseUrl.isBlank();
    }
}
