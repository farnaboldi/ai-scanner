package com.ioactive.aiscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;

import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Burp's BUILT-IN AI engine ({@code api.ai()}) — the App-Store-preferred backend: it uses the user's own
 * Burp AI (their consent + credits), so no scan data is sent to a third-party endpoint the extension picked.
 * All targeting/triage prompts come from {@link PromptAiEngine}; this class only maps {@code chat()} onto
 * {@code api.ai().prompt().execute(...)}. Availability is {@code api.ai().isEnabled()} (subscription + the
 * user's per-extension AI opt-in), re-checked on every call.
 */
public final class MontoyaAiEngine extends PromptAiEngine {

    private final MontoyaApi api;
    private final EngineConfig cfg;
    private final Consumer<String> logger;

    // ---- Burp AI credit-watch (Burp AI is PAID; every prompt spends credits, and PromptResponse exposes no
    // token/credit field, so we ESTIMATE tokens from text length ~ chars/4 and keep a running JVM-session tally.
    // One scan == one JVM launch here (exitOnComplete quits Burp), so the session total == the per-scan total). ----
    private static final AtomicLong CALLS = new AtomicLong();
    private static final AtomicLong IN_TOKENS = new AtomicLong();
    private static final AtomicLong OUT_TOKENS = new AtomicLong();
    /** Rough token estimate (~4 chars/token) — good enough to track credit burn and project scans-per-budget. */
    static long estTokens(String s) { return (s == null || s.isEmpty()) ? 0L : Math.max(1L, (s.length() + 3L) / 4L); }
    public static long totalCalls() { return CALLS.get(); }
    public static long totalInTokens() { return IN_TOKENS.get(); }
    public static long totalOutTokens() { return OUT_TOKENS.get(); }
    public static long totalTokens() { return IN_TOKENS.get() + OUT_TOKENS.get(); }

    // ---- Burp AI credit balance (Montoya exposes NO API for it; Burp caches it in WorkspaceConfig.json,
    // refreshed on sync/exit). We snapshot it on the FIRST AI call (true pre-scan balance, before it bills)
    // and read it again at scan end, so the log shows start / end / spent. ----
    private static volatile String scanStartCredits = null;
    private static final AtomicBoolean CREDIT_START_LOGGED = new AtomicBoolean(false);
    public static String scanStartCredits() { return scanStartCredits; }
    /** Best-effort read of Burp's cached AI credit balance. Returns null if unavailable. */
    public static String readCreditBalance() {
        try {
            java.nio.file.Path p = java.nio.file.Path.of(System.getProperty("user.home"), ".BurpSuite", "WorkspaceConfig.json");
            if (!java.nio.file.Files.exists(p)) return null;
            org.json.JSONObject ai = new org.json.JSONObject(java.nio.file.Files.readString(p)).optJSONObject("ai_credits");
            if (ai == null) return null;
            String b = ai.optString("last_known_balance", "");
            return b.isEmpty() ? null : b;
        } catch (Throwable t) { return null; }
    }

    // ---- Burp AI CREDIT EXHAUSTION: Burp AI is PAID; when the balance hits 0, prompt().execute() fails. Montoya
    // exposes NO balance/error code, so we DETECT it by the error signature (broad keyword set), then HALT: set a
    // session-wide flag so (1) further chat() calls short-circuit instead of re-failing and burning wall-clock, and
    // (2) the scan's cancelled() check stops launching more tests. Logged UNMISTAKABLY once. Override the halt with
    // -Daiscanner.haltOnCreditExhaustion=false to instead DEGRADE (deterministic probes/auth/audit keep running).
    private static volatile boolean CREDITS_EXHAUSTED = false;
    public static boolean creditsExhausted() { return CREDITS_EXHAUSTED; }
    private static final AtomicBoolean EXHAUSTION_LOGGED = new AtomicBoolean(false);
    private static final java.util.regex.Pattern CREDIT_ERR = java.util.regex.Pattern.compile(
            "(?i)credit|insufficient|\\bbalance\\b|exhaust|out of|no (more )?(ai )?credits|top[- ]?up|purchase|"
            + "billing|payment required|\\b402\\b|depleted|run out|quota|subscription (expired|inactive|required)");
    // A TRANSIENT rate limit ("too many requests" / 429) is NOT credit exhaustion — it retries. Don't halt on it.
    private static final java.util.regex.Pattern RATE_LIMIT = java.util.regex.Pattern.compile(
            "(?i)rate.?limit|too many request|\\b429\\b|slow down");
    private static boolean looksLikeCreditExhaustion(String msg) {
        if (msg == null || RATE_LIMIT.matcher(msg).find()) return false;
        return CREDIT_ERR.matcher(msg).find();
    }
    /** Corroborating signal for when Burp AI's error wording is unknown: an AI call FAILED and the cached balance
     *  reads a clear numeric 0 (null/unreadable → not assumed exhausted, to avoid false halts). */
    private static boolean creditBalanceEmpty() {
        String b = readCreditBalance();
        if (b == null || b.isBlank()) return false;
        try { return Double.parseDouble(b.replaceAll("[^0-9.\\-]", "")) <= 0.0; } catch (Exception e) { return false; }
    }

    public MontoyaAiEngine(MontoyaApi api, EngineConfig cfg, Consumer<String> logger) {
        this.api = api;
        this.cfg = cfg;
        this.logger = logger != null ? logger : s -> { };
    }

    @Override public String name() { return "Burp AI (built-in)"; }

    @Override
    public boolean isConfigured() {
        if (CREDITS_EXHAUSTED) return false;   // out of credits → treat as unavailable so preflight/health reflect it
        try { return api.ai().isEnabled(); } catch (Throwable t) { return false; }
    }

    /** Don't spend a paid Burp AI credit just to health-check — the isEnabled() gate is the cheap test. */
    @Override public boolean testConnection() { return isConfigured(); }

    /** Retry attempts for a single prompt (flaky connectivity to Burp AI is common — a dropped call is wasted). */
    private static final int MAX_ATTEMPTS = 3;
    private static final long[] BACKOFF_MS = { 3000L, 8000L, 15000L };
    private static final AtomicLong TRANSIENT_FAILS = new AtomicLong();
    public static long totalTransientFails() { return TRANSIENT_FAILS.get(); }

    @Override
    public String chat(String systemPrompt, String userPrompt) {
        setLastError("");
        if (CREDITS_EXHAUSTED) {   // already detected this session — don't re-attempt a doomed paid call
            setLastError("Burp AI credits exhausted — AI calls disabled for the rest of this session.");
            return "";
        }
        try {
            if (!api.ai().isEnabled()) {
                setLastError("Burp AI not enabled for this extension. Turn on Settings → AI, then reload this "
                        + "extension and approve the AI-access prompt Burp shows. Or switch to a local LLM in the "
                        + "AI Scanner Settings tab — no Burp AI needed.");
                return "";
            }
        } catch (Throwable t) {
            setLastError("Burp AI availability check failed: " + t);
            return "";
        }
        // First AI call of the scan: snapshot + log the pre-scan credit balance (before this call bills).
        if (CREDIT_START_LOGGED.compareAndSet(false, true)) {
            scanStartCredits = readCreditBalance();
            if (scanStartCredits != null)
                logger.accept("[AI Scanner] Burp AI credits available (start of scan): " + scanStartCredits);
        }
        PromptOptions opts = PromptOptions.promptOptions().withTemperature(clampTemp(cfg.temperature));
        Message[] msgs = (systemPrompt != null && !systemPrompt.isEmpty())
                ? new Message[]{ Message.systemMessage(systemPrompt), Message.userMessage(userPrompt == null ? "" : userPrompt) }
                : new Message[]{ Message.userMessage(userPrompt == null ? "" : userPrompt) };

        // Retry transient "Burp can't connect to Burp AI / try again later" failures with backoff, so a flaky
        // connection doesn't silently drop a call (and waste the intent). Non-transient errors fail fast.
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                PromptResponse resp = api.ai().prompt().execute(opts, msgs);
                String content = resp == null || resp.content() == null ? "" : resp.content().trim();
                // Credit-watch: estimate this call's token cost and log a running session tally so the PAID Burp
                // AI burn is always visible in the log (local logging is free; Burp calls cost credits).
                long pin = estTokens(systemPrompt) + estTokens(userPrompt);
                long pout = estTokens(content);
                long n = CALLS.incrementAndGet();
                long tin = IN_TOKENS.addAndGet(pin);
                long tout = OUT_TOKENS.addAndGet(pout);
                logger.accept(String.format(
                        "[AI Scanner] Burp AI $$ call #%d: ~%d in + ~%d out = ~%d tok | session: %d calls, ~%d tok (~%d in / ~%d out)",
                        n, pin, pout, pin + pout, n, tin + tout, tin, tout));
                if (cfg.verbose) {
                    String c = content.replaceAll("\\s+", " ").trim();
                    if (c.length() > 160) c = c.substring(0, 160) + "…";
                    logger.accept("[AI Scanner] Burp AI ← " + c);
                }
                return content;
            } catch (Throwable e) {   // PromptException is a RuntimeException — cover it and any transport error
                setLastError(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()));
                String m = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
                // CREDIT EXHAUSTION — the paid balance is gone: stop, don't retry (a retry can't refill it).
                // Detected by the error signature, OR corroborated by a cached balance that reads 0 on this failure.
                if (looksLikeCreditExhaustion(lastError()) || creditBalanceEmpty()) {
                    CREDITS_EXHAUSTED = true;
                    if (EXHAUSTION_LOGGED.compareAndSet(false, true)) {
                        String bal = readCreditBalance();
                        boolean degrade = "false".equalsIgnoreCase(System.getProperty("aiscanner.haltOnCreditExhaustion", "true"));
                        logger.accept("[AI Scanner] *** BURP AI CREDITS EXHAUSTED *** — " + lastError()
                                + ". Credits at scan start: " + (scanStartCredits == null ? "?" : scanStartCredits)
                                + (bal == null ? "" : " -> now: " + bal) + ". Burp AI spend this session: " + CALLS.get()
                                + " call(s), ~" + (IN_TOKENS.get() + OUT_TOKENS.get()) + " tok. Further AI calls are "
                                + "skipped" + (degrade
                                    ? "; deterministic probes/auth/native audit CONTINUE (haltOnCreditExhaustion=false)."
                                    : "; the scan will STOP at the next checkpoint. Set -Daiscanner.haltOnCreditExhaustion=false "
                                      + "to keep the credit-free deterministic layer running instead."));
                    }
                    return "";
                }
                boolean transientErr = m.contains("try again") || m.contains("connect") || m.contains("tim")
                        || m.contains("temporar") || m.contains("unavailable") || m.contains("reset");
                if (attempt < MAX_ATTEMPTS && transientErr) {
                    TRANSIENT_FAILS.incrementAndGet();
                    long wait = BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)];
                    logger.accept("[AI Scanner] Burp AI transient failure (attempt " + attempt + "/" + MAX_ATTEMPTS
                            + ", connectivity): " + lastError() + " — retrying in " + (wait / 1000) + "s");
                    try { Thread.sleep(wait); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return ""; }
                    continue;
                }
                logger.accept("[AI Scanner] Burp AI call failed" + (transientErr ? " (gave up after " + MAX_ATTEMPTS + " tries)" : "") + ": " + lastError());
                return "";
            }
        }
        return "";
    }

    /** Burp AI accepts a temperature in [0,1]; keep our shared default sane if a wild value was entered. */
    private static double clampTemp(double t) { return t < 0 ? 0 : (t > 1 ? 1 : t); }
}
