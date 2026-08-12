package com.ioactive.aiscanner.engine;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Session-wide LLM latency accounting for the benchmark's speed column. Both engines
 * ({@link LocalAiEngine}, {@link MontoyaAiEngine}) wrap their network chat() call with
 * {@link #record(long)} so we can report, at scan end, how much of the wall-clock was
 * spent WAITING ON THE MODEL — the part that varies by model and explains "why is X slower".
 * Reset per scan at run start so numbers are per-scan, not cumulative across a GUI session.
 */
public final class LlmTiming {
    private LlmTiming() { }
    private static final AtomicLong CALLS = new AtomicLong();
    private static final AtomicLong TOTAL_MS = new AtomicLong();
    private static final AtomicLong MAX_MS = new AtomicLong();

    /** Record one completed LLM call's latency in milliseconds (success or fail — both cost wall-clock). */
    public static void record(long ms) {
        if (ms < 0) ms = 0;
        CALLS.incrementAndGet();
        TOTAL_MS.addAndGet(ms);
        long cur;
        while (ms > (cur = MAX_MS.get()) && !MAX_MS.compareAndSet(cur, ms)) { /* retry */ }
    }

    /** Zero the counters at the start of a scan so the summary is per-scan. */
    public static void reset() { CALLS.set(0); TOTAL_MS.set(0); MAX_MS.set(0); }

    public static long calls()    { return CALLS.get(); }
    public static long totalMs()  { return TOTAL_MS.get(); }

    /** One-line human summary, or null when no LLM call was made (e.g. no-ai / native-only). */
    public static String summary() {
        long n = CALLS.get();
        if (n <= 0) return null;
        long tot = TOTAL_MS.get();
        long avg = tot / n;
        long max = MAX_MS.get();
        return "LLM latency: " + fmt(tot) + " total across " + n + " call(s)  (avg " + avg + "ms, slowest " + fmt(max) + ")";
    }

    private static String fmt(long ms) {
        if (ms < 1000) return ms + "ms";
        long s = ms / 1000;
        return s >= 60 ? (s / 60) + "m " + (s % 60) + "s" : s + "s";
    }
}
