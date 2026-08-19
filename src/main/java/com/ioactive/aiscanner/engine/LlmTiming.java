package com.ioactive.aiscanner.engine;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Per-scan LLM latency accounting for the benchmark's speed column. Both engines
 * ({@link LocalAiEngine}, {@link MontoyaAiEngine}) wrap their network chat() call with
 * {@link #record(long)} so we can report, at scan end, how much of the wall-clock was
 * spent WAITING ON THE MODEL — the part that varies by model and explains "why is X slower".
 *
 * <p>PER-TARGET: keyed by the current scan's {@link com.ioactive.aiscanner.ui.ScanLog#TARGET_TAG} so a PARALLEL
 * two-target run reports each target's OWN latency instead of a blended JVM-wide total. record()/reset()/summary()
 * all run on the target's own thread-lineage, so they resolve to the right bucket automatically. A normal
 * single-target scan uses one default ("") bucket — unchanged behaviour.
 */
public final class LlmTiming {
    private LlmTiming() { }

    private static final class Bucket {
        final AtomicLong calls = new AtomicLong();
        final AtomicLong totalMs = new AtomicLong();
        final AtomicLong maxMs = new AtomicLong();
    }
    private static final ConcurrentHashMap<String, Bucket> BY_TAG = new ConcurrentHashMap<>();

    private static String key() {
        String t = com.ioactive.aiscanner.ui.ScanLog.TARGET_TAG.get();
        return t != null ? t : "";
    }
    private static Bucket cur() { return BY_TAG.computeIfAbsent(key(), k -> new Bucket()); }

    /** Record one completed LLM call's latency in milliseconds (success or fail — both cost wall-clock). */
    public static void record(long ms) {
        if (ms < 0) ms = 0;
        Bucket b = cur();
        b.calls.incrementAndGet();
        b.totalMs.addAndGet(ms);
        long cur;
        while (ms > (cur = b.maxMs.get()) && !b.maxMs.compareAndSet(cur, ms)) { /* retry */ }
    }

    /** Zero THIS scan's counters at run start so the summary is per-scan (drops just the current tag's bucket). */
    public static void reset() { BY_TAG.remove(key()); }

    public static long calls()    { return cur().calls.get(); }
    public static long totalMs()  { return cur().totalMs.get(); }

    /** One-line human summary for the CURRENT scan, or null when it made no LLM call (no-ai / native-only). */
    public static String summary() {
        Bucket b = cur();
        long n = b.calls.get();
        if (n <= 0) return null;
        long tot = b.totalMs.get();
        long avg = tot / n;
        long max = b.maxMs.get();
        return "LLM latency: " + fmt(tot) + " total across " + n + " call(s)  (avg " + avg + "ms, slowest " + fmt(max) + ")";
    }

    private static String fmt(long ms) {
        if (ms < 1000) return ms + "ms";
        long s = ms / 1000;
        return s >= 60 ? (s / 60) + "m " + (s % 60) + "s" : s + "s";
    }
}
