package com.ioactive.aiscanner.scan;

import com.ioactive.aiscanner.ui.ScanLog;

import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Adaptive concurrency throttle for the read-only parallel probe slice (behind {@code -Daiscanner.concurrency}).
 *
 * <p>Starts at {@code concurrency} in-flight UNITS. On a rate-limit signal (HTTP 429/503) it (a) opens a short
 * backoff window that every worker waits out before its next unit, and (b) PERMANENTLY shrinks the effective
 * concurrency toward 1 — so a rate-limited or fragile target degrades to sequential instead of getting hammered.
 * This is the exact self-sabotage we must avoid: parallel bursts trip 429s that then block our own auth/probes.
 * Conservative by design — once a host shows rate limiting we stay slow (never ramp back up mid-scan).
 *
 * <p>Generic and per-scan: no app knowledge, only HTTP status. {@link #observe} is fed from the probe's single
 * send chokepoint so a 429 caused by ANY worker throttles the whole pool.
 */
public final class Throttle {

    private final Semaphore slots;          // available in-flight unit permits (shrinks on rate limiting)
    private final AtomicInteger effective;  // current effective concurrency (floor 1)
    private final ScanLog log;
    private volatile long backoffUntilMs = 0;

    public Throttle(int concurrency, ScanLog log) {
        int c = Math.max(1, concurrency);
        this.slots = new Semaphore(c, true);
        this.effective = new AtomicInteger(c);
        this.log = log;
    }

    public int concurrency() { return effective.get(); }

    /** Acquire a slot before running one unit; waits out any active backoff window and respects a shrunk pool. */
    public void acquire() throws InterruptedException {
        long wait = backoffUntilMs - System.currentTimeMillis();
        if (wait > 0) Thread.sleep(Math.min(wait, 15_000L));
        slots.acquire();
    }

    public void release() { slots.release(); }

    /**
     * Feed every probe RESPONSE status here. On 429/503: open a 10s backoff window and take one permit
     * permanently out of circulation (down to a floor of 1) — so the pool converges to the rate the target
     * tolerates. No-op on any other status.
     */
    public void observe(int status) {
        if (status != 429 && status != 503) return;
        backoffUntilMs = System.currentTimeMillis() + 10_000L;
        synchronized (this) {
            if (effective.get() > 1 && slots.tryAcquire()) {   // hold this permit forever → -1 effective concurrency
                int now = effective.decrementAndGet();
                if (log != null) log.log("throttle: HTTP " + status
                        + " (rate limit) → concurrency reduced to " + now + " + 10s backoff");
            }
        }
    }
}
