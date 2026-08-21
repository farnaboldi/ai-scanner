package com.ioactive.aiscanner.scan;

/**
 * Single source of truth for the numeric exploration / timeout knobs that BOUND COVERAGE. Each accessor reads
 * {@code -Daiscanner.<prop>} or {@code AISCANNER_<ENV>} at CALL TIME — so a per-run override needs no rebuild and a
 * Settings-tab change applies to the next scan — clamped to a sane range, else the default. The Settings tab
 * reads/writes the SAME system properties, so the UI and the CLI can never diverge (same pattern as ScanPhases for
 * the module list). Keep every exploration-limiting constant here, not scattered as private static finals, so what
 * limits the scan is discoverable in one place and configurable.
 */
public final class Tuning {
    private Tuning() {}

    // ---- Crawl reach (authenticated self-crawl BFS in AiContextMenuProvider.seedSiteMap) ----
    /** Breadth cap: max pages the self-crawl fetches. Low values starve deep pages (labs behind category hubs). */
    public static int crawlPages()   { return i("aiscanner.crawlPages",   "AISCANNER_CRAWL_PAGES",   60,  5, 1000); }
    /** Depth cap: how many link-clicks deep the self-crawl follows from the landing page. */
    public static int crawlDepth()   { return i("aiscanner.crawlDepth",   "AISCANNER_CRAWL_DEPTH",    3,  1,    8); }
    /** Max seconds to wait for Burp's native crawl to stabilise before proceeding (the waitForCrawl deadline). */
    public static int crawlWaitSec() { return i("aiscanner.crawlWaitSec", "AISCANNER_CRAWL_WAIT_SEC",240, 20, 1800); }

    // ---- Discovery budgets (EndpointDiscovery) ----
    /** Max client-side sources (pages/scripts) mined per host. */
    public static int maxSources()    { return i("aiscanner.maxSources",    "AISCANNER_MAX_SOURCES",    40,  5,  300); }
    /** Max ~30k-char chunks fed to the LLM per discovery round. */
    public static int maxLlmChunks()  { return i("aiscanner.maxLlmChunks",  "AISCANNER_MAX_LLM_CHUNKS",  8,  1,   40); }
    /** Max candidate endpoints probed (the deterministic probe budget). */
    public static int maxCandidates() { return i("aiscanner.maxCandidates","AISCANNER_MAX_CANDIDATES", 200, 10, 2000); }

    // ---- Stall watchdog (ScanLog) — detect a scan that stops emitting progress because a phase blocked on a hung
    //      Burp/Collaborator/LLM call, so a wedged scan surfaces (with a thread-stack dump) in minutes instead of
    //      sitting silent for hours. Progress = any log line; the clock resets on every line and the watchdog's own
    //      output is excluded so a continuing stall keeps being reported. ----
    /** Seconds with NO log output before the watchdog dumps the scan threads' stacks (repeats each interval while
     *  still stalled). Set ABOVE the longest LEGITIMATELY-quiet wait so a healthy scan stays silent: a single LLM
     *  call is bounded by llmHardDeadlineMs (default 180s, ×parallelism), so the default (240s) clears one normal
     *  call. OOB Collaborator polls also run ~quiet — lower this only for debugging a suspected hang. */
    public static int stallWarnSec()  { return i("aiscanner.stallWarnSec",  "AISCANNER_STALL_WARN_SEC",  240, 15,  3600); }
    /** Seconds with NO log output before the watchdog force-ends a truly wedged scan (via the Stop handler), so an
     *  infinite hang self-terminates instead of blocking the run for hours. Must exceed any slow-but-progressing
     *  phase (worst case ≈ llmHardDeadlineMs × max parallelism ≈ 1440s at 8×). 0 disables the auto-abort. */
    public static int stallAbortSec() { return i("aiscanner.stallAbortSec", "AISCANNER_STALL_ABORT_SEC", 2400, 0, 21600); }

    /** Read an int knob from {@code -Dprop} / {@code ENV}, clamped to [min,max]; the default when unset/unparseable. */
    public static int i(String prop, String env, int def, int min, int max) {
        String v = System.getProperty(prop);
        if (v == null || v.isBlank()) v = System.getenv(env);
        if (v == null || v.isBlank()) return def;
        try { return Math.max(min, Math.min(max, Integer.parseInt(v.trim()))); }
        catch (NumberFormatException e) { return def; }
    }
}
