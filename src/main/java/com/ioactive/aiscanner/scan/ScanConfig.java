package com.ioactive.aiscanner.scan;

import com.ioactive.aiscanner.vulns.VulnClass;
import com.ioactive.aiscanner.vulns.VulnClasses;

import java.util.List;

/** Tunables for the adaptive attack loop (surfaced in the settings tab). */
public final class ScanConfig {

    public volatile int rounds = 2;             // adaptive refine rounds per (insertion point, class)
    public volatile int payloadsPerRound = 6;   // LLM payloads requested each round
    public volatile int delayMs = 100;          // politeness delay between attack requests
    public volatile List<VulnClass> enabledClasses = VulnClasses.all();

    /** Hard cap on attack requests per (insertion point, class) to bound cost. */
    public int maxRequestsPerClass() {
        return Math.max(1, rounds) * Math.max(1, payloadsPerRound) + 8; // +8 for fallback seeds
    }
}
