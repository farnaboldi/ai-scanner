package com.ioactive.aiscanner.scan;

import com.ioactive.aiscanner.vulns.VulnClass;
import com.ioactive.aiscanner.vulns.VulnClasses;

import java.util.List;

/** Tunables for the adaptive attack loop (surfaced in the settings tab). */
public final class ScanConfig {

    /** Which scan mode to run. DAST = black-box probes only; SAST = route discovery + Burp native audit only;
     *  DAST_SAST = full pipeline (SAST hints + all extension probes + Burp native audit). */
    public enum ScanMode { DAST, SAST, DAST_SAST }
    public volatile ScanMode scanMode = ScanMode.DAST_SAST;

    public volatile int rounds = 2;             // adaptive refine rounds per (insertion point, class)
    public volatile int payloadsPerRound = 6;   // LLM payloads requested each round
    public volatile int delayMs = 100;          // politeness delay between attack requests
    public volatile int requestTimeoutMs = 12000; // per-request response timeout for probe→target HTTP sends
    public volatile boolean logToFile = false;    // mirror the scan log + chat to a file (Settings toggle / -Daiscanner.logFile)
    public volatile String logFilePath = "";      // destination path when logToFile is on
    public volatile List<VulnClass> enabledClasses = VulnClasses.all();

    /** Hard cap on attack requests per (insertion point, class) to bound cost. */
    public int maxRequestsPerClass() {
        return Math.max(1, rounds) * Math.max(1, payloadsPerRound) + 8; // +8 for fallback seeds
    }
}
