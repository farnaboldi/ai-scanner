package com.ioactive.aiscanner.vulns;

/**
 * Deterministic detection for one vuln class. Pure (strings only) so it is
 * unit-testable off-Burp. It compares a mutated response against the baseline;
 * timing is provided for time-based checks and the payload for reflection/canary
 * checks.
 */
@FunctionalInterface
public interface Oracle {
    Signal detect(String baselineBody, String mutatedBody, long timingMs, String payload);
}
