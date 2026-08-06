package com.ioactive.aiscanner.vulns;

/** Result of a deterministic oracle check on a single mutated response. */
public final class Signal {

    public enum Confidence { FIRM, TENTATIVE }

    public final boolean hit;
    public final String evidence;       // short human-readable proof (matched string, timing, etc.)
    public final Confidence confidence;

    private Signal(boolean hit, String evidence, Confidence confidence) {
        this.hit = hit;
        this.evidence = evidence == null ? "" : evidence;
        this.confidence = confidence;
    }

    public static Signal miss() { return new Signal(false, "", Confidence.TENTATIVE); }

    public static Signal hit(String evidence, Confidence confidence) {
        return new Signal(true, evidence, confidence);
    }
}
