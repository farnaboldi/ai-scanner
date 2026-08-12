package com.ioactive.aiscanner.engine;

/**
 * Single source of truth for how chatty the log is. Replaces the old scattered flags (a "verbose" checkbox +
 * a separate "debug" toggle + ad-hoc -Daiscanner.debug reads) with one ordered level, selectable from Settings
 * and the command line (-Daiscanner.logLevel / AISCANNER_LOG_LEVEL).
 *
 *  INFO  (default) — phases + confirmed vulnerabilities only. Clean.
 *  DEBUG           — + diagnostic chatter, discovery internals, and per-LLM-call METADATA (seed + sizes). No bodies.
 *  TRACE           — + full LLM request/response BODIES (the deepest dump; rarely needed).
 */
public enum LogLevel {
    INFO, DEBUG, TRACE;

    private static volatile LogLevel current = INFO;

    public static LogLevel current() { return current; }
    public static void set(LogLevel l) { if (l != null) current = l; }
    /** True at DEBUG or TRACE. */
    public static boolean debug() { return current.ordinal() >= DEBUG.ordinal(); }
    /** True only at TRACE. */
    public static boolean trace() { return current == TRACE; }

    /** Parse a level name (case-insensitive): INFO / DEBUG / TRACE. Unknown or blank → INFO. */
    public static LogLevel parse(String s) {
        if (s == null) return INFO;
        switch (s.trim().toUpperCase()) {
            case "TRACE": return TRACE;
            case "DEBUG": return DEBUG;
            default:      return INFO;
        }
    }
}
