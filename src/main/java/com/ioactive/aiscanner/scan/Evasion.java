package com.ioactive.aiscanner.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/**
 * WAF-evasion mode — a toggle that makes the probes ALSO send obfuscated variants of their payloads, so a
 * signature WAF (e.g. ModSecurity + OWASP CRS) that blocks the naive payload lets the equivalent obfuscated
 * one through. Purpose: A/B a target with and without a WAF — scan the unprotected origin to learn the true
 * findings, then scan the WAF-fronted host WITH evasion on to see whether the WAF actually stops the scanner
 * or merely its naive requests. Enabled via -Daiscanner.wafEvasion=true or AISCANNER_WAF_EVASION=true (the
 * Settings checkbox flips the same system property).
 *
 * <p>The transforms are the same tricks a real tester uses and are semantics-preserving — the server decodes
 * them back to the original payload, so a positive finding is still real.
 */
public final class Evasion {
    private Evasion() {}

    public static boolean enabled() {
        if (Boolean.getBoolean("aiscanner.wafEvasion")) return true;
        String e = System.getenv("AISCANNER_WAF_EVASION");
        return e != null && e.equalsIgnoreCase("true");
    }

    /**
     * Unicode-escape the leading '$' of Mongo operator keys in a JSON body: {@code "$ne"} → {@code "$ne"}.
     * A JSON parser decodes {@code $} back to '$', so the operator still reaches the query, but a WAF rule
     * matching a literal {@code "$op"} in the raw body no longer sees it (validated bypass of OWASP CRS 942290
     * and of naive custom rules). Only rewrites a '$' that immediately follows a quote (a key position).
     */
    public static String jsonDollarEscape(String jsonBody) {
        if (jsonBody == null) return null;
        return jsonBody.replaceAll("\"\\$", Matcher.quoteReplacement("\"\\u0024"));
    }

    /**
     * Obfuscated variants of a SQL-injection payload that are semantically identical but defeat common
     * signature matches: inline SQL comments between keywords, random case, and both combined. The server's
     * SQL parser ignores inline comments and is case-insensitive, so the injection still runs.
     */
    public static List<String> sqlVariants(String payload) {
        List<String> out = new ArrayList<>();
        if (payload == null || payload.isBlank()) return out;
        final String INLINE = "/" + "**" + "/";      // inline SQL comment, built to avoid a Javadoc terminator
        // inline comments replacing spaces (e.g. "OR 1=1" -> "OR<inline-comment>1=1")
        out.add(payload.replaceAll("\\s+", Matcher.quoteReplacement(INLINE)));
        // random-ish case flip of alpha keywords (OR → oR, UNION → UnIoN, SELECT → SeLeCt)
        out.add(caseFlip(payload));
        // both
        out.add(caseFlip(payload).replaceAll("\\s+", Matcher.quoteReplacement(INLINE)));
        return out;
    }

    /** Alternate the case of alphabetic characters — evades case-sensitive signature fragments. */
    public static String caseFlip(String s) {
        StringBuilder sb = new StringBuilder();
        boolean up = false;
        for (char c : s.toCharArray()) {
            if (Character.isLetter(c)) { sb.append(up ? Character.toUpperCase(c) : Character.toLowerCase(c)); up = !up; }
            else sb.append(c);
        }
        return sb.toString();
    }
}
