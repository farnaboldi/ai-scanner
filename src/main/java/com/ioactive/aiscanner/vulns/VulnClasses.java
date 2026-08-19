package com.ioactive.aiscanner.vulns;

import java.util.List;

/**
 * Registry of v1 vuln classes. Each is a thin descriptor + a deterministic
 * oracle. Payloads are LLM-generated at scan time; {@code fallbackSeeds} are
 * deterministic canaries the oracle is aligned to (always tried first so the
 * oracle has a reliable signal even if the LLM wanders).
 */
public final class VulnClasses {

    /** Canary token embedded in XSS payloads; the oracle looks for it reflected unescaped. */
    public static final String XSS_CANARY = "ioaxss7";
    /** SSTI arithmetic canary: {@code SSTI_A*SSTI_A} evaluates to SSTI_RESULT iff the template engine runs it.
     *  Product is COMPUTED from the operand — never hand-typed — so the oracle value can't drift from the payload. */
    private static final long SSTI_A = 1337L;
    public static final String SSTI_INPUT = SSTI_A + "*" + SSTI_A;
    public static final String SSTI_RESULT = String.valueOf(SSTI_A * SSTI_A);

    private VulnClasses() { }

    public static List<VulnClass> all() {
        return List.of(sqlInjection(), reflectedXss(), ssti(), pathTraversal());
    }

    private static String lc(String s) { return s == null ? "" : s.toLowerCase(); }

    // ---- SQL Injection: DB error strings that appear only after injection ----
    private static final String[] SQL_ERRORS = {
            "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
            "quoted string not properly terminated", "sqlstate", "ora-00", "ora-01",
            "pg::syntaxerror", "psqlexception", "syntax error at or near", "sqlite3::",
            "sqlite error", "microsoft ole db provider", "odbc sql server driver",
            "native client", "mysql_fetch", "supplied argument is not a valid mysql",
            "org.hibernate", "com.microsoft.sqlserver.jdbc"
    };

    private static VulnClass sqlInjection() {
        Oracle oracle = (base, mutated, timing, payload) -> {
            String m = lc(mutated), b = lc(base);
            for (String sig : SQL_ERRORS) {
                if (m.contains(sig) && !b.contains(sig)) {
                    return Signal.hit("SQL error string in response: \"" + sig + "\"", Signal.Confidence.FIRM);
                }
            }
            return Signal.miss();
        };
        return new VulnClass(
                "SQL Injection",
                "Break the query syntax to elicit a database error (single quote, double quote, "
                        + "comment sequences, boolean/UNION probes). Tailor quoting to the parameter type.",
                VulnClass.Severity.HIGH,
                "Use parameterized queries / prepared statements; never concatenate untrusted input into SQL.",
                oracle,
                List.of("'", "\"", "')", "1' OR '1'='1", "1)) OR ((1=1"));
    }

    // ---- Reflected XSS: canary reflected unescaped ----
    private static VulnClass reflectedXss() {
        Oracle oracle = (base, mutated, timing, payload) -> {
            String m = lc(mutated), b = lc(base);
            // unescaped reflection of the canary tag
            if ((m.contains("<" + XSS_CANARY) || m.contains(XSS_CANARY + ">"))
                    && !(b.contains("<" + XSS_CANARY) || b.contains(XSS_CANARY + ">"))) {
                return Signal.hit("Canary reflected unescaped: <" + XSS_CANARY + "> in response body",
                        Signal.Confidence.FIRM);
            }
            return Signal.miss();
        };
        return new VulnClass(
                "Cross-Site Scripting (Reflected)",
                "Break out of the reflection context and inject an HTML tag containing the literal token "
                        + XSS_CANARY + " (e.g. \"><" + XSS_CANARY + "> or <" + XSS_CANARY + ">). "
                        + "Always include the token " + XSS_CANARY + " so reflection can be confirmed.",
                VulnClass.Severity.MEDIUM,
                "Context-aware output encoding; a strict Content-Security-Policy.",
                oracle,
                List.of("\"><" + XSS_CANARY + ">", "'><" + XSS_CANARY + ">", "<" + XSS_CANARY + ">"));
    }

    // ---- SSTI: arithmetic canary evaluated by the template engine ----
    private static VulnClass ssti() {
        Oracle oracle = (base, mutated, timing, payload) -> {
            if (mutated != null && mutated.contains(SSTI_RESULT) && (base == null || !base.contains(SSTI_RESULT))) {
                return Signal.hit("Template engine evaluated " + SSTI_INPUT + " to " + SSTI_RESULT,
                        Signal.Confidence.FIRM);
            }
            return Signal.miss();
        };
        return new VulnClass(
                "Server-Side Template Injection",
                "Inject template expressions that evaluate the arithmetic marker " + SSTI_INPUT
                        + " across engines ({{...}}, ${...}, #{...}, <%= ... %>, {...}). "
                        + "The response should contain " + SSTI_RESULT + " if evaluated.",
                VulnClass.Severity.HIGH,
                "Do not embed untrusted input in templates; use logic-less templates / sandboxing.",
                oracle,
                List.of("{{" + SSTI_INPUT + "}}", "${" + SSTI_INPUT + "}", "#{" + SSTI_INPUT + "}",
                        "<%= " + SSTI_INPUT + " %>", "{" + SSTI_INPUT + "}"));
    }

    // ---- Path traversal: OS file signatures in the response ----
    private static VulnClass pathTraversal() {
        Oracle oracle = (base, mutated, timing, payload) -> {
            String m = mutated == null ? "" : mutated;
            String b = base == null ? "" : base;
            // FILE-path traversal only. If the OS-file disclosure came via a shell-metacharacter payload it is OS
            // command injection (a distinct class Burp's audit + our cmdi check own) — don't mislabel it as LFI.
            // Require a path-shaped payload (traversal sequence, scheme wrapper, or an absolute OS path) with no
            // command separators; otherwise defer (miss). Generic — no per-endpoint rules.
            String pl = payload == null ? "" : payload;
            boolean pathShaped = pl.contains("..") || pl.contains("://")
                    || pl.toLowerCase().matches("(?s).*(/etc/|/proc/|\\\\windows\\\\|%2e).*");
            boolean cmdiShaped = pl.matches("(?s).*[;&|`\\n\\r].*") || pl.contains("$(");
            if (!pathShaped || cmdiShaped) return Signal.miss();
            if (m.matches("(?s).*root:.*:0:0:.*") && !b.matches("(?s).*root:.*:0:0:.*")) {
                return Signal.hit("Contents of /etc/passwd returned (root:...:0:0:)", Signal.Confidence.FIRM);
            }
            String ml = lc(m), bl = lc(b);
            if ((ml.contains("[fonts]") || ml.contains("[extensions]") || ml.contains("for 16-bit app support"))
                    && !(bl.contains("[fonts]") || bl.contains("[extensions]"))) {
                return Signal.hit("Contents of Windows win.ini returned", Signal.Confidence.FIRM);
            }
            return Signal.miss();
        };
        return new VulnClass(
                "Path Traversal / Local File Inclusion",
                "Traverse out of the intended directory to read a known OS file (/etc/passwd or "
                        + "C:\\Windows\\win.ini), including encoded and nested-traversal variants.",
                VulnClass.Severity.HIGH,
                "Canonicalize and validate file paths against an allow-list; avoid passing user input to file APIs.",
                oracle,
                List.of("../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2fetc/passwd",
                        "....//....//....//etc/passwd", "../../../../../windows/win.ini"));
    }
}
