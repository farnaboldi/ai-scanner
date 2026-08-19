package com.ioactive.aiscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.regex.Pattern;

/**
 * Shared, STRONG, zero-FP stack-trace / verbose-error oracle. Used by {@link SamlProbe} (SAML routes) and
 * {@link VerboseErrorProbe} (host-wide) so the disclosure detection is defined once. Fires only on a real stack
 * frame paired with an exception token, OR an unmistakable framework error-page signature — a bare generic 500
 * (custom error page, no frames) does NOT match.
 */
final class StackTraceOracle {
    private StackTraceOracle() {}

    /** A real stack frame: `at Namespace.Class.Method(` (.NET/Java) — deliberately narrow to avoid prose matches. */
    static final Pattern STACK_FRAME = Pattern.compile("at [A-Za-z_][A-Za-z0-9_.]+\\.[A-Za-z0-9_]+\\(");
    /** An exception type token, or a Python traceback header. */
    static final Pattern EXCEPTION_TOKEN = Pattern.compile("(?i)\\b([A-Za-z0-9_.]*Exception|Traceback \\(most recent call last\\))\\b");
    /** Framework error-page signatures that are themselves conclusive (ASP.NET yellow-screen, etc.). */
    static final Pattern FRAMEWORK_ERR = Pattern.compile("(?i)Server Error in |ASP\\.NET Version:|Stack Trace:");
    /** V8 / Node.js stack frame: `at <fn> (<file>:line:col)` or bare `at <file>:line:col`. The trailing
     *  {@code :line:col} preceded by a JS source file, a {@code node:} core module, or an absolute {@code /path}
     *  is the distinctive V8 shape — a bare "at 12:30:00" time-of-day has no such prefix and cannot match, which
     *  keeps this zero-FP. Node frames use a space before `(` (or no `(` at all), so {@link #STACK_FRAME} misses them. */
    static final Pattern V8_FRAME = Pattern.compile(
            "(?i)\\bat\\s+[^\\r\\n<]*?(?:\\.[cm]?[jt]sx?|node:[\\w./]+|/[\\w.$@+-]+):\\d+:\\d+");
    /** JavaScript / Node built-in error types — none end in {@code Exception}, so {@link #EXCEPTION_TOKEN} misses them. */
    static final Pattern JS_EXCEPTION = Pattern.compile(
            "\\b(?:Type|Reference|Syntax|Range|Eval|URI|Aggregate|Assertion|Internal)Error\\b");
    /** Generic RDBMS error text that discloses schema (db/table/column names) or SQL — engine-agnostic, not
     *  app-specific. A verbose error carrying this leaks far more than a bare framework trace, so it ranks higher
     *  as evidence. Covers SQL Server, Oracle, MySQL/PDO, PostgreSQL, SQLite and the .NET/ODBC/OLE-DB data layer. */
    static final Pattern DB_ERROR = Pattern.compile("(?i)("
            + "Cannot insert the value NULL into column|Incorrect syntax near|Unclosed quotation mark|"
            + "conflicted with the (FOREIGN|PRIMARY) KEY constraint|conflicted with the CHECK constraint|"
            + "Conversion failed when converting|Violation of \\w+ KEY constraint|Invalid column name|"   // SQL Server
            + "ORA-\\d{5}|"                                                                                // Oracle
            + "SQLSTATE\\[|You have an error in your SQL syntax|"                                          // MySQL/PDO
            + "PG::\\w+|invalid input syntax for|"                                                         // PostgreSQL
            + "SQLite3?::|"                                                                                // SQLite
            + "ODBC[^<]*Driver|OLE DB|System\\.Data\\.(SqlClient|OleDb|Odbc)|JDBC"                         // .NET / generic
            + ")");

    /** True on (a real .NET/Java frame AND an exception token), OR a V8/Node stack trace, OR a framework error page. */
    static boolean hasStackTrace(HttpRequestResponse rr) {
        String body = body(rr);
        if (body == null) return false;
        // .NET / Java / Python: a real stack frame paired with an exception token.
        if (STACK_FRAME.matcher(body).find() && EXCEPTION_TOKEN.matcher(body).find()) return true;
        // Node.js / V8: ≥2 frames, or one frame + a JS error type — the distinctive frame shape keeps this zero-FP.
        if (hasV8StackTrace(body)) return true;
        // Conclusive framework error-page signatures (ASP.NET yellow-screen, etc.).
        return FRAMEWORK_ERR.matcher(body).find();
    }

    /** ≥2 V8 stack frames, OR one V8 frame paired with a JS error type — either is conclusive of a real trace. */
    private static boolean hasV8StackTrace(String body) {
        java.util.regex.Matcher m = V8_FRAME.matcher(body);
        int frames = 0;
        while (m.find() && frames < 2) frames++;
        return frames >= 2 || (frames == 1 && JS_EXCEPTION.matcher(body).find());
    }

    /** True if the response's verbose error also leaks database schema / SQL (see {@link #DB_ERROR}). */
    static boolean leaksDbSchema(HttpRequestResponse rr) {
        String body = body(rr);
        return body != null && DB_ERROR.matcher(body).find();
    }

    /** Generic sensitivity rank of a disclosure — higher = leaks more, used to pick the most damaging artifact
     *  as a finding's primary evidence. 0 = not a stack trace; 1 = framework trace; 2 = also leaks DB schema/SQL. */
    static int disclosureSeverity(HttpRequestResponse rr) {
        if (!hasStackTrace(rr)) return 0;
        return leaksDbSchema(rr) ? 2 : 1;
    }

    // ---- concrete-artifact extraction: show WHAT leaked (internal paths, DB objects, versions), not just THAT it did.
    /** Windows filesystem path (drive-letter, ≥1 dir segment) — e.g. C:\inetpub\wwwroot\app\Foo.cs. */
    private static final Pattern WIN_PATH = Pattern.compile("[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)+[^\\\\/:*?\"<>|\\r\\n]*");
    /** Deep Unix source path ending in a code file (optionally :line) — e.g. /var/www/app/models/user.rb:42. */
    private static final Pattern UNIX_SRC = Pattern.compile("(?:/[\\w.$-]+){2,}\\.(?:java|rb|py|php|cs|go|js|ts|pl|c|cpp|h)(?::\\d+)?");
    /** SQL error phrasings that name a schema object, capturing the object. Engine-agnostic; the object may be
     *  wrapped in single OR double quotes (SQL Server varies: table "s.t", column 'c', database "Db"). */
    private static final Pattern DB_TABLE  = Pattern.compile("(?i)\\btable\\s+['\"]([^'\"]{1,160})['\"]");
    private static final Pattern DB_COLUMN = Pattern.compile("(?i)\\bcolumn\\s+['\"]([^'\"]{1,160})['\"]");
    private static final Pattern DB_NAME   = Pattern.compile("(?i)\\b(?:database|initial catalog)\\b\\s*[=:]?\\s*['\"]?([\\w.$#-]{2,120})");
    /** Framework / server version banners commonly present in a verbose error page. */
    private static final Pattern VERSION   = Pattern.compile(
            "(?i)(ASP\\.NET Version:[\\d.]+|\\.NET Framework Version:[\\d.]+|PHP/[\\d.]+|Apache/[\\d.]+|nginx/[\\d.]+|Python/[\\d.]+|Java/[\\d._]+|Rails [\\d.]+)");
    /** A leaked internal code path — the fully-qualified type.method of a stack frame (Namespace.Class.Method).
     *  This IS a form of path disclosure even when no filesystem path is present (e.g. a .NET/Java trace). */
    private static final Pattern CODE_FRAME = Pattern.compile("\\bat\\s+([A-Za-z_][\\w.]+\\.[A-Za-z0-9_<>]+)\\s*\\(");
    /** The exception type token (`*Exception`, or a JS/Node `*Error` builtin), captured to name what failed. */
    private static final Pattern EXC_TYPE = Pattern.compile(
            "\\b([A-Za-z_][\\w.]*Exception|(?:Type|Reference|Syntax|Range|Eval|URI|Aggregate|Assertion|Internal)Error)\\b");

    /** Extract the concrete sensitive artifacts a verbose error disclosed — internal file paths, DB schema objects
     *  (table/column/database names), and framework/version banners — so a finding can show WHAT leaked. Generic
     *  (no vendor/app strings), de-duplicated and bounded. May be empty. */
    static java.util.List<String> leakedArtifacts(HttpRequestResponse rr) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        String body = body(rr);
        if (body == null) return new java.util.ArrayList<>(out);
        collect(out, DB_NAME,   1, "db name: ",   body, 3);
        collect(out, DB_TABLE,  1, "db table: ",  body, 4);
        collect(out, DB_COLUMN, 1, "db column: ", body, 6);
        collect(out, WIN_PATH,  0, "path: ",      body, 5);
        collect(out, UNIX_SRC,  0, "path: ",      body, 5);
        collect(out, EXC_TYPE,  1, "exception: ", body, 2);
        collect(out, CODE_FRAME,1, "code path: ", body, 4);
        collect(out, VERSION,   0, "version: ",   body, 4);
        return new java.util.ArrayList<>(out);
    }

    private static void collect(java.util.Set<String> out, Pattern p, int group, String label, String body, int max) {
        try {
            java.util.regex.Matcher m = p.matcher(body);
            int n = 0;
            while (m.find() && n < max) {
                String v = m.group(group);
                if (v == null) continue;
                v = v.trim();
                if (v.length() > 200) v = v.substring(0, 200) + "…";
                if (!v.isEmpty()) { out.add(label + v); n++; }
            }
        } catch (Throwable ignore) { }
    }

    private static String body(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return null;
        try { String b = rr.response().bodyToString(); return (b == null || b.isEmpty()) ? null : b; }
        catch (Throwable t) { return null; }
    }
}
