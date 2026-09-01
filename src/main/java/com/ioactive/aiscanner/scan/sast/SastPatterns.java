package com.ioactive.aiscanner.scan.sast;

import java.util.regex.Pattern;

/**
 * Shared regexes for the SAST source analyzers. {@link #SINK} is the comprehensive multi-language dangerous-sink
 * set; {@link #PARAM_READ} matches a request-parameter read inside a handler body. Used by {@link SastRouteTable}
 * to pick which files carry attacker-reachable sinks/params when building the flat-app handler context.
 */
final class SastPatterns {
    private SastPatterns() {}

    /** Dangerous sinks (SQL / command / file / redirect / SSRF / deserialization / template) across 10+ languages. */
    static final Pattern SINK = Pattern.compile(
            "(?i)(execute(query|update)?\\s*\\(|createquery\\s*\\(|rawquery\\s*\\(|cursor\\.execute\\s*\\(|"
            + "preparestatement|\\bstatement\\b|runtime\\.getruntime\\(\\)\\.exec|processbuilder|child_process|"
            + "os\\.system|subprocess\\.(call|run|popen)|\\bexec\\s*\\(|new\\s+file\\s*\\(|fileinputstream|"
            + "sendfile|fopen|readfilesync|include(_once)?\\s*\\(|readobject|objectinputstream|pickle\\.loads|"
            + "yaml\\.load|unserialize|marshal\\.load|\\$where|\\.aggregate\\s*\\(|res\\.redirect\\s*\\(|"
            + "sendredirect|documentbuilderfactory|"
            // Go: SSRF (http.Get/NewRequest) + child-process exec.
            + "http\\.get\\s*\\(|http\\.post\\s*\\(|http\\.newrequest|exec\\.command|"
            // Rust: file read (path traversal) + child-process.
            + "fs::read|read_to_string|command::new|std::process|"
            // C/C++: classic memory-unsafe + command sinks.
            + "strcpy\\s*\\(|strncpy\\s*\\(|strcat\\s*\\(|sprintf\\s*\\(|memcpy\\s*\\(|\\bgets\\s*\\(|"
            + "\\bsystem\\s*\\(|popen\\s*\\(|exec[lv][ep]?\\s*\\(|"
            // PHP: SQL, command, code (eval/assert), and file read/write sinks.
            + "mysqli?_query\\s*\\(|mysql_query\\s*\\(|->query\\s*\\(|->prepare\\s*\\(|->get_results\\s*\\(|->get_row\\s*\\(|->get_var\\s*\\(|->get_col\\s*\\(|pg_query\\s*\\(|"
            + "shell_exec\\s*\\(|passthru\\s*\\(|proc_open\\s*\\(|\\beval\\s*\\(|\\bassert\\s*\\(|"
            + "file_get_contents\\s*\\(|readfile\\s*\\(|move_uploaded_file\\s*\\(|"
            // Python ORM raw-SQL escape hatches.
            + "\\.raw\\s*\\(|\\.extra\\s*\\(|"
            // Python HTTP client SSRF sinks (requests / httpx / aiohttp / urllib).
            + "requests\\.(get|post|put|patch|delete|head|request)\\s*\\(|"
            + "httpx\\.(get|post|put|patch|delete|request|AsyncClient)\\s*\\(|"
            + "aiohttp\\.ClientSession|urllib\\.request\\.urlopen\\s*\\(|"
            // Python subprocess (shell=True is the dangerous variant — command injection).
            + "subprocess\\.check_output\\s*\\(|subprocess\\.Popen\\s*\\()");

    /** A request-parameter READ inside a handler body (query/body/path params, form fields). */
    static final Pattern PARAM_READ = Pattern.compile(
            "(?i)\\breq\\.(query|params|body)\\b|request\\.(get|post|args|form|values|json|data|params|query)\\b"
          + "|getparameter\\s*\\(|\\$_(get|post|request)\\b");
}
