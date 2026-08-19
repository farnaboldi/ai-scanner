package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Coarse, single-shot source analyzer: read a bounded slice of the repo (route declarations + dangerous-sink
 * lines), hand it to the local LLM with a VulnHunter-style attacker-first prompt, and parse back a JSON array
 * of {@link StaticHint} directives. Read-only and offline (only the configured local LLM is contacted). It
 * intentionally does NOT reason like the full agentic tool-loop — it trades depth for a single bounded call,
 * which is the right MVP given a local model. Failures degrade to {@link SourceFindings#empty()}.
 */
public final class CoarseSourceAnalyzer implements SourceAnalyzer {

    // Bounds — keep the pass fast and within a local model's context budget. (File selection/ordering is in
    // the shared SastFiles helper.)
    private static final int  MAX_FILE_BYTES  = 200_000;   // per-file read cap
    private static final int  MAX_SNIPS       = 400;       // route/sink snippets collected
    private static final int  MAX_CONTEXT     = 48_000;    // chars of context handed to the LLM

    private static final Pattern ROUTE = Pattern.compile(
            "(?i)(@(get|post|put|delete|patch|request)mapping|@app\\.route|@rest?controller|"
            + "app\\.(get|post|put|delete|patch)\\s*\\(|router\\.(get|post|put|delete|patch|use)\\s*\\(|"
            + "route::(get|post|put|delete|any|match)|resources\\s+:|urlpatterns|@(getmapping|postmapping)|"
            // Go / generic net/http routing and query-param reads (the attacker-controlled entry points).
            + "http\\.handlefunc|http\\.handle\\s*\\(|mux\\.handle|\\.url\\.path|url\\.query\\(\\)\\.get|"
            // Route string LITERALS — Go switch-on-path (case "/x"), and mux/router path args — so the model
            // maps each entry-point param to its REAL route instead of guessing "/" from HandleFunc("/").
            + "case\\s+\"/|r\\.formvalue|request\\.querystring|"
            // PHP: request superglobals ARE the entry points in framework-less apps (no router).
            + "\\$_(get|post|request|cookie|files|server)\\b|"
            // Python/Django/Flask/DRF + Java servlets: routers, url tables, and request accessors.
            + "@api_view|\\bpath\\s*\\(|\\bre_path\\s*\\(|router\\.register|@(app|blueprint)\\.route|"
            + "request\\.(get|post|args|form|values|json|data|params|query)\\b|getparameter\\s*\\(|"
            // Express short form (req.query['id']/req.body.x) — the KEY-binding line, so the model names the
            // real param ('id') not the accessor ('query').
            + "\\breq\\.(query|params|body|headers|cookies)\\b)");
    private static final Pattern SINK = Pattern.compile(
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
            // PHP: SQL (mysql[i]_query / ->query / PDO prepare / pg_query), command (shell_exec/passthru/proc_open),
            // code (eval/assert), and file read/write sinks — the classic PHP dangerous-function set.
            + "mysqli?_query\\s*\\(|mysql_query\\s*\\(|->query\\s*\\(|->prepare\\s*\\(|pg_query\\s*\\(|"
            + "shell_exec\\s*\\(|passthru\\s*\\(|proc_open\\s*\\(|\\beval\\s*\\(|\\bassert\\s*\\(|"
            + "file_get_contents\\s*\\(|readfile\\s*\\(|move_uploaded_file\\s*\\(|"
            // Python ORM raw-SQL escape hatches.
            + "\\.raw\\s*\\(|\\.extra\\s*\\()");

    private final AiEngine engine;
    private final ScanLog scanLog;

    public CoarseSourceAnalyzer(AiEngine engine, ScanLog scanLog) {
        this.engine = engine;
        this.scanLog = scanLog;
    }

    @Override
    public SourceFindings analyze(String host, String repoPath) {
        if (engine == null || repoPath == null || repoPath.isBlank()) return SourceFindings.empty();
        final Path root;
        try {
            root = Paths.get(repoPath).toRealPath();     // resolves symlinks so the escape-guard below is sound
        } catch (Exception e) {
            scanLog.debug("[AI Scanner] SAST: repo path unreadable (" + repoPath + "): " + e);
            return SourceFindings.empty();
        }
        if (!Files.isDirectory(root)) {
            scanLog.debug("[AI Scanner] SAST: not a directory: " + root);
            return SourceFindings.empty();
        }

        List<String> snips = new ArrayList<>();
        int[] chars = {0};
        int[] files = {0};
        for (Path p : SastFiles.candidates(root)) {   // route/sink-bearing server files first (shared ordering)
            if (snips.size() >= MAX_SNIPS || chars[0] >= MAX_CONTEXT) break;
            collect(root, p, snips, chars, files);
        }

        if (snips.isEmpty()) {
            scanLog.debug("[AI Scanner] SAST: no route/sink signals found under " + root + " — no hints.");
            return SourceFindings.empty();
        }
        scanLog.log("[AI Scanner] SAST: scanned " + files[0] + " file(s), " + snips.size()
                + " route/sink signal(s) → querying the model…");

        String skills = SkillLibrary.promptExcerpt(root, 3500);
        if (!skills.isBlank()) scanLog.debug("[AI Scanner] SAST: injected stack skill guidance (" + skills.length() + " chars).");
        String reply;
        try {
            reply = engine.chat(SkillLibrary.augment(systemPrompt(), skills), userPrompt(host, snips));
        } catch (Exception e) {
            scanLog.debug("[AI Scanner] SAST: model call failed: " + e);
            return SourceFindings.empty();
        }
        List<StaticHint> hints = StaticHint.parseArray(reply);
        if (hints.isEmpty()) scanLog.debug("[AI Scanner] SAST: model returned no usable directives.");
        return new SourceFindings(hints);
    }

    /** Read one file (bounded) and stash route/sink line snippets, honoring the global char/snippet budget. */
    private void collect(Path root, Path p, List<String> snips, int[] chars, int[] files) {
        if (snips.size() >= MAX_SNIPS || chars[0] >= MAX_CONTEXT) return;
        try {
            if (!p.toRealPath().startsWith(root)) return;         // symlinked file escaping the repo → skip
            if (Files.size(p) > MAX_FILE_BYTES) return;
            String rel = root.relativize(p).toString().replace('\\', '/');
            byte[] bytes = Files.readAllBytes(p);
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (text.indexOf('\0') >= 0) return;                  // binary
            String[] lines = text.split("\n", -1);
            files[0]++;
            for (int i = 0; i < lines.length; i++) {
                if (snips.size() >= MAX_SNIPS || chars[0] >= MAX_CONTEXT) return;
                String line = lines[i];
                if (line.length() > 300) line = line.substring(0, 300);
                String tag = null;
                if (ROUTE.matcher(line).find()) tag = "ROUTE";
                else if (SINK.matcher(line).find()) tag = "SINK";
                if (tag == null) continue;
                String snip = tag + " " + rel + ":" + (i + 1) + "  " + line.trim();
                snips.add(snip);
                chars[0] += snip.length() + 1;
            }
        } catch (Exception ignore) { /* unreadable file → skip */ }
    }

    private static String systemPrompt() {
        return "You are a security code reviewer doing ATTACKER-FIRST triage of a web application's SOURCE to "
             + "GUIDE a dynamic (DAST) scanner of the SAME running app. You are given route declarations and "
             + "dangerous-sink lines (file:line). Identify concrete, remotely attacker-reachable HTTP inputs and "
             + "where each flows to a dangerous sink.\n"
             + "Output ONLY a JSON array (no prose, no markdown). Each element is ONE testing directive:\n"
             + "  method       HTTP method for the route (GET/POST/…), or \"\"\n"
             + "  path         route/path, e.g. /api/users/{id} or /admin/export, or \"\"\n"
             + "  params       array of parameter names the route accepts (may be empty)\n"
             + "  paramName    the single tainted parameter KEY to attack, exactly as read in code (req.query['id'] "
             + "/ req.body.accountno / request.args.get('q') → id / accountno / q) — NEVER the accessor word "
             + "('query','body','params','args'), else \"\"\n"
             + "  vulnClass    one of: SQL Injection | NoSQL | IDOR | BFLA | mass-assignment | "
             + "Path traversal / File inclusion (LFI) | Command injection | SSRF | XXE | "
             + "Insecure deserialization | Open redirect | Cross-Site Scripting (Reflected)\n"
             + "  sinkType     sql | nosql | path | command | deser | idor | massassign | redirect | ssrf | xxe | other\n"
             + "  sinkLocation file:line of the sink\n"
             + "  confidence   0..1 (how sure a remote attacker can reach and exploit this)\n"
             + "Rules: ONLY include inputs a remote HTTP attacker can reach. Prefer precision over recall — a few "
             + "high-confidence directives beat many speculative ones. Do NOT invent endpoints not evidenced by the "
             + "snippets.\n"
             + "When the code has NO explicit route declarations — the request handler is selected by the web server "
             + "from the file's location and inputs arrive via request globals / query or form parameters rather than "
             + "a router — treat the SINK'S FILE as the endpoint: derive the path from that file's location relative to "
             + "the application/web root (dropping conventional non-URL wrapper segments), and use the request "
             + "parameter key as the parameter. Emit the directive at a modest confidence instead of returning "
             + "nothing. Return [] only if there is genuinely no attacker-reachable input.";
    }

    private static String userPrompt(String host, List<String> snips) {
        StringBuilder sb = new StringBuilder();
        sb.append("Target host being scanned dynamically: ").append(host == null ? "(unknown)" : host).append('\n');
        sb.append("Source signals (ROUTE = route declaration, SINK = dangerous sink), file:line:\n\n");
        for (String s : snips) sb.append(s).append('\n');
        sb.append("\nReturn the JSON array of testing directives now.");
        return sb.toString();
    }
}
