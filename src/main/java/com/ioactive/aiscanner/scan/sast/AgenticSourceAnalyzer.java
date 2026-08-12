package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Phase-2 agentic analyzer that FOLLOWS THE CHILD-PROCESS BOUNDARY.
 *
 * <p>The coarse analyzer feeds the model a flat pile of route/sink lines, so on a polyglot app it attributes
 * a cross-unit sink to the gateway's {@code exec.Command} line rather than the real sink inside the spawned
 * child. This analyzer reasons in two bounded steps, like an agent tracing data across a process boundary:</p>
 * <ol>
 *   <li><b>Map</b> — from the entry/gateway files, identify each attacker-reachable HTTP route + param and
 *       whether it is handled inline or dispatched to a child program (which one).</li>
 *   <li><b>Follow</b> — resolve each dispatched-to child to its OWN source and ask the model to pin the real
 *       sink there (vuln class + file:line in the child), so provenance points at the true sink.</li>
 * </ol>
 * Two LLM calls total, read-only, offline. Degrades to {@link SourceFindings#empty()} on any problem.
 */
public final class AgenticSourceAnalyzer implements SourceAnalyzer {

    private static final int MAX_FILE_BYTES = 200_000;
    private static final int MAX_ENTRY_CHARS = 24_000;    // entry/gateway snippets fed to step 1
    private static final int MAX_CHILD_BYTES = 24_000;    // per child source fed to step 2
    private static final int MAX_CHILDREN = 6;
    // (File selection + read-priority ordering live in the shared SastFiles helper.)

    // Lines that mark an HTTP entry point OR a child-process dispatch (the boundary we follow).
    private static final Pattern ENTRY = Pattern.compile(
            "(?i)(@(get|post|put|delete|patch|request)mapping|@app\\.route|app\\.(get|post|put|delete|patch)\\s*\\(|"
            + "router\\.(get|post|put|delete|patch|use)\\s*\\(|route::(get|post|put|delete|any|match)|urlpatterns|"
            + "http\\.handlefunc|\\.url\\.path|url\\.query\\(\\)\\.get|case\\s+\"/|"
            + "exec\\.command|processbuilder|runtime\\.getruntime|subprocess\\.(call|run|popen)|os\\.system|"
            + "child_process|command::new|std::process|popen\\s*\\(|"
            // PHP request superglobals + Python/Django/Flask/DRF routers & request accessors (framework-less entry).
            + "\\$_(get|post|request|cookie|files)\\b|@api_view|\\bpath\\s*\\(|\\bre_path\\s*\\(|router\\.register|"
            + "@(app|blueprint)\\.route|request\\.(get|post|args|form|values|json|data|params|query)\\b|"
            // Express short form: req.query['id'] / req.query.id / req.body.x / req.params.x — the line that
            // BINDS the real request KEY to a variable. Capturing it lets the model emit paramName='id' (the
            // actual key) instead of the accessor 'query'; without it the synthesized probe hits the wrong param.
            + "\\breq\\.(query|params|body|headers|cookies)\\b|"
            + "shell_exec\\s*\\(|mysqli?_query\\s*\\(|->query\\s*\\(|getparameter\\s*\\()");

    private final AiEngine engine;
    private final ScanLog scanLog;

    public AgenticSourceAnalyzer(AiEngine engine, ScanLog scanLog) {
        this.engine = engine;
        this.scanLog = scanLog;
    }

    @Override
    public SourceFindings analyze(String host, String repoPath) {
        if (engine == null || repoPath == null || repoPath.isBlank()) return SourceFindings.empty();
        final Path root;
        try { root = Paths.get(repoPath).toRealPath(); } catch (Exception e) {
            scanLog.debug("[AI Scanner] SAST(agentic): repo unreadable: " + e); return SourceFindings.empty();
        }
        if (!Files.isDirectory(root)) return SourceFindings.empty();

        // Index every code file by basename (for child resolution) and gather entry/dispatch snippets.
        Map<String, Path> byName = new LinkedHashMap<>();
        List<String> entrySnips = new ArrayList<>();
        int[] entryChars = {0};
        List<Path> cands = SastFiles.candidates(root);   // route/entry files first (shared selection/ordering)
        for (Path p : cands) byName.putIfAbsent(p.getFileName().toString().toLowerCase(), p);  // child-resolution index (no read)
        for (Path p : cands) {
            if (entryChars[0] >= MAX_ENTRY_CHARS) break;
            indexEntries(root, p, entrySnips, entryChars);
        }
        if (entrySnips.isEmpty()) return coarseFallback(host, repoPath, "no entry/dispatch signals found");

        scanLog.log("[AI Scanner] SAST(agentic): " + entrySnips.size() + " entry/dispatch signal(s) across "
                + byName.size() + " unit file(s) → step 1 (map entry points)…");

        // --- Step 1: map entry points + dispatch targets ---
        List<Entry> entries;
        try {
            entries = parseEntries(engine.chat(MAP_SYS, mapUser(host, entrySnips)));
        } catch (Exception e) { return coarseFallback(host, repoPath, "step 1 error (" + e.getClass().getSimpleName() + ")"); }
        if (entries.isEmpty()) return coarseFallback(host, repoPath, "step 1 mapped no entry points (flat/non-routed app)");

        // --- resolve each dispatch target to a child source file (follow the boundary) ---
        Map<String, String> childSrc = new LinkedHashMap<>();   // dispatch token -> "path\n<code>"
        for (Entry en : entries) {
            if (en.dispatch == null || en.dispatch.isBlank() || childSrc.size() >= MAX_CHILDREN) continue;
            Path cp = resolveChild(root, byName, en.dispatch);
            if (cp != null && !childSrc.containsKey(en.dispatch)) {
                String rel = root.relativize(cp).toString().replace('\\', '/');
                childSrc.put(en.dispatch, rel + "\n" + readBounded(cp));
            }
        }
        scanLog.log("[AI Scanner] SAST(agentic): mapped " + entries.size() + " entry point(s); following "
                + childSrc.size() + " child unit(s) → step 2 (pin real sinks)…");

        // --- Step 2: pin the real sink inside each child (or inline) ---
        List<StaticHint> hints;
        try {
            hints = StaticHint.parseArray(engine.chat(SINK_SYS, sinkUser(entries, childSrc)));
        } catch (Exception e) { return coarseFallback(host, repoPath, "step 2 error (" + e.getClass().getSimpleName() + ")"); }
        if (hints.isEmpty()) return coarseFallback(host, repoPath, "step 2 produced no hints");
        // FLAT-APP MERGE: the two-step boundary-follow fits framework-routed / process-boundary apps, but a flat
        // app (many inline routes in one file, no gateway→child dispatch — e.g. an Express server.js with 14
        // app.get/post sinks) makes step 2 collapse N mapped entry points into a handful of sinks, starving the
        // dynamic surface (observed on xvna: 14 entries → 1 hint). When agentic clearly under-produces vs what
        // step 1 mapped, UNION with the coarse flat-sink pass. Hints only STEER probes (oracles still decide), so
        // merging can only ADD coverage — never a false finding.
        if (hints.size() < Math.max(3, entries.size() / 2)) {
            scanLog.log("[AI Scanner] SAST(agentic): under-produced (" + hints.size() + " hint(s) for "
                    + entries.size() + " mapped entry point(s)) → merging the coarse flat-sink pass.");
            try {
                SourceFindings coarse = new CoarseSourceAnalyzer(engine, scanLog).analyze(host, repoPath);
                hints = mergeHints(hints, coarse.all());
                scanLog.log("[AI Scanner] SAST(agentic+coarse): " + hints.size() + " merged hint(s).");
            } catch (Throwable t) { scanLog.debug("[AI Scanner] SAST: coarse merge failed: " + t); }
        }
        return new SourceFindings(hints);
    }

    /** Union two hint lists, deduping by (method,path,param,class) — keeps the agentic hint when both name the
     *  same directive (its sinkLocation follows the boundary), then appends coarse-only directives. */
    private static List<StaticHint> mergeHints(List<StaticHint> agentic, List<StaticHint> coarse) {
        LinkedHashMap<String, StaticHint> m = new LinkedHashMap<>();
        for (StaticHint h : agentic) m.putIfAbsent(hintKey(h), h);
        for (StaticHint h : coarse) m.putIfAbsent(hintKey(h), h);
        return new ArrayList<>(m.values());
    }

    private static String hintKey(StaticHint h) {
        return (h.method + "|" + h.path + "|" + h.paramName + "|" + h.vulnClass).toLowerCase();
    }

    /** Agentic mapping fits framework-routed apps with process boundaries; flat apps (file-based PHP, no
     *  routes/dispatch) yield nothing there. Fall back to the coarse flat-sink pass so agentic is never worse. */
    private SourceFindings coarseFallback(String host, String repoPath, String why) {
        scanLog.log("[AI Scanner] SAST(agentic): " + why + " → falling back to coarse SAST.");
        try { return new CoarseSourceAnalyzer(engine, scanLog).analyze(host, repoPath); }
        catch (Throwable t) { scanLog.debug("[AI Scanner] SAST: coarse fallback failed: " + t); return SourceFindings.empty(); }
    }

    // ---- indexing ----

    private void indexEntries(Path root, Path p, List<String> entrySnips, int[] chars) {
        try {
            if (!p.toRealPath().startsWith(root)) return;      // symlink escape guard
            if (Files.size(p) > MAX_FILE_BYTES) return;
            if (chars[0] >= MAX_ENTRY_CHARS) return;
            String rel = root.relativize(p).toString().replace('\\', '/');
            String[] lines = new String(Files.readAllBytes(p), StandardCharsets.UTF_8).split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                if (chars[0] >= MAX_ENTRY_CHARS) return;
                String line = lines[i];
                if (line.length() > 300) line = line.substring(0, 300);
                if (!ENTRY.matcher(line).find()) continue;
                String snip = rel + ":" + (i + 1) + "  " + line.trim();
                entrySnips.add(snip);
                chars[0] += snip.length() + 1;
            }
        } catch (Exception ignore) { }
    }

    /** Resolve a dispatch token (a binary/script name like "worker", "exiftrim", "report/report.py") to its
     *  source file: exact basename, then any code file whose path contains the token stem, preferring a main. */
    private Path resolveChild(Path root, Map<String, Path> byName, String dispatch) {
        String d = dispatch.toLowerCase().trim();
        String base = d.replaceAll(".*[/\\\\]", "");                 // strip any path
        if (byName.containsKey(base)) return byName.get(base);       // e.g. report.py
        String stem = base.replaceAll("\\.[a-z0-9]+$", "");          // worker(.rs), exiftrim(.c)
        if (stem.isBlank()) return null;
        Path mainHit = null, anyHit = null;
        for (Map.Entry<String, Path> e : byName.entrySet()) {
            String path = root.relativize(e.getValue()).toString().replace('\\', '/').toLowerCase();
            if (!path.contains(stem)) continue;
            if (e.getKey().startsWith("main.") || e.getKey().startsWith("index.")) { mainHit = e.getValue(); }
            if (anyHit == null) anyHit = e.getValue();
        }
        return mainHit != null ? mainHit : anyHit;
    }

    private String readBounded(Path p) {
        try {
            byte[] b = Files.readAllBytes(p);
            String s = new String(b, StandardCharsets.UTF_8);
            return s.length() > MAX_CHILD_BYTES ? s.substring(0, MAX_CHILD_BYTES) : s;
        } catch (Exception e) { return ""; }
    }

    // ---- step 1 parse ----

    private static final class Entry {
        final String method, path, param, dispatch;
        Entry(String m, String p, String pr, String d) { method = m; path = p; param = pr; dispatch = d; }
    }

    private List<Entry> parseEntries(String raw) {
        List<Entry> out = new ArrayList<>();
        if (raw == null) return out;
        int a = raw.indexOf('['), b = raw.lastIndexOf(']');
        if (a < 0 || b <= a) return out;
        try {
            JSONArray arr = new JSONArray(raw.substring(a, b + 1));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o == null) continue;
                out.add(new Entry(o.optString("method", "GET"), o.optString("path", ""),
                        o.optString("param", o.optString("paramName", "")),
                        o.optString("dispatch", o.optString("dispatchesTo", ""))));
            }
        } catch (Exception ignore) { }
        return out;
    }

    // ---- prompts ----

    private static final String MAP_SYS =
            "You are tracing attacker-reachable HTTP entry points in a web app's SOURCE to guide a dynamic scanner "
            + "of the SAME app. From the entry/gateway and child-dispatch lines below, list each HTTP route that "
            + "reads an attacker-controlled parameter. If the handler hands that parameter to a CHILD PROGRAM "
            + "(exec/spawn/subprocess), record which child (the program/script name), because the real vulnerability "
            + "is usually in that child, not at the boundary. Output ONLY a JSON array; each element:\n"
            + "  method   HTTP method (GET/POST/…)\n"
            + "  path     the route path (e.g. /import, /jobs) — use the routed path, NOT the catch-all handler mount\n"
            + "  param    the attacker-controlled parameter KEY exactly as read in code — for req.query['id'] / "
            + "req.query.id / req.body.accountno / request.args.get('q') emit id / id / accountno / q. NEVER the "
            + "accessor word itself ('query','body','params','args') — that is not a real parameter name.\n"
            + "  dispatch the child program/script this param is passed to (e.g. worker, exiftrim, report/report.py), "
            + "or \"\" if handled inline\n"
            + "No prose, no markdown.";

    private static String mapUser(String host, List<String> snips) {
        StringBuilder sb = new StringBuilder();
        sb.append("Target host (dynamic): ").append(host == null ? "(unknown)" : host).append('\n');
        sb.append("Entry / dispatch signals (file:line):\n\n");
        for (String s : snips) sb.append(s).append('\n');
        sb.append("\nReturn the JSON array of entry points now.");
        return sb.toString();
    }

    private static final String SINK_SYS =
            "You are pinning the REAL sink for each HTTP entry point, following into the child program the "
            + "parameter is dispatched to. You are given the entry points and, for each dispatched-to child, its "
            + "FULL source. For each entry point, determine the concrete vulnerability at the true sink (inside the "
            + "child when dispatched, else inline) and output ONLY a JSON array; each element:\n"
            + "  method, path, params (array), paramName\n"
            + "  vulnClass    one of: SQL Injection | NoSQL | IDOR | BFLA | mass-assignment | "
            + "Path traversal / File inclusion (LFI) | Command injection | SSRF | XXE | Insecure deserialization | "
            + "Open redirect | Cross-Site Scripting (Reflected)\n"
            + "  sinkType     sql|nosql|path|command|deser|idor|massassign|redirect|ssrf|xxe|other\n"
            + "  sinkLocation the file:line of the REAL sink (inside the child source when the input crosses a "
            + "process boundary — NOT the gateway's exec/spawn line)\n"
            + "  confidence   0..1\n"
            + "Prefer precision; only attacker-reachable inputs. No prose, no markdown.";

    private static String sinkUser(List<Entry> entries, Map<String, String> childSrc) {
        StringBuilder sb = new StringBuilder();
        sb.append("Entry points (JSON):\n[");
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"method\":\"").append(esc(e.method)).append("\",\"path\":\"").append(esc(e.path))
              .append("\",\"param\":\"").append(esc(e.param)).append("\",\"dispatch\":\"").append(esc(e.dispatch)).append("\"}");
        }
        sb.append("]\n\n");
        if (childSrc.isEmpty()) {
            sb.append("(No child programs dispatched to — sinks are inline in the entry files.)\n");
        } else {
            for (Map.Entry<String, String> c : childSrc.entrySet()) {
                int nl = c.getValue().indexOf('\n');
                String rel = nl > 0 ? c.getValue().substring(0, nl) : c.getKey();
                String code = nl > 0 ? c.getValue().substring(nl + 1) : c.getValue();
                sb.append("=== CHILD dispatched as '").append(c.getKey()).append("'  (source: ").append(rel).append(") ===\n");
                sb.append(code).append("\n\n");
            }
        }
        sb.append("Return the JSON array of directives now.");
        return sb.toString();
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
