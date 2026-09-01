package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Coarse, single-shot source analyzer: {@link SastRouteTable} harvests an authoritative route table + handler
 * context from the repo, which is handed to the local LLM with an attacker-first, copy-paths-verbatim prompt;
 * the reply is parsed back into a JSON array of {@link StaticHint} directives. Read-only and offline (only the
 * configured local LLM is contacted). Trades the full agentic tool-loop's depth for a single bounded call.
 * Failures degrade to {@link SourceFindings#empty()}.
 */
public final class CoarseSourceAnalyzer implements SourceAnalyzer {

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
            scanLog.debug("SAST: repo path unreadable (" + repoPath + "): " + e);
            return SourceFindings.empty();
        }
        if (!Files.isDirectory(root)) {
            scanLog.debug("SAST: not a directory: " + root);
            return SourceFindings.empty();
        }

        java.util.List<Path> cands = SastFiles.candidates(root);   // route/sink-bearing server files first
        SastRouteTable.Result rt = SastRouteTable.build(root, cands);

        if (rt.isEmpty()) {
            scanLog.debug("SAST: no routes/handlers found under " + root + " — no hints.");
            return SourceFindings.empty();
        }
        scanLog.log("SAST: scanned " + cands.size() + " file(s), " + rt.routes + " route(s) + "
                + rt.handlerUnits + " handler " + rt.handlerType + " → querying the model…");

        String skills = SkillLibrary.promptExcerpt(root, 3500);
        if (!skills.isBlank()) scanLog.debug("SAST: injected stack skill guidance (" + skills.length() + " chars).");
        String reply;
        try {
            reply = engine.chat(SkillLibrary.augment(systemPrompt(), skills), userPrompt(host, rt.context), "sast: coarse");
        } catch (Exception e) {
            scanLog.debug("SAST: model call failed: " + e);
            return SourceFindings.empty();
        }
        List<StaticHint> hints = StaticHint.parseArray(reply);
        if (hints.isEmpty()) scanLog.debug("SAST: model returned no usable directives.");
        // (Deterministic WP AJAX harvesting moved to WpAjaxHarvester, run mode-independently by AiScanner.)
        return new SourceFindings(hints);
    }

    private static String systemPrompt() {
        return "You map a web application's SOURCE to a JSON array of VULNERABLE HTTP routes that a dynamic (DAST) "
             + "scanner will test against the SAME running app. You are given TWO linked sections:\n"
             + "  (1) AUTHORITATIVE ROUTE TABLE — the app's REAL HTTP method+path registrations (Express app.get, "
             + "ASP.NET/Spring attribute routes already composed with their controller prefix, Flask/Django/Rails/Go "
             + "routes, or — for file-routed apps — one entry per source file). These are the ground truth for paths.\n"
             + "  (2) HANDLER CODE — the request params each route reads and the dangerous sinks it reaches (either "
             + "coherent code blocks with a `// in handler:` footer, or `file:line  code` signal lines, or whole "
             + "controller/handler bodies).\n"
             + "RULES:\n"
             + "1. The \"path\" MUST be copied VERBATIM from the ROUTE TABLE. NEVER invent a path or reconstruct one "
             + "from a filename or handler name. If a vulnerable handler has no matching ROUTE TABLE entry, omit it.\n"
             + "2. Emit a route ONLY when a handler shows attacker-controlled input reaching a dangerous sink. Prefer "
             + "precision over recall — a few high-confidence directives beat many speculative ones.\n"
             + "3. Output ONLY a JSON array (no prose, no markdown). Each element is ONE testing directive:\n"
             + "  method       HTTP method from the ROUTE TABLE (GET/POST/…)\n"
             + "  path         the route path, copied VERBATIM from the ROUTE TABLE (e.g. /api/products/search)\n"
             + "  params       array of parameter names the route accepts (may be empty)\n"
             + "  paramName    the single tainted parameter KEY to attack, exactly as read in code (req.query['id'] / "
             + "req.body.accountno / request.args.get('q') / a handler arg like `string keyword` → id / accountno / q / "
             + "keyword) — NEVER the accessor word ('query','body','params','args'), else \"\"\n"
             + "  vulnClass    one of: SQL Injection | NoSQL | IDOR | BFLA | mass-assignment | "
             + "Path traversal / File inclusion (LFI) | Command injection | SSRF | XXE | "
             + "Insecure deserialization | Open redirect | Cross-Site Scripting (Reflected)\n"
             + "  sinkType     sql | nosql | path | command | deser | idor | massassign | redirect | ssrf | xxe | other\n"
             + "  sinkLocation file:line of the sink\n"
             + "  confidence   0..1 (how sure a remote attacker can reach and exploit this)\n"
             + "Return [] only if there is genuinely no attacker-reachable input.";
    }

    private static String userPrompt(String host, String ctx) {
        return "Target host being scanned dynamically: " + (host == null ? "(unknown)" : host) + "\n\n"
             + ctx
             + "\n\nReturn the JSON array of vulnerable testing directives now (paths copied VERBATIM from the ROUTE TABLE).";
    }
}
