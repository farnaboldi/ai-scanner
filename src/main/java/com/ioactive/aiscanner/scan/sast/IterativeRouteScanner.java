package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;

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
 * SAST mode focused on EXHAUSTIVE route discovery rather than vulnerability-sink steering.
 * Three rounds: enumerate (recall > precision) → enrich (params / auth / body shape) →
 * critique (self-critique: what routes are still missing?).
 *
 * <p>Reuses SastFiles / SkillLibrary / StaticHint / SourceFindings unchanged.
 * Select via {@code -Daiscanner.sastMode=iterative} or Settings → SAST mode → iterative.</p>
 */
public final class IterativeRouteScanner implements SourceAnalyzer {

    private static final int MAX_CONTEXT   = 40_000;
    private static final int MAX_SNIPS     = 300;
    private static final int MAX_FILE_BYTES = 200_000;

    // Same ROUTE pattern as CoarseSourceAnalyzer so file prioritisation is consistent.
    private static final Pattern ROUTE = Pattern.compile(
            "(?i)(@(get|post|put|delete|patch|request)mapping|@app\\.route|@rest?controller|"
          + "app\\.(get|post|put|delete|patch)\\s*\\(|router\\.(get|post|put|delete|patch|use)\\s*\\(|"
          + "route::(get|post|put|delete|any|match)|resources\\s+:|urlpatterns|@(getmapping|postmapping)|"
          + "http\\.handlefunc|http\\.handle\\s*\\(|mux\\.handle|"
          + "case\\s+\"/|\\$_(get|post|request|cookie|files|server)\\b|php://input|"
          + "add_action\\s*\\(\\s*['\"]wp_ajax|"
          + "@api_view|\\bpath\\s*\\(|\\bre_path\\s*\\(|router\\.register|@(app|blueprint)\\.route|"
          + "request\\.(get|post|args|form|values|json|data|params|query)\\b|getparameter\\s*\\(|"
          + "\\breq\\.(query|params|body|headers|cookies)\\b|"
          + "^\\s*['\"]/(\\w[\\w./{}:@-]*)[\\'\"\\s,])");

    private final AiEngine engine;
    private final ScanLog  scanLog;

    public IterativeRouteScanner(AiEngine engine, ScanLog scanLog) {
        this.engine  = engine;
        this.scanLog = scanLog;
    }

    @Override
    public SourceFindings analyze(String host, String repoPath) {
        if (engine == null || repoPath == null || repoPath.isBlank()) return SourceFindings.empty();
        final Path root;
        try {
            root = Paths.get(repoPath).toRealPath();
        } catch (Exception e) {
            scanLog.debug("SAST(iterative): repo path unreadable: " + e);
            return SourceFindings.empty();
        }
        if (!Files.isDirectory(root)) return SourceFindings.empty();

        List<String> snips = new ArrayList<>();
        int[] chars = {0}, files = {0};
        for (Path p : SastFiles.candidates(root)) {
            if (snips.size() >= MAX_SNIPS || chars[0] >= MAX_CONTEXT) break;
            collect(root, p, snips, chars, files);
        }
        if (snips.isEmpty()) {
            scanLog.debug("SAST(iterative): no route signals found under " + root);
            return SourceFindings.empty();
        }

        String skills  = SkillLibrary.promptExcerpt(root, 3500);
        String codeCtx = String.join("\n", snips);
        scanLog.log("SAST(iterative): " + files[0] + " file(s), " + snips.size()
                + " signal(s) — starting 3-round route scan…");

        // Round 1 — enumerate: exhaustive, recall > precision
        List<StaticHint> r1 = call(SkillLibrary.augment(ENUMERATE_SYS, skills),
                enumerateUser(host, codeCtx), "sast:enumerate");
        scanLog.log("SAST(iterative) round 1 (enumerate): " + r1.size() + " route(s)");

        // Round 2 — enrich: fill params / auth / body, add newly spotted routes
        List<StaticHint> r2 = call(SkillLibrary.augment(ENRICH_SYS, skills),
                enrichUser(host, r1, codeCtx), "sast:enrich");
        scanLog.log("SAST(iterative) round 2 (enrich): " + r2.size() + " route(s) (Δ+" + delta(r1, r2) + ")");

        // Round 3 — critique: self-critique, find what the first two rounds missed
        List<StaticHint> r3 = call(CRITIQUE_SYS,
                critiqueUser(host, merge(r1, r2), codeCtx), "sast:critique");
        scanLog.log("SAST(iterative) round 3 (critique): +" + r3.size() + " new route(s)");

        List<StaticHint> all = merge(r1, r2, r3);
        scanLog.log("SAST(iterative): " + all.size() + " total unique route(s) across 3 rounds.");
        return new SourceFindings(all);
    }

    // ── Prompts ──────────────────────────────────────────────────────────────

    private static final String ENUMERATE_SYS =
            "You are mapping every navigable HTTP route in a web application's source code.\n"
          + "GOAL: EXHAUSTIVE coverage — recall beats precision. List every path the app can serve, "
          + "even without an obvious vulnerability. A missing route is worse than a speculative one.\n"
          + "Output ONLY a JSON array (no prose, no markdown). Each element:\n"
          + "  method        HTTP method (GET/POST/PUT/PATCH/DELETE) or \"\"\n"
          + "  path          route path template e.g. /api/users/{id}; use {param} for path variables\n"
          + "  params        array of parameter names (query, body, path) — can be []\n"
          + "  paramName     primary parameter for testing, or \"\"\n"
          + "  vulnClass     \"\" — leave blank, this round is route discovery only\n"
          + "  sinkType      \"\"\n"
          + "  sinkLocation  file:line of the route declaration, or \"\"\n"
          + "  confidence    0.0..1.0\n"
          + "Include explicit routes, middleware-mounted routes, resource helpers, REST patterns, "
          + "admin panels, health/metrics/debug endpoints, file upload/download paths, WebSocket upgrades. "
          + "Do NOT skip a route because you see no vulnerability — completeness is the goal.";

    private static final String ENRICH_SYS =
            "You are enriching a list of discovered HTTP routes with missing details.\n"
          + "For routes with empty params arrays, unclear methods, or missing path variables:\n"
          + "  - Fill params[] with all query params, body fields, and path variables visible in source\n"
          + "  - Correct the HTTP method if wrong\n"
          + "  - Set sinkLocation to file:line of the route declaration\n"
          + "  - Set vulnClass/sinkType ONLY when a clear dangerous sink is visible (else leave \"\")\n"
          + "Also add any routes visible in the source NOT already in the list.\n"
          + "Output ONLY the COMPLETE updated list as a JSON array — all routes, not just changes.";

    private static final String CRITIQUE_SYS =
            "You are reviewing a route discovery pass for completeness.\n"
          + "Look ONLY for routes NOT yet in the provided list:\n"
          + "  - Routes mounted via middleware (app.use, Blueprint.register_blueprint, include, Router)\n"
          + "  - Nested/child resource routes (resources :x do resources :y end)\n"
          + "  - Conditionally-registered routes (feature flags, env-var-gated, version-gated)\n"
          + "  - Routes in unexpected files (utility modules, admin gems, third-party plugins)\n"
          + "  - Dynamic route registration (loop-registered, metadata-driven, auto-discovered)\n"
          + "  - API versioning prefixes (/v1/, /v2/, /api/v1/)\n"
          + "  - GraphQL queries/mutations if a /graphql endpoint is present\n"
          + "Return ONLY the new routes NOT already in the list. Return [] if nothing is missing.\n"
          + "Output ONLY a JSON array in the same format as before.";

    // ── User prompts ──────────────────────────────────────────────────────────

    private static String enumerateUser(String host, String codeCtx) {
        return "Target host: " + (host == null ? "(unknown)" : host) + "\n\n"
             + "Source code (route declarations, controller files):\n" + codeCtx
             + "\n\nList every HTTP route this app serves.";
    }

    private static String enrichUser(String host, List<StaticHint> routes, String codeCtx) {
        return "Target host: " + (host == null ? "(unknown)" : host) + "\n\n"
             + "Routes found so far:\n" + hintsJson(routes) + "\n\n"
             + "Source code:\n" + codeCtx
             + "\n\nEnrich the list and add any missing routes. Return the complete updated list.";
    }

    private static String critiqueUser(String host, List<StaticHint> routes, String codeCtx) {
        return "Target host: " + (host == null ? "(unknown)" : host) + "\n\n"
             + "Routes found so far (" + routes.size() + " total):\n" + hintsJson(routes) + "\n\n"
             + "Source code:\n" + codeCtx
             + "\n\nWhat routes are MISSING from the list? Return only the new ones (or [] if complete).";
    }

    // ── Snippet collector (mirrors CoarseSourceAnalyzer.collect) ─────────────

    private void collect(Path root, Path p, List<String> snips, int[] chars, int[] files) {
        if (snips.size() >= MAX_SNIPS || chars[0] >= MAX_CONTEXT) return;
        try {
            if (!p.toRealPath().startsWith(root)) return;
            if (Files.size(p) > MAX_FILE_BYTES) return;
            String rel  = root.relativize(p).toString().replace('\\', '/');
            String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            if (text.indexOf('\0') >= 0) return;   // binary
            String[] lines = text.split("\n", -1);
            files[0]++;
            for (int i = 0; i < lines.length; i++) {
                if (snips.size() >= MAX_SNIPS || chars[0] >= MAX_CONTEXT) return;
                String line = lines[i];
                if (line.length() > 300) line = line.substring(0, 300);
                if (!ROUTE.matcher(line).find()) continue;
                String snip = "ROUTE " + rel + ":" + (i + 1) + "  " + line.trim();
                snips.add(snip);
                chars[0] += snip.length() + 1;
            }
        } catch (Exception ignore) { }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private List<StaticHint> call(String sys, String user, String tag) {
        try {
            return StaticHint.parseArray(engine.chat(sys, user, tag));
        } catch (Exception e) {
            scanLog.debug("SAST(iterative) " + tag + " failed: " + e);
            return new ArrayList<>();
        }
    }

    @SafeVarargs
    private static List<StaticHint> merge(List<StaticHint>... rounds) {
        Map<String, StaticHint> seen = new LinkedHashMap<>();
        for (List<StaticHint> round : rounds)
            for (StaticHint h : round)
                seen.putIfAbsent(key(h), h);
        return new ArrayList<>(seen.values());
    }

    private static String key(StaticHint h) {
        return ((h.method == null ? "" : h.method) + "|" + (h.path == null ? "" : h.path))
                .toLowerCase().trim();
    }

    private static int delta(List<StaticHint> prev, List<StaticHint> next) {
        java.util.Set<String> old = new java.util.HashSet<>();
        for (StaticHint h : prev) old.add(key(h));
        int n = 0;
        for (StaticHint h : next) if (!old.contains(key(h))) n++;
        return n;
    }

    private static String hintsJson(List<StaticHint> hints) {
        if (hints == null || hints.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < hints.size(); i++) {
            StaticHint h = hints.get(i);
            if (i > 0) sb.append(",");
            sb.append("{\"method\":\"").append(esc(h.method))
              .append("\",\"path\":\"").append(esc(h.path))
              .append("\",\"params\":").append(paramsJson(h.params))
              .append(",\"paramName\":\"").append(esc(h.paramName))
              .append("\",\"sinkLocation\":\"").append(esc(h.sinkLocation))
              .append("\",\"confidence\":").append(h.confidence).append("}");
        }
        return sb.append("]").toString();
    }

    private static String paramsJson(List<String> params) {
        if (params == null || params.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < params.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(esc(params.get(i))).append("\"");
        }
        return sb.append("]").toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
