package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SAST mode focused on EXHAUSTIVE route discovery rather than vulnerability-sink steering.
 * Three rounds: enumerate (recall > precision) → enrich (params / auth / body shape) →
 * critique (self-critique: what routes are still missing?).
 *
 * <p>Reuses SastFiles / SkillLibrary / StaticHint / SourceFindings unchanged.
 * Select via {@code -Daiscanner.sastMode=iterative} or Settings → SAST mode → iterative.</p>
 */
public final class IterativeRouteScanner implements SourceAnalyzer {

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

        java.util.List<Path> cands = SastFiles.candidates(root);
        SastRouteTable.Result rt = SastRouteTable.build(root, cands);
        if (rt.isEmpty()) {
            scanLog.debug("SAST(iterative): no routes/handlers found under " + root);
            return SourceFindings.empty();
        }

        String skills  = SkillLibrary.promptExcerpt(root, 3500);
        String codeCtx = rt.context;   // AUTHORITATIVE ROUTE TABLE + adaptive handler context
        scanLog.log("SAST(iterative): " + cands.size() + " file(s), " + rt.routes + " route(s) + "
                + rt.handlerUnits + " handler " + rt.handlerType + " — starting 3-round route scan…");

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
          + "You are given an AUTHORITATIVE ROUTE TABLE (the app's REAL HTTP method+path registrations) followed by "
          + "HANDLER CODE. GOAL: EXHAUSTIVE coverage — recall beats precision. Emit EVERY entry from the ROUTE TABLE.\n"
          + "RULE: copy each \"path\" VERBATIM from the ROUTE TABLE — NEVER invent or reconstruct a path from a "
          + "filename/handler name. Only emit paths that appear in the ROUTE TABLE.\n"
          + "Output ONLY a JSON array (no prose, no markdown). Each element:\n"
          + "  method        HTTP method from the ROUTE TABLE (GET/POST/PUT/PATCH/DELETE)\n"
          + "  path          route path, copied VERBATIM from the ROUTE TABLE (path variables kept as written)\n"
          + "  params        array of parameter names (query, body, path) — can be []\n"
          + "  paramName     primary parameter for testing, or \"\"\n"
          + "  vulnClass     \"\" — leave blank, this round is route discovery only\n"
          + "  sinkType      \"\"\n"
          + "  sinkLocation  file:line of the route declaration/handler, or \"\"\n"
          + "  confidence    0.0..1.0\n"
          + "Completeness is the goal — list every route in the table, even without an obvious vulnerability.";

    private static final String ENRICH_SYS =
            "You are enriching a list of discovered HTTP routes with missing details, using the AUTHORITATIVE ROUTE "
          + "TABLE + HANDLER CODE you are given.\n"
          + "For each route:\n"
          + "  - Fill params[] with all query params, body fields, and path variables the route's handler reads\n"
          + "  - Set paramName to the primary tainted parameter KEY (the key read in code: req.query['id'] / "
          + "req.body.accountno / request.args.get('q') / a handler arg like `string keyword` → id / accountno / q / "
          + "keyword) — NEVER the accessor word ('query','body','params','args')\n"
          + "  - Set sinkLocation to file:line of the sink or handler\n"
          + "  - Set vulnClass/sinkType ONLY when a clear dangerous sink is visible in the handler (else leave \"\")\n"
          + "Bind params by matching each route to the HANDLER CODE that serves it (by handler name, controller, or "
          + "file). Do NOT copy a param onto a route whose handler does not read it (no guessing by resemblance).\n"
          + "Keep every \"path\" EXACTLY as it appears in the ROUTE TABLE — never rewrite a path. You may add routes "
          + "from the ROUTE TABLE not yet in the list, but never invent paths outside it.\n"
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
