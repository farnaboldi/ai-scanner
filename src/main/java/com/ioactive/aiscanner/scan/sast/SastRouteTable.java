package com.ioactive.aiscanner.scan.sast;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds the SAST LLM context as two linked sections: an <b>AUTHORITATIVE ROUTE TABLE</b> of the app's real
 * HTTP method+path registrations (so the model copies exact paths instead of guessing them from filenames),
 * plus <b>handler context</b> that shows each route's params + dangerous sink. Multi-framework harvest:
 * Express, ASP.NET, Spring/Java (class+method composed), Flask, Django (include()-chain prefixes composed),
 * Go (mux/gin), Rails (routes.rb, nested {@code resources} CRUD-expanded), and file-routed (path=file).
 *
 * <p>Rationale + measurements in [[sast-integration-test-harness]]: verbatim-path table took cross-file
 * validity from 0–26% to ~100%; the composition fixes (Django include prefixes, nested Rails resources)
 * repair the paths the model itself mangles (e.g. crapi {@code /api/mechanic/} missing its {@code /workshop/}
 * mount).</p>
 */
final class SastRouteTable {

    private SastRouteTable() {}

    private static final int MAX_ROUTES     = 600;
    private static final int MAX_CONTEXT    = 60_000;
    private static final int MAX_SIGNALS    = 500;
    private static final int MAX_BODY_CHARS = 7_000;
    private static final int MAX_FILE_BYTES = 200_000;

    private static final Pattern EXPRESS = Pattern.compile(
            "(?:app|router|route)\\.(get|post|put|delete|patch|all|use)\\(\\s*['\"`](/[^'\"`]*)['\"`]",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CS_CLASS  = Pattern.compile("class\\s+(\\w+Controller)\\b");
    private static final Pattern CS_ROUTE  = Pattern.compile("\\[Route\\(\\s*\"([^\"]*)\"");
    private static final Pattern CS_ACTION = Pattern.compile("\\[Http(Get|Post|Put|Delete|Patch)(?:\\(\\s*\"([^\"]*)\"\\s*\\))?\\s*\\]");
    private static final Pattern J_CLASSRT = Pattern.compile("@RequestMapping\\s*\\(\\s*(?:value|path)?\\s*=?\\s*[\"']([^\"']+)[\"']");
    private static final Pattern J_METHOD  = Pattern.compile("@(Get|Post|Put|Delete|Patch)Mapping\\s*\\(\\s*(?:value\\s*=\\s*)?[\"']([^\"']+)[\"']");
    private static final Pattern PY_FLASK   = Pattern.compile("@\\w+\\.route\\(\\s*['\"]([^'\"]+)['\"](?:[^)]*methods\\s*=\\s*\\[([^\\]]+)\\])?");
    // FastAPI / Starlette: @router.get("/path") @app.post("/path") etc. — HTTP verb is the method name
    private static final Pattern PY_FASTAPI = Pattern.compile("@\\w+\\.(get|post|put|delete|patch)\\(\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern PY_DJANGO  = Pattern.compile("(?:re_path|url|path)\\(\\s*r?['\"]\\^?([^'\"$]*?)\\$?['\"]\\s*,");
    private static final Pattern PY_INCLUDE= Pattern.compile("(?:re_path|url|path)\\(\\s*r?['\"]\\^?([^'\"$]*?)\\$?['\"]\\s*,\\s*include\\(\\s*['\"]([\\w.]+)['\"]");
    private static final Pattern GO_MUX    = Pattern.compile("\\.HandleFunc\\(\\s*\"([^\"]+)\"(?:[^)]*)\\)(?:\\.Methods\\(([^)]*)\\))?");
    private static final Pattern GO_GIN    = Pattern.compile("\\.(GET|POST|PUT|DELETE|PATCH)\\(\\s*\"([^\"]+)\"");
    private static final Pattern RB_VERB   = Pattern.compile("^\\s*(get|post|put|patch|delete)\\s+['\"]([^'\"]+)['\"]");
    private static final Pattern RB_RES    = Pattern.compile("^\\s*(resources?)\\s+:(\\w+)");
    private static final Pattern RB_SCOPE  = Pattern.compile("^\\s*(?:namespace|scope)\\s+[:'\"]?([\\w/]+)");

    private static final Pattern MULTI_SINK = Pattern.compile(
            "(?i)(Runtime\\.getRuntime|ProcessBuilder|readObject|XMLDecoder|createStatement|\\.execute(Query|Update)?\\(|"
          + "FromSql|ExecuteSql|JdbcTemplate|openConnection|os\\.system|subprocess\\.|\\beval\\(|\\bexec\\(|render_template|"
          + "pickle\\.(loads|load)|cursor\\.execute|mark_safe|\\.Query\\(|\\.Raw\\(|exec\\.Command|system\\(|"
          + "mysqli?_query|->query|pg_query|shell_exec|passthru|include(_once)?|require(_once)?)");
    private static final Pattern HANDLER_PATH = Pattern.compile(
            "(?i)(controller|handler|route|view|service|resource|endpoint|api)");

    static final class Result {
        final String context; final int routes, handlerUnits; final String handlerType;
        Result(String c, int r, int h, String t) { context = c; routes = r; handlerUnits = h; handlerType = t; }
        boolean isEmpty() { return routes == 0 && handlerUnits == 0; }
    }

    static Result build(Path root, List<Path> cands) {
        Set<String> table = new LinkedHashSet<>();
        Set<Path> routeFiles = new LinkedHashSet<>();
        Map<Path, String> djangoPfx = djangoPrefixes(cands);   // include()-chain mount prefixes

        for (Path p : cands) {
            if (table.size() >= MAX_ROUTES) break;
            String name = p.getFileName().toString().toLowerCase();
            int before = table.size();
            if (name.matches(".*\\.(js|mjs|cjs|ts|tsx|jsx)$"))               harvestExpress(p, table);
            else if (name.endsWith(".cs"))                                   harvestCSharp(p, table);
            else if (name.endsWith(".java"))                                 harvestJava(p, table);
            else if (name.endsWith(".py"))                                   harvestPython(p, table, djangoPfx.getOrDefault(p, ""));
            else if (name.endsWith(".go"))                                   harvestGo(p, table);
            else if (name.equals("routes.rb"))                              harvestRuby(p, table);
            if (table.size() > before) routeFiles.add(p);
        }

        // Postman collection: always harvest if present — routes are authoritative (human-written, not inferred).
        // Adds to whatever framework harvesters found, or provides the full table when they found nothing.
        harvestPostman(root, table);

        boolean flat = table.size() < 3;
        if (flat) {
            table.clear(); routeFiles.clear();
            for (Path p : cands) {
                String rel = "/" + root.relativize(p).toString().replace('\\', '/');
                if (rel.matches("(?i).*\\.(php|jsp|asp|aspx|cfm|py|rb)$")) table.add("GET " + rel);
                if (table.size() >= MAX_ROUTES) break;
            }
        }

        List<String> handler = new ArrayList<>();
        String htype;
        if (flat) {
            htype = "line signals";
            int budget = 0;
            for (Path p : cands) {
                if (handler.size() >= MAX_SIGNALS || budget >= MAX_CONTEXT) break;
                try {
                    if (Files.size(p) > MAX_FILE_BYTES) continue;
                    String rel = "/" + root.relativize(p).toString().replace('\\', '/');
                    List<String> lines = Files.readAllLines(p);
                    for (int i = 0; i < lines.size() && handler.size() < MAX_SIGNALS && budget < MAX_CONTEXT; i++) {
                        String ln = lines.get(i);
                        if (SastPatterns.SINK.matcher(ln).find() || SastPatterns.PARAM_READ.matcher(ln).find()
                                || MULTI_SINK.matcher(ln).find()) {
                            String s = rel + ":" + (i + 1) + "  " + ln.trim();
                            if (s.length() > 300) s = s.substring(0, 300);
                            handler.add(s); budget += s.length();
                        }
                    }
                } catch (Exception ignore) { }
            }
        } else {
            htype = "handler bodies";
            int budget = 0;
            List<Path> ordered = new ArrayList<>(routeFiles);
            for (Path p : cands) if (!routeFiles.contains(p)) ordered.add(p);
            for (Path p : ordered) {
                if (handler.size() >= 40 || budget >= MAX_CONTEXT) break;
                try {
                    if (Files.size(p) > MAX_FILE_BYTES) continue;
                    String rel = root.relativize(p).toString().replace('\\', '/');
                    boolean interesting = routeFiles.contains(p) || HANDLER_PATH.matcher(rel).find();
                    String txt = new String(Files.readAllBytes(p));
                    if (!interesting && !MULTI_SINK.matcher(txt).find() && !SastPatterns.SINK.matcher(txt).find()) continue;
                    if (txt.length() > MAX_BODY_CHARS) txt = txt.substring(0, MAX_BODY_CHARS) + "\n… (truncated)";
                    handler.add("=== " + rel + " ===\n" + txt);
                    budget += txt.length();
                } catch (Exception ignore) { }
            }
        }

        String ctx = "=== AUTHORITATIVE ROUTE TABLE (" + table.size()
                + " real HTTP method+path registrations — COPY paths VERBATIM, never reconstruct from a filename) ===\n"
                + String.join("\n", table)
                + "\n\n=== HANDLER CODE (params each route reads + dangerous sinks) ===\n"
                + String.join("\n", handler);
        return new Result(ctx, table.size(), handler.size(), htype);
    }

    // ---- per-framework harvesters ----

    private static void harvestExpress(Path p, Set<String> table) {
        forEachLine(p, ln -> { Matcher m = EXPRESS.matcher(ln);
            while (m.find() && table.size() < MAX_ROUTES) table.add(m.group(1).toUpperCase() + " " + m.group(2)); });
    }

    private static void harvestCSharp(Path p, Set<String> table) {
        composeAttr(p, table, CS_CLASS, CS_ROUTE, CS_ACTION, "Controller");
    }

    private static void harvestJava(Path p, Set<String> table) {
        try {
            List<String> lines = Files.readAllLines(p);
            String base = "";
            for (String ln : lines) { Matcher m = J_CLASSRT.matcher(ln); if (m.find()) { base = m.group(1); break; } }
            for (String ln : lines) {
                Matcher m = J_METHOD.matcher(ln);
                while (m.find()) { addComposed(table, m.group(1).toUpperCase(), base, m.group(2)); if (table.size() >= MAX_ROUTES) return; }
                // @RequestMapping(value="/x", method=RequestMethod.GET) — extract both from the annotation args
                if (ln.contains("@RequestMapping") && ln.contains("method")) {
                    Matcher path = Pattern.compile("[\"']([^\"']+)[\"']").matcher(ln);
                    Matcher meth = Pattern.compile("RequestMethod\\.(\\w+)").matcher(ln);
                    if (path.find() && meth.find()) addComposed(table, meth.group(1).toUpperCase(), base, path.group(1));
                }
            }
        } catch (Exception ignore) { }
    }

    private static void harvestPython(Path p, Set<String> table, String mountPrefix) {
        forEachLine(p, ln -> {
            // FastAPI/Starlette: @router.get("/path") @app.post("/path") — verb-specific decorators
            Matcher fa = PY_FASTAPI.matcher(ln);
            while (fa.find() && table.size() < MAX_ROUTES)
                table.add(fa.group(1).toUpperCase() + " " + join(mountPrefix, fa.group(2)));
            // Flask: @app.route("/path", methods=["GET","POST"])
            Matcher f = PY_FLASK.matcher(ln);
            while (f.find()) {
                String path = f.group(1), methods = f.group(2);
                if (methods == null) table.add("GET " + join(mountPrefix, path));
                else for (String mm : methods.split(",")) table.add(clean(mm) + " " + join(mountPrefix, path));
                if (table.size() >= MAX_ROUTES) return;
            }
            if (PY_INCLUDE.matcher(ln).find()) return;   // include() line handled by djangoPrefixes, not a leaf route
            Matcher d = PY_DJANGO.matcher(ln);
            while (d.find() && table.size() < MAX_ROUTES) {
                String path = d.group(1);
                if (path != null && !path.contains("admin") && !ln.contains("include("))
                    table.add("GET " + join(mountPrefix, path));
            }
        });
    }

    private static void harvestGo(Path p, Set<String> table) {
        forEachLine(p, ln -> {
            Matcher mux = GO_MUX.matcher(ln);
            while (mux.find()) {
                String path = mux.group(1), methods = mux.group(2);
                if (methods == null || methods.isBlank()) table.add("GET " + path);
                else for (String mm : methods.split(",")) table.add(clean(mm) + " " + path);
                if (table.size() >= MAX_ROUTES) return;
            }
            Matcher gin = GO_GIN.matcher(ln);
            while (gin.find() && table.size() < MAX_ROUTES) table.add(gin.group(1).toUpperCase() + " " + gin.group(2));
        });
    }

    /** Rails routes.rb: verb shortcuts + resources (CRUD), with namespace/scope AND nested-resource prefixes. */
    private static void harvestRuby(Path p, Set<String> table) {
        try {
            List<String> stack = new ArrayList<>();   // accumulated path segments (namespaces, parent resources)
            for (String ln : Files.readAllLines(p)) {
                String t = ln.trim();
                boolean opens = t.endsWith(" do") || t.endsWith("do");
                String prefix = String.join("", stack);

                Matcher res = RB_RES.matcher(ln);
                Matcher scp = RB_SCOPE.matcher(ln);
                Matcher vb  = RB_VERB.matcher(ln);
                if (res.find()) {
                    String name = res.group(2);
                    String base = prefix + "/" + name;
                    crud(table, base);
                    if (opens) stack.add("/" + name + "/:" + singular(name) + "_id");
                } else if (scp.find()) {
                    if (opens) stack.add("/" + scp.group(1));
                } else if (vb.find()) {
                    table.add(vb.group(1).toUpperCase() + " " + prefix + "/" + vb.group(2).replaceAll("^/+", ""));
                } else if (t.startsWith("root")) {
                    table.add("GET /");
                } else if (opens) {
                    stack.add("");   // member/collection/other block — keep stack balanced
                }
                if (t.equals("end") && !stack.isEmpty()) stack.remove(stack.size() - 1);
                if (table.size() >= MAX_ROUTES) return;
            }
        } catch (Exception ignore) { }
    }

    private static void crud(Set<String> table, String base) {
        table.add("GET " + base); table.add("POST " + base);
        table.add("GET " + base + "/new"); table.add("GET " + base + "/:id");
        table.add("GET " + base + "/:id/edit"); table.add("PATCH " + base + "/:id");
        table.add("PUT " + base + "/:id"); table.add("DELETE " + base + "/:id");
    }

    // ---- Django include() prefix resolution ----

    /** Map each urls.py to its full mount prefix by following path('p/', include('module')) chains. */
    private static Map<Path, String> djangoPrefixes(List<Path> cands) {
        Map<Path, String> parentPrefix = new HashMap<>();
        Map<Path, Path> parentFile = new HashMap<>();
        for (Path p : cands) {
            if (!p.getFileName().toString().endsWith(".py")) continue;
            try {
                if (Files.size(p) > MAX_FILE_BYTES) continue;
                for (String ln : Files.readAllLines(p)) {
                    Matcher m = PY_INCLUDE.matcher(ln);
                    if (m.find()) {
                        Path child = resolveModule(cands, m.group(2));
                        if (child != null && !child.equals(p)) { parentFile.put(child, p); parentPrefix.put(child, m.group(1)); }
                    }
                }
            } catch (Exception ignore) { }
        }
        Map<Path, String> full = new HashMap<>();
        for (Path f : parentFile.keySet()) {
            StringBuilder acc = new StringBuilder();
            Path cur = f; int guard = 0;
            while (parentFile.containsKey(cur) && guard++ < 12) {
                acc.insert(0, "/" + parentPrefix.get(cur).replaceAll("^/+|/+$", ""));
                cur = parentFile.get(cur);
            }
            full.put(f, acc.toString().replaceAll("//+", "/"));
        }
        return full;
    }

    /** Resolve a dotted Python module ('crapi.mechanic.urls') to a candidate file ('.../crapi/mechanic/urls.py'). */
    private static Path resolveModule(List<Path> cands, String mod) {
        String rel = mod.replace('.', '/') + ".py";
        String relPkg = mod.replace('.', '/') + "/urls.py";
        for (Path p : cands) {
            String s = p.toString().replace('\\', '/');
            if (s.endsWith("/" + rel) || s.endsWith("/" + relPkg)) return p;
        }
        return null;
    }

    // ---- helpers ----

    private static void composeAttr(Path p, Set<String> table, Pattern classRe, Pattern baseRe, Pattern actionRe, String suffix) {
        try {
            List<String> lines = Files.readAllLines(p);
            String cls = null, base = "";
            for (String ln : lines) { Matcher m = classRe.matcher(ln); if (m.find()) { cls = m.group(1); break; } }
            if (cls == null) return;   // not a controller
            String ctrl = cls.replaceAll(suffix + "$", "");
            for (String ln : lines) { Matcher m = baseRe.matcher(ln); if (m.find()) { base = m.group(1); break; } }
            base = base.replace("[controller]", ctrl).replace("[action]", "");
            for (String ln : lines) {
                Matcher m = actionRe.matcher(ln);
                while (m.find()) { addComposed(table, m.group(1).toUpperCase(), base, m.group(2) == null ? "" : m.group(2));
                    if (table.size() >= MAX_ROUTES) return; }
            }
        } catch (Exception ignore) { }
    }

    private static void addComposed(Set<String> table, String verb, String base, String sub) {
        String path = join(base, sub == null ? "" : sub);
        table.add(verb + " " + path.toLowerCase());
    }

    private static String join(String base, String sub) {
        String a = base == null ? "" : base.replaceAll("/+$", "");
        String b = sub == null ? "" : sub.replaceAll("^/+", "");
        String path = b.isEmpty() ? a : (a.isEmpty() ? "/" + b : a + "/" + b);
        if (!path.startsWith("/")) path = "/" + path;
        return path.replaceAll("//+", "/");
    }

    private static String clean(String httpMethod) { return httpMethod.replaceAll("[^A-Za-z]", "").toUpperCase(); }
    private static String singular(String s) { return s.endsWith("s") ? s.substring(0, s.length() - 1) : s; }

    /** Harvest routes from Postman collections in the repo — human-written, authoritative paths. */
    private static void harvestPostman(Path root, Set<String> table) {
        if (table.size() >= MAX_ROUTES) return;
        try {
            SourceFindings pf = PostmanParser.parse(root.toString());
            for (StaticHint h : pf.all()) {
                if (h.path == null || h.path.isBlank() || h.path.contains("{{")) continue;
                String verb = (h.method == null || h.method.isBlank()) ? "GET" : h.method.toUpperCase();
                table.add(verb + " " + h.path);
                if (table.size() >= MAX_ROUTES) return;
            }
        } catch (Throwable ignore) { }
    }

    private interface LineFn { void accept(String ln); }
    private static void forEachLine(Path p, LineFn fn) {
        try { if (Files.size(p) > MAX_FILE_BYTES) return; for (String ln : Files.readAllLines(p)) fn.accept(ln); }
        catch (Exception ignore) { }
    }
}
