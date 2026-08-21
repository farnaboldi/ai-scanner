package com.ioactive.aiscanner.scan.sast;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * DETERMINISTIC source-side route/schema harvester (SAST gap 5b). Parses a repo's GraphQL SDL and framework
 * route tables into {@link StaticHint}s with populated params — surface a black-box crawl and even the LLM
 * passes can miss (hidden/admin routes, every GraphQL resolver argument).
 *
 * <p>No LLM: pure regex/parse, so it runs with or without an AI backend and adds coverage in no-AI mode. Like
 * every SAST output it only STEERS — each harvested route is live-probed by discovery and each param is decided
 * by a deterministic oracle, so a wrong route costs one 404, never a false finding.</p>
 */
public final class RouteHarvester {
    private RouteHarvester() {}

    private static final int MAX_FILES = 4000;
    private static final int MAX_HINTS = 400;
    private static final long MAX_FILE_BYTES = 400_000;
    private static final int MAX_LINE = 5000;   // skip minified/bundled files (one huge line): no route decls + a catastrophic-regex hazard

    private static final Pattern SKIP = Pattern.compile(
            "(?i)(^|/)(\\.git|node_modules|dist|build|target|vendor|\\.venv|venv|__pycache__|bower_components|bin|obj|\\.next|\\.nuxt)(/|$)");
    private static final Pattern EXT = Pattern.compile(
            "(?i)\\.(java|kt|js|mjs|cjs|ts|tsx|jsx|py|rb|php|go|cs|scala|graphql|graphqls|gql)$");

    /** Harvest deterministic route/GraphQL directives from a local checkout. Empty on any problem (never null). */
    public static SourceFindings harvest(String repoPath) {
        if (repoPath == null || repoPath.isBlank()) return SourceFindings.empty();
        final Path root;
        try { root = Paths.get(repoPath).toRealPath(); } catch (Exception e) { return SourceFindings.empty(); }
        if (!Files.isDirectory(root)) return SourceFindings.empty();

        LinkedHashMap<String, StaticHint> dedup = new LinkedHashMap<>();
        int[] files = {0};
        try (Stream<Path> walk = Files.walk(root, 12)) {
            List<Path> cands = new ArrayList<>();
            walk.filter(Files::isRegularFile)
                .filter(p -> !SKIP.matcher(rel(root, p)).find())
                .filter(p -> EXT.matcher(p.getFileName().toString()).find())
                .limit(20_000)
                .forEach(cands::add);
            for (Path p : cands) {
                if (files[0] >= MAX_FILES || dedup.size() >= MAX_HINTS) break;
                try {
                    if (!p.toRealPath().startsWith(root)) continue;      // symlink escape guard
                    if (Files.size(p) > MAX_FILE_BYTES) continue;
                    String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                    if (text.indexOf('\0') >= 0) continue;               // binary
                    if (maxLineLen(text) > MAX_LINE) continue;           // minified/bundled (jquery/bootstrap): no routes + regex hazard
                    files[0]++;
                    String prov = rel(root, p);
                    for (StaticHint h : parseGraphqlSdl(text, prov)) dedup.putIfAbsent(key(h), h);
                    for (StaticHint h : parseRoutes(text, prov)) dedup.putIfAbsent(key(h), h);
                } catch (Exception ignore) { }
            }
        } catch (Exception ignore) { }
        return new SourceFindings(new ArrayList<>(dedup.values()));
    }

    // ---- GraphQL SDL ----

    private static final Pattern GQL_TYPE  = Pattern.compile("(?is)type\\s+(Query|Mutation)\\s*\\{");
    private static final Pattern GQL_FIELD = Pattern.compile("(?m)^\\s*(\\w+)\\s*(\\(([^)\\n]{0,200})\\))?\\s*:\\s*[\\[\\]\\w!]{1,100}");
    private static final Pattern GQL_ARG   = Pattern.compile("(\\w+)\\s*:");

    /** Parse {@code type Query{...}} / {@code type Mutation{...}} blocks; each field+args → a /graphql directive. */
    static List<StaticHint> parseGraphqlSdl(String sdl, String prov) {
        List<StaticHint> out = new ArrayList<>();
        if (sdl == null || sdl.indexOf('{') < 0) return out;
        Matcher t = GQL_TYPE.matcher(sdl);
        while (t.find()) {
            String kind = t.group(1);
            int open = t.end() - 1;                 // the '{'
            int close = sdl.indexOf('}', open);     // GraphQL type bodies don't nest braces
            if (close < 0) continue;
            String body = sdl.substring(open + 1, Math.min(close, open + 1 + 20_000));
            Matcher f = GQL_FIELD.matcher(body);
            while (f.find()) {
                String field = f.group(1);
                if (field == null || field.isBlank() || field.equalsIgnoreCase("type")) continue;
                List<String> params = new ArrayList<>();
                String argsRaw = f.group(3);
                if (argsRaw != null) {
                    Matcher a = GQL_ARG.matcher(argsRaw);
                    while (a.find()) addUnique(params, a.group(1));
                }
                String paramName = params.isEmpty() ? field : params.get(0);
                out.add(new StaticHint("POST", "/graphql", new ArrayList<>(params), paramName,
                        "", "graphql", prov + " " + kind + "." + field, 0.5, ""));
            }
        }
        return out;
    }

    // ---- framework route tables ----

    // NOTE: path-literal groups are bounded to {1,300} and exclude newlines — an UNBOUNDED [^'"]+ over a
    // minified bundle's multi-KB line recurses per char in java.util.regex and blows the stack (StackOverflowError).
    private static final Pattern EXPRESS = Pattern.compile("(?i)\\b(app|router)\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"`]([^'\"`\\n]{1,300})['\"`]");
    private static final Pattern FASTAPI = Pattern.compile("(?i)@\\s*\\w+\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"]([^'\"\\n]{1,300})['\"]");
    private static final Pattern FLASK   = Pattern.compile("(?i)@\\s*\\w+\\.route\\s*\\(\\s*['\"]([^'\"\\n]{1,300})['\"]");
    // Spring MVC is COMPOSITIONAL like ASP.NET: a class-level @RequestMapping("/api/foo") prefix + each method's
    // @GetMapping("/bar"). A Spring method path is RELATIVE to the class prefix (concatenated), NEVER absolute —
    // so /api/foo + /bar = /api/foo/bar (distinct from ASP.NET, where a leading-'/' method route overrides).
    private static final Pattern SPRING_CLASS    = Pattern.compile("\\bclass\\s+\\w+");
    private static final Pattern SPRING_CLASSMAP = Pattern.compile("(?i)@RequestMapping\\s*\\(\\s*(?:value\\s*=\\s*|path\\s*=\\s*)?(?:\\{\\s*)?['\"]([^'\"\\n]{1,300})['\"]");
    private static final Pattern SPRING_METHOD   = Pattern.compile("(?i)@(Get|Post|Put|Delete|Patch|Request)Mapping\\b(?:\\s*\\(([^)]{0,400})\\))?");
    private static final Pattern SPRING_ANNOVAL  = Pattern.compile("(?i)(?:value|path)\\s*=\\s*(?:\\{\\s*)?['\"]([^'\"\\n]{0,300})['\"]");
    private static final Pattern SPRING_FIRSTSTR = Pattern.compile("['\"]([^'\"\\n]{0,300})['\"]");
    private static final Pattern SPRING_REQVERB  = Pattern.compile("(?i)RequestMethod\\.(GET|POST|PUT|DELETE|PATCH)");
    private static final Pattern LARAVEL = Pattern.compile("(?i)Route::(get|post|put|delete|patch|any|match)\\s*\\(\\s*['\"]([^'\"\\n]{1,300})['\"]");
    private static final Pattern DJANGO  = Pattern.compile("(?i)\\b(?:path|re_path|url)\\s*\\(\\s*r?['\"]([^'\"\\n]{1,300})['\"]");
    private static final Pattern DRF     = Pattern.compile("(?i)\\brouter\\.register\\s*\\(\\s*r?['\"]([^'\"\\n]{1,300})['\"]");
    private static final Pattern RAILS_V = Pattern.compile("(?im)^\\s*(get|post|put|patch|delete)\\s+['\"]([^'\"\\n]{1,300})['\"]");
    private static final Pattern RAILS_R = Pattern.compile("(?i)\\bresources?\\s+:(\\w+)");
    // ASP.NET Core attribute routing is COMPOSITIONAL: a class-level [Route("api/[controller]")] prefix + each
    // method's [HttpGet("sub")] / [HttpPost] etc. The [controller] token resolves to the class name minus "Controller".
    private static final Pattern ASPNET_CLASSNAME = Pattern.compile("(?i)\\bclass\\s+(\\w+?)Controller\\b");
    private static final Pattern ASPNET_ROUTE     = Pattern.compile("(?i)\\[\\s*Route\\s*\\(\\s*\"([^\"\\n]{1,300})\"");
    private static final Pattern ASPNET_METHOD    = Pattern.compile("(?i)\\[\\s*Http(Get|Post|Put|Delete|Patch)\\b(?:\\s*\\(\\s*\"([^\"\\n]{0,300})\")?");
    // Go routers: gorilla/mux r.HandleFunc("/x"), and gin/echo/chi r.GET("/x") (UPPERCASE verbs, Go convention —
    // stays case-sensitive so it does NOT collide with Express's lowercase app.get). {id:[0-9]+} constraints are
    // normalized to {id} by normPath. Go string literals are double-quoted.
    private static final Pattern GO_MUX  = Pattern.compile("\\.HandleFunc\\s*\\(\\s*\"([^\"\\n]{1,300})\"");
    private static final Pattern GO_VERB = Pattern.compile("\\b\\w+\\.(GET|POST|PUT|DELETE|PATCH|Handle)\\s*\\(\\s*\"([^\"\\n]{1,300})\"");

    /** Parse framework route declarations from a source string into route directives. */
    static List<StaticHint> parseRoutes(String code, String prov) {
        List<StaticHint> out = new ArrayList<>();
        if (code == null || code.isBlank()) return out;
        collect(out, EXPRESS, code, prov, 2, 3, null);      // app/router.<verb>('/x')
        collect(out, FASTAPI, code, prov, 1, 2, null);      // @router.<verb>('/x')
        collect(out, FLASK,   code, prov, 0, 1, "GET");     // @app.route('/x')
        out.addAll(parseSpring(code, prov));                // Spring MVC (class @RequestMapping prefix + method @*Mapping)
        collect(out, LARAVEL, code, prov, 1, 2, null);      // Route::<verb>('/x')
        collect(out, DJANGO,  code, prov, 0, 1, "GET");     // path('x/<int:id>/')
        collect(out, DRF,     code, prov, 0, 1, "GET");     // router.register(r'accounts')
        collect(out, RAILS_V, code, prov, 1, 2, null);      // get '/x'
        collect(out, GO_VERB, code, prov, 1, 2, null);      // Go gin/echo/chi: r.GET("/x") / r.Handle("/x")
        collect(out, GO_MUX,  code, prov, 0, 1, "");        // Go gorilla/mux: r.HandleFunc("/x")
        // rails resources :things → /things (collection)
        Matcher r = RAILS_R.matcher(code);
        while (r.find()) {
            String path = "/" + r.group(1);
            out.add(new StaticHint("", path, new ArrayList<>(), "", "", "route", prov, 0.5, ""));
        }
        out.addAll(parseAspNet(code, prov));                // ASP.NET Core attribute routing (class [Route] + method [Http*])
        return out;
    }

    /** ASP.NET Core attribute routing → concrete routes. One controller per file (the standard convention):
     *  resolve the class-level [Route] prefix (expanding the [controller] token) then append each method's [Http*] path. */
    static List<StaticHint> parseAspNet(String code, String prov) {
        List<StaticHint> out = new ArrayList<>();
        if (code == null || code.indexOf('[') < 0) return out;   // no C# attributes → nothing to do (cheap gate)
        Matcher cm = ASPNET_CLASSNAME.matcher(code);
        if (!cm.find()) return out;                              // not a *Controller file → not attribute routing
        String ctrl = cm.group(1).toLowerCase();                // UsersController → "users"
        int classAt = cm.start();
        String prefix = "";                                     // class-level [Route]: keep the one nearest the class keyword
        Matcher rp = ASPNET_ROUTE.matcher(code.substring(0, classAt));
        while (rp.find()) prefix = rp.group(1);
        prefix = resolveAspNetTokens(prefix, ctrl);
        Matcher hm = ASPNET_METHOD.matcher(code.substring(classAt));
        while (hm.find()) {
            String method = normMethod(hm.group(1));
            String sub = resolveAspNetTokens(hm.group(2), ctrl);            // null-safe (bare [HttpGet] → "")
            String path = normPath(joinAspNet(prefix, sub));
            if (path.isBlank()) continue;
            // Params = path tokens ({id}) PLUS the action method's signature parameters (e.g. Search(string keyword)
            // → keyword). The signature params are the QUERY/BODY inputs a probe must fuzz — without them a GET route
            // with no path token (…/products/search) is harvested with ZERO params and its keyword-based SQLi is
            // never reached. Deterministic, steering-only; discovery live-probes and the oracles decide.
            List<String> params = new ArrayList<>(pathParams(path));
            for (String mp : aspNetMethodParams(code, hm.end())) if (!params.contains(mp)) params.add(mp);
            out.add(new StaticHint(method, path, params, params.isEmpty() ? "" : params.get(0), "", "route", prov, 0.5, ""));
        }
        return out;
    }

    // C# action parameter types that are framework/DI plumbing, not user input — excluded from the fuzzable param set.
    private static final Pattern ASPNET_SKIP_PARAM_TYPE = Pattern.compile(
            "(?i)^(cancellationtoken|httpcontext|httprequest|httpresponse|iformcollection|claimsprincipal|"
          + "ilogger|iloggerfactory|iconfiguration|iserviceprovider|imediator)$");

    /** Extract the action METHOD's declared parameters (query/body inputs) from the C# signature that follows a
     *  {@code [Http*]} attribute at {@code from}. The signature is the {@code (...)} immediately before the method
     *  body {@code {}; each comma segment's LAST identifier is the param name (attributes/defaults/types stripped).
     *  Framework/DI-typed params are dropped. Best-effort + regex-bounded — a miss costs coverage, never soundness. */
    static List<String> aspNetMethodParams(String code, int from) {
        List<String> names = new ArrayList<>();
        try {
            int brace = code.indexOf('{', from);
            int end = brace < 0 ? Math.min(code.length(), from + 600) : Math.min(brace, from + 600);
            if (end <= from) return names;
            String window = code.substring(from, end);
            int close = window.lastIndexOf(')');
            int open = close < 0 ? -1 : window.lastIndexOf('(', close);
            if (open < 0 || open >= close) return names;
            String sig = window.substring(open + 1, close);
            for (String part : sig.split(",")) {
                String seg = part.replaceAll("\\[[^\\]]*\\]", " ").trim();      // strip [FromQuery]/[FromBody]/…
                int eq = seg.indexOf('='); if (eq >= 0) seg = seg.substring(0, eq).trim();   // strip default value
                Matcher idm = Pattern.compile("(\\w+)\\s*$").matcher(seg);
                if (!idm.find()) continue;
                String name = idm.group(1);
                String type = seg.substring(0, seg.length() - name.length()).trim();
                type = type.replaceAll("[?<>\\[\\],].*$", "").trim();           // Type<...>/Type[]/Type? → base token
                if (type.isEmpty() || ASPNET_SKIP_PARAM_TYPE.matcher(type).find()) continue;   // no bare word / DI plumbing
                if (!name.isEmpty() && !names.contains(name)) names.add(name);
            }
        } catch (Throwable ignore) { }
        return names;
    }

    private static String resolveAspNetTokens(String s, String ctrl) {
        if (s == null) return "";
        return s.replaceAll("(?i)\\[controller\\]", ctrl == null ? "" : ctrl)
                .replaceAll("(?i)\\[action\\]", "");
    }

    /** Combine a class route prefix with a method sub-path (a method path starting with '/' overrides the prefix). */
    private static String joinAspNet(String prefix, String sub) {
        String p = prefix == null ? "" : prefix.trim();
        String s = sub == null ? "" : sub.trim();
        if (s.startsWith("/")) return s;                        // method route absolute
        if (!s.isEmpty()) return (p.isEmpty() ? "" : p) + "/" + s;
        return p;                                               // bare [HttpGet] → prefix is the endpoint
    }

    /** Spring MVC attribute routing → concrete routes. One controller per file (the standard convention):
     *  resolve the class-level @RequestMapping prefix, then CONCATENATE each method @*Mapping path (Spring paths
     *  are relative to the class prefix, so /api + /x = /api/x even when the method path starts with '/'). */
    static List<StaticHint> parseSpring(String code, String prov) {
        List<StaticHint> out = new ArrayList<>();
        if (code == null || code.indexOf('@') < 0 || !code.contains("Mapping")) return out;   // cheap gate: no Spring annos
        Matcher cm = SPRING_CLASS.matcher(code);
        int classAt = cm.find() ? cm.start() : 0;
        String prefix = "";                                     // class-level @RequestMapping (before the class keyword)
        Matcher rp = SPRING_CLASSMAP.matcher(code.substring(0, classAt));
        while (rp.find()) prefix = rp.group(1);
        Matcher mm = SPRING_METHOD.matcher(code.substring(classAt));
        while (mm.find()) {
            String kind = mm.group(1);                          // Get|Post|Put|Delete|Patch|Request
            String args = mm.group(2);                          // may be null (bare @GetMapping) — method = prefix
            String sub  = springAnnoPath(args);
            String verb = kind.equalsIgnoreCase("Request") ? springAnnoVerb(args) : kind;
            String path = normPath(joinSpring(prefix, sub));
            if (path.isBlank()) continue;
            List<String> params = pathParams(path);
            out.add(new StaticHint(normMethod(verb), path, params, params.isEmpty() ? "" : params.get(0), "", "route", prov, 0.5, ""));
        }
        return out;
    }

    /** Extract a route path from a Spring mapping annotation's arg string: value=/path= wins, else a positional
     *  first string literal (@GetMapping("/x")); a key='...' that isn't value/path (produces=, consumes=) is ignored. */
    private static String springAnnoPath(String args) {
        if (args == null) return "";
        Matcher v = SPRING_ANNOVAL.matcher(args);
        if (v.find()) return v.group(1);
        Matcher s = SPRING_FIRSTSTR.matcher(args);
        if (s.find() && !args.substring(0, s.start()).matches("(?s).*[A-Za-z_]\\s*=\\s*$")) return s.group(1);
        return "";
    }

    private static String springAnnoVerb(String args) {
        if (args == null) return "";
        Matcher m = SPRING_REQVERB.matcher(args);
        return m.find() ? m.group(1) : "";                      // @RequestMapping(method=RequestMethod.POST) → POST
    }

    /** Spring join: ALWAYS concatenate prefix + sub (method paths are relative to the class prefix). */
    private static String joinSpring(String prefix, String sub) {
        String p = prefix == null ? "" : prefix.trim();
        String s = sub == null ? "" : sub.trim();
        if (p.isEmpty()) return s;
        if (s.isEmpty()) return p;
        return p + "/" + s;                                     // normPath() collapses the resulting //
    }

    private static void collect(List<StaticHint> out, Pattern p, String code, String prov,
                                int verbGroup, int pathGroup, String fixedMethod) {
        Matcher m = p.matcher(code);
        while (m.find()) {
            String method = verbGroup > 0 ? normMethod(m.group(verbGroup)) : (fixedMethod == null ? "" : fixedMethod);
            String path = normPath(m.group(pathGroup));
            if (path.isBlank()) continue;
            List<String> params = pathParams(path);
            String paramName = params.isEmpty() ? "" : params.get(0);
            out.add(new StaticHint(method, path, params, paramName, "", "route", prov, 0.5, ""));
        }
    }

    // ---- normalization ----

    private static final Pattern P_BRACE = Pattern.compile("\\{(\\w+)\\}");        // {id}
    private static final Pattern P_COLON = Pattern.compile(":(\\w+)");             // :id
    private static final Pattern P_ANGLE = Pattern.compile("<(?:\\w+:)?(\\w+)>");  // <int:pk> / <pk>

    static String normMethod(String v) {
        if (v == null) return "";
        switch (v.trim().toUpperCase()) {
            case "GET": return "GET";
            case "POST": return "POST";
            case "PUT": return "PUT";
            case "DELETE": return "DELETE";
            case "PATCH": return "PATCH";
            default: return "";   // any/match/request/unknown → let discovery default it
        }
    }

    static String normPath(String raw) {
        if (raw == null) return "";
        String p = raw.trim();
        p = p.replaceAll("\\{(\\w+)[^}]{0,60}\\}", "{$1}");          // route constraints/optionals: {id:int} {id?} -> {id}
        p = p.replaceFirst("^\\^", "").replaceFirst("\\$$", "");     // drop regex anchors
        p = p.replaceAll("\\(\\?P<(\\w+)>[^)]*\\)", "{$1}");         // django named group → {name}
        p = p.replaceAll("\\([^)]*\\)", "");                          // drop remaining regex groups
        p = p.replace("\\", "");                                      // stray regex escapes
        if (p.isBlank()) return "";
        if (!p.startsWith("/")) p = "/" + p;
        p = p.replaceAll("/{2,}", "/");
        return p;
    }

    static List<String> pathParams(String path) {
        List<String> ps = new ArrayList<>();
        for (Pattern pat : new Pattern[]{P_BRACE, P_COLON, P_ANGLE}) {
            Matcher m = pat.matcher(path);
            while (m.find()) addUnique(ps, m.group(1));
        }
        return ps;
    }

    // ---- helpers ----

    private static void addUnique(List<String> list, String v) {
        if (v != null && !v.isBlank() && !list.contains(v)) list.add(v);
    }

    private static String key(StaticHint h) {
        return (h.method + "|" + h.path + "|" + h.paramName + "|" + h.sinkType).toLowerCase();
    }

    private static String rel(Path root, Path p) {
        try { return root.relativize(p).toString().replace('\\', '/'); } catch (Exception e) { return p.toString(); }
    }

    /** Longest line (in chars) — used to skip minified/bundled files before running regexes over them. */
    private static int maxLineLen(String s) {
        int max = 0, cur = 0;
        for (int i = 0, n = s.length(); i < n; i++) {
            if (s.charAt(i) == '\n') { if (cur > max) max = cur; cur = 0; } else cur++;
        }
        return Math.max(max, cur);
    }
}
