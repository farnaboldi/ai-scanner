package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ABSTRACT authenticated SPA navigator (pure-Montoya + LLM; NO browser / external dep). A static crawl never executes
 * a JS-driven app's client code, so the app's DATA surface — the record lists / grids / detail views / searches loaded
 * on demand — never enters the site map and the audit battery never audits it (the login can succeed while the data
 * layer behind menu→interface→grid navigation stays unreachable to a static crawl).
 *
 * <p>This navigator hands the app's OWN client JavaScript (the code that calls its data endpoints) plus a running log
 * of what it has already fetched to the model, and asks for the NEXT read-only requests that navigate DEEPER into the
 * data (enumerate menus/modules, open a module, load its list, open a record, run a search), REUSING ids the responses
 * returned. Each request it executes (authenticated, read-only) is added to the site map so every downstream probe
 * (IDOR / BOLA / SQLi / authz / secret-exposure / …) then audits it. Generic: the MODEL derives each app's protocol
 * from its JS — no per-app rule. Safety: STRICTLY read-only (state-changing calls are blocked), scope-locked, bounded.</p>
 */
public final class SpaNavigator {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private final AiEngine engine;
    private final SessionStore session;
    private final List<HttpRequestResponse> reachedRrs = new ArrayList<>();   // data endpoints reached, for the caller to add as targets

    private static final int MAX_ROUNDS = 6;
    private static final int MAX_TOTAL = 40;
    private static final int SATURATE = 2;   // reach an operation this many times, then stop re-enumerating its ids
    private static final Pattern SELECTOR_KV = Pattern.compile(
            "[\"']?(callType|call|action|op|operation|cmd|command|method|verb|func|fn|rpc|service|mode)[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9_./-]{1,40})[\"']");
    private static final Pattern DATA_CALL = Pattern.compile(
            "(?i)(callWebService|postWebResource|\\.ajax\\s*\\(|\\$\\.(?:get|post)\\s*\\(|fetch\\s*\\(|XMLHttpRequest|PageMethods\\.)");
    private static final Pattern GUID = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    // Clear STATE-CHANGE tokens in a call/callType/url ⇒ never execute (live-prod safety). Read verbs pass.
    private static final Pattern DESTRUCTIVE = Pattern.compile(
            "(?i)(\"(?:call|callType)\"?\\s*:\\s*\"?(?:delete|remove|save|update|insert|create|add|set|edit|submit|approve|reject|assign|upload|import|send|reset|clear|revoke|grant|move|copy|merge|purge|drop|truncate))"
          + "|/(?:delete|remove|save|update|insert|create|add|edit|submit|approve|reject|assign|upload|import|reset)\\b");

    public SpaNavigator(MontoyaApi api, ScanLog scanLog, AiEngine engine, SessionStore session) {
        this.api = api; this.scanLog = scanLog; this.engine = engine; this.session = session;
    }

    /** Drive the authenticated SPA's data protocol; returns the number of data endpoints reached + bridged to audit. */
    public int navigate(String host, String landingUrl) {
        if (engine == null || !engine.isConfigured() || session == null || !session.authenticated()) return 0;
        String origin = originOf(landingUrl != null && !landingUrl.isBlank() ? landingUrl : ("https://" + host + "/"));
        // Pull the app's ON-DEMAND JS modules into view FIRST. A JS-driven app loads its grid/interface-load
        // protocol code lazily (head.load / requirejs / dynamic <script>), so a static crawl never fetches it and
        // the data protocol is invisible. BFS the app's OWN .js references (authenticated) into the site map so the
        // deep protocol becomes readable below. Deterministic + generic: it only follows refs the app itself emits.
        fetchOnDemandJs(host, origin);
        String appJs = gatherDataCallJs(host);
        if (appJs.length() < 80) { scanLog.debug("[AI Scanner] SPA-nav: no client data-call JS in the site map — nothing to drive."); return 0; }
        // Vocabulary from the FULL data-call JS corpus (every fetched module), NOT the truncated call-site context —
        // otherwise a rich module that got crowded out of the 38k budget (e.g. the interface-load file) takes its
        // exact op names with it and the model keeps guessing. The corpus scan guarantees the real names are present.
        String vocab = extractOpVocab(host);
        List<String> observed = new ArrayList<>();
        Set<String> tried = new HashSet<>();
        java.util.Map<String,Integer> opCount = new java.util.HashMap<>();   // per-OPERATION (url+selector) reach count
        int reached = 0;
        for (int round = 0; round < MAX_ROUNDS && reached < MAX_TOTAL; round++) {
            String out;
            try { out = engine.chat(SYSTEM, buildUser(origin, appJs, vocab, observed, saturatedOps(opCount)), "spa-nav: plan"); }
            catch (Throwable t) { scanLog.debug("[AI Scanner] SPA-nav chat error: " + t); break; }
            List<Req> reqs = parseReqs(out);
            if (reqs.isEmpty()) break;
            boolean anyNew = false;
            for (Req r : reqs) {
                if (reached >= MAX_TOTAL) break;
                String url = absolutize(origin, r.url);
                if (url == null || !sameHost(url, host)) continue;
                if (isDestructive(r)) { scanLog.debug("[AI Scanner] SPA-nav skip (state-changing): " + r.method + " " + url); continue; }
                // OPERATION saturation: a dispatcher op already reached SATURATE× (same url+selector, different ids)
                // adds no audit surface — the id is one fuzzable param, tested once. Stop burning budget re-enumerating
                // it; force the model toward NEW operation types + descending into each module's grid/search.
                String op = opSignature(url, r.body);
                if (opCount.getOrDefault(op, 0) >= SATURATE) { scanLog.debug("[AI Scanner] SPA-nav skip saturated op: " + op); continue; }
                String sig = up(r.method) + " " + url + " " + Integer.toHexString((r.body == null ? "" : r.body).hashCode());
                if (!tried.add(sig)) continue;
                HttpRequestResponse rr = execRepair(r.method, url, r.contentType, r.body);
                if (rr == null || rr.response() == null) continue;
                int st = rr.response().statusCode();
                observed.add(summary(r.method, url, r.body, rr));   // feed EVERY response to the model (a 401/500 still guides navigation)
                anyNew = true;
                if (st < 400) {                                     // but only a USABLE response joins the audit surface (no 401/5xx noise)
                    try { api.siteMap().add(rr); } catch (Throwable ignore) {}
                    reachedRrs.add(rr);
                    reached++;
                    opCount.merge(op, 1, Integer::sum);
                }
                scanLog.debug("[AI Scanner]   SPA-nav " + up(r.method) + " " + url.replaceAll("^https?://[^/]+", "")
                        + (r.body != null && !r.body.isEmpty() ? " body=" + clip(r.body, 160) : "")
                        + " -> HTTP " + rr.response().statusCode());
            }
            if (!anyNew) break;
        }
        if (reached > 0) scanLog.log("[AI Scanner] SPA navigator: reached " + reached
                + " authenticated data endpoint(s) the static crawl missed → added to the audit surface for probing.");
        return reached;
    }

    /** The 2xx/data request-responses the navigator reached — for the caller to also register as audit targets. */
    public List<HttpRequestResponse> reachedResponses() { return reachedRrs; }

    /** Operation identity = url + its dispatch-selector values (callType/call/…) — NOT the record id. So
     *  LoadUserInterface(id1) and LoadUserInterface(id2) share one signature; GetMenu is a different one. */
    private String opSignature(String url, String body) {
        StringBuilder sb = new StringBuilder(url.replaceAll("^https?://[^/]+", "").replaceAll("\\?.*$", ""));
        if (body != null) {
            Matcher m = SELECTOR_KV.matcher(body);
            java.util.TreeSet<String> kv = new java.util.TreeSet<>();
            while (m.find()) kv.add(m.group(1).toLowerCase() + "=" + m.group(2));
            for (String s : kv) sb.append('|').append(s);
        }
        return sb.toString();
    }

    /** Operations already reached >= SATURATE× — fed to the model as "done, don't re-enumerate; go elsewhere/deeper". */
    private String saturatedOps(java.util.Map<String,Integer> opCount) {
        java.util.List<String> done = new java.util.ArrayList<>();
        for (java.util.Map.Entry<String,Integer> e : opCount.entrySet())
            if (e.getValue() >= SATURATE) done.add(e.getKey().replaceAll("^[^|]*\\|?", ""));
        return String.join("; ", done);
    }

    /** Collect the client JS (bounded) that actually CALLS data endpoints — the protocol the model must reproduce.
     *  Files are ranked by dispatcher DENSITY (how many data-call sites they contain) so that when many on-demand
     *  modules were fetched, the richest ones (the interface-load / grid protocol) win the budget instead of being
     *  crowded out by whatever the site map happened to iterate first. */
    private String gatherDataCallJs(String host) {
        StringBuilder sb = new StringBuilder();
        try {
            List<String[]> files = new ArrayList<>();   // [url, body]
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.response() == null) continue;
                String u = safeUrl(rr.request());
                if (u == null || !host.equalsIgnoreCase(hostOf(u)) || !u.toLowerCase().contains(".js")) continue;
                String body = rr.response().bodyToString();
                if (body == null || !DATA_CALL.matcher(body).find()) continue;
                files.add(new String[]{u, body});
            }
            files.sort((a, b) -> Integer.compare(density(b[1]), density(a[1])));   // richest dispatcher files first
            for (String[] f : files) {
                if (sb.length() > 38000) break;
                sb.append("// ").append(f[0].replaceAll("^https?://[^/]+", "")).append("\n");
                Matcher m = DATA_CALL.matcher(f[1]);
                int added = 0;
                // Wide windows so the FULL call site is visible — the (callType, call, data-template) triple a
                // dispatcher needs is what lets the model reproduce a deeper op, not just the call primitive.
                while (m.find() && added < 10 && sb.length() < 38000) {
                    int s = Math.max(0, m.start() - 550), e = Math.min(f[1].length(), m.end() + 550);
                    sb.append(f[1], s, e).append("\n----\n");
                    added++;
                }
            }
        } catch (Throwable ignore) {}
        return sb.toString();
    }

    private static int density(String body) {
        int n = 0; Matcher m = DATA_CALL.matcher(body);
        while (m.find() && n < 1000) n++;
        return n;
    }

    // A path-like `.js` reference: a src=/href= attribute value OR a bare quoted string literal (head.load /
    // requirejs / systemjs module lists are exactly these). Path chars only, so it matches module refs not prose.
    private static final Pattern JS_REF = Pattern.compile(
            "(?i)(?:src|href)\\s*=\\s*[\"']([^\"'>]+?\\.js)(?:\\?[^\"']*)?[\"']"
          + "|[\"']([A-Za-z0-9_.~/\\-]+?\\.js)(?:\\?[^\"']*)?[\"']");
    private static final int MAX_JS_FETCH = 80;

    /**
     * Deterministic, generic BFS of the app's OWN JavaScript dependency graph. Seeds from the HTML shells + JS
     * already in the site map, extracts every same-host `.js` reference (script-src AND bare string-literal module
     * paths — head.load / requirejs / systemjs), fetches each authenticated into the site map, and recurses into
     * what those modules reference. No hardcoded paths — it only follows refs the application itself emits. This is
     * what turns the on-demand grid/interface-load protocol from invisible into readable for the navigation below.
     */
    private void fetchOnDemandJs(String host, String origin) {
        try {
            LinkedHashSet<String> queued = new LinkedHashSet<>();
            Set<String> done = new HashSet<>();
            java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
            StringBuilder loader = new StringBuilder();   // module-loader code, for the LLM arm (computed paths)
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.response() == null) continue;
                String u = safeUrl(rr.request());
                if (u == null || !host.equalsIgnoreCase(hostOf(u))) continue;
                if (u.toLowerCase().contains(".js")) done.add(canon(u));     // already have it
                String body = rr.response().bodyToString();
                if (body == null) continue;
                for (String abs : jsRefsAbs(body, u, origin)) if (queued.add(abs)) q.add(abs);
                collectLoaderRegions(body, loader);
            }
            // (1) DETERMINISTIC backbone — follow every literal .js ref the app emits (no hallucination, exhaustive).
            int det = 0;
            while (!q.isEmpty() && det < MAX_JS_FETCH) {
                String jsUrl = q.poll();
                if (!sameHost(jsUrl, host) || !done.add(canon(jsUrl))) continue;
                String body = fetchJs(jsUrl);
                if (body == null) continue;
                det++;
                for (String abs : jsRefsAbs(body, jsUrl, origin)) if (queued.add(abs)) q.add(abs);
                collectLoaderRegions(body, loader);
            }
            // (2) LLM arm — computed/templated module paths (head.load(base+name+'.js')) are invisible to a literal
            // regex; have the model read the loader code and infer the concrete URLs. Fetched with the same 404 guard,
            // so a hallucinated path is simply dropped. Free on a local model; the one thing the backbone structurally
            // can't do. Runs only when a module loader is actually present.
            int llm = 0;
            if (loader.length() > 60) {
                for (String ref : llmInferModuleUrls(loader.toString(), origin)) {
                    if (det + llm >= MAX_JS_FETCH) break;
                    String abs = ref.regionMatches(true, 0, "http", 0, 4) ? ref
                               : (ref.startsWith("/") ? origin + ref : origin + "/" + ref.replaceAll("^\\./", ""));
                    if (!sameHost(abs, host) || !done.add(canon(abs))) continue;
                    if (fetchJs(abs) != null) llm++;
                }
            }
            if (det + llm > 0) scanLog.log("[AI Scanner] SPA-nav: pulled " + (det + llm)
                    + " on-demand JS module(s) into the site map" + (llm > 0 ? " (" + llm + " via LLM-inferred computed paths)" : "")
                    + " — exposing the grid/interface-load protocol.");
            else scanLog.debug("[AI Scanner] SPA-nav: no new on-demand JS modules to fetch.");
        } catch (Throwable t) { scanLog.debug("[AI Scanner] SPA-nav on-demand JS fetch error: " + t); }
    }

    /** GET a .js url (authenticated), add to site map if it's a real script (not an HTML 200-fallback); return body. */
    private String fetchJs(String jsUrl) {
        HttpRequestResponse rr = exec("GET", jsUrl, null, null);
        if (rr == null || rr.response() == null || rr.response().statusCode() >= 400) return null;
        String body = rr.response().bodyToString();
        if (body == null || body.length() < 20 || looksHtml(body)) return null;
        try { api.siteMap().add(rr); } catch (Throwable ignore) {}
        return body;
    }

    private static final Pattern MODULE_LOADER = Pattern.compile(
            "(?i)(head\\.load|head\\.js|require\\s*\\(|requirejs|System\\.import|\\.getScript|loadScript|loadModule|import\\s*\\()");
    /** Collect bounded regions around module-loader calls — the code that COMPUTES module paths, for the LLM arm. */
    private void collectLoaderRegions(String body, StringBuilder loader) {
        if (loader.length() > 16000 || !MODULE_LOADER.matcher(body).find()) return;
        Matcher m = MODULE_LOADER.matcher(body);
        int added = 0;
        while (m.find() && added < 8 && loader.length() < 16000) {
            int s = Math.max(0, m.start() - 220), e = Math.min(body.length(), m.end() + 300);
            loader.append(body, s, e).append("\n--\n");
            added++;
        }
    }

    /** Ask the model to resolve the module loader's COMPUTED .js paths to concrete URLs the regex couldn't. */
    private List<String> llmInferModuleUrls(String loaderJs, String origin) {
        List<String> out = new ArrayList<>();
        try {
            String sys = "You are given a web app's client-side MODULE-LOADER JavaScript. It loads .js modules on demand, "
                    + "frequently via COMPUTED paths (string concatenation, a base variable + a name, a version suffix). "
                    + "Enumerate the concrete .js module URLs it would request — resolve computed pieces to literal paths "
                    + "wherever the fragments are visible. Output ONLY a JSON array of url strings (absolute or "
                    + "root-relative), no prose.";
            String resp = engine.chat(sys, "BASE: " + origin + "\n\nMODULE-LOADER JS:\n" + loaderJs, "spa-nav: module-loader");
            if (resp == null) return out;
            Matcher m = Pattern.compile("[\"']([^\"']+?\\.js)(?:\\?[^\"']*)?[\"']").matcher(resp);
            LinkedHashSet<String> s = new LinkedHashSet<>();
            while (m.find() && s.size() < 60) { String r = m.group(1); if (!r.contains("${") && !r.contains("{{")) s.add(r); }
            out.addAll(s);
        } catch (Throwable ignore) {}
        return out;
    }

    /** Resolve every `.js` reference in `body` to absolute same-origin candidate URL(s), relative to `pageUrl`. */
    private List<String> jsRefsAbs(String body, String pageUrl, String origin) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        Matcher m = JS_REF.matcher(body);
        while (m.find() && out.size() < 400) {
            String ref = m.group(1) != null ? m.group(1) : m.group(2);
            if (ref == null || ref.isBlank() || ref.contains("${") || ref.contains("{{") || ref.startsWith("//")) continue;
            if (ref.regionMatches(true, 0, "http", 0, 4)) { out.add(ref); continue; }
            if (ref.startsWith("/")) { out.add(origin + ref); continue; }
            try { out.add(URI.create(pageUrl).resolve(ref).toString()); } catch (Throwable ignore) {}
            out.add(origin + "/" + ref);   // head.load paths are often root-relative-without-slash → also try origin root
        }
        return new ArrayList<>(out);
    }

    private static boolean looksHtml(String body) {
        String h = body.length() > 300 ? body.substring(0, 300) : body;
        h = h.trim().toLowerCase();
        return h.startsWith("<!doctype") || h.startsWith("<html") || h.startsWith("<?xml") || h.contains("<head");
    }
    private static String canon(String url) {
        try { URI u = URI.create(url); String p = u.getPath(); return Net.authority(url).toLowerCase() + (p == null ? "" : p); }
        catch (Throwable t) { return url; }
    }

    private static final String SYSTEM =
            "You navigate a JS-driven web application that a security scanner is ALREADY AUTHENTICATED to, so the scanner "
          + "can reach the app's DATA surface (record lists, grids, detail views, search, lookups) that a static crawler "
          + "misses. You are given the app's OWN client JavaScript (the code that calls its data endpoints) and a log of "
          + "requests already executed with their response summaries. Produce the NEXT batch of HTTP requests that "
          + "navigate DEEPER into the data: enumerate menus/modules/interfaces, open a module, load its record list/grid, "
          + "open a record, run a search/lookup. Go BROAD — enumerate as many interfaces/modules as you can to reach and "
          + "exercise their data operations; and where a prior response already gave you a module's REAL datasource/source "
          + "id, you may also load its record rows (only ever with a real id you actually saw — never a blank/empty one). "
          + "REUSE ids/GUIDs/values that appear in the observed responses — NEVER "
          + "invent ids. Reproduce the EXACT request shape the JS builds (wrappers like {data:'...'}, @-prefixed keys, "
          + "callType/call dispatchers, etc.). IMPORTANT: if the JS calls JSON.stringify() on a payload/data field "
          + "before sending (very common for dispatcher 'data'/'request'/'payload' fields), that field MUST be a "
          + "STRING containing escaped JSON in your output, NOT a nested object. Output ONLY a compact JSON array, no prose: "
          + "[{\"method\":\"POST\",\"url\":\"<app-relative or absolute>\",\"contentType\":\"application/json\",\"body\":\"<verbatim>\"}]. "
          + "STRICTLY READ-ONLY: only list/load/get/read/view/search/lookup operations — NEVER delete, save, update, "
          + "insert, create, submit, approve, upload or any state change.";

    /** Distinct identifier-like ('PascalCase') quoted string literals from the data-call JS — the app's operation
     *  vocabulary (callType/call/operation names). Handing the model the EXACT names stops it inventing a
     *  plausible-but-wrong name instead of the real one the JS actually uses. Generic. */
    private static final Pattern OP_LITERAL = Pattern.compile("['\"]([A-Z][A-Za-z0-9]{2,39})['\"]");
    /** Operation vocabulary over EVERY data-call JS module in the site map (not the truncated context), so exact op
     *  names from modules crowded out of the context budget still reach the model. Generic. */
    private String extractOpVocab(String host) {
        LinkedHashSet<String> ops = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (ops.size() >= 200) break;
                if (rr == null || rr.response() == null) continue;
                String u = safeUrl(rr.request());
                if (u == null || !host.equalsIgnoreCase(hostOf(u)) || !u.toLowerCase().contains(".js")) continue;
                String body = rr.response().bodyToString();
                if (body == null || !DATA_CALL.matcher(body).find()) continue;
                Matcher m = OP_LITERAL.matcher(body);
                while (m.find() && ops.size() < 200) ops.add(m.group(1));
            }
        } catch (Throwable ignore) {}
        return String.join(", ", ops);
    }

    private String buildUser(String origin, String appJs, String vocab, List<String> observed, String saturated) {
        StringBuilder sb = new StringBuilder();
        sb.append("BASE: ").append(origin).append("\n\nAPP DATA-CALL JAVASCRIPT:\n").append(appJs).append("\n\n");
        if (vocab != null && !vocab.isBlank())
            sb.append("OPERATION NAMES that literally appear in that JS — use ONLY these EXACT strings for a dispatcher's "
                    + "callType/call and for operation/endpoint names; do NOT invent a similar-sounding name — copy the "
                    + "exact spelling the JS uses:\n").append(vocab).append("\n\n");
        if (observed.isEmpty()) {
            sb.append("Nothing executed yet. Start by enumerating the app's menu / modules / interfaces (the calls the "
                    + "JS makes on load), then we will go deeper.\n");
        } else {
            sb.append("ALREADY EXECUTED (request -> HTTP status, ids, snippet). Lines marked OK worked — COPY that exact "
                    + "shape for the same dispatcher; lines with 4xx/5xx failed — change the operation or params, do NOT repeat them:\n");
            int from = Math.max(0, observed.size() - 24);
            for (String o : observed.subList(from, observed.size())) sb.append("  ").append(o).append("\n");
            sb.append("\nGo DEEPER and BROADER: propose DIFFERENT operations you have NOT run yet (a working call chains to the "
                    + "next: menu -> interface/module list -> load an interface/module -> load its record list/grid -> open a "
                    + "record), feeding ids from the OK responses above. Do not repeat an operation already shown.\n");
            if (saturated != null && !saturated.isBlank())
                sb.append("SATURATED — you have already exercised these operations enough; do NOT call them again with new ids: "
                        + saturated + "\n");
            sb.append("HIGHEST VALUE NOW: descend to the actual RECORD ROWS and SEARCHES. When a load/search-options response "
                    + "reveals a module's datasource/source id and its filterable field names, ISSUE THE SEARCH/GRID LOAD — a "
                    + "list/items/search-results call that carries that real source id plus a filter/search VALUE for a field "
                    + "(these free-text filter/search values are the real injectable surface). Never use a blank source id.\n");
        }
        return sb.toString();
    }

    /**
     * Send, and if the server 500s on a JSON body, auto-repair a COMMON SPA-dispatcher shape mismatch: many
     * page-method / dispatcher endpoints require a nested payload field to arrive as a STRINGIFIED json string
     * (the client does {@code JSON.stringify(payload)}), not as a nested object — the model often emits the object.
     * On a 5xx we retry with each object/array-valued top-level field stringified (then all of them). Deterministic,
     * generic (no per-app rule): a dispatcher that wants data-as-string 500s on data-as-object; the retry recovers it.
     */
    private HttpRequestResponse execRepair(String method, String url, String ct, String body) {
        HttpRequestResponse rr = exec(method, url, ct, body);
        if (rr == null || rr.response() == null) return rr;
        if (rr.response().statusCode() < 500 || body == null || body.isEmpty() || "GET".equalsIgnoreCase(up(method))) return rr;
        for (String variant : stringifiedVariants(body)) {
            HttpRequestResponse rr2 = exec(method, url, ct, variant);
            if (rr2 != null && rr2.response() != null && rr2.response().statusCode() < 400) {
                scanLog.debug("[AI Scanner]   SPA-nav shape-repair: nested payload field stringified → HTTP "
                        + rr2.response().statusCode());
                return rr2;
            }
        }
        return rr;   // no variant worked → keep the original (its 5xx body still guides the model)
    }

    /** Variants of a JSON object body with one (then all) object/array-valued field(s) replaced by their string form. */
    private List<String> stringifiedVariants(String body) {
        List<String> out = new ArrayList<>();
        try {
            org.json.JSONObject o = new org.json.JSONObject(body.trim());
            List<String> objKeys = new ArrayList<>();
            for (String k : o.keySet()) {
                Object v = o.get(k);
                if (v instanceof org.json.JSONObject || v instanceof org.json.JSONArray) objKeys.add(k);
            }
            if (objKeys.isEmpty()) return out;
            for (String k : objKeys) {                                   // one field at a time (usual case: a single 'data'/'payload')
                org.json.JSONObject c = new org.json.JSONObject(body.trim());
                c.put(k, o.get(k).toString());
                out.add(c.toString());
            }
            if (objKeys.size() > 1) {                                    // all nested fields stringified
                org.json.JSONObject c = new org.json.JSONObject(body.trim());
                for (String k : objKeys) c.put(k, o.get(k).toString());
                out.add(c.toString());
            }
        } catch (Throwable ignore) {}
        return out;
    }

    private HttpRequestResponse exec(String method, String url, String ct, String body) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod(up(method));
            if (body != null && !body.isEmpty() && !"GET".equalsIgnoreCase(up(method))) {
                // Normalise JS-object-literal bodies (unquoted keys / single quotes, which the model often emits and
                // the server tolerates) into STRICT JSON, so Burp parses the fields as fuzzable JSON params and the
                // audit target-dedup can key on the operation-selector value — otherwise every dispatcher op collapses
                // to one un-parseable, un-fuzzable target.
                req = req.withBody(normalizeJson(body)).withHeader("Content-Type", ct == null || ct.isBlank() ? "application/json" : ct);
            }
            req = withSession(req);
            return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(20000L));
        } catch (Throwable t) { return null; }
    }

    /** JS-object-literal (or already-JSON) body → strict JSON; org.json's tokenizer is lenient on input. */
    private static String normalizeJson(String body) {
        String t = body == null ? "" : body.trim();
        if (t.isEmpty() || (t.charAt(0) != '{' && t.charAt(0) != '[')) return body;
        try { return t.charAt(0) == '[' ? new org.json.JSONArray(t).toString() : new org.json.JSONObject(t).toString(); }
        catch (Throwable ignore) { return body; }
    }

    private HttpRequest withSession(HttpRequest req) {
        HttpRequest r = req;
        if (session.has()) r = r.withHeader("Cookie", session.cookieHeader());
        if (session.hasBearer()) r = r.withHeader("Authorization", "Bearer " + session.bearer());
        if (session.hasSigningKey()) r = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKey()).sign(r);
        return r;
    }

    /** Response summary for the model's next round: a SUCCESS gets a wide body window (the record/menu/interface
     *  structure it must navigate into); an error gets a short window (the message that says what to fix). Plus the
     *  exact request body sent (so the model reuses the shape that WORKED and avoids the ones that 500'd). */
    private String summary(String method, String url, String body, HttpRequestResponse rr) {
        int st = rr.response().statusCode();
        String rb = rr.response().bodyToString(); if (rb == null) rb = "";
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        Matcher m = GUID.matcher(rb); while (m.find() && ids.size() < 14) ids.add(m.group());
        int win = st < 400 ? 700 : 200;
        String snip = (rb.length() > win ? rb.substring(0, win) : rb).replaceAll("\\s+", " ");
        return up(method) + " " + url.replaceAll("^https?://[^/]+", "")
             + (body != null && !body.isEmpty() ? " body=" + clip(body, 220) : "")
             + " -> " + st + (st < 400 ? " OK" : "") + " ids=" + ids + " | " + snip;
    }

    private boolean isDestructive(Req r) {
        String meth = up(r.method);
        if (!meth.equals("GET") && !meth.equals("POST")) return true;   // block PUT/PATCH/DELETE outright
        String hay = (r.url == null ? "" : r.url) + " " + (r.body == null ? "" : r.body);
        return DESTRUCTIVE.matcher(hay).find();
    }

    // ---- Robust request extraction. The model may wrap the array in prose/reasoning, a {requests:[…]} object, or
    // markdown fences, and a big multi-request round is exactly when the naive first-'['/last-']' slice breaks (a
    // bracket in the reasoning → whole round drops → navigation stalls one level early). Instead pull EVERY balanced
    // top-level {…} object (string-aware) and keep the ones that look like a request (have a url). ----
    private List<Req> parseReqs(String out) {
        List<Req> list = new ArrayList<>();
        if (out == null || out.isBlank()) return list;
        String t = out.replaceAll("```+(?:json)?", " ");
        int depth = 0, start = -1;
        boolean inStr = false; char q = 0;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (inStr) {
                if (c == '\\') { i++; continue; }
                if (c == q) inStr = false;
                continue;
            }
            if (c == '"' || c == '\'') { inStr = true; q = c; continue; }
            if (c == '{') { if (depth == 0) start = i; depth++; }
            else if (c == '}') {
                if (depth > 0 && --depth == 0 && start >= 0) {
                    Req r = toReq(t.substring(start, i + 1));
                    if (r != null) list.add(r);
                    start = -1;
                }
            }
        }
        if (list.isEmpty()) scanLog.debug("[AI Scanner]   SPA-nav: no parseable request objects in model output (" + clip(t.trim(), 140) + ")");
        return list;
    }

    /** Parse one {…} object into a Req; null unless it carries a url. A nested-object/array `body` is stringified. */
    private Req toReq(String obj) {
        try {
            org.json.JSONObject o = new org.json.JSONObject(obj);
            String url = o.optString("url", o.optString("URL", ""));
            if (url.isBlank()) return null;
            Req r = new Req();
            r.method = o.optString("method", o.optString("verb", "POST"));
            r.url = url;
            r.contentType = o.optString("contentType", o.optString("content_type", "application/json"));
            Object bodyVal = o.opt("body");
            r.body = bodyVal == null ? "" : (bodyVal instanceof String ? (String) bodyVal : bodyVal.toString());
            return r;
        } catch (Throwable t) { return null; }
    }

    // ---- url helpers ----
    private static String up(String m) { return m == null || m.isBlank() ? "POST" : m.trim().toUpperCase(); }
    private String absolutize(String origin, String url) {
        if (url == null || url.isBlank()) return null;
        if (url.toLowerCase().startsWith("http")) return url;
        return origin == null ? null : origin + "/" + url.replaceAll("^/", "");
    }
    private boolean sameHost(String url, String host) {
        try { return host.equalsIgnoreCase(Net.authority(url)); } catch (Throwable t) { return false; }
    }
    private static String originOf(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : ""); }
        catch (Throwable t) { return null; }
    }
    private static String hostOf(String url) { return Net.authority(url); }
    private String safeUrl(HttpRequest r) { try { return r == null ? null : r.url(); } catch (Throwable t) { return null; } }
    private static String clip(String s, int n) { return s == null ? "" : (s.length() <= n ? s : s.substring(0, n) + "…"); }

    private static final class Req { String method, url, contentType, body; }
}
