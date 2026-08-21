package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Closes Burp's coverage gap on JS-heavy apps. Burp's crawler doesn't execute JS, so
 * endpoints referenced only from JavaScript/HTML (AJAX calls, SPA routes, form actions)
 * never enter the site map. We mine the client-side code Burp already fetched — with a
 * regex pass (obvious URLs) AND the LLM (templated routes, inferred params) — build
 * candidate authenticated requests, then <b>probe each one</b> so hallucinated or dead
 * paths are filtered by reality. Only live endpoints are returned for auditing.
 *
 * <p>Entirely site-agnostic: no hardcoded paths, hosts, or credentials.
 */
public final class EndpointDiscovery {

    private final MontoyaApi api;
    private final Supplier<AiEngine> engine;
    private final SessionStore session;
    private final ScanLog scanLog;
    // Response pairs that discovery already fetched AND accepted as a real live endpoint. The caller
    // (AiScanner) drains this into api.siteMap() so the site-map-reading probes (IdorGet/Bfla/ChainReplay)
    // can see endpoints that discovery reached but Burp's crawler never did. Only pairs that pass keep()'s
    // guards enter — the same conditions under which the request was accepted, so no junk/FP surface.
    private final List<HttpRequestResponse> keptResponses = new ArrayList<>();

    // AI-path-discovered PAGES (see probeAiProposedPaths). Unlike keptResponses (JSON endpoints for the
    // IDOR/BFLA bridge, which deliberately filters out text/html via isHtmlShell), these are the real HTML
    // pages we set out to find — e.g. an unlinked /admin/ console. The caller adds them to the site map and
    // runs form-derivation over them (so an /admin/*-add form becomes a CSRF target).
    private final List<HttpRequestResponse> discoveredPages = new ArrayList<>();

    private static final Pattern STATIC = Pattern.compile(
            "(?i).*\\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)($|\\?).*");
    // quoted absolute URL or root-relative path (optionally with a query string)
    private static final Pattern URLISH = Pattern.compile(
            "[\"'`]((?:https?://[^\"'`\\s]+)|(?:/[A-Za-z0-9_][A-Za-z0-9_\\-/.]*(?:\\?[^\"'`\\s]*)?))[\"'`]");
    // A quoted page-ish leaf ending in a server-page extension (login.html, transfer.jsp, do…). Used AFTER collapsing
    // string concatenations, to recover URLs JS builds by concat (e.g. path + "login" + ".html") that URLISH misses.
    private static final Pattern CONCAT_PAGE = Pattern.compile(
            "[\"'`]([A-Za-z0-9_][A-Za-z0-9_\\-/]{0,60}\\.(?:html?|jspx?|php|do|action|aspx?|mvc))(?:\\?[^\"'`]*)?[\"'`]");
    private static final String SEP = "\u0001"; // spec field delimiter
    // third-party libraries: no business endpoints, and they used to eat the mining budget
    private static final Pattern LIBRARY_JS = Pattern.compile("(?i).*\\b(jquery|bootstrap|angular|backbone"
            + "|underscore|lodash|modernizr|placeholders?|require|requirejs|moment|d3|react|vue|polyfill"
            + "|respond|html5shiv|popper|slick|select2|datatables|handlebars|ember|zepto|prototype|mootools)"
            + "[.\\-].*");
    private static final int PER_SOURCE_CHARS = 8000; // cap on any single page/script body
    private static final int CHUNK_CHARS = 30000;     // sources are packed into ~30k chunks, 1 LLM call each
    // Discovery budgets (maxCandidates / maxSources / maxLlmChunks) live in Tuning — configurable at scan time via
    // -Daiscanner.maxCandidates|maxSources|maxLlmChunks (or the Settings tab), read at use below. Defaults 200/40/8.
    /** LLM discovery rounds to UNION (temp>0 samples differently each round → more coverage, and the union
     *  converges → reproducible). Default 3; override -Daiscanner.discoveryRounds / AISCANNER_DISCOVERY_ROUNDS.
     *  At temp=0 the early-stop collapses this to 1 round (greedy = identical each pass). Clamped to [1,10]. */
    private static int discoveryRounds() {
        String v = System.getProperty("aiscanner.discoveryRounds");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_DISCOVERY_ROUNDS");
        if (v == null || v.isBlank()) return 3;
        try { return Math.max(1, Math.min(10, Integer.parseInt(v.trim()))); } catch (NumberFormatException e) { return 3; }
    }
    /** Public accessor so the run-start banner can log the configured round count alongside the engine params. */
    public static int discoveryRoundsPublic() { return discoveryRounds(); }
    private static final int MAX_FETCH_SCRIPTS = 30;  // referenced JS chunks to ACTIVELY fetch for mining (SPAs)
    // Any .js referenced by a page (script src / preload link href) — the SPA bundles that hold the real API.
    private static final Pattern SCRIPT_REF = Pattern.compile("(?i)(?:src|href)\\s*=\\s*[\"']([^\"']+\\.js(?:\\?[^\"']*)?)[\"']");
    // A quoted, path-like `.js` STRING LITERAL (inline module-loader lists: headJS head.load, RequireJS, System.import).
    // Path chars only (no scheme/space) so it matches module refs, not arbitrary prose; same-host filter applied later.
    private static final Pattern INLINE_JS_REF = Pattern.compile("[\"']([A-Za-z0-9_./~-]+\\.js(?:\\?[^\"']*)?)[\"']");

    public EndpointDiscovery(MontoyaApi api, Supplier<AiEngine> engine, SessionStore session, ScanLog scanLog) {
        this.api = api;
        this.engine = engine;
        this.session = session;
        this.scanLog = scanLog;
    }

    /** Response pairs discovery fetched+accepted as real, for the caller to add to the site map. */
    public List<HttpRequestResponse> lastKeptResponses() { return keptResponses; }

    /** AI-path-discovered HTML pages, for the caller to bridge to the site map + derive forms from. */
    public List<HttpRequestResponse> lastDiscoveredPages() { return discoveredPages; }

    /** Source-derived endpoint hints (hidden routes/params from SAST). Empty = no effect on discovery. */
    private final java.util.List<com.ioactive.aiscanner.scan.sast.StaticHint> sourceHints = new java.util.ArrayList<>();

    /** Feed source-analysis directives so their routes/params get probed as candidate endpoints too. */
    public void addSourceHints(com.ioactive.aiscanner.scan.sast.SourceFindings f) {
        if (f != null) sourceHints.addAll(f.hiddenEndpoints());
    }

    /**
     * Stash a probe response for the site-map bridge — ONLY when it passes the same guards discovery
     * already used to accept the endpoint: in scope, a real (non-null) response, NOT the SPA HTML shell,
     * and a status that means a handler processed it (2xx / 400 / 401 / 403 / 409 / 422 — never 404/405).
     * So nothing enters the site map that discovery didn't already classify as a real live endpoint.
     */
    private void keep(HttpRequestResponse rr, String host) {
        if (rr == null || rr.response() == null) return;
        if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) return;
        if (isHtmlShell(rr)) return;
        int st = rr.response().statusCode();
        // A real handler ran for this path. 405 = the path exists but our METHOD was wrong (GET a POST-only API);
        // 500 = the handler ran and threw (e.g. a REST endpoint that errors on a malformed/GET request). Both mean a
        // live endpoint worth bridging so the probes can exercise it with the right method — a GET-only 404 does not.
        boolean handlerRan = (st >= 200 && st < 300)
                || st == 400 || st == 401 || st == 403 || st == 405 || st == 409 || st == 422 || st == 500;
        // Bounded (defensive): this list is per-scan and drained into the site map, but cap it so a huge
        // discovered surface can never pin an unbounded set of HTTP messages in memory (BApp large-project rule).
        if (handlerRan && keptResponses.size() < 500) keptResponses.add(rr);
    }

    /**
     * Mine candidate endpoint specs ("METHOD SEP path SEP csv-params") from the host's client-side
     * code (regex + LLM over ~30k chunks). Shared by {@link #discover} and {@link #discoverAuthRequests}.
     */
    // Per-host memo of the mined spec set + the source-count it was built from. mineSpecs() is called by BOTH
    // discover() and discoverAuthRequests(); without this the whole mine (regex + full-body harvest + LLM calls)
    // ran TWICE per host — double LLM cost and every "harvested endpoint" logged twice. We re-mine ONLY when the
    // source set actually grew (e.g. authed scripts entered the site map), so post-auth coverage is preserved.
    // STATIC (scan-scoped) memo: AiScanner.discoverAuthRequests() news a FRESH EndpointDiscovery per call, and
    // the auth orchestration calls it 4× (+ discover() once) — so an instance-field memo reset every time and the
    // full mine (gatherSources fetch + regex + full-body harvest + 3× LLM chunk calls) ran ~5× per host: 5× LLM
    // cost + the mine-src fetch spam. A static memo shares the result across all instances for the host. Safe
    // across targets/cells: keyed by host, and each matrix cell is its own Burp process (fresh statics).
    private static final java.util.Map<String, Set<String>> specsCache = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, Integer> specsSiteMapCount = new java.util.concurrent.ConcurrentHashMap<>();
    // Per-host set of content-hashes (url+body) of sources ALREADY sent to the LLM. When the site map grows and we
    // re-mine, only sources whose hash is NOT here are fed to the LLM — byte-identical bodies are never re-sent
    // (dedup). Static/scan-scoped like specsCache: shared across the fresh EndpointDiscovery instances the auth
    // orchestration news per call, reset per matrix cell (own Burp process).
    private static final java.util.Map<String, Set<String>> llmMinedSourceHashes = new java.util.concurrent.ConcurrentHashMap<>();

    /** Same-host site-map entry count — a CHEAP freshness signal (no body reads / fetches / LLM) so a memo hit
     *  skips gatherSources() entirely. Re-mine only when the surface actually grew (e.g. authed pages arrived). */
    private int siteMapCountForHost(String host) {
        int n = 0;
        try { for (HttpRequestResponse rr : api.siteMap().requestResponses())
                if (rr.request() != null && host.equalsIgnoreCase(hostOf(rr.request().url()))) n++; }
        catch (Throwable ignore) { }
        return n;
    }

    Set<String> mineSpecs(String host) {
        // Cheap pre-check BEFORE the expensive gatherSources(): reuse the memoized specs when the site map hasn't
        // grown since the last mine — this is what actually kills the 5× re-mine + mine-src fetch spam.
        int smc = siteMapCountForHost(host);
        Set<String> cachedEarly = specsCache.get(host);
        Integer prevSmc = specsSiteMapCount.get(host);
        if (cachedEarly != null && prevSmc != null && prevSmc == smc) {
            scanLog.debug("endpoint discovery: reusing " + cachedEarly.size() + " mined spec(s) for "
                    + host + " (site map unchanged since last pass — skipping re-mine + re-LLM + re-fetch)");
            return new LinkedHashSet<>(cachedEarly);
        }
        // The site map GREW (e.g. authenticated pages/scripts arrived). Seed from the previous mine so the specs the
        // LLM already derived from UNCHANGED sources are RETAINED — otherwise a fresh empty set would lose them, since
        // below we feed the LLM ONLY the new/changed sources. This seed + the per-source hash dedup are what stop the
        // LLM being re-burned on byte-identical JS/HTML every post-auth / re-crawl pass.
        Set<String> specs = new LinkedHashSet<>(cachedEarly != null ? cachedEarly : java.util.Collections.emptySet());
        List<String[]> sources = gatherSources(host);   // {url, body}, deep/authenticated pages first
        if (sources.isEmpty()) {
            scanLog.log("endpoint discovery: no client-side code to mine for " + host + ".");
            return specs;
        }
        scanLog.phase("AI endpoint discovery (mining JS/HTML)");
        AiEngine eng = engine != null ? engine.get() : null;
        boolean canLlm = eng != null && eng.isConfigured();
        // CONTENT-HASH DEDUP: split sources into those already sent to the LLM (unchanged) vs new/changed. The hash
        // keys on url+body, so a same-URL page whose body changed (anon → authenticated /dashboard) counts as new and
        // is re-mined — only byte-identical bodies are skipped. This is the fix for the repeated full re-discovery.
        Set<String> minedHashes = llmMinedSourceHashes.computeIfAbsent(host, k -> java.util.concurrent.ConcurrentHashMap.newKeySet());
        List<String[]> newSources = new ArrayList<>();
        for (String[] src : sources) if (!minedHashes.contains(srcHash(src[0], src[1]))) newSources.add(src);
        int skipped = sources.size() - newSources.size();
        int regex = 0, llm = 0;
        // DETERMINISTIC, EXHAUSTIVE pass: harvest every /api/vN/ literal from the FULL body of every same-host
        // script — no truncation, no sampling — so the API surface we probe does NOT depend on which 8k window
        // or which 8 chunks happened to be fed to the LLM (that sampling is what left agents/kb/chat undiscovered
        // run-to-run). This is the coverage floor; the LLM pass below only ADDS non-literal/inferred routes. Regex +
        // harvest are cheap and idempotent (re-adding a known spec to the Set is free), so they run over the FULL
        // source set every pass — the dedup applies ONLY to the expensive LLM pass.
        for (String[] src : sources) regex += regexCandidates(src[1], specs);
        int harvested = harvestApiPaths(host, specs);
        // LLM mines ONLY the new/changed sources. Unchanged ones contributed to the seeded `specs` in a prior pass.
        List<String> chunks = packChunks(newSources);
        // N-ROUND UNION: at temp>0 the LLM samples DIFFERENT candidates each pass, so we run discovery N times and
        // UNION the results (specs is a Set → dedup is automatic). This tames the sampling variance WITHOUT losing
        // the LLM's exploratory coverage: as N grows, two "N-round" runs converge to the same set (the model's
        // high-probability endpoints appear every round; only the rare tail differs). EARLY-STOP when a round adds
        // nothing new (converged) — so at temp=0 (greedy, identical each pass) this collapses to a single round.
        int rounds = discoveryRounds();
        int roundsRun = 0;
        int emptyStreak = 0;                            // consecutive rounds that added nothing new
        for (int r = 0; r < rounds && canLlm && !chunks.isEmpty(); r++) {
            int roundBefore = specs.size();
            int rawThisRound = 0;                       // RAW endpoints the LLM parsed this round (pre-dedup)
            for (int i = 0; i < chunks.size() && i < Tuning.maxLlmChunks(); i++) {
                int before = specs.size();
                rawThisRound += llmCandidates(eng, chunks.get(i), specs);   // returns RAW parsed count
                llm += specs.size() - before;
            }
            roundsRun++;
            int added = specs.size() - roundBefore;
            // Log RAW parsed (what the model actually returned) AND new-after-union — so we can see whether a round
            // added nothing because the LLM returned nothing vs. returned dupes (the variance we've been chasing).
            if (rounds > 1) scanLog.log("  discovery round " + (r + 1) + "/" + rounds
                    + ": LLM parsed " + rawThisRound + " endpoint(s), +" + added + " new (union now " + specs.size() + ")");
            // Each round uses a DIFFERENT seed → a single empty/weak round is just a bad roll, NOT convergence: the
            // next round (fresh seed) can recover. So only stop after TWO CONSECUTIVE empty rounds (true convergence,
            // or greedy temp=0 where every round is identical). Stopping on the FIRST +0 wasted the seed diversity.
            emptyStreak = (added == 0) ? emptyStreak + 1 : 0;
            if (emptyStreak >= 2) break;
        }
        // Mark the new sources as mined so a later pass won't re-send them. Only when the LLM actually ran — if it
        // wasn't configured we mined nothing, so leave them unmarked for a later configured pass.
        if (canLlm) for (String[] src : newSources) minedHashes.add(srcHash(src[0], src[1]));
        scanLog.log("endpoint discovery: regex " + regex + " + full-body harvest " + harvested
                + " + LLM " + llm + " candidate(s) from " + newSources.size() + " new source(s)"
                + (skipped > 0 ? " (" + skipped + " unchanged skipped — already LLM-mined)" : "")
                + " in " + Math.min(chunks.size(), Tuning.maxLlmChunks()) + " chunk(s) × " + roundsRun + " round(s); probing with "
                + (session.has() ? "authenticated session" : "no session") + "…");
        specsCache.put(host, new LinkedHashSet<>(specs));   // memoize; re-mined only when the site map grows
        specsSiteMapCount.put(host, smc);
        return specs;
    }

    // A relative endpoint-leaf literal (crAPI: "api/shop/orders", "api/v2/coupon/validate-coupon") that
    // URLISH/REST_PATH miss because it has no leading slash. REST roots (api/rest/vN) are universal
    // conventions, not app names. Cross-joined with SERVICE_BASE for prefix-mounted SPAs.
    private static final Pattern REL_LEAF = Pattern.compile(
            "[\"']((?:api|rest|v[0-9]+)/[a-z0-9][a-z0-9/_.-]{1,60})[\"']", Pattern.CASE_INSENSITIVE);
    private boolean synthDone = false;   // LLM body-synthesis runs once (in the authenticated pass)

    /** True when a 2xx response is really the SPA's HTML app shell (nginx catch-all), not a real endpoint. */
    private static boolean isHtmlShell(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String ct = rr.response().headerValue("Content-Type");
        if (ct != null && ct.toLowerCase().contains("text/html")) return true;
        String b = rr.response().bodyToString();
        if (b == null) return false;
        String t = b.trim().toLowerCase();
        return t.startsWith("<!doctype html") || t.startsWith("<html");
    }

    private HttpRequest authedGet(String abs) {
        return withSessionCookie(HttpRequest.httpRequestFromUrl(abs).withMethod("GET"));   // cookie + bearer
    }

    /** Authenticated GET that explicitly asks for JSON — for APIs whose default content negotiation is XML. */
    private HttpRequest jsonGet(String abs) {
        return authedGet(abs).withHeader("Accept", "application/json");
    }

    /**
     * SPAs assemble many endpoints as {@code base + leaf} at runtime (crAPI: og="identity/" + "api/shop/…")
     * so the full path is never a single literal and host-root resolution 404s. Mine both halves from FULL
     * JS bodies and cross-join base × leaf — the app's OWN strings, no hardcoded service names.
     *
     * <p>Two safeguards make this safe on catch-all SPAs (crAPI's nginx answers ANY /api/* with the HTML
     * shell): (1) a CONTENT ORACLE rejects api-ish 2xx whose body is the app shell; (2) ADAPTIVE BASE
     * PRUNING — iterate base-major and drop a base after {@code HTML_STRIKES} shell-only hits with no real
     * endpoint, so junk bases (image/, chatbot/) cost ~3 probes, not one-per-leaf. Only responses that are
     * genuinely non-HTML 2xx are kept. Bearer-authenticated so authed services (workshop/community) answer.
     */
    private void discoverAssembled(String host, String baseUrl, List<HttpRequest> live, Set<String> seen) {
        try {
            List<String> bases = new ArrayList<>();
            List<String> leaves = new ArrayList<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                String body = rr.response().bodyToString();
                Matcher mb = SERVICE_BASE.matcher(body);
                while (mb.find()) if (!bases.contains(mb.group(1)) && bases.size() < 16) bases.add(mb.group(1));
                Matcher ml = REL_LEAF.matcher(body);
                while (ml.find()) { String l = ml.group(1).toLowerCase(); if (!leaves.contains(l) && leaves.size() < 60) leaves.add(l); }
            }
            if (leaves.isEmpty()) return;
            final int HTML_STRIKES = 3, BUDGET = 140;
            int probed = 0, found = 0;
            bases.add(0, "");   // also try each leaf base-less (root-mounted APIs)
            for (String base : bases) {
                if (probed >= BUDGET) break;
                int strikes = 0; boolean baseReal = false;
                for (String leaf : leaves) {
                    if (probed >= BUDGET) break;
                    if (!base.isEmpty() && strikes >= HTML_STRIKES && !baseReal) break;   // prune junk base
                    String abs;
                    try { abs = URI.create(baseUrl).resolve(base + leaf).toString(); } catch (Exception e) { continue; }
                    if (!host.equalsIgnoreCase(hostOf(abs))) continue;
                    if (!seen.add("GET " + Net.stripQuery(abs))) continue;
                    HttpRequestResponse rr = probe(authedGet(abs));
                    probed++;
                    int st = statusOf(rr);
                    if (st >= 200 && st < 300 && isHtmlShell(rr)) { strikes++; continue; }   // SPA catch-all
                    if (st >= 200 && st < 400) {
                        baseReal = true; found++;
                        HttpRequest keep = authedGet(abs);
                        live.add(keep);
                        scanLog.log("  -> LIVE " + st + "  GET " + Net.stripQuery(abs) + " (assembled)");
                    }
                }
            }
            if (found > 0) scanLog.log("assembled discovery: " + found
                    + " endpoint(s) via base×leaf (" + probed + " probes).");
        } catch (Throwable t) {
            scanLog.log("assembled discovery failed: " + t);
        }
    }

    // A client-side route or nav-link noun in the SPA's JS/HTML: react-router `path="movies"` (minified to
    // `path:"movies"`) or a link `to="/movies"`. The noun, not app-specific — every SPA has these.
    private static final Pattern CLIENT_ROUTE = Pattern.compile(
            "(?i)(?:\\bpath\\b|\\bto\\b)\\s*[:=]\\s*[\"']/?([A-Za-z][A-Za-z0-9_-]{1,30})[\"']");
    // scheme://host[:port] up to and including a /rest or /api[/vN] segment — the API mount point.
    private static final Pattern API_MOUNT = Pattern.compile(
            "(?i)(https?://[^/\"'\\s]+(?:/[A-Za-z0-9_-]+)*?/(?:rest|api)(?:/v\\d+)?)/");
    private static final String READ_SEED = "1";

    /**
     * Reach API resources the SPA never CALLS but whose noun it exposes as a client-side ROUTE. Single-page apps
     * name routes after resources (/movies, /orders, /users) and the REST API mirrors them (/rest/movie(s),
     * /api/orders). Mine the route table from the app's OWN JS/HTML (react-router path= / link to=), then probe
     * each noun (as-is + singular/plural) under every OBSERVED API mount, keeping only a real JSON handler
     * (oracle: 2xx + JSON + not the SPA HTML shell). For each kept collection, ALSO synthesize param-seeded reads
     * by inferring query-param names from the response's own field keys — handing a search/filter param (e.g.
     * title=) to the audit for SQLi/XSS. Fully generic: nouns + params come from the app's route names and
     * response shapes, nothing hardcoded. This is how the vuln API surface of a SPA that orphans its endpoints
     * from client code (no fetch literal, no OpenAPI spec) still becomes auditable.
     */
    private void discoverClientRouteApis(String host, String baseUrl, List<HttpRequest> live, Set<String> seen) {
        try {
            LinkedHashSet<String> mounts = new LinkedHashSet<>();   // API mounts (sibling origins incl.)
            // FIRST mine ABSOLUTE API-base literals from the app's JS — an SPA whose API is a sibling origin
            // (localhost:3001 → localhost:8080/rest/) bakes that base as a string it concatenates onto; that
            // real mount is NOT in the site map (the browser never calls it unauth, and our own probes to it
            // aren't recorded). Without this the only "mounts" are phantom seed-origin /api paths that just
            // echo the SPA HTML shell.
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = rr.request() == null ? null : rr.request().url();
                if (u == null || rr.response() == null || !host.equalsIgnoreCase(hostOf(u))
                        || !u.toLowerCase().contains(".js")) continue;
                Matcher mb = API_MOUNT.matcher(rr.response().bodyToString());
                while (mb.find() && mounts.size() < 8) {
                    String mm = mb.group(1);
                    if (host.equalsIgnoreCase(hostOf(mm))) mounts.add(mm);   // e.g. http://localhost:8080/rest
                }
            }
            // THEN add mounts from observed same-host request URLs (covers same-origin REST APIs).
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = rr.request() == null ? null : rr.request().url();
                if (u == null || !host.equalsIgnoreCase(hostOf(u))) continue;
                Matcher m = API_MOUNT.matcher(u);
                if (m.find() && mounts.size() < 8) mounts.add(m.group(1));
            }
            if (mounts.isEmpty()) return;
            LinkedHashSet<String> nouns = new LinkedHashSet<>();     // route nouns from the app's own code
            // Mine from the FULL JS body (not gatherSources, which caps each source at 8 KB): an SPA's route
            // table is a compiled data structure that sits deep in the minified bundle (megabytes in), past any
            // window. Read the whole same-host script bodies Burp already fetched.
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                Matcher m = CLIENT_ROUTE.matcher(rr.response().bodyToString());
                while (m.find() && nouns.size() < 48) {
                    String n = m.group(1).toLowerCase();
                    // skip auth/nav nouns that aren't resources (avoid re-hitting login and generic pages)
                    if (n.length() < 2 || n.matches("login|logout|register|signup|home|index|about|contact|help")) continue;
                    nouns.add(n); nouns.add(singularize(n)); nouns.add(pluralize(n));
                }
            }
            nouns.remove("");
            int probed = 0, found = 0;
            for (String mount : mounts) {
                for (String noun : nouns) {
                    if (probed >= 60) break;
                    String abs = mount + "/" + noun;
                    if (!host.equalsIgnoreCase(hostOf(abs)) || !seen.add("GET " + abs)) continue;
                    // Ask for JSON: a Spring app with a JAXB DTO defaults its content negotiation to XML when no
                    // Accept is set, so respIsJson would reject a real handler. JSON also lets us mine response
                    // KEYS as query-param candidates (title/id/…) for the param-seeded reads below.
                    HttpRequestResponse rr = probe(jsonGet(abs));
                    probed++;
                    int st = statusOf(rr);
                    if (st < 200 || st >= 300 || !respIsJson(rr) || isHtmlShell(rr)) continue;
                    found++;
                    live.add(jsonGet(abs));   // the collection read itself (exposure / IDOR surface)
                    scanLog.log("  -> LIVE " + st + "  GET " + abs + " (client-route → API resource)");
                    for (String key : responseKeys(rr, 6)) {   // response field keys → candidate query params
                        if (seen.add("GET " + abs + "?" + key)) {
                            live.add(jsonGet(abs + "?" + key + "=" + READ_SEED));
                            scanLog.log("     + param-seeded read: GET " + abs + "?" + key + "= (SQLi/XSS surface)");
                        }
                    }
                }
            }
            if (found > 0) scanLog.log("client-route API inference: " + found
                    + " resource(s) reached from the SPA's route vocabulary (" + probed + " probes over "
                    + mounts.size() + " mount(s) × " + nouns.size() + " noun(s)).");
            else scanLog.debug("client-route API inference: 0 from " + mounts.size()
                    + " mount(s) × " + nouns.size() + " noun(s) (" + probed + " probes); nouns=" + nouns);
        } catch (Throwable t) {
            scanLog.log("client-route API inference failed: " + t);
        }
    }

    private static String singularize(String n) { return n.endsWith("s") && n.length() > 3 ? n.substring(0, n.length() - 1) : n; }
    private static String pluralize(String n) { return n.endsWith("s") ? n : n + "s"; }

    /** Top-level scalar field names from the first object of a JSON array/object response — candidate query params. */
    private List<String> responseKeys(HttpRequestResponse rr, int max) {
        List<String> out = new ArrayList<>();
        try {
            String b = rr.response().bodyToString().trim();
            JSONObject o = null;
            if (b.startsWith("[")) { JSONArray a = new JSONArray(b); if (a.length() > 0 && a.get(0) instanceof JSONObject) o = a.getJSONObject(0); }
            else if (b.startsWith("{")) o = new JSONObject(b);
            if (o != null) for (String k : o.keySet()) {
                Object v = o.get(k);
                if ((v instanceof String || v instanceof Number) && k.matches("[A-Za-z_][A-Za-z0-9_]{0,40}") && out.size() < max) out.add(k);
            }
        } catch (Throwable ignore) { }
        return out;
    }

    /**
     * Turn every REACHED JSON collection into parameterized reads for the active audit. A REST endpoint that
     * returns {@code [{id,title,description,…}]} tells us its OWN filter/query field names — the response keys
     * ARE the candidate query params (Spring {@code @RequestParam(required=false)} filters, IDs, etc. that no
     * HTML or JS ever reveals on a JSON-only API / SPA-orphaned backend). A param-less {@code GET /rest/movie}
     * is a dead read; {@code GET /rest/movie?id=&title=&…} goes to Burp's active audit, which fuzzes each param
     * (SQLi / reflected-XSS / etc.). Fully generic: params come from the server's OWN response shape — no
     * wordlist, no app knowledge. Covers the seed endpoint and anything the crawl reached. Bounded per the
     * BApp large-project rule. This is the piece that lets Burp fuzz a JSON API it would otherwise see as a
     * single unparameterized GET.
     */
    private void synthesizeParamReadsFromJson(String host, List<HttpRequest> live, Set<String> seen) {
        int collections = 0, added = 0;
        try {
            // Dedupe candidate collection URLs first (the crawl may hold many copies of the same path).
            Set<String> candidates = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (candidates.size() >= 40) break;
                if (rr == null || rr.response() == null) continue;
                HttpRequest req = rr.request();
                if (!"GET".equalsIgnoreCase(req.method())) continue;
                if (!host.equalsIgnoreCase(hostOf(req.url()))) continue;
                if (req.url().contains("?")) continue;                    // already parameterized — Burp fuzzes it already
                if (STATIC.matcher(req.url()).matches() || req.url().toLowerCase().contains(".js")) continue;
                int st = rr.response().statusCode();
                if (st < 200 || st >= 300 || isHtmlShell(rr)) continue;
                if (!respIsStructured(rr)) continue;                       // JSON or XML collection, not the HTML shell
                candidates.add(Net.stripQuery(req.url()));
            }
            for (String abs : candidates) {
                // Re-probe forcing JSON (Spring/JAXB apps content-negotiate to XML under a browser Accept, so the
                // crawl's copy is XML): a JSON body lets responseKeys mine the field names cleanly. Fall back to XML
                // element names when the server ignores Accept. Either way the field names ARE the query params.
                HttpRequestResponse jr = probe(jsonGet(abs));
                List<String> keys = (jr != null && jr.response() != null) ? responseKeys(jr, 6) : java.util.Collections.emptyList();
                if (keys.isEmpty()) keys = xmlElementNames(jr, 6);        // JAXB/XML-only API fallback
                if (keys.isEmpty()) continue;
                collections++;
                for (String key : keys) {
                    if (seen.add("GET " + abs + "?" + key)) {
                        live.add(jsonGet(abs + "?" + key + "=" + READ_SEED));   // one param present → active audit fuzzes it
                        added++;
                    }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("JSON param-read synthesis failed: " + t);
        }
        if (added > 0) scanLog.log("JSON param-read synthesis: " + added
                + " param-seeded read(s) from " + collections + " reached JSON/XML collection(s) → active audit (SQLi/XSS surface).");
    }

    /** True when a 2xx body is structured data (JSON or XML) a handler produced — not the SPA HTML shell. */
    private static boolean respIsStructured(HttpRequestResponse rr) {
        if (respIsJson(rr)) return true;
        if (isHtmlShell(rr)) return false;
        try {
            String ct = rr.response().headerValue("Content-Type");
            if (ct != null && ct.toLowerCase().contains("xml")) return true;
            String b = rr.response().bodyToString();
            return b != null && b.trim().startsWith("<") && !b.trim().toLowerCase().startsWith("<!doctype")
                    && !b.trim().toLowerCase().startsWith("<html");
        } catch (Throwable ignore) { return false; }
    }

    // Leaf XML elements that carry text — <id>1</id>, <title>…</title>. Their names are the candidate query params
    // for a JAXB/XML REST collection, exactly as JSON keys are. Container tags (List/item/rows) carry no text → skipped.
    private static final Pattern XML_LEAF = Pattern.compile("<([A-Za-z_][A-Za-z0-9_]{0,40})>[^<>\\s]");

    private List<String> xmlElementNames(HttpRequestResponse rr, int max) {
        List<String> out = new ArrayList<>();
        try {
            if (rr == null || rr.response() == null) return out;
            String b = rr.response().bodyToString();
            if (b == null) return out;
            Matcher m = XML_LEAF.matcher(b);
            while (m.find() && out.size() < max) { String k = m.group(1); if (!out.contains(k)) out.add(k); }
        } catch (Throwable ignore) { }
        return out;
    }

    /** True when a response body looks like a handler's structured output (JSON), not the HTML app shell. */
    private static boolean respIsJson(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String ct = rr.response().headerValue("Content-Type");
        if (ct != null && ct.toLowerCase().contains("json")) return true;
        String b = rr.response().bodyToString();
        if (b == null) return false;
        String t = b.trim();
        return t.startsWith("{") || t.startsWith("[");
    }

    private static final Pattern BASE_DEF = Pattern.compile("=[\"']([a-z][a-z0-9_-]{1,30}/)[\"']");
    private static final Pattern LEAF_MAP = Pattern.compile(
            "([A-Za-z_]{2,40}):[\"']((?:api|rest|v[0-9]+)/[a-z0-9/_.<>-]{1,70})[\"']", Pattern.CASE_INSENSITIVE);

    /** Compact, COMPLETE assembly context: every distinct service-base def + KEY:"leaf" map entry across ALL
     *  JS (deduped). Small (a few hundred entries fit easily) and lossless — unlike raw windows, which repeat
     *  the same region and truncate before later leaves (e.g. community's validate-coupon). The KEY names
     *  (BUY_PRODUCT, VALIDATE_COUPON, …) also give the LLM method/purpose hints. */
    private String assemblyContext(String host) {
        Set<String> bases = new LinkedHashSet<>();
        Set<String> pairs = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                String body = rr.response().bodyToString();
                Matcher mb = BASE_DEF.matcher(body);
                while (mb.find() && bases.size() < 16) bases.add(mb.group(1));
                Matcher mp = LEAF_MAP.matcher(body);
                while (mp.find() && pairs.size() < 200) pairs.add(mp.group(1) + ":\"" + mp.group(2) + "\"");
            }
        } catch (Throwable ignore) { }
        if (pairs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        if (!bases.isEmpty()) sb.append("bases: ").append(String.join(", ", bases)).append('\n');
        for (String p : pairs) sb.append(p).append('\n');
        return sb.toString();
    }

    /**
     * LLM BODY-SYNTHESIS: the base×leaf GET probe can only find read collections; crAPI's vulnerable
     * endpoints need real request BODIES (POST apply_coupon{coupon_code}, orders{quantity}, …) that a bare
     * leaf can't reconstruct. The LLM reads the app's OWN served code (base defs + leaf maps) and proposes
     * {method, full path, body field names} — TARGETING only, never a verdict. Each proposal is then
     * DETERMINISTICALLY probed: kept only if a real handler processed it (JSON response, not the HTML shell),
     * so hallucinated paths just 404/HTML away. Survivors carry real fields → the injection/mass-assign/IDOR
     * probes fire on them. Runs once, authenticated (workshop/community are session-gated).
     */
    private void synthesizeEndpointsLlm(String host, String baseUrl, List<HttpRequest> live, Set<String> seen) {
        if (synthDone) return;
        AiEngine eng = engine != null ? engine.get() : null;
        if (eng == null || !eng.isConfigured()) return;
        synthDone = true;
        try {
            String ctx = assemblyContext(host);
            if (ctx.isBlank()) return;
            // Mine the service bases here (Java) — the LLM only supplies the leaf/method/fields; WE pick the base.
            List<String> bases = new ArrayList<>();
            bases.add("");   // base-less first (root-mounted)
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                Matcher mb = SERVICE_BASE.matcher(rr.response().bodyToString());
                while (mb.find()) if (!bases.contains(mb.group(1)) && bases.size() < 16) bases.add(mb.group(1));
            }
            String system =
                    "You are a web-security assistant reading ONE web app's MINIFIED client code (base defs + an\n"
                    + "endpoint-leaf map). For each DISTINCT server endpoint the app calls, output the LEAF PATH\n"
                    + "EXACTLY as it appears in the code (e.g. \"api/foo/bar\") — do NOT prepend any base/prefix and\n"
                    + "do NOT invent a host. Infer the HTTP method and the request body/JSON FIELD NAMES it sends.\n"
                    + "ORDER THE ARRAY so WRITE endpoints (POST/PUT/PATCH) and any shop/order/coupon/cart/\n"
                    + "mechanic/product/report endpoints come FIRST (they matter most). ALWAYS populate \"params\"\n"
                    + "with the request body/query FIELD NAMES — if the code doesn't spell them out, INFER the\n"
                    + "most likely ones from the endpoint's purpose (a coupon endpoint → coupon_code; an order →\n"
                    + "product_id,quantity; a report → report_id; a profile update → the field being changed).\n"
                    + "Never return an endpoint with an empty params list. Output ONLY a JSON array, no markdown:\n"
                    + "[{\"method\":\"POST\",\"leaf\":\"api/foo/bar\",\"params\":[\"field1\",\"field2\"]}]\n"
                    + "Skip auth (login/signup/token) and static assets. [] if none.";
            String raw = eng.chat(system, "Client code fragments:\n" + ctx + "\n\nReturn the JSON array now.", "discovery: mine-endpoints");
            if (raw == null) return;
            List<JSONObject> objs = lenientObjects(raw);   // salvage complete objects even if the array is truncated
            if (objs.isEmpty()) { scanLog.log("synth: LLM returned 0 parseable endpoint(s)."); return; }
            final int BUDGET = 240;   // was 80 — too low for ~44 candidates × service-bases, dropped validate-coupon etc.
            // TRACE: exactly what the LLM proposed, so coverage is visible instead of inferred.
            List<String> allLeaves = new ArrayList<>();
            for (JSONObject o : objs) {
                String lf = o.optString("leaf", o.optString("path", "")).trim();
                if (!lf.isBlank()) allLeaves.add(o.optString("method", "GET").trim().toUpperCase() + " " + lf);
            }
            scanLog.log("synth: LLM returned " + objs.size() + " candidate(s): " + allLeaves);
            int kept = 0, probed = 0;
            for (JSONObject o : objs) {
                if (probed >= BUDGET) { scanLog.log("synth: probe budget " + BUDGET
                        + " exhausted — remaining candidates NOT probed"); break; }
                String leaf = o.optString("leaf", o.optString("path", "")).trim();
                if (leaf.isBlank() || STATIC.matcher(leaf).matches()) continue;
                leaf = leaf.replaceFirst("^/+", "");
                // substitute path-id placeholders (<id> / :id / {id}) with a benign value so the route resolves
                leaf = leaf.replaceAll("[<{:][A-Za-z0-9_]+[>}]?", "1");
                String method = o.optString("method", "GET").trim().toUpperCase();
                if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH") && !method.equals("GET"))
                    method = "GET";
                List<String> fields = new ArrayList<>();
                JSONArray pj = o.optJSONArray("params");
                if (pj != null) for (int k = 0; k < pj.length(); k++) {
                    String pn = pj.optString(k, "").trim(); if (!pn.isEmpty()) fields.add(pn);
                }
                // cross-join leaf × service bases; keep the first that a real handler answers (JSON, not HTML shell)
                boolean keptThis = false;
                List<String> trail = new ArrayList<>();   // per-base outcome, so a DROPPED candidate is explainable
                for (String b : bases) {
                    if (probed >= BUDGET) break;
                    String abs;
                    try { abs = URI.create(baseUrl).resolve(b + leaf).toString(); } catch (Exception ex) { continue; }
                    if (!host.equalsIgnoreCase(hostOf(abs))) continue;
                    if (AuthenticatedExplorer.SESSION_RESET.matcher(abs).matches()) continue;
                    if (!seen.add(method + " " + Net.stripQuery(abs) + " synth")) { trail.add((b.isEmpty()?"/":b)+"dup"); continue; }
                    HttpRequest req; HttpRequestResponse rr; int st;
                    if (method.equals("GET")) {
                        req = authedGet(abs);
                        // Attach the LLM-proposed params as URL query params (dummy id "1"). This both (a) makes
                        // endpoints that REQUIRE an id param answer 2xx instead of erroring (so they're kept), and
                        // (b) exposes id-like params (report_id, …) to IdorGetProbe for enumeration.
                        for (String f : fields) {
                            if (!f.isEmpty()) req = req.withAddedParameters(HttpParameter.parameter(f, "1", HttpParameterType.URL));
                        }
                        rr = probe(req); probed++; st = statusOf(rr);
                    } else {
                        // POST/PUT/PATCH — BODY-MINIMIZATION: PREFER a minimal NUMERIC-ONLY body over the full one.
                        // A hallucinated/extra field (e.g. coupon_code on an order) makes crAPI 400/500 — and even
                        // when the full body TRANSIENTLY 2xx's, keeping it (with coupon_code) gives BodyMutatorProbe
                        // an unstable baseline. The clean {product_id,quantity} body is the reliable 2xx baseline
                        // BodyMutatorProbe needs to mutate quantity→-1000 (mass-assignment). So try numeric-only
                        // FIRST; keep the best by rank (2xx > handler-ran 4xx/JSON-5xx > other).
                        List<String> numOnly = new ArrayList<>();
                        for (String f : fields) if (NUM_KEY.matcher(f.toLowerCase()).matches()) numOnly.add(f);
                        List<List<String>> variants = new ArrayList<>();
                        if (!numOnly.isEmpty() && numOnly.size() < fields.size()) variants.add(numOnly);   // minimal first
                        variants.add(fields);
                        req = null; rr = null; st = -1; int bestRank = -1;
                        for (List<String> fs : variants) {
                            if (probed >= BUDGET) break;
                            if (session != null && session.mutatesOwnAccount(method, abs)) {
                                scanLog.debug("  discovery: skip self-account mutation " + method + " " + Net.stripQuery(abs));
                                break;   // req stays null → this candidate is skipped below (protects our own login)
                            }
                            HttpRequest r = withSessionCookie(HttpRequest.httpRequestFromUrl(abs).withMethod(method)
                                    .withAddedHeader("Content-Type", "application/json").withBody(jsonBody(fs)));
                            if (session != null && session.hasBearer())
                                r = r.withHeader("Authorization", "Bearer " + session.bearer());
                            HttpRequestResponse rp = probe(r); probed++;
                            int s = statusOf(rp);
                            int rank = (s >= 200 && s < 300) ? 3
                                    : (!isHtmlShell(rp) && (s == 400 || s == 401 || s == 403 || s == 409 || s == 422
                                            || (s >= 500 && respIsJson(rp)))) ? 2 : 1;
                            if (rank > bestRank) { bestRank = rank; req = r; rr = rp; st = s; }
                            if (rank == 3) break;   // clean 2xx baseline (minimal body preferred) — stop
                        }
                        if (req == null) continue;
                    }
                    // Oracle: THIS route exists under THIS base — the handler processed our request (2xx) or
                    // validated/authz-rejected it (400/401/403/409/422), and it isn't the SPA HTML shell.
                    // 404/405 mean wrong base or wrong method (services return JSON 404 for any unknown path,
                    // which would otherwise pin every leaf to the first service) → keep trying other bases.
                    // A handler processed our request here: 2xx, a validation/authz rejection, OR a JSON 5xx
                    // (the service errored on our dummy input — e.g. validate-coupon 500 on an invalid coupon;
                    // that endpoint is real and its 500→200 flip under {$ne:null} is the NoSQL signal). Reject
                    // 404/405 (wrong base/method) and NON-JSON 5xx (generic crash/route-miss) and the HTML shell.
                    boolean handlerRan = !isHtmlShell(rr) && ((st >= 200 && st < 300)
                            || st == 400 || st == 401 || st == 403 || st == 409 || st == 422
                            || (st >= 500 && respIsJson(rr)));
                    // trail entry: base + status + why-rejected tag, so DROPPED candidates are fully explainable
                    trail.add((b.isEmpty() ? "/" : b) + "→" + st
                            + (isHtmlShell(rr) ? "html" : respIsJson(rr) ? "json" : "raw"));
                    if (handlerRan) {
                        live.add(req); kept++;
                        keep(rr, host);   // bridge to site map for IdorGet/Bfla/ChainReplay
                        scanLog.log("  -> LIVE " + st + "  " + method + " " + Net.stripQuery(abs)
                                + (fields.isEmpty() ? "" : " {" + String.join(",", fields) + "}") + " (llm-synth)");
                        keptThis = true;
                        break;   // found this leaf's real base — stop trying other bases
                    }
                }
                if (!keptThis && !trail.isEmpty())   // TRACE: how far this candidate got before being dropped
                    scanLog.log("  -· DROPPED " + method + " " + leaf
                            + (fields.isEmpty() ? "" : " {" + String.join(",", fields) + "}") + " — " + trail);
            }
            if (kept > 0) scanLog.log("LLM body-synthesis: " + kept + " endpoint(s) from "
                    + objs.size() + " candidate(s), " + probed + " probes.");
        } catch (Throwable t) {
            scanLog.log("LLM synthesis failed: " + t);
        }
    }

    /** Salvage every COMPLETE top-level {…} object from a possibly-truncated JSON array (brace/string scan),
     *  dropping the incomplete tail — so a maxTokens cutoff loses only the last object, not the whole reply. */
    private static List<JSONObject> lenientObjects(String raw) {
        List<JSONObject> out = new ArrayList<>();
        if (raw == null) return out;
        int i = Math.max(0, raw.indexOf('[')), n = raw.length();
        while (i < n) {
            int start = raw.indexOf('{', i);
            if (start < 0) break;
            int depth = 0, j = start; boolean inStr = false; char q = 0;
            for (; j < n; j++) {
                char c = raw.charAt(j);
                if (inStr) { if (c == '\\') { j++; } else if (c == q) inStr = false; }
                else if (c == '"' || c == '\'') { inStr = true; q = c; }
                else if (c == '{') depth++;
                else if (c == '}') { if (--depth == 0) { j++; break; } }
            }
            if (depth != 0) break;   // truncated final object — stop here
            try { out.add(new JSONObject(raw.substring(start, j))); } catch (Exception ignore) { }
            i = j;
        }
        return out;
    }

    /** Discover + probe endpoints for the host; returns live requests (with params) to audit. */
    private static final int MAX_FORMS = 80;
    private static final Pattern FORM_BLOCK  = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>");
    private static final Pattern F_ACTION    = Pattern.compile("(?is)\\baction\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_METHOD    = Pattern.compile("(?is)\\bmethod\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_INPUT     = Pattern.compile("(?is)<(input|select|textarea|button)\\b([^>]*)>");
    private static final Pattern F_NAME      = Pattern.compile("(?is)\\bname\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_VALUE     = Pattern.compile("(?is)\\bvalue\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_TYPE      = Pattern.compile("(?is)\\btype\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static String attrOf(Pattern p, String s) {
        Matcher m = p.matcher(s); if (!m.find()) return null; String v = m.group(1).trim();
        if (v.length() >= 2 && (v.charAt(0) == '"' || v.charAt(0) == '\'')) v = v.substring(1, v.length() - 1);
        return v;
    }
    private static String urlenc(String s) { try { return java.net.URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; } }

    /**
     * Generic HTML-form → parameterized-request synthesis. Server-rendered apps (DVWA's /vulnerabilities/*,
     * classic MPAs) put their real injectable surface in {@code <form>}s; the crawler records the action URL but
     * no PARAMETERS, so the fields are never exercised. This parses every same-host HTML form already in the site
     * map, fills each named field with its own value or a benign seed, and emits a GET (query) or POST (body)
     * request — an insertion-point set Burp's active audit + our probes then fuzz. Universal HTML, no app rules.
     */
    private void harvestHtmlForms(String host, List<HttpRequest> live, Set<String> seen) {
        int added = 0;
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (added >= MAX_FORMS) break;
            if (rr.response() == null || rr.request() == null) continue;
            String pageUrl = rr.request().url();
            if (!host.equalsIgnoreCase(hostOf(pageUrl))) continue;
            String ct = rr.response().statedMimeType() == null ? "" : rr.response().statedMimeType().name();
            String body = rr.response().bodyToString();
            if (!"HTML".equals(ct) && !body.toLowerCase().contains("<form")) continue;
            Matcher fm = FORM_BLOCK.matcher(body);
            while (fm.find() && added < MAX_FORMS) {
                String attrs = fm.group(1), inner = fm.group(2);
                String action = attrOf(F_ACTION, attrs);
                String method = attrOf(F_METHOD, attrs);
                method = (method == null ? "GET" : method).toUpperCase();
                if (!"GET".equals(method) && !"POST".equals(method)) method = "GET";
                String abs;
                try { abs = (action == null || action.isBlank()) ? Net.stripQuery(pageUrl) : URI.create(pageUrl).resolve(action).toString(); }
                catch (Exception e) { continue; }
                if (!host.equalsIgnoreCase(hostOf(abs))) continue;
                if (AuthenticatedExplorer.SESSION_RESET.matcher(abs).matches()) continue;   // never re-submit login/logout
                java.util.LinkedHashMap<String, String> fields = new java.util.LinkedHashMap<>();
                Matcher im = F_INPUT.matcher(inner);
                String firstPw = null;   // mirror the first password value into confirm/matching fields
                while (im.find()) {
                    String tag = im.group(2);
                    String name = attrOf(F_NAME, tag); if (name == null || name.isBlank()) continue;
                    String type = attrOf(F_TYPE, tag); type = type == null ? "text" : type.toLowerCase();
                    if (type.equals("button") || type.equals("reset")) continue;
                    String val = attrOf(F_VALUE, tag);
                    if ("password".equals(type)) {
                        // register / change-password forms validate password == confirm/matching: reuse ONE value
                        // across every password field, else the form is rejected before any injection is reached.
                        if (val == null) { if (firstPw == null) firstPw = String.valueOf(seedFor(name, type)); val = firstPw; }
                        else if (firstPw == null) firstPw = val;
                    } else if (val == null) {
                        val = String.valueOf(seedFor(name, type));   // keep submit values (isset checks)
                    }
                    fields.put(name, val);
                }
                if (fields.isEmpty()) continue;
                String key = method + " " + Net.stripQuery(abs) + " " + fields.keySet();
                if (!seen.add(key)) continue;
                if (session != null && session.mutatesOwnAccount(method, abs)) {
                    scanLog.debug("  html-form: skip self-account mutation " + method + " " + Net.stripQuery(abs));
                    continue;
                }
                StringBuilder enc = new StringBuilder();
                for (Map.Entry<String, String> e : fields.entrySet()) {
                    if (enc.length() > 0) enc.append('&');
                    enc.append(urlenc(e.getKey())).append('=').append(urlenc(e.getValue()));
                }
                HttpRequest req;
                if ("POST".equals(method)) {
                    req = withSessionCookie(HttpRequest.httpRequestFromUrl(Net.stripQuery(abs)).withMethod("POST"))
                            .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                            .withBody(enc.toString());
                } else {
                    req = withSessionCookie(HttpRequest.httpRequestFromUrl(Net.stripQuery(abs) + "?" + enc).withMethod("GET"));
                }
                live.add(req); added++;
                scanLog.log("  -> FORM " + method + " " + Net.stripQuery(abs) + " {" + String.join(",", fields.keySet()) + "}");
            }
        }
        if (added > 0) scanLog.log("html-form synthesis: " + added + " parameterized form request(s) for the active audit.");
    }

    public List<HttpRequest> discover(String host) {
        List<HttpRequest> live = new ArrayList<>();
        try {
            String baseUrl = baseUrlFor(host);
            Set<String> specs = mineSpecs(host);
            if (baseUrl == null) return live;

            // SAST-driven surface expansion: source analysis may name routes/params the crawler never linked
            // to. Add them as candidate specs — they ride the SAME live-probe + keep() path below, so any
            // hallucinated/dead route is filtered out exactly like a mined one (no phantom coverage).
            if (!sourceHints.isEmpty()) {
                int addedFromSource = 0;
                for (com.ioactive.aiscanner.scan.sast.StaticHint h : sourceHints) {
                    if (specs.add(h.toEndpointSpec(SEP))) addedFromSource++;
                }
                if (addedFromSource > 0) scanLog.log("  +" + addedFromSource
                        + " source-derived endpoint spec(s) to probe (SAST-driven surface).");
            }

            Set<String> seen = new LinkedHashSet<>();
            int probed = 0;
            for (String spec : specs) {
                if (probed >= Tuning.maxCandidates()) break;
                // A POST to an API-ish path may consume JSON, not form-encoding: build both variants,
                // probe each, and keep whichever the server accepts. Without this, a JSON API is fed
                // form-encoded bodies (rejected / never reaching the JSON sink) and our JSON insertion
                // points never fire. GET is unaffected. Entirely heuristic by path — no hardcoding.
                List<HttpRequest> variants = buildVariants(spec, baseUrl);
                if (variants.isEmpty()) continue;
                HttpRequest sample = variants.get(0);
                if (!host.equalsIgnoreCase(hostOf(sample.url()))) continue;   // stay in scope
                if (STATIC.matcher(sample.url()).matches() || sample.url().toLowerCase().contains(".js")) continue;
                if (AuthenticatedExplorer.SESSION_RESET.matcher(sample.url()).matches()) continue; // never probe login/logout
                String key = sample.method() + " " + Net.stripQuery(sample.url());
                if (!seen.add(key)) continue;

                HttpRequest best = null; int bestSt = -1; HttpRequestResponse bestRr = null;
                for (HttpRequest req : variants) {
                    if (probed >= Tuning.maxCandidates()) break;
                    probed++;
                    HttpRequestResponse rr = probe(req);
                    int st = statusOf(rr);
                    if (liveRank(st) > liveRank(bestSt)) { bestSt = st; best = req; bestRr = rr; }
                }
                boolean realLive = best != null && bestSt >= 200 && bestSt < 400 && !isHtmlShell(bestRr);
                if (realLive) {
                    live.add(best);
                    keep(bestRr, host);   // bridge to site map for IdorGet/Bfla/ChainReplay
                    scanLog.log("  -> LIVE " + bestSt + "  " + best.method() + " "
                            + Net.stripQuery(best.url()) + paramSuffix(best));
                } else {
                    String leafPath; try { leafPath = URI.create(sample.url()).getPath(); } catch (Exception e) { leafPath = ""; }
                    boolean bareLeaf = leafPath != null && !leafPath.startsWith("/api/") && !leafPath.startsWith("/rest/");
                    if (bareLeaf) {
                        // A bare endpoint-map leaf (/financing/eligibility/, /fx/quote/) is mounted under the API
                        // base, NOT the web root — bare it hits the SPA shell (false 2xx) or 404s. Resolve it
                        // under the observed API base (base×leaf) to reach the REAL JSON API and fuzz it.
                        HttpRequest resolved = resolveUnderApiBase(sample.url(), host, live);
                        if (resolved != null) live.add(resolved);
                    } else {
                        // Already an /api/ path that a bodyless GET couldn't resolve (405/404/4xx): reconstruct a
                        // valid POST body from the server's own validation errors so write endpoints resolve+fuzz.
                        HttpRequest resolved = resolveWriteBody(sample.url(), host, bestSt);
                        if (resolved != null) live.add(resolved);
                    }
                }
            }
            // NOTE: discoverAssembled (base×leaf GET, content-oracle + base-pruning) is DISABLED. The oracle
            // correctly rejects crAPI's HTML-shell catch-all (found only real JSON endpoints), but bare
            // no-param GET probing only surfaces clean read collections (dashboard/vehicles) — NOT crAPI's
            // vulnerable surface, which needs real request bodies/params (POST apply_coupon {coupon_code},
            // POST orders {quantity}, mechanic_report?report_id=). Static leaf-mining can't reconstruct those;
            // the browser gets 6/8 because it captures the real bodies. Enabling it also destabilized the
            // signup-SQLi audit (2/8 -> 1/8, twice). Kept as dead code for apps whose GET surface IS the target.
            // discoverAssembled(host, baseUrl, live, seen);
            // LLM body-synthesis (synthesizeEndpointsLlm) is DISABLED by default. It WORKS at the discovery
            // layer — reconstructs crAPI's write endpoints with correct service bases (POST workshop/api/shop/
            // orders, .../apply_coupon, community/api/v2/coupon/validate-coupon) browser-free, oracle-gated,
            // zero FPs. BUT it did not lift the crAPI benchmark: no create→consume finding fired on the
            // discovered endpoints (they need valid STATE — a coupon from the NoSQL leak, a product_id, an
            // added vehicle — i.e. the create→consume CHAIN, not just the endpoint), and enabling it correlated
            // with losing the separate signup-SQLi audit (2/8→1/8). Kept as a proven, reusable capability;
            // re-enable behind -Daiscanner.synthEndpoints once the chaining/state layer lands.
            if (Boolean.getBoolean("aiscanner.synthEndpoints") && session != null && session.hasBearer())
                synthesizeEndpointsLlm(host, baseUrl, live, seen);
            ingestApiSpec(host, baseUrl, live, seen);     // OpenAPI/Swagger spec → documented endpoints
            probeWellKnown(host, baseUrl, live, seen);   // standards/infra paths + i18n negative-diff
            probeAiProposedPaths(host, baseUrl, live, seen);   // LLM-proposed UNLINKED sensitive paths (admin/*, etc.)
            discoverClientRouteApis(host, baseUrl, live, seen); // SPA route nouns → API resources (frontend-orphaned endpoints)
            harvestHtmlForms(host, live, seen);          // server-rendered <form>s → parameterized GET/POST for the active audit
            synthesizeParamReadsFromJson(host, live, seen); // reached JSON collections → param-seeded reads (response keys ARE the query params)
            scanLog.log("endpoint discovery: " + live.size()
                    + " live endpoint(s) Burp's crawler missed.");
        } catch (Throwable t) {
            scanLog.log("endpoint discovery failed: " + t);
        }
        return live;
    }

    // Common locations a served OpenAPI/Swagger spec is published at. Generic convention, not app-specific.
    private static final String[] SPEC_LOCATIONS = {
            "/openapi.json", "/swagger.json", "/openapi.yaml", "/openapi.yml", "/swagger.yaml",
            "/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger/v1/swagger.json", "/api/openapi.json",
            // NestJS @nestjs/swagger publishes the raw JSON at "<swaggerPath>-json" (default /api-json or
            // /swagger-json) — BrokenCrystals uses /swagger-json. Without this the SPA's catch-all serves
            // index.html (200, text/html) at /openapi.json, the real spec is never found, and the spec-driven
            // auth bootstrap + documented surface are missed. (The loop already skips the HTML and keeps going.)
            "/swagger-json", "/api-json", "/swagger/json", "/docs-json",
            // drf-spectacular / DRF publish the OpenAPI doc here (Content-Type application/vnd.oai.openapi);
            // often auth-gated, so this pays off on the authenticated re-scan → the full documented surface.
            "/api/schema/", "/api/schema", "/schema/", "/schema", "/api/v1/schema/", "/api/v1/openapi.json",
    };

    /**
     * INGEST A SERVED OpenAPI/Swagger SPEC. A pure REST API has no crawlable HTML links, so its endpoints
     * (/eval, /uptime/{flag}, /search, /user, /tokens…) are invisible to a crawler — but the app PUBLISHES
     * them in its own OpenAPI document. We fetch it (the app's own served artifact — no fingerprinting),
     * parse paths × methods × parameters (query/header/path) × requestBody (json/xml example or schema),
     * build a concrete request for each, LIVE-PROBE it, and keep the ones a real handler answers. Each kept
     * request carries fuzzable insertion points (query param, path segment, JSON/XML body) so Burp's active
     * audit + our probes fire on the documented surface. JSON specs are parsed deterministically; a YAML-only
     * spec is converted via the LLM (targeting only — every endpoint is still live-probed, nothing trusted).
     */
    private String apiAuthHeader = null;   // the spec's auth header name (e.g. X-Auth-Token), if any
    private String apiAuthToken = null;    // a token acquired via the spec's login endpoint (SQLi-bypass / default creds)
    private JSONObject specRoot = null;    // the full parsed spec, for $ref resolution (#/definitions/… 2.0, #/components/… 3.0)
    private static final java.util.concurrent.atomic.AtomicInteger REG_SEQ = new java.util.concurrent.atomic.AtomicInteger();

    // Header names that denote an auth token, and login-body field names — generic conventions, not app paths.
    private static final Pattern AUTH_HEADER = Pattern.compile("(?i).*(auth[_-]?token|x-?token|api[_-]?key|authorization|access[_-]?token).*");
    private static final Pattern PW_FIELD = Pattern.compile("(?i)^(password|passwd|pwd|pass)$");
    private static final Pattern USER_FIELD = Pattern.compile("(?i)^(username|user|email|login|userid|user_name)$");
    private static final Pattern TOKENISH = Pattern.compile("^[A-Za-z0-9._=+/-]{16,4000}$");   // JWTs (full payload) run 200-400+ chars
    private static final String BOOTSTRAP_PW = "AiScan9zQ7v";   // distinctive, proper-length (survives cleartext-pw detection)

    /** Candidate auth bodies built from a login op's OWN field names: a fresh unique REGISTRATION first
     *  (a signup returns a token for a brand-new account), then SQLi auth-bypass, then generic default creds. */
    private static List<String> credentialBodies(String uf, String pf, String extra) {
        List<String> out = new ArrayList<>();
        String e = extra == null ? "" : extra;   // ,"op":"basic" — other REQUIRED login fields (auth-method selector, …)
        String canary = "aiscan" + REG_SEQ.incrementAndGet() + "@x.io";
        out.add("{\"" + uf + "\":\"" + canary + "\",\"" + pf + "\":\"" + BOOTSTRAP_PW + "\"" + e + "}");
        for (String inj : new String[]{"' OR '1'='1' -- ", "' OR 1=1 -- ", "admin' -- "})
            out.add("{\"" + uf + "\":\"" + inj + "\",\"" + pf + "\":\"x\"" + e + "}");
        String[] users = {"admin", "administrator", "user", "test", "guest", "root"};
        String[] passes = {"admin", "password", "admin123", "test", "guest", "root", "123456", "changeme"};
        for (String u : users) for (String pw : passes) out.add("{\"" + uf + "\":\"" + u + "\",\"" + pf + "\":\"" + pw + "\"" + e + "}");
        return out;
    }

    /** JSON fragment (comma-prefixed) for a login op's REQUIRED body fields OTHER than user/pass — e.g. an
     *  auth-method selector some APIs demand beside the credentials (BrokenCrystals: {@code op} enum). Enum → first
     *  listed value; number/bool → a default; else a benign string. Without them the login body is INVALID (the
     *  server can't even pick an auth method), so no token is ever issued. Read from the spec — nothing hardcoded. */
    private String extraRequiredFields(JSONObject op, String uf, String pf) {
        try {
            JSONObject schema = bodySchema(op);
            JSONArray req = schema == null ? null : schema.optJSONArray("required");
            JSONObject props = schema == null ? null : schema.optJSONObject("properties");
            if (req == null || props == null) return "";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < req.length(); i++) {
                String name = req.optString(i);
                if (name.isEmpty() || name.equals(uf) || name.equals(pf)) continue;
                JSONObject ps = resolveSchema(props.optJSONObject(name));
                JSONArray en = ps == null ? null : ps.optJSONArray("enum");
                String ty = ps == null ? "string" : ps.optString("type", "string");
                String val;
                if (en != null && en.length() > 0) val = "\"" + en.get(0) + "\"";
                else if (ty.equals("integer") || ty.equals("number")) val = "1";
                else if (ty.equals("boolean")) val = "true";
                else val = "\"x\"";
                sb.append(",\"").append(name).append("\":").append(val);
            }
            return sb.toString();
        } catch (Throwable t) { return ""; }
    }

    /** A bearer/JWT handed back in an auth-ish RESPONSE header (Authorization / X-Auth-Token / access-token) rather
     *  than the body — common for APIs that set {@code Authorization: <jwt>} on login (e.g. BrokenCrystals). */
    private static String bearerFromResponseHeaders(burp.api.montoya.http.message.responses.HttpResponse resp) {
        try {
            for (burp.api.montoya.http.message.HttpHeader h : resp.headers()) {
                if (h == null || !AUTH_HEADER.matcher(h.name()).matches()) continue;
                String v = h.value();
                if (v == null) continue;
                String cand = v.replaceFirst("(?i)^Bearer\\s+", "").trim();
                if (TOKENISH.matcher(cand).matches()) return cand;
            }
        } catch (Throwable ignore) { }
        return null;
    }

    /**
     * SPEC-DRIVEN AUTH BOOTSTRAP (no hardcoding — everything is read from the app's own OpenAPI doc). A REST
     * API that authenticates via a custom header (X-Auth-Token) keeps its authed surface (e.g. /user/{id}
     * returning a stored password) out of reach until we hold a token. We (1) learn the auth-header NAME from
     * the spec's header parameters, (2) find the login op (POST whose body has username+password), (3) obtain
     * a token WITHOUT knowing credentials via a SQL-injection auth-bypass body (falling back to a small
     * generic default-credential list), and (4) parse the token out of the response. The token is then
     * injected into the auth header on every subsequent spec-built request, so the authed surface is scanned.
     * Also proves a WEAK-TOKEN finding deterministically: if the returned token == md5(a sibling value in the
     * same response), the session token is a predictable hash of a known value (zero-FP: a proven equality).
     */
    private void acquireSpecToken(JSONObject spec, String host, String root) {
        if (apiAuthToken != null) return;
        try {
            JSONObject paths = spec.optJSONObject("paths");
            if (paths == null) return;
            // (1) most common auth-header name across operations
            java.util.Map<String,Integer> hdrCount = new java.util.HashMap<>();
            List<String> loginPaths = new ArrayList<>();     // ALL POSTs whose body carries credentials
            java.util.Map<String,JSONObject> loginOps = new java.util.LinkedHashMap<>();  // path -> its op (for field names)
            for (String path : paths.keySet()) {
                JSONObject item = paths.optJSONObject(path); if (item == null) continue;
                for (String m : item.keySet()) {
                    JSONObject op = item.optJSONObject(m); if (op == null) continue;
                    JSONArray ps = op.optJSONArray("parameters");
                    if (ps != null) for (int i = 0; i < ps.length(); i++) {
                        JSONObject p = ps.optJSONObject(i);
                        if (p != null && "header".equals(p.optString("in")) && AUTH_HEADER.matcher(p.optString("name","")).matches())
                            hdrCount.merge(p.optString("name"), 1, Integer::sum);
                    }
                    if ("post".equalsIgnoreCase(m) && bodyHasCredentials(op)) { loginPaths.add(path); loginOps.put(path, op); }
                }
            }
            apiAuthHeader = hdrCount.entrySet().stream().max(java.util.Map.Entry.comparingByValue())
                    .map(java.util.Map.Entry::getKey).orElse(null);
            // Prefer login-shaped paths (token/login/auth/signin/session) — a /user create endpoint also carries
            // username+password but is NOT the login (and org.json keySet order is undefined, so we can't rely on it).
            Pattern LOGINISH = Pattern.compile("(?i).*(token|login|auth|signin|session|oauth).*");
            loginPaths.sort((a, b) -> Integer.compare(LOGINISH.matcher(b).matches() ? 1 : 0, LOGINISH.matcher(a).matches() ? 1 : 0));
            scanLog.log("  -> API AUTH: spec auth header=" + apiAuthHeader + ", login candidate(s)=" + loginPaths);
            if (loginPaths.isEmpty()) return;

            // (3) candidate bodies per login path, built from the SPEC's own credential field names (not
            //     hardcoded username/password): a fresh CANARY REGISTRATION (a register/signup op returns a
            //     token for a brand-new account — no guessing), then SQLi auth-bypass, then generic defaults.
            int tries = 0;
            for (String loginPath : loginPaths) {
                String[] cf = credentialFieldNames(loginOps.get(loginPath));
                String uf = cf != null ? cf[0] : "username";
                String pf = cf != null ? cf[1] : "password";
                String extra = extraRequiredFields(loginOps.get(loginPath), uf, pf);   // e.g. ,"op":"basic"
                String url = root + (loginPath.startsWith("/") ? loginPath : "/" + loginPath);
                for (String b : credentialBodies(uf, pf, extra)) {
                    if (tries++ > 80) break;
                    HttpRequest r = withSessionCookie(HttpRequest.httpRequestFromUrl(url).withMethod("POST"))
                            .withHeader("Content-Type", "application/json").withBody(b);
                    HttpRequestResponse rr = probe(r);
                    if (statusOf(rr) < 200 || statusOf(rr) >= 300 || rr.response() == null) continue;
                    String resp = rr.response().bodyToString();
                    boolean jsonBody = resp != null && resp.trim().startsWith("{");
                    String tok = jsonBody ? extractToken(new JSONObject(resp)) : null;
                    String src = "body";
                    if (tok == null) { tok = bearerFromResponseHeaders(rr.response()); src = "Authorization header"; }
                    if (tok != null) {
                        apiAuthToken = tok;
                        // Feed it to the shared session as a bearer so it's injected as `Authorization: Bearer <tok>`
                        // on every subsequent spec-built request AND every probe (JWT/IDOR/BFLA now run authenticated).
                        if (session != null) session.setBearer(tok);
                        String how = b.contains("OR ") ? "SQLi auth-bypass" : b.contains("@x.io") ? "fresh registration" : "default creds";
                        scanLog.log("  -> API AUTH: obtained a token via " + loginPath + " (" + how
                                + ", fields " + uf + "/" + pf + (extra.isEmpty() ? "" : " + required" + extra) + ", from " + src
                                + "); auth header = " + (apiAuthHeader == null ? "Authorization: Bearer" : apiAuthHeader));
                        if (jsonBody) checkWeakToken(new JSONObject(resp), tok, url, rr);
                        return;
                    }
                }
            }
            // (4) TWO-STEP register -> login. APIs like VAmPI/crAPI create the account on a register endpoint that
            //     returns NO token, then issue the token only on a SEPARATE login endpoint — the single-step loop
            //     above can't bridge that. Pair a register-ish path with a login-ish one, register a fresh account,
            //     then log in with the SAME registered handle (username=tag, NOT the email — VAmPI answers "Username
            //     does not exist" for the email). Generic: unique nonce creds, spec password field, no app specifics.
            Pattern REGISTERISH = Pattern.compile("(?i).*(register|signup|sign-?up|create).*");
            String regPath = loginPaths.stream().filter(p -> REGISTERISH.matcher(p).find()).findFirst().orElse(null);
            String logPath = loginPaths.stream().filter(p -> !REGISTERISH.matcher(p).find()).findFirst().orElse(null);
            if (regPath != null && logPath != null && !regPath.equals(logPath)) {
                long n = Math.abs(System.nanoTime());
                String tag = "aisc" + Long.toString(n, 36), pass = "Aisc!" + (n % 100000) + "Zx", email = tag + "@example.com";
                String[] rcf = credentialFieldNames(loginOps.get(regPath)), lcf = credentialFieldNames(loginOps.get(logPath));
                String rpf = (rcf != null && rcf.length > 1 && rcf[1] != null) ? rcf[1] : "password";
                String lpf = (lcf != null && lcf.length > 1 && lcf[1] != null) ? lcf[1] : "password";
                String regUrl = root + (regPath.startsWith("/") ? regPath : "/" + regPath);
                String logUrl = root + (logPath.startsWith("/") ? logPath : "/" + logPath);
                try {
                    probe(withSessionCookie(HttpRequest.httpRequestFromUrl(regUrl).withMethod("POST"))
                            .withHeader("Content-Type", "application/json").withBody(superCreds(tag, email, pass, rpf)));
                    HttpRequestResponse rr = probe(withSessionCookie(HttpRequest.httpRequestFromUrl(logUrl).withMethod("POST"))
                            .withHeader("Content-Type", "application/json").withBody(superCreds(tag, email, pass, lpf)));
                    if (rr != null && rr.response() != null && statusOf(rr) >= 200 && statusOf(rr) < 300) {
                        String resp = rr.response().bodyToString();
                        String tok = (resp != null && resp.trim().startsWith("{")) ? extractToken(new JSONObject(resp)) : null;
                        if (tok == null) tok = bearerFromResponseHeaders(rr.response());
                        if (tok != null) {
                            apiAuthToken = tok; if (session != null) session.setBearer(tok);
                            scanLog.log("  -> API AUTH: registered '" + tag + "' on " + regPath
                                    + " -> logged in via " + logPath + " -> token adopted (register-then-login).");
                            if (resp != null && resp.trim().startsWith("{")) checkWeakToken(new JSONObject(resp), tok, logUrl, rr);
                            return;
                        }
                    }
                } catch (Throwable t) { scanLog.debug("  -> API AUTH: two-step register-then-login error: " + t); }
            }
            scanLog.log("  -> API AUTH: login candidate(s) tried but no token extracted (" + tries + " attempt(s)).");
        } catch (Throwable t) { scanLog.log("spec auth bootstrap error: " + t); }
    }

    /** Superset JSON credential body: the registered handle (tag) in every common identity field + email + the
     *  spec's password field, so a lenient JSON register/login endpoint finds what it needs regardless of naming.
     *  Log in with tag (username-keyed APIs reject the email); email is present for email-keyed apps. */
    private static String superCreds(String tag, String email, String pass, String pf) {
        StringBuilder b = new StringBuilder("{\"username\":\"").append(tag).append("\",\"user\":\"").append(tag)
                .append("\",\"login\":\"").append(tag).append("\",\"name\":\"").append(tag)
                .append("\",\"email\":\"").append(email).append("\",\"password\":\"").append(pass)
                .append("\",\"passwordConfirm\":\"").append(pass).append("\",\"repeatPassword\":\"").append(pass).append("\"");
        if (pf != null && !pf.isBlank() && !pf.equalsIgnoreCase("password"))
            b.append(",\"").append(pf).append("\":\"").append(pass).append("\"");
        return b.append("}").toString();
    }

    /** Resolve a schema object, following a {@code $ref} ({@code #/definitions/X} in Swagger 2.0 or
     *  {@code #/components/schemas/X} in OpenAPI 3.0) against the full spec. Returns the concrete schema. */
    private JSONObject resolveSchema(JSONObject schema) {
        if (schema == null) return null;
        for (int hop = 0; hop < 5 && schema != null && schema.has("$ref"); hop++) {
            String ref = schema.optString("$ref", "");
            if (!ref.startsWith("#/")) break;
            JSONObject node = specRoot;
            for (String seg : ref.substring(2).split("/")) {
                if (node == null) break;
                node = node.optJSONObject(seg);
            }
            schema = node;
        }
        return schema;
    }

    /** The request body's property map for an operation, resolving BOTH OpenAPI 3.0 ({@code requestBody.content})
     *  and Swagger 2.0 ({@code parameters[in=body].schema}) and any {@code $ref}. */
    private JSONObject bodyProps(JSONObject op) {
        try {
            JSONObject schema = null;
            // OpenAPI 3.0
            JSONObject rb = op.optJSONObject("requestBody");
            if (rb != null) {
                JSONObject content = rb.optJSONObject("content");
                if (content != null) {
                    JSONObject media = content.optJSONObject("application/json");
                    if (media == null && !content.keySet().isEmpty()) media = content.optJSONObject(content.keySet().iterator().next());
                    if (media != null) schema = media.optJSONObject("schema");
                }
            }
            // Swagger 2.0: a parameter with in=body carries the schema
            if (schema == null) {
                JSONArray params = op.optJSONArray("parameters");
                if (params != null) for (int i = 0; i < params.length(); i++) {
                    JSONObject p = params.optJSONObject(i);
                    if (p != null && "body".equalsIgnoreCase(p.optString("in"))) { schema = p.optJSONObject("schema"); break; }
                }
            }
            schema = resolveSchema(schema);
            return schema == null ? null : schema.optJSONObject("properties");
        } catch (Throwable t) { return null; }
    }

    private boolean bodyHasCredentials(JSONObject op) {
        JSONObject props = bodyProps(op);
        if (props == null) return false;
        boolean u = false, p = false;
        for (String k : props.keySet()) { if (USER_FIELD.matcher(k).matches()) u = true; if (PW_FIELD.matcher(k).matches()) p = true; }
        return u && p;
    }

    /** The credential field NAMES (user-like, pass-like) declared by an operation's body schema, or null. */
    private String[] credentialFieldNames(JSONObject op) {
        JSONObject props = bodyProps(op);
        if (props == null) return null;
        String uf = null, pf = null;
        for (String k : props.keySet()) {
            if (uf == null && USER_FIELD.matcher(k).matches()) uf = k;
            if (pf == null && PW_FIELD.matcher(k).matches()) pf = k;
        }
        return (uf != null && pf != null) ? new String[]{uf, pf} : null;
    }

    /** Deep-search a JSON response for the longest token-shaped string value (prefers keys under a "token"). */
    private static String extractToken(Object node) {
        return extractToken(node, false);
    }
    private static String extractToken(Object node, boolean underToken) {
        if (node instanceof JSONObject) {
            JSONObject o = (JSONObject) node;
            String best = null;
            for (String k : o.keySet()) {
                Object v = o.get(k);
                boolean kt = underToken || k.toLowerCase().contains("token") || k.equalsIgnoreCase("access");
                if (v instanceof String) {
                    String s = ((String) v).trim();
                    boolean idish = k.equalsIgnoreCase("id") || k.toLowerCase().contains("token");
                    if (TOKENISH.matcher(s).matches() && (kt || idish) && !s.contains(" ")
                            && (best == null || s.length() > best.length())) best = s;
                } else {
                    String d = extractToken(v, kt);
                    if (d != null && (best == null || d.length() > best.length())) best = d;
                }
            }
            return best;
        } else if (node instanceof JSONArray) {
            JSONArray a = (JSONArray) node; String best = null;
            for (int i = 0; i < a.length(); i++) { String d = extractToken(a.get(i), underToken); if (d != null && (best == null || d.length() > best.length())) best = d; }
            return best;
        }
        return null;
    }

    /** If token == md5(any sibling scalar value) → a predictable session token (proven, zero-FP). */
    private void checkWeakToken(JSONObject resp, String token, String url, HttpRequestResponse evidence) {
        try {
            java.util.List<String> scalars = new ArrayList<>();
            collectScalars(resp, scalars);
            for (String s : scalars) {
                if (s.equals(token)) continue;
                if (token.equalsIgnoreCase(md5(s)) || token.equalsIgnoreCase(md5(s.trim()))) {
                    scanLog.found("Predictable session token (weak token generation)", url,
                            "The session token equals md5(\"" + (s.length() > 40 ? s.substring(0, 40) + "…" : s)
                            + "\") — a value returned in the SAME response. The token is a plain hash of a known/"
                            + "guessable value (CWE-330/CWE-338), so it is forgeable. Proven: md5 equality.", evidence);
                    scanLog.incFinding();
                    return;
                }
            }
        } catch (Throwable ignore) { }
    }

    private static void collectScalars(Object node, java.util.List<String> out) {
        if (node instanceof JSONObject) { JSONObject o = (JSONObject) node; for (String k : o.keySet()) collectScalars(o.get(k), out); }
        else if (node instanceof JSONArray) { JSONArray a = (JSONArray) node; for (int i = 0; i < a.length(); i++) collectScalars(a.get(i), out); }
        else if (node != null && node != JSONObject.NULL) out.add(String.valueOf(node));
    }

    private static String md5(String s) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("MD5").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    private void ingestApiSpec(String host, String baseUrl, List<HttpRequest> live, Set<String> seen) {
        String root = baseUrl.replaceAll("/+$", "");
        for (String loc : SPEC_LOCATIONS) {
            try {
                HttpRequestResponse rr = probe(withSessionCookie(
                        HttpRequest.httpRequestFromUrl(root + loc).withMethod("GET")));
                if (statusOf(rr) != 200 || rr.response() == null) continue;
                String body = rr.response().bodyToString();
                if (body == null || body.isBlank()) continue;
                String t = body.trim();
                JSONObject spec = null;
                if (t.startsWith("{")) {
                    try { spec = new JSONObject(t); } catch (Exception ignore) { }
                } else if (t.toLowerCase().contains("openapi") || t.toLowerCase().contains("swagger")) {
                    spec = specFromYamlViaLlm(t);   // YAML spec → LLM converts to a JSON paths object
                }
                if (spec == null || !spec.has("paths")) continue;
                specRoot = spec;                      // enable $ref resolution against the full spec
                acquireSpecToken(spec, host, root);   // spec-driven auth bootstrap (sets apiAuthHeader/apiAuthToken)
                int before = live.size();
                parseSpecPaths(spec, host, root, live, seen);
                scanLog.log("  -> API SPEC " + loc + ": ingested "
                        + (live.size() - before) + " live endpoint(s).");
                if (live.size() > before) return;   // one good spec is enough
            } catch (Exception ignore) { }
        }
    }

    /** Build + live-probe a request for every path×method in an OpenAPI paths object; keep the live ones. */
    private void parseSpecPaths(JSONObject spec, String host, String root, List<HttpRequest> live, Set<String> seen) {
        JSONObject paths = spec.optJSONObject("paths");
        if (paths == null) return;
        for (String path : paths.keySet()) {
            JSONObject item = paths.optJSONObject(path);
            if (item == null) continue;
            for (String method : new String[]{"get", "post", "put", "patch", "delete"}) {
                JSONObject op = item.optJSONObject(method);
                if (op == null) continue;
                try {
                    HttpRequest req = buildFromOperation(path, method.toUpperCase(), op, root);
                    if (req == null || !host.equalsIgnoreCase(hostOf(req.url()))) continue;
                    if (AuthenticatedExplorer.SESSION_RESET.matcher(req.url()).matches()) continue;
                    if (!seen.add(method.toUpperCase() + " " + Net.stripQuery(req.url()))) continue;
                    HttpRequestResponse rr = probe(req);
                    int st = statusOf(rr);
                    if (st <= 0 || st == 404 || st == 405) continue;   // route absent → not real
                    live.add(req);
                    keep(rr, host);                                    // bridge to site map
                    scanLog.log("  -> SPEC " + st + "  " + method.toUpperCase()
                            + " " + Net.stripQuery(req.url()) + paramSuffix(req));
                } catch (Exception ignore) { }
            }
        }
    }

    // A reference field NAMES another resource (its value is that resource's id/key) → harvestable from a sibling
    // collection. A prompt-ish field is free text the LLM probes fuzz. Both are generic naming conventions, not
    // app paths. REF_FIELD stays case-EXACT (snake `_id`/`_ref`/… or camel `Id`/`Ref`/…) so it doesn't match plain
    // words that merely end in "id" (android, valid, grid). PROMPT_FIELD is case-insensitive (free-text hints).
    private static final Pattern REF_FIELD = Pattern.compile(".*(_id|_ref|_key|_slug|Id|Ref|Key)$|^(id|scenario|resource)$");
    private static final Pattern PROMPT_FIELD = Pattern.compile("(?i).*(input|prompt|message|msg|query|text|question|content|search|q)$");
    private final java.util.Map<String, String> harvestCache = new java.util.concurrent.ConcurrentHashMap<>();

    /** The resolved request-body schema for an operation (OpenAPI 3.0 content, or Swagger 2.0 in=body param). */
    private JSONObject bodySchema(JSONObject op) {
        try {
            JSONObject schema = null;
            JSONObject rb = op.optJSONObject("requestBody");
            if (rb != null) {
                JSONObject content = rb.optJSONObject("content");
                if (content != null) {
                    JSONObject media = content.optJSONObject("application/json");
                    if (media == null && !content.keySet().isEmpty()) media = content.optJSONObject(content.keySet().iterator().next());
                    if (media != null) schema = media.optJSONObject("schema");
                }
            }
            if (schema == null) {                                // Swagger 2.0: schema hangs off the in=body param
                JSONArray params = op.optJSONArray("parameters");
                if (params != null) for (int i = 0; i < params.length(); i++) {
                    JSONObject p = params.optJSONObject(i);
                    if (p != null && "body".equalsIgnoreCase(p.optString("in"))) { schema = p.optJSONObject("schema"); break; }
                }
            }
            return resolveSchema(schema);
        } catch (Throwable t) { return null; }
    }

    /**
     * A JSON body from a (possibly $ref) request schema, filling REQUIRED fields with USABLE values so the request
     * returns a real 2xx baseline the probes can attack instead of a 422/404 on an empty/invalid body: an enum uses
     * a listed value; a REFERENCE field (scenario_id, user_id, …) is HARVESTED from a sibling collection endpoint
     * (generic "&lt;x&gt;_id → GET /&lt;x&gt;s" correlation) so a consume-endpoint gets a valid id; a prompt-ish string gets a
     * benign seed the LLM probes then fuzz (prompt-injection / system-prompt-leak inject HERE); other types get a
     * type default. Optional fields are omitted (a spurious optional can itself 422). Null if no usable properties.
     */
    private String schemaBody(JSONObject schema, String path, String root) {
        schema = resolveSchema(schema);
        if (schema == null) return null;
        JSONObject props = schema.optJSONObject("properties");
        if (props == null || props.keySet().isEmpty()) return null;
        java.util.Set<String> required = new java.util.LinkedHashSet<>();
        JSONArray req = schema.optJSONArray("required");
        if (req != null) for (int i = 0; i < req.length(); i++) required.add(req.optString(i));
        JSONObject body = new JSONObject();
        for (String name : props.keySet()) {
            boolean isRef = REF_FIELD.matcher(name).matches();
            if (!required.contains(name) && !isRef) continue;    // only what's needed for a valid write
            JSONObject ps = resolveSchema(props.optJSONObject(name));
            JSONArray en = ps == null ? null : ps.optJSONArray("enum");
            String type = ps == null ? "string" : ps.optString("type", "string");
            Object val;
            if (en != null && en.length() > 0) val = en.get(0);  // a documented valid value
            else if (isRef) {                                    // a valid id from the sibling collection, else a seed
                String harvested = harvestFieldValue(name, path, root);
                val = harvested != null ? harvested : seedFor(name, type);
            } else val = seedFor(name, type);
            body.put(name, val);
        }
        return body.keySet().isEmpty() ? null : body.toString();
    }

    /** A benign, type-appropriate seed for a body field (a prompt-ish string gets a real phrase LlmFuzz mutates). */
    private static Object seedFor(String name, String type) {
        String t = type == null ? "string" : type;
        if (t.equals("integer") || t.equals("number")) return 1;
        if (t.equals("boolean")) return true;
        if (t.equals("array")) return new JSONArray();
        if (t.equals("object")) return new JSONObject();
        String n = name == null ? "" : name.toLowerCase();
        if (n.contains("email")) return "aiscan" + REG_SEQ.incrementAndGet() + "@x.io";
        if (n.contains("pass")) return BOOTSTRAP_PW;
        if (PROMPT_FIELD.matcher(n).matches()) return "hello";   // a real seed for the LLM probes to fuzz
        return "test";
    }

    /**
     * Harvest a valid value for a reference field (e.g. scenario_id) from a sibling COLLECTION endpoint: strip the
     * id/ref suffix to the resource noun, GET the plural/singular collection under the SAME path parent and the API
     * root, and return the first usable id/name/string from the JSON. Best-effort + cached per (root,noun); null if
     * nothing answers. Fully generic — the noun and the collection come from the app's own spec paths + responses.
     */
    private String harvestFieldValue(String field, String path, String root) {
        try {
            String noun = field.replaceAll("(_id|_ref|_key|_slug|Id|Ref|Key)$", "");
            if (noun.length() < 2) return null;
            String nl = noun.toLowerCase(), cacheKey = root + "|" + nl;
            String cached = harvestCache.get(cacheKey);
            if (cached != null) return cached.isEmpty() ? null : cached;
            String parent = path.replaceAll("/[^/]*$", "");      // /api/v1/run -> /api/v1
            java.util.LinkedHashSet<String> paths = new java.util.LinkedHashSet<>();
            for (String base : new String[]{ nl, noun }) {       // /api/v1/scenarios, /api/v1/scenario, /scenarios…
                paths.add(parent + "/" + pluralize(base));
                paths.add(parent + "/" + base);
                paths.add("/" + pluralize(base));
                paths.add("/" + base);
            }
            String found = "";
            for (String p : paths) {
                HttpRequest g = withSessionCookie(HttpRequest.httpRequestFromUrl(root + p).withMethod("GET"));
                if (session != null && session.hasBearer()) g = g.withHeader("Authorization", "Bearer " + session.bearer());
                HttpRequestResponse rr = probe(g);
                if (statusOf(rr) != 200 || rr.response() == null) continue;
                String v = firstIdIn(rr.response().bodyToString(), nl);
                if (v != null && !v.isBlank()) { found = v; break; }
            }
            harvestCache.put(cacheKey, found);                   // cache the miss too (don't re-probe every field)
            return found.isEmpty() ? null : found;
        } catch (Throwable ignore) { return null; }
    }

    /** First usable value from a collection response: a bare string/number element, an object's id/name/key, or the
     *  array under a key related to the noun ({"scenarios":["code_assistant",…]} → "code_assistant"). */
    private static String firstIdIn(String body, String noun) {
        try {
            String t = body == null ? "" : body.trim();
            JSONArray arr = null;
            if (t.startsWith("[")) arr = new JSONArray(t);
            else if (t.startsWith("{")) {
                JSONObject o = new JSONObject(t);
                for (String k : o.keySet())                       // prefer the array under a noun-related key
                    if (o.opt(k) instanceof JSONArray && k.toLowerCase().contains(noun)) { arr = o.optJSONArray(k); break; }
                if (arr == null) for (String k : o.keySet()) if (o.opt(k) instanceof JSONArray) { arr = o.optJSONArray(k); break; }
                if (arr == null) {                                // a single object → its own id-ish field
                    for (String key : new String[]{ "id", "_id", noun + "_id", noun + "id", "name", "slug", "key" })
                        if (o.has(key) && o.opt(key) != null) return String.valueOf(o.get(key));
                }
            }
            if (arr == null || arr.length() == 0) return null;
            Object first = arr.get(0);
            if (first instanceof String) return (String) first;
            if (first instanceof Number) return String.valueOf(first);
            if (first instanceof JSONObject) {
                JSONObject fo = (JSONObject) first;
                for (String key : new String[]{ "id", "_id", noun + "_id", noun + "id", "name", "slug", "key", "value" })
                    if (fo.has(key) && fo.opt(key) != null) return String.valueOf(fo.get(key));
            }
        } catch (Throwable ignore) { }
        return null;
    }

    /** Turn one OpenAPI operation into a concrete, seeded request (path/query/header params + json/xml body). */
    private HttpRequest buildFromOperation(String path, String method, JSONObject op, String root) {
        // path params: substitute {name}/:name with the declared example, else a benign "1"
        String resolvedPath = path;
        StringBuilder query = new StringBuilder();
        java.util.List<String[]> headers = new java.util.ArrayList<>();
        JSONArray params = op.optJSONArray("parameters");
        if (params != null) for (int i = 0; i < params.length(); i++) {
            JSONObject p = params.optJSONObject(i);
            if (p == null) continue;
            String in = p.optString("in", ""), name = p.optString("name", "");
            if (name.isEmpty()) continue;
            String ex = paramExample(p);
            if ("path".equals(in)) {
                resolvedPath = resolvedPath.replace("{" + name + "}", ex).replace(":" + name, ex);
            } else if ("query".equals(in)) {
                query.append(query.length() == 0 ? '?' : '&').append(name).append('=').append(ex);
            } else if ("header".equals(in)) {
                // inject the bootstrapped token when this is the spec's auth header, else the declared example
                if (apiAuthToken != null && apiAuthHeader != null && name.equalsIgnoreCase(apiAuthHeader))
                    ex = apiAuthToken;
                headers.add(new String[]{name, ex});
            }
        }
        resolvedPath = resolvedPath.replaceAll("\\{[^}]+}", "1");   // any leftover path template → benign value
        String url = root + (resolvedPath.startsWith("/") ? resolvedPath : "/" + resolvedPath) + query;
        HttpRequest req = withSessionCookie(HttpRequest.httpRequestFromUrl(url).withMethod(method));
        for (String[] h : headers) req = req.withHeader(h[0], h[1]);
        if (session != null && session.hasBearer()) req = req.withHeader("Authorization", "Bearer " + session.bearer());

        // requestBody: prefer JSON, then XML, then form — a declared example wins; else build from the schema.
        String bodyStr = null, bodyCt = "application/json";
        boolean write = method.equals("POST") || method.equals("PUT") || method.equals("PATCH");
        JSONObject jsonSchema = null;
        JSONObject rb = op.optJSONObject("requestBody");
        if (rb != null) {                                        // OpenAPI 3.0
            JSONObject content = rb.optJSONObject("content");
            if (content != null) {
                String ct = content.has("application/json") ? "application/json"
                        : content.has("application/xml") ? "application/xml"
                        : content.keySet().stream().findFirst().orElse(null);
                if (ct != null) {
                    bodyCt = ct;
                    JSONObject media = content.optJSONObject(ct);
                    if (media != null && (media.has("example") || media.has("examples"))) bodyStr = exampleBody(media, ct);
                    else if (ct.contains("json") && media != null) jsonSchema = media.optJSONObject("schema");
                    else bodyStr = exampleBody(media, ct);        // xml/form
                }
            }
        }
        // Build a REAL JSON body from the (possibly $ref) schema: resolve it, fill REQUIRED fields with USABLE
        // values — an id/reference field (scenario_id, user_id, …) is HARVESTED from a sibling collection endpoint
        // so a consume-endpoint gets a valid id (e.g. run{scenario_id} <- GET /scenarios); enums use a listed
        // value; a prompt-ish string gets a benign seed the LLM probes then fuzz. This is what turns a 422/404
        // (empty/invalid body) into a 2xx baseline the LLM/injection probes can actually attack.
        if (bodyStr == null && write) {
            JSONObject schema = jsonSchema != null ? jsonSchema : bodySchema(op);
            bodyStr = schemaBody(schema, path, root);
            if (bodyStr == null) {                               // fall back to the old flat seed
                JSONObject props = bodyProps(op);
                if (props != null && !props.keySet().isEmpty()) bodyStr = jsonBody(new ArrayList<>(props.keySet()));
            }
            bodyCt = "application/json";
        }
        if (bodyStr != null) req = req.withHeader("Content-Type", bodyCt).withBody(bodyStr);
        return req;
    }

    /** An example value for a parameter: declared example/enum, else a type-appropriate benign default. */
    private static String paramExample(JSONObject p) {
        if (p.has("example")) return String.valueOf(p.get("example"));
        JSONObject sch = p.optJSONObject("schema");
        if (sch != null) {
            if (sch.has("example")) return String.valueOf(sch.get("example"));
            JSONArray en = sch.optJSONArray("enum");
            if (en != null && en.length() > 0) return String.valueOf(en.get(0));
            String ty = sch.optString("type", "string");
            if (ty.equals("integer") || ty.equals("number")) return "1";
        }
        return "1";
    }

    /** A request body from a media object: its declared example, else JSON seeded from schema properties. */
    private static String exampleBody(JSONObject media, String ct) {
        if (media == null) return null;
        if (media.has("example")) return String.valueOf(media.get("example"));
        JSONObject examples = media.optJSONObject("examples");
        if (examples != null) for (String k : examples.keySet()) {
            JSONObject e = examples.optJSONObject(k);
            if (e != null && e.has("value")) return String.valueOf(e.get("value"));
        }
        JSONObject schema = media.optJSONObject("schema");
        if (schema != null && ct.contains("json")) {
            JSONObject props = schema.optJSONObject("properties");
            if (props != null && !props.keySet().isEmpty())
                return jsonBody(new java.util.ArrayList<>(props.keySet()));
        }
        if (ct.contains("xml")) return "<root><user>1</user></root>";
        return ct.contains("json") ? "{}" : null;
    }

    /** YAML-only spec → LLM extracts a minimal OpenAPI JSON ({paths:{...}}). Targeting only; live-probed after. */
    private JSONObject specFromYamlViaLlm(String yaml) {
        AiEngine eng = engine != null ? engine.get() : null;
        if (eng == null || !eng.isConfigured()) return null;
        try {
            String y = yaml.length() > 12000 ? yaml.substring(0, 12000) : yaml;
            String sys = "Convert this OpenAPI/Swagger YAML to COMPACT JSON. Output ONLY the JSON object with a "
                    + "top-level \"paths\" key mirroring the spec (each path -> method -> {parameters, requestBody}). "
                    + "Preserve parameter name/in and any example values and requestBody content-types/examples. No markdown.";
            String raw = eng.chat(sys, y, "discovery: openapi-yaml");
            if (raw == null) return null;
            int s = raw.indexOf('{'), e = raw.lastIndexOf('}');
            if (s < 0 || e <= s) return null;
            return new JSONObject(raw.substring(s, e + 1));
        } catch (Exception ignore) { return null; }
    }

    // Generic standards/infrastructure paths — the request itself is the finding (metrics/security.txt/etc.).
    // Kept deliberately app-agnostic (RFC / common infra), never target-specific.
    private static final String[] WELL_KNOWN = {
            "/metrics", "/.well-known/security.txt", "/security.txt", "/health", "/status",
            "/server-status", "/sitemap.xml", "/crossdomain.xml", "/.env", "/.git/config",
            "/actuator", "/actuator/health", "/swagger.json", "/openapi.json", "/api-docs",
    };

    /** GET a generic well-known wordlist (and an i18n negative-diff); keep live ones. */
    private void probeWellKnown(String host, String baseUrl, List<HttpRequest> live, Set<String> seen) {
        String root = baseUrl.replaceAll("/+$", "");
        for (String p : WELL_KNOWN) {
            try {
                String abs = root + p;
                if (!seen.add("GET " + abs)) continue;
                HttpRequest req = withSessionCookie(HttpRequest.httpRequestFromUrl(abs).withMethod("GET"));
                int st = statusOf(probe(req));
                if (st >= 200 && st < 400) {
                    live.add(req);
                    scanLog.log("  -> WELL-KNOWN " + st + "  GET " + p);
                }
            } catch (Exception ignore) { }
        }
        probeExtraLanguage(host, root);
    }

    /** Extra-language: request an i18n file whose key is NOT in the app's official language set. */
    private void probeExtraLanguage(String host, String root) {
        try {
            HttpRequestResponse lr = probe(withSessionCookie(
                    HttpRequest.httpRequestFromUrl(root + "/rest/languages").withMethod("GET")));
            if (lr == null || lr.response() == null) return;
            Set<String> official = new LinkedHashSet<>();
            Matcher km = Pattern.compile("\"key\"\\s*:\\s*\"([A-Za-z_-]+)\"").matcher(lr.response().bodyToString());
            while (km.find()) official.add(km.group(1));
            if (official.isEmpty()) return;
            Set<String> tried = new LinkedHashSet<>();
            for (String[] src : gatherSources(host)) {
                Matcher im = Pattern.compile("assets/i18n/([A-Za-z_-]+)\\.json").matcher(src[1]);
                while (im.find()) {
                    String key = im.group(1);
                    if (official.contains(key) || !tried.add(key)) continue;
                    int st = statusOf(probe(withSessionCookie(
                            HttpRequest.httpRequestFromUrl(root + "/assets/i18n/" + key + ".json").withMethod("GET"))));
                    if (st >= 200 && st < 400)
                        scanLog.log("  -> extra-language i18n served (not in /rest/languages): " + key + ".json");
                }
            }
        } catch (Exception ignore) { }
    }

    // Burp's automated crawler only FOLLOWS references, and its wordlist "Discover content" is a manual
    // engagement tool with NO Montoya API. So an UNLINKED sensitive path (e.g. an /admin/ console absent from
    // robots/sitemap and referenced by no href) is invisible to the automated scan. We fill that gap generically:
    // the LLM PROPOSES likely paths from the fingerprint (a dozen idiomatic guesses, not a dictionary), then a
    // deterministic live-probe confirms which exist — nothing hallucinated survives. A confirmed 200 page is
    // link-followed (bounded) so child pages Burp would have crawled (e.g. /admin/users.html, /admin/*-add forms)
    // enter the site map + target list; Burp's own passive checks (e.g. SSN disclosure) and our CsrfProbe then
    // do the detection. No app-specific paths are ever hardcoded.
    private static final Pattern HREF = Pattern.compile("(?i)(?:href|action)\\s*=\\s*[\"']([^\"'#>]+)[\"']");

    private void probeAiProposedPaths(String host, String baseUrl, List<HttpRequest> live, Set<String> seen) {
        AiEngine eng = engine != null ? engine.get() : null;
        if (eng == null || !eng.isConfigured()) return;
        String fingerprint = buildFingerprint(host);
        if (fingerprint.isBlank()) return;
        List<String> proposed;
        try { proposed = eng.proposeSensitivePaths(fingerprint, 15); }
        catch (Throwable t) { return; }
        if (proposed == null || proposed.isEmpty()) return;

        String root = baseUrl.replaceAll("/+$", "");
        java.util.ArrayDeque<String[]> queue = new java.util.ArrayDeque<>();   // {absUrl, depth}
        int confirmed = 0;
        for (String p : proposed) {
            if (p == null || p.isBlank()) continue;
            String path = p.trim();
            int sp = path.indexOf(' '); if (sp > 0) path = path.substring(0, sp);   // tolerate "GET /x"
            if (!path.startsWith("/")) path = "/" + path;
            HttpRequestResponse rr = confirmPath(host, root + path, seen);
            if (rr == null) continue;
            String finalUrl = rr.request().url();          // may differ from the guess (302 /admin -> /admin/)
            int st = statusOf(rr);
            live.add(withSessionCookie(HttpRequest.httpRequestFromUrl(finalUrl).withMethod("GET")));
            recordPage(rr, host);
            confirmed++;
            scanLog.log("  -> AI-PATH " + st + "  GET " + pathOnly(finalUrl));
            if (st >= 200 && st < 300) enqueueLinks(rr, finalUrl, host, root, 1, queue, seen);
        }
        // Bounded link-follow from confirmed 200 pages (reach the children Burp's crawler would have).
        int budget = 30;
        while (!queue.isEmpty() && budget-- > 0) {
            String[] cur = queue.poll();
            HttpRequestResponse rr = confirmPath(host, cur[0], seen);   // already de-duped via seen when enqueued
            if (rr == null) continue;
            int st = statusOf(rr);
            String finalUrl = rr.request().url();
            live.add(withSessionCookie(HttpRequest.httpRequestFromUrl(finalUrl).withMethod("GET")));
            recordPage(rr, host);
            confirmed++;
            scanLog.log("  -> AI-PATH(link) " + st + "  GET " + pathOnly(finalUrl));
            int depth = Integer.parseInt(cur[1]);
            if (st >= 200 && st < 300 && depth < 2) enqueueLinks(rr, finalUrl, host, root, depth + 1, queue, seen);
        }
        if (confirmed > 0)
            scanLog.log("AI path-discovery: " + confirmed + " unlinked path(s) confirmed live "
                    + "(proposed " + proposed.size() + ").");
    }

    /** Live-probe an absolute URL once (de-duped via {@code seen}); return the rr only if it EXISTS
     *  (200, or 401/403 = present but access-controlled). 404/405/errors → null (discarded). */
    private HttpRequestResponse confirmPath(String host, String abs, Set<String> seen) {
        try {
            if (!host.equalsIgnoreCase(hostOf(abs))) return null;
            if (STATIC.matcher(abs).matches() || abs.toLowerCase().contains(".js")) return null;
            if (AuthenticatedExplorer.SESSION_RESET.matcher(abs).matches()) return null;   // never login/logout
            if (!seen.add("GET " + Net.stripQuery(abs))) return null;
            return resolveConfirm(host, abs, 2);
        } catch (Exception e) { return null; }
    }

    /** Record an AI-path-confirmed page: keep() bridges any JSON endpoint to the IDOR/BFLA site map (HTML is
     *  filtered there, which is correct); discoveredPages additionally holds the HTML pages so the caller can
     *  site-map + form-derive them (bounded, defensive — same rationale as keptResponses' cap). */
    private void recordPage(HttpRequestResponse rr, String host) {
        keep(rr, host);
        if (rr != null && rr.response() != null && discoveredPages.size() < 80) discoveredPages.add(rr);
    }

    /** Probe a URL; keep it if it EXISTS (200, or 401/403 = present but access-controlled). Follows up to
     *  {@code hops} same-host redirects so a trailing-slash / directory redirect (Tomcat /admin -> /admin/,
     *  which would otherwise be discarded as a 302) resolves to the real page. Never follows into login. */
    private HttpRequestResponse resolveConfirm(String host, String url, int hops) {
        HttpRequestResponse rr = probe(withSessionCookie(HttpRequest.httpRequestFromUrl(url).withMethod("GET")));
        int st = statusOf(rr);
        if (st == 200 || st == 401 || st == 403) return rr;
        if (hops > 0 && st >= 300 && st < 400 && rr != null && rr.response() != null && rr.response().hasHeader("Location")) {
            try {
                String loc = java.net.URI.create(url).resolve(rr.response().headerValue("Location")).toString();
                if (host.equalsIgnoreCase(hostOf(loc)) && !AuthenticatedExplorer.SESSION_RESET.matcher(loc).matches()
                        && !Net.stripQuery(loc).equalsIgnoreCase(Net.stripQuery(url)))
                    return resolveConfirm(host, loc, hops - 1);
            } catch (Exception ignore) { }
        }
        return null;
    }

    /** Queue same-host href/action links found in a page body, scoped to the confirmed root (so we follow
     *  the discovered subtree, not the whole app the main crawl already covered). */
    private void enqueueLinks(HttpRequestResponse rr, String base, String host, String root,
                              int depth, java.util.ArrayDeque<String[]> queue, Set<String> seen) {
        try {
            if (rr == null || rr.response() == null) return;
            Matcher m = HREF.matcher(rr.response().bodyToString());
            while (m.find()) {
                String v = m.group(1).trim();
                if (v.isEmpty() || v.regionMatches(true, 0, "javascript:", 0, 11)
                        || v.regionMatches(true, 0, "mailto:", 0, 7) || v.regionMatches(true, 0, "data:", 0, 5)) continue;
                String abs;
                try { abs = java.net.URI.create(base).resolve(v).toString(); } catch (Exception e) { continue; }
                if (!host.equalsIgnoreCase(hostOf(abs))) continue;
                if (seen.contains("GET " + Net.stripQuery(abs))) continue;
                queue.add(new String[]{abs, String.valueOf(depth)});
            }
        } catch (Exception ignore) { }
    }

    /** Compact fingerprint (server banner + observed in-scope paths) to seed the LLM path proposal. */
    private String buildFingerprint(String host) {
        String server = null;
        java.util.LinkedHashSet<String> paths = new java.util.LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (server == null && rr.response() != null && rr.response().hasHeader("Server"))
                    server = rr.response().headerValue("Server");
                String pth = pathOnly(rr.request().url());
                if (pth != null && !pth.isBlank() && !STATIC.matcher(pth).matches() && paths.size() < 20) paths.add(pth);
            }
        } catch (Exception ignore) { }
        if (paths.isEmpty()) return "";
        StringBuilder sb = new StringBuilder("Target host: ").append(host).append('\n');
        if (server != null && !server.isBlank()) sb.append("Server: ").append(server).append('\n');
        sb.append("Observed (link-reachable) paths:\n");
        for (String p : paths) sb.append("  ").append(p).append('\n');
        return sb.toString();
    }

    private static String pathOnly(String url) {
        try { String p = java.net.URI.create(url).getPath(); return p == null ? url : p; }
        catch (Exception e) { return url; }
    }

    private static final Pattern PASS_LIKE = Pattern.compile("(?i).*(pass|pwd|clave|secret).*");
    // Numeric-looking field names. NOTE: match "quant" ANYWHERE (not suffix-only) so "quantity" counts —
    // that miss made jsonBody emit quantity as a string (unmutatable) AND body-minimization drop it, so the
    // crAPI order {quantity:-1000} mass-assignment never formed a valid 2xx baseline.
    // Numeric-looking field names: CONTAINS quant/qty (so "quantity" counts), OR ENDS with a numeric suffix.
    // The old suffix-only "quant$" missed "quantity" → jsonBody emitted it as a string (unmutatable) AND
    // body-minimization dropped it, so the crAPI order {quantity:-1000} mass-assignment never got a 2xx baseline.
    private static final Pattern NUM_KEY = Pattern.compile(
            "(?i).*(quant|qty).*|.*(id|rating|stars?|amount|price|total|number|count|score|age|year)$");

    /**
     * Discovery-depth: SPAs often don't POST every collection during a crawl, so create/update
     * endpoints never get audited. We LEARN each REST collection's schema from its own GET response
     * (the app tells us its field names) and synthesize a POST create request with plausible values.
     * Fully generic — the schema comes from the target's data, no hardcoded fields/paths. These feed
     * the audit + the NoSQL/body-mutation probes so mass-assignment/boundary/injection get exercised.
     */
    // A templated sub-resource path in client code: /rest|api/<coll>/<id-placeholder>/<sub>
    private static final Pattern TEMPLATE_PATH = Pattern.compile(
            "/(?:rest|api)/[A-Za-z][\\w-]*/(?:\\$\\{[^}/]+\\}|:[A-Za-z]\\w*|%\\w+|#\\{[^}/]+\\})/[A-Za-z][\\w-]+");
    private static final Pattern ID_VALUE = Pattern.compile("\"[A-Za-z]*[Ii]d\"\\s*:\\s*(\\d{1,7})");
    private static final Pattern PLACEHOLDER = Pattern.compile("/(?:\\$\\{[^}/]+\\}|:[A-Za-z]\\w*|%\\w+|#\\{[^}/]+\\})/");
    // An id-TERMINATED resource in client code, e.g. `rest/basket/${id}` (a per-object GET, no sub-resource
    // after the id). group(1) is the collection base ("rest/basket/"). The lookahead rejects a trailing path
    // char so `rest/basket/${id}/checkout` is left to TEMPLATE_PATH. Reaching the user's OWN object seeds IDOR.
    private static final Pattern RESOURCE_ID = Pattern.compile(
            "((?:rest|api)/[A-Za-z][\\w-]*/)(?:\\$\\{[^}/]+\\}|:[A-Za-z]\\w*|%\\w+|#\\{[^}/]+\\})(?![\\w{}$:%#/-])");

    /**
     * Resolve templated sub-resource GETs the crawl never issued: mine paths like
     * {@code /rest/products/${id}/reviews} from client code, substitute REAL ids harvested from the
     * app's own collection responses, and GET them — so their schema enters the site map and feeds
     * the write-synthesis + probes. Abstract: templates from the code, ids from the data.
     */
    private void resolveTemplatedGets(String host, String root) {
        try {
            List<String> ids = new ArrayList<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                Matcher m = ID_VALUE.matcher(rr.response().bodyToString());
                while (m.find() && ids.size() < 8) if (!ids.contains(m.group(1))) ids.add(m.group(1));
            }
            if (ids.isEmpty()) ids.add("1");
            // Scan FULL JS bundle bodies from the site map (gatherSources truncates to ~8k and would
            // miss templates deep in main.js).
            Set<String> templates = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                Matcher m = TEMPLATE_PATH.matcher(rr.response().bodyToString());
                while (m.find()) templates.add(m.group());
            }
            Set<String> done = new LinkedHashSet<>();
            for (String tpl : templates) {
                for (int i = 0; i < ids.size() && i < 3; i++) {
                    String resolved = PLACEHOLDER.matcher(tpl).replaceFirst("/" + ids.get(i) + "/");
                    if (!done.add(resolved)) continue;
                    int st = statusOf(probe(withSessionCookie(
                            HttpRequest.httpRequestFromUrl(root + resolved).withMethod("GET"))));
                    if (st >= 200 && st < 300) {
                        scanLog.log("  -> resolved sub-resource GET " + resolved + " (id=" + ids.get(i) + ")");
                        break;   // one live id per template is enough to learn the schema
                    }
                }
            }
            // Reach id-terminated resources (e.g. rest/basket/${id}) authenticated so the user's OWN object
            // lands in the site map — then IdorGetProbe pivots to a neighbor id (cross-user / IDOR). Base from
            // the app's own client code, id from its own data. No hardcoded paths.
            Set<String> resBases = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                Matcher m = RESOURCE_ID.matcher(rr.response().bodyToString());
                while (m.find()) resBases.add(m.group(1).replaceAll("^/+", ""));
            }
            for (String base : resBases) {
                for (int i = 0; i < ids.size() && i < 2; i++) {
                    String url = root + "/" + base + ids.get(i);
                    HttpRequestResponse rr = probe(authedGet(url));
                    if (statusOf(rr) >= 200 && statusOf(rr) < 300) {
                        keep(rr, host);   // bridge → IdorGetProbe enumerates a neighbor id (View Basket etc.)
                        scanLog.log("  -> reached own resource GET /" + base + ids.get(i) + " (IDOR seed)");
                        break;
                    }
                }
            }
        } catch (Exception ignore) { }
    }

    public List<HttpRequest> synthesizeWrites(String host) {
        List<HttpRequest> out = new ArrayList<>();
        try {
            String bu = baseUrlFor(host);
            if (bu != null) resolveTemplatedGets(host, bu.replaceAll("/+$", ""));
            Set<String> seen = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                HttpRequest req = rr.request();
                if (!"GET".equals(req.method()) || !host.equalsIgnoreCase(hostOf(req.url()))) continue;
                String path = Net.stripQuery(req.url());
                if (!path.matches("(?i).*/(api|rest)/[A-Za-z].*")) continue;
                List<String> keys = sampleKeys(rr.response().bodyToString());
                if (keys.isEmpty()) continue;
                String coll = path.replaceAll("/[0-9a-fA-F-]{2,}/?$", "");   // strip a trailing id segment
                if (!seen.add(coll)) continue;
                HttpRequest w = HttpRequest.httpRequestFromUrl(coll).withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(synthBody(keys));
                if (session != null && session.has()) w = w.withHeader("Cookie", session.cookieHeader());
                if (session != null && session.hasBearer()) w = w.withHeader("Authorization", "Bearer " + session.bearer());
                out.add(w);
            }
            if (!out.isEmpty())
                scanLog.log("synthesized " + out.size() + " REST write request(s) from collection schemas.");
            exerciseWrites(host);   // actively send input-validation writes that need a SENT request, not an audit point
        } catch (Throwable t) {
            scanLog.log("synthesizeWrites: " + t);
        }
        return out;
    }

    // ---- active input-validation writes (require a real SENT request, not a Burp audit insertion point) ----
    private static final Pattern RATING_KEY    = Pattern.compile("(?i).*(rating|stars?|score).*");
    private static final Pattern EMAIL_KEY     = Pattern.compile("(?i).*(e-?mail).*");
    private static final Pattern CHALLENGE_KEY = Pattern.compile("(?i)^(captcha|challenge|question|puzzle|quiz|riddle|problem)$");
    private static final Pattern ANSWER_KEY    = Pattern.compile("(?i)^(answer|solution|result)$");
    private static final Pattern IDFIELD_KEY   = Pattern.compile("(?i).+id$");
    // A REST collection root in client code, e.g. /api/Users, /rest/basket. mineSpecs truncates JS to ~8k and
    // can miss collections that live deep in a lazy chunk (Juice's /api/Users), so we mine these from the FULL
    // bundles and GET them authenticated — surfacing users-like collections for the empty-registration check.
    private static final Pattern COLLECTION_PATH = Pattern.compile("/(?:api|rest)/[A-Za-z][A-Za-z0-9_-]*");

    /**
     * Some input-validation flaws are only tripped by a REAL create request, not a Burp audit insertion point:
     * (a) a boundary rating (0) on a rating-bearing write — but if the app gates writes with a companion
     * challenge whose answer it DISCLOSES (a captcha), satisfy it FRESH; (b) an empty-credentials registration
     * on a users-like (email-bearing) collection. Fully generic: field names, the challenge, and its answer all
     * come from the app's OWN responses — no app identification, no hardcoded paths/fields.
     */
    private void exerciseWrites(String host) {
        try {
            String provider = findChallengeProvider(host);   // GET that discloses {idField, challengeField, answerField}

            // Gather candidate collections as {collectionPath -> a sample JSON body}: first from site-map GETs,
            // then from REST collection roots mined out of the FULL JS bundles and fetched AUTHENTICATED (this
            // reaches lazy-chunk endpoints like /api/Users that mineSpecs' 8k truncation misses).
            Map<String, String> colls = new LinkedHashMap<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) continue;
                HttpRequest req = rr.request();
                if (!"GET".equals(req.method()) || !host.equalsIgnoreCase(hostOf(req.url()))) continue;
                String path = Net.stripQuery(req.url());
                if (!path.matches("(?i).*/(api|rest)/[A-Za-z].*")) continue;
                int st = rr.response().statusCode();
                if (st >= 200 && st < 300) colls.putIfAbsent(path, rr.response().bodyToString());
            }
            String root = baseUrlFor(host);
            if (root != null) {
                root = root.replaceAll("/+$", "");
                Set<String> mined = new LinkedHashSet<>();
                for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                    if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                    if (!rr.request().url().toLowerCase().contains(".js")) continue;
                    Matcher m = COLLECTION_PATH.matcher(rr.response().bodyToString());
                    while (m.find() && mined.size() < 40) mined.add(m.group());
                }
                for (String c : mined) {
                    String url = root + c;
                    if (colls.containsKey(url) || colls.containsKey(url + "/")) continue;
                    HttpRequestResponse rr = probe(authedGet(url));
                    if (rr == null || rr.response() == null) continue;
                    int st = rr.response().statusCode();
                    if (st >= 200 && st < 300 && !isHtmlShell(rr)) { keep(rr, host); colls.put(url, rr.response().bodyToString()); }
                }
            }

            Set<String> done = new LinkedHashSet<>();
            for (Map.Entry<String, String> e : colls.entrySet()) {
                List<String> keys = sampleKeys(e.getValue());
                if (keys.isEmpty()) continue;
                String coll = e.getKey().replaceAll("/[0-9a-fA-F-]{2,}/?$", "");
                boolean hasRating = keys.stream().anyMatch(k -> RATING_KEY.matcher(k).matches());
                boolean hasEmail  = keys.stream().anyMatch(k -> EMAIL_KEY.matcher(k).matches());

                // (a) boundary rating (0) + a freshly-solved self-disclosed challenge  (e.g. Juice "Zero Stars")
                if (hasRating && provider != null && done.add("rate:" + coll)) {
                    JSONObject b = synthObj(keys);
                    for (String k : keys) if (RATING_KEY.matcher(k).matches()) b.put(k, 0);
                    if (attachFreshChallenge(b, provider)) sendExercise(coll, b, "boundary rating 0 + solved challenge");
                }
                // (b) empty-credentials registration — ONLY on a PLAUSIBLE registration sink (WriteGuard),
                // so we don't blind-POST to arbitrary email-bearing collections (order history, login-IP logs)
                // and emit spurious 500s. (e.g. Juice "Empty User Registration")
                if (hasEmail && done.add("empty:" + coll)) {
                    if (!WriteGuard.allowsRegistration(coll, keys)) {
                        scanLog.debug("  write-gate: skip empty-cred POST to non-registration sink " + Net.stripQuery(coll));
                        continue;
                    }
                    JSONObject b = new JSONObject();
                    for (String k : keys) if (EMAIL_KEY.matcher(k).matches()) b.put(k, "");
                    if (b.length() == 0) b.put("email", "");
                    b.put("password", "");   // canonical registration companion (schema GETs never expose it)
                    sendExercise(coll, b, "empty credentials");
                }
            }
        } catch (Throwable t) { scanLog.log("exerciseWrites: " + t); }
    }

    /** A GET whose JSON response discloses a challenge together with its answer (a self-defeating captcha). */
    private String findChallengeProvider(String host) {
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null || !"GET".equals(rr.request().method())) continue;
            if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
            int st = rr.response().statusCode(); if (st < 200 || st >= 300) continue;
            JSONObject o = asObject(rr.response().bodyToString());
            if (o == null) continue;
            boolean ch = false, ans = false;
            for (String k : o.keySet()) {
                if (CHALLENGE_KEY.matcher(k).matches()) ch = true;
                if (ANSWER_KEY.matcher(k).matches()) ans = true;
            }
            if (ch && ans) return rr.request().url();
        }
        return null;
    }

    /** Fetch the challenge provider FRESH and merge its {idField, challengeField=answerValue} into the body. */
    private boolean attachFreshChallenge(JSONObject body, String providerUrl) {
        try {
            HttpRequestResponse rr = probe(authedGet(providerUrl));
            if (rr == null || rr.response() == null) return false;
            JSONObject o = asObject(rr.response().bodyToString());
            if (o == null) return false;
            String idF = null, chF = null, ansF = null;
            for (String k : o.keySet()) {
                if (CHALLENGE_KEY.matcher(k).matches()) chF = k;
                else if (ANSWER_KEY.matcher(k).matches()) ansF = k;
                else if (IDFIELD_KEY.matcher(k).matches()) idF = k;
            }
            if (chF == null || ansF == null) return false;
            if (idF != null) body.put(idF, o.get(idF));
            body.put(chF, String.valueOf(o.get(ansF)));   // set the challenge field to the disclosed answer
            return true;
        } catch (Exception e) { return false; }
    }

    /** Build a create body (JSONObject) from learned keys, dropping server-managed fields. */
    private static JSONObject synthObj(List<String> keys) {
        JSONObject o = new JSONObject();
        for (String k : keys) {
            String lk = k.toLowerCase();
            if (lk.equals("id") || lk.contains("createdat") || lk.contains("updatedat") || lk.contains("deletedat")) continue;
            if (lk.contains("email")) o.put(k, "test@test.test");
            else if (PASS_LIKE.matcher(lk).matches()) o.put(k, "Passw0rd!");
            else if (NUM_KEY.matcher(lk).matches()) o.put(k, 1);
            else o.put(k, "test");
        }
        return o;
    }

    /** Parse a JSON body to its representative object ({data:{…}} / {…}); null if not an object. */
    private static JSONObject asObject(String body) {
        try {
            String t = body == null ? "" : body.trim();
            if (t.startsWith("{")) {
                JSONObject o = new JSONObject(t);
                Object d = o.has("data") ? o.get("data") : o;
                if (d instanceof JSONObject) return (JSONObject) d;
                return o;
            }
        } catch (Exception ignore) { }
        return null;
    }

    /** Send one authenticated create and log the outcome (state-changing by design; no AuditIssue raised).
     *  Risk-tiered (WriteGuard): only WRITE-tier exercises are sent unattended — never a DESTRUCTIVE method. */
    private void sendExercise(String coll, JSONObject body, String what) {
        try {
            if (!WriteGuard.allowsUnattended("POST")) return;   // defensive: never blind-send a DESTRUCTIVE tier
            HttpRequest w = withSessionCookie(HttpRequest.httpRequestFromUrl(coll).withMethod("POST")
                    .withAddedHeader("Content-Type", "application/json").withBody(body.toString()));
            int st = statusOf(probe(w));
            scanLog.log("  exercise write [WRITE-tier] [" + what + "] POST " + Net.stripQuery(coll) + " -> HTTP " + st);
        } catch (Exception ignore) { }
    }

    /** Field names from a sample record in a JSON collection response ({data:[{...}]} / [{...}] / {...}). */
    private static List<String> sampleKeys(String body) {
        List<String> keys = new ArrayList<>();
        try {
            String t = body == null ? "" : body.trim();
            JSONObject sample = null;
            if (t.startsWith("{")) {
                JSONObject o = new JSONObject(t);
                Object d = o.has("data") ? o.get("data") : o;
                if (d instanceof JSONArray && ((JSONArray) d).length() > 0 && ((JSONArray) d).opt(0) instanceof JSONObject)
                    sample = ((JSONArray) d).getJSONObject(0);
                else if (d instanceof JSONObject) sample = (JSONObject) d;
            } else if (t.startsWith("[")) {
                JSONArray a = new JSONArray(t);
                if (a.length() > 0 && a.opt(0) instanceof JSONObject) sample = a.getJSONObject(0);
            }
            if (sample != null) keys.addAll(sample.keySet());
        } catch (Exception ignore) { }
        return keys;
    }

    /** Build a create body from learned keys, guessing value types (server-managed fields dropped). */
    private static String synthBody(List<String> keys) {
        StringBuilder sb = new StringBuilder("{");
        int n = 0;
        for (String k : keys) {
            String lk = k.toLowerCase();
            if (lk.equals("id") || lk.contains("createdat") || lk.contains("updatedat") || lk.contains("deletedat")) continue;
            String v = lk.contains("email") ? "\"test@test.test\""
                    : PASS_LIKE.matcher(lk).matches() ? "\"Passw0rd!\""
                    : NUM_KEY.matcher(lk).matches() ? "1"
                    : "\"test\"";
            if (n++ > 0) sb.append(',');
            sb.append('"').append(k).append("\":").append(v);
        }
        return sb.append('}').toString();
    }
    // A REST/API path fragment as it appears in a bundle (even inside a `${base}/rest/...` template literal).
    // Match /rest|/api paths AND relative ones (headJS/ajax often reference "rest/UserAccess/…" with no leading
    // slash), but the lookbehind stops it firing inside a word (e.g. "forest/…"). Normalized to a leading slash below.
    private static final Pattern REST_PATH = Pattern.compile("(?<![A-Za-z0-9_])/?(?:rest|api)/[A-Za-z0-9_./-]+");
    // A base fragment an SPA appends an auth verb to at runtime (this.host = ".../rest/user"; post(host+"/login")).
    private static final Pattern AUTH_BASE = Pattern.compile("(?i).*/(users?|accounts?|auth|identity|session|customers?|members?)$");
    private static final Pattern AUTH_LEAF = Pattern.compile("(?i).*/(login|signin|sign-in|logon|authenticate|authentication|session|token)$");
    private static final String[] AUTH_VERBS = {"login", "signin", "authenticate", "session", "token"};
    // A service-base literal an SPA prepends to endpoint leaves at runtime: a single path segment ending
    // in "/", stored on its own (crAPI: og="identity/", ig="workshop/"). The whole quoted string must BE
    // the segment (so "text/html" etc. don't match).
    private static final Pattern SERVICE_BASE = Pattern.compile("[\"']([a-z][a-z0-9_-]{1,30}/)[\"']");
    // A relative auth-endpoint leaf literal (crAPI: "api/auth/login"), which URLISH/REST_PATH miss because
    // it has no leading slash. Kept generic: any path-ish literal ending in an auth verb.
    private static final Pattern AUTH_LEAF_LITERAL = Pattern.compile(
            "[\"'](/?[a-z0-9][a-z0-9/_.-]{0,60}?(?:login|signin|sign-in|logon|authenticate|signup|sign-up|register))[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * Find login/auth POST endpoints WITHOUT manual browsing or brute force. Two sources:
     *   1) LLM-mined POST specs that already carry a credential field;
     *   2) DERIVED endpoints — SPAs assemble the login URL at runtime
     *      ({@code this.host = ".../rest/user"; login → post(host + "/login")}), so the full path is
     *      never a literal. We collect {@code /rest|/api} fragments (mined + raw JS), join each auth-base
     *      fragment with auth verbs, keep auth-leaf paths, and PROBE each — keeping the ones that behave
     *      like an auth endpoint (accept the POST, or reject the creds with 400/401/403).
     * Returned pre-auth so the pipeline can authenticate and seed the auth-page audit. Fully abstract.
     */
    public List<HttpRequest> discoverAuthRequests(String host) {
        List<HttpRequest> out = new ArrayList<>();
        try {
            String baseUrl = baseUrlFor(host);
            if (baseUrl == null) return out;
            Set<String> seen = new LinkedHashSet<>();
            Set<String> specs = mineSpecs(host);

            // (1) mined POST specs that already carry a credential field
            for (String spec : specs) {
                String[] p = spec.split(SEP, -1);
                if (p.length < 3 || !"POST".equals(p[0].trim()) || !hasPasswordLike(p[2])) continue;
                for (HttpRequest req : buildVariants(spec, baseUrl)) addAuthCandidate(out, seen, req, host);
            }

            // (2) derive auth endpoints from base fragments + auth verbs, then probe
            Set<String> paths = new LinkedHashSet<>();
            for (String spec : specs) {
                String[] p = spec.split(SEP, -1);
                if (p.length > 1 && !p[1].isBlank()) paths.add(p[1].trim());
            }
            for (String[] src : gatherSources(host)) {
                Matcher m = REST_PATH.matcher(src[1]);
                while (m.find()) { String p = m.group(); paths.add(p.startsWith("/") ? p : "/" + p); }
            }
            Set<String> derived = new LinkedHashSet<>();
            // SIBLING DERIVATION (first, so it's probed within budget): /login|/signin are siblings of ANY /api/
            // endpoint already in the site map (e.g. /api/v1/merchant/me → /api/v1/merchant/login). The site map
            // reliably holds SOME API endpoint even when the login path is assembled from base+leaf (not a single
            // JS literal) — this removes the run-to-run variance where the login endpoint was found only sometimes.
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                String p;
                try { p = URI.create(rr.request().url()).getPath(); } catch (Exception e) { continue; }
                if (p == null || !p.contains("/api/")) continue;
                p = p.replaceAll("/+$", "");
                int slash = p.lastIndexOf('/');
                if (slash <= 0) continue;
                String base = p.substring(0, slash + 1);        // parent path, e.g. /api/v1/merchant/
                for (String v : AUTH_VERBS) derived.add(base + v);
            }
            for (String raw : paths) {
                String path = raw.split("\\?")[0].replaceAll("/+$", "");
                if (path.isEmpty()) continue;
                if (AUTH_LEAF.matcher(path).matches()) derived.add(path);
                if (AUTH_BASE.matcher(path).matches()) for (String v : AUTH_VERBS) derived.add(path + "/" + v);
            }
            // (3) ASSEMBLY: SPAs store the service base ("identity/") and the endpoint leaf
            // ("api/auth/login") as SEPARATE literals and concatenate them at runtime, so the full
            // path is never a single literal. Mine both from FULL JS bodies (gatherSources truncates)
            // and cross-join base × leaf. The app's OWN strings — no hardcoded service names.
            Set<String> bases = new LinkedHashSet<>();
            Set<String> leaves = new LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                if (!rr.request().url().toLowerCase().contains(".js")) continue;
                String body = rr.response().bodyToString();
                Matcher mb = SERVICE_BASE.matcher(body);
                while (mb.find() && bases.size() < 12) bases.add(mb.group(1));
                Matcher ml = AUTH_LEAF_LITERAL.matcher(body);
                while (ml.find() && leaves.size() < 12) leaves.add(ml.group(1));
            }
            for (String leaf : leaves) {
                String l = leaf.startsWith("/") ? leaf.substring(1) : leaf;
                derived.add(l);                                  // leaf as-is (root-mounted APIs)
                for (String b : bases) derived.add(b + l);       // base + leaf (prefix-mounted SPAs)
            }

            int probed = 0;
            for (String c : derived) {
                if (probed >= 48) break;
                String abs;
                try {
                    abs = c.startsWith("http") ? c
                            : URI.create(baseUrl).resolve(c.startsWith("/") ? c.substring(1) : c).toString();
                } catch (Exception e) { continue; }
                if (!host.equalsIgnoreCase(hostOf(abs))) continue;
                if (!seen.add("POST " + Net.stripQuery(abs) + " json")) continue;
                HttpRequest req = withSessionCookie(HttpRequest.httpRequestFromUrl(abs).withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody("{\"email\":\"1\",\"password\":\"1\"}"));
                probed++;
                int st = statusOf(probe(req));
                boolean exists = st == 200 || st == 201 || st == 204 || (st >= 300 && st < 400)
                        || st == 400 || st == 401 || st == 403 || st == 422;
                if (exists) {
                    out.add(req);
                    scanLog.log("derived auth endpoint: POST " + Net.stripQuery(abs) + " → HTTP " + st);
                }
            }
            StringBuilder us = new StringBuilder();
            java.util.LinkedHashSet<String> uu = new java.util.LinkedHashSet<>();
            for (HttpRequest r : out) uu.add(Net.stripQuery(r.url()));
            for (String u : uu) { if (us.length() > 0) us.append(", "); us.append(u); if (us.length() > 400) { us.append("…"); break; } }
            scanLog.log("auth discovery: " + out.size() + " candidate login request(s)"
                    + (uu.isEmpty() ? "." : ": " + us));
        } catch (Throwable t) {
            scanLog.log("auth discovery failed: " + t);
        }
        return out;
    }

    // An auth verb in the path (login/register/…). // and a clearly POST-AUTH / profile / change-password path.
    private static final Pattern AUTH_VERB_PATH = Pattern.compile(
            "(?i).*(log-?in|sign-?in|authenticate|/auth\\b|register|sign-?up|/session|/token|users?/create|account/create).*");
    private static final Pattern POST_AUTH_PATH = Pattern.compile(
            "(?i).*(useredit|user-edit|profile|/account|settings|preferences|change-?pass|update-?pass|/edit|myaccount|dashboard).*");

    private void addAuthCandidate(List<HttpRequest> out, Set<String> seen, HttpRequest req, String host) {
        if (req == null || !host.equalsIgnoreCase(hostOf(req.url()))) return;
        // A change-password / profile form (password + confirm) looks like a register form but is NOT an auth
        // endpoint — it needs an existing session, so registering/logging-in against it just wastes the whole
        // battery (DVNA /app/useredit was hammered as a login/register candidate). Skip clearly post-auth paths
        // unless the path ALSO carries an auth verb. Generic path heuristic, no app-specific names.
        String path; try { path = java.net.URI.create(req.url()).getPath(); } catch (Exception e) { path = req.url(); }
        if (path != null && POST_AUTH_PATH.matcher(path).matches() && !AUTH_VERB_PATH.matcher(path).matches()) return;
        String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
        String kind = ct != null && ct.toLowerCase().contains("json") ? "json" : "form";
        if (seen.add(req.method() + " " + Net.stripQuery(req.url()) + " " + kind)) out.add(req);
    }

    private static boolean hasPasswordLike(String params) {
        for (String p : params.split(",")) if (PASS_LIKE.matcher(p.trim()).matches()) return true;
        return false;
    }

    // ---- candidate extraction ----

    private int regexCandidates(String code, Set<String> out) {
        int n = 0;
        Matcher m = URLISH.matcher(code);
        while (m.find() && out.size() < 400) {
            String p = m.group(1);
            if (p == null || p.isBlank() || STATIC.matcher(p).matches()) continue;
            if (!looksLikeEndpoint(p)) continue;
            if (out.add("GET" + SEP + p + SEP)) n++;
        }
        // Concatenated URLs: JS commonly builds a page URL by string concat — e.g. Zero Bank does
        //   window.location.href = path + "login" + ".html";
        // The literal "/login.html" never appears, so URLISH (and the whole HTTP crawl that relies on static links)
        // misses it → the app is unreachable. Collapse adjacent string-literal concatenations ("a" + "b" → "ab"),
        // then recover any page-ish leaf that results (login.html → /login.html). Generic, deterministic (no LLM).
        String merged = code.replaceAll("[\"'`]\\s*\\+\\s*[\"'`]", "");
        Matcher cm = CONCAT_PAGE.matcher(merged);
        while (cm.find() && out.size() < 400) {
            String leaf = cm.group(1).trim();
            if (leaf.isBlank() || STATIC.matcher(leaf).matches()) continue;
            String path = leaf.startsWith("/") ? leaf : "/" + leaf;
            if (out.add("GET" + SEP + path + SEP)) n++;
        }
        return n;
    }

    // Deterministic FULL-BODY API-path harvest. The 8k per-source truncation + 8-chunk LLM cap can drop
    // endpoints that live deep in a large minified bundle (this is exactly how /api/v1/agents/*,
    // /api/v1/kb/* and /api/v1/merchant/chat/* were being missed). Scan EVERY same-host script body
    // UNTRUNCATED for absolute /api/vN/ path literals — they're exact strings, so this needs no LLM and
    // yields no false positives — and register each as a spec to probe. Dynamic id segments (${id}, :id)
    // simply end the match, leaving the collection root, which is what we want to hit anyway.
    // Generic API-endpoint path literal (NOT app-specific): an absolute path rooted at a universal API
    // convention — /api/…, /rest/…, /graphql, or a bare version prefix /vN/…. Matches the exact string the
    // app itself ships, so it never invents a route. A dynamic segment (${id}, :id, backtick) ends the match,
    // leaving the collection root. Every hit is LIVE-PROBED downstream and dropped if it 404s or returns the
    // SPA's HTML shell (isHtmlShell oracle) — so extracting broadly here cannot create a false positive.
    // The /api|/rest branch also matches RELATIVE refs ("rest/UserAccess/RequestAccess" with no leading slash —
    // how headJS/ajax bundles like ASP.NET page.*.js reference their own API), normalized to a leading slash in the
    // loop below. The lookbehind stops it firing mid-word (e.g. "forest/…"). /vN and /graphql stay absolute-only.
    private static final Pattern API_PATH_LITERAL = Pattern.compile(
            "(?<![A-Za-z0-9_])/?(?:api|rest)/[A-Za-z0-9_./-]*|/v[0-9]+/[A-Za-z0-9_./-]+|/graphql\\b");
    // SPAs also declare their API surface in "endpoints objects" as QUOTED absolute-path VALUES that don't
    // carry an /api prefix (e.g. businessDetails:"/application/forms/submit/", create:"/transfers/"). Harvesting
    // only /api/… misses that whole business surface. So ALSO take quoted absolute paths that end in a slash
    // (the app's REST convention) with ≥2 lowercase-ish segments — the endpoint-map values, generically. Every
    // hit is live-probed and 404/HTML-shell-filtered downstream, so a non-endpoint literal can't become an FP.
    private static final Pattern ENDPOINT_MAP_LITERAL = Pattern.compile(
            "[\"'`](/[a-z][a-z0-9_-]{1,40}(?:/[a-z0-9][a-z0-9_-]{0,40})+/)[\"'`]");
    // Obvious non-endpoint absolute paths to keep out of the endpoint-map harvest (asset/build dirs, i18n).
    private static final Pattern SKIP_HARVEST = Pattern.compile(
            "(?i)^/(?:_next|static|assets?|images?|img|fonts?|media|locales?|i18n|css|js|public|favicon)(/|$).*");
    private int harvestApiPaths(String host, Set<String> out) {
        int n = 0, scripts = 0;
        java.util.TreeSet<String> found = new java.util.TreeSet<>();   // sorted, for a legible coverage dump
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null) continue;
            String url = rr.request().url();
            if (!host.equalsIgnoreCase(hostOf(url)) || !url.toLowerCase().contains(".js")) continue;
            String body = rr.response().bodyToString();
            if (body == null) continue;
            scripts++;
            Matcher m = API_PATH_LITERAL.matcher(body);
            while (m.find() && out.size() < 500) {
                String p = m.group();
                if (!p.startsWith("/")) p = "/" + p;   // relative "rest/…" ref (headJS/ajax bundle) → absolute
                // Trim a trailing partial segment / stray separators; require a real path (a segment after root).
                while (p.length() > 1 && (p.endsWith(".") || p.endsWith("-") || p.endsWith("_"))) p = p.substring(0, p.length() - 1);
                if (p.length() < 6 || STATIC.matcher(p).matches()) continue;   // skip trivial / static-asset paths
                if (p.chars().filter(c -> c == '/').count() < 2) continue;     // need root + at least one segment
                if (out.add("GET" + SEP + p + SEP)) { n++; found.add(p); }
            }
            // endpoint-map absolute-path values (business surface without an /api prefix)
            Matcher em = ENDPOINT_MAP_LITERAL.matcher(body);
            while (em.find() && out.size() < 500) {
                String p = em.group(1);
                if (STATIC.matcher(p).matches() || SKIP_HARVEST.matcher(p).matches()) continue;
                if (out.add("GET" + SEP + p + SEP)) { n++; found.add(p); }
            }
        }
        // Debug: the exact, deterministic API surface extracted from the app's own JS — check it against the
        // bundles to confirm nothing was left undiscovered. Runs every discovery pass (grows as more auth
        // scripts enter the site map).
        // Name the harvested paths inline (bounded) so a run shows WHICH API surface was extracted — the /rest/…
        // page-method endpoints (e.g. RequestAccess) are exactly what the downstream verbose-error/SQLi probes need.
        StringBuilder fs = new StringBuilder();
        for (String p : found) { if (fs.length() > 0) fs.append(", "); fs.append(p); if (fs.length() > 500) { fs.append("…"); break; } }
        scanLog.log("full-body API harvest: scanned " + scripts + " script(s), "
                + n + " new distinct API path(s)" + (found.isEmpty() ? "." : ": " + fs));
        for (String p : found) scanLog.debug("  harvested endpoint: " + p);
        return n;
    }

    // A JSON `"key":"value"` STRING field — the injectable shape BlindSqliProbe/BodyMutator fuzz. A synthesized
    // body carrying one is a usable SQLi/fuzz target even if the write itself keeps erroring.
    private static final Pattern HAS_JSON_STR_FIELD = Pattern.compile("\"[^\"]+\"\\s*:\\s*\"[^\"]*\"");

    /**
     * Reconstruct a VALID POST body for a discovered endpoint that a bodyless probe can't reach, using the
     * server's own validation errors (the generic form of signup's fillRegistration). Bounded LLM-driven fill
     * loop; each attempt is live-probed. Returns the request that resolved to 2xx (and bridges it to the site
     * map for the write-aware probes); failing a 2xx, returns the best-effort synthesized POST if it carries an
     * injectable JSON field (so the SQLi/fuzz oracles can still reach a write that only ever errors); else null.
     * Gated: only API-ish paths, only non-destructive methods.
     */
    private HttpRequest resolveWriteBody(String abs, String host, int getStatus) {
        try {
            AiEngine eng = engine != null ? engine.get() : null;
            if (eng == null || !eng.isConfigured()) return null;
            // Gate: any non-static same-host endpoint (these come from the app's OWN endpoint maps, so a bare
            // /application/forms/submit/ or /transfers/quote/ is as real as an /api/… one). NOT restricted to
            // API_ISH — that missed the whole business surface. Safe: WriteGuard blocks destructive methods, the
            // loop branches on the REAL status, and a non-fillable route just stops after one probe.
            if (STATIC.matcher(abs).matches() || abs.toLowerCase().contains(".js")) return null;
            if (!com.ioactive.aiscanner.scan.WriteGuard.allowsUnattended("POST")) return null;
            // Work on the REAL status of each probe, no assumptions. RequestSigner slash-normalizes the path
            // (proven: the server validates the signature over the trailing-slash path), so a single URL suffices
            // — no per-slash variants, and no duplicate writes. POST and branch on the ACTUAL response status.
            String path; try { path = URI.create(abs).getPath(); } catch (Exception e) { path = abs; }
            String body = "{}";
            HttpRequest bestSynth = null;   // best-effort filled POST to hand the fuzzers even if the write never 2xx-es
            for (int i = 0; i < 4; i++) {
                HttpRequest post = withSessionCookie(HttpRequest.httpRequestFromUrl(abs).withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json").withBody(body));
                HttpRequestResponse rr = probe(post);
                int st = statusOf(rr);
                String vb = rr != null && rr.response() != null ? rr.response().bodyToString() : null;
                scanLog.debug("  write-body POST " + path + " step " + i + " → HTTP " + st
                        + "  " + trunc(vb == null ? "" : vb.replaceAll("\\s+", " "), 140));
                if (st >= 200 && st < 300) {
                    keep(rr, host);   // bridge for IdorGet/Bfla/ChainReplay/BodyMutator
                    scanLog.log("  -> LIVE " + st + "  POST " + Net.stripQuery(abs)
                            + "  [body reconstructed from server validation in " + i + " step(s)]");
                    return post;
                }
                // Fillable validation error → let the model complete the body from the server's own errors.
                // Include 500: an ASP.NET Web-API write endpoint with customErrors Off returns its column/field
                // errors as a 500 XML <Error> doc ("Cannot insert the value NULL into column 'email'"), NOT a
                // 400/JSON — so learn from `<`-structured error bodies too, not just `{`. This is exactly the
                // RequestAccess case: {} → 500 naming 'email', which the model turns into {"email":…}.
                if (st == 400 || st == 422 || st == 409 || st == 415 || st == 500) {
                    if (vb == null || (!vb.contains("{") && !vb.contains("<"))) break;   // no structured errors to learn from
                    String filled = eng.completeRequestBody("POST", path, body, vb);
                    if (filled == null || filled.isBlank() || filled.equals(body)) break;   // no progress
                    body = filled;
                    // A body that now carries a JSON string field is an injectable SQLi/fuzz target even if the
                    // write keeps erroring on a later column — a quote still reaches the SQL string sink. Remember it.
                    if (HAS_JSON_STR_FIELD.matcher(body).find())
                        bestSynth = withSessionCookie(HttpRequest.httpRequestFromUrl(abs).withMethod("POST")
                                .withAddedHeader("Content-Type", "application/json").withBody(body));
                    continue;
                }
                break;   // 404/405 (wrong method)/403 (authz) → not fillable; stop
            }
            // No 2xx, but we synthesized a body with an injectable field: hand THAT to the targets-iterating probes
            // (BlindSqli/BodyMutator/NoSql). A write that 500s on a NULL column still reaches the SQL string, so the
            // error-based SQLi oracle can fire on it — the RequestAccess SQLi a bodyless probe can never reach.
            if (bestSynth != null) {
                scanLog.debug("  write-body: no 2xx for " + path
                        + " — feeding best-effort synthesized POST (JSON field present) to the fuzzers.");
                return bestSynth;
            }
        } catch (Throwable t) { scanLog.debug("  write-body resolve error: " + t); }
        return null;
    }

    /**
     * A bare endpoint-map leaf (e.g. {@code /financing/eligibility/}) is mounted under the app's API BASE
     * ({@code /api/v1/merchant}), not the web root — so probing it bare hits the SPA HTML shell (a false 2xx).
     * Re-probe the leaf under each observed API base and keep the one that returns real (non-shell) JSON.
     * Generic: bases are the {@code /api/vN/<seg>} prefixes of paths already seen returning JSON, no hardcoding.
     */
    private HttpRequest resolveUnderApiBase(String leafUrl, String host, List<HttpRequest> live) {
        try {
            String leaf; try { leaf = URI.create(leafUrl).getPath(); } catch (Exception e) { return null; }
            if (leaf == null || leaf.startsWith("/api/") || leaf.startsWith("/rest/")) return null;   // already based
            for (String base : apiBases(host)) {
                String candidate;
                try { candidate = URI.create(baseUrlFor(host)).resolve(base + leaf).toString(); }
                catch (Exception e) { continue; }
                HttpRequest get = withSessionCookie(HttpRequest.httpRequestFromUrl(candidate).withMethod("GET"));
                HttpRequestResponse rr = probe(get);
                int st = statusOf(rr);
                if (st >= 200 && st < 300 && !isHtmlShell(rr)) {
                    keep(rr, host);
                    scanLog.log("  -> LIVE " + st + "  GET " + Net.stripQuery(candidate) + "  [resolved under API base " + base + "]");
                    return get;
                }
                if (st == 405 || st == 400 || st == 422) {   // real route, needs POST/body → reconstruct
                    HttpRequest w = resolveWriteBody(candidate, host, st);
                    if (w != null) { live.add(w); return null; }
                }
            }
        } catch (Throwable t) { scanLog.debug("  base-resolve error: " + t); }
        return null;
    }

    /** API base prefixes (/api/vN/<seg>) observed returning JSON on this host — the mount points to cross-join
     *  bare endpoint-map leaves against. Generic: derived from real traffic, not hardcoded. */
    private java.util.LinkedHashSet<String> apiBases(String host) {
        java.util.LinkedHashSet<String> bases = new java.util.LinkedHashSet<>();
        Pattern seg = Pattern.compile("^(/api/v[0-9]+/[a-z0-9_-]+)(/|$)", Pattern.CASE_INSENSITIVE);
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
            int st = rr.response().statusCode();
            if (st < 200 || st >= 500 || isHtmlShell(rr)) continue;      // a real API response (JSON/4xx), not the shell
            String ct = rr.response().headerValue("Content-Type");
            boolean jsonish = (ct != null && ct.toLowerCase().contains("json")) || st == 401 || st == 403 || st == 405;
            if (!jsonish) continue;
            String path; try { path = URI.create(rr.request().url()).getPath(); } catch (Exception e) { continue; }
            Matcher m = seg.matcher(path == null ? "" : path);
            if (m.find()) bases.add(m.group(1));
        }
        return bases;
    }

    private int llmCandidates(AiEngine eng, String code, Set<String> out) {
        int n = 0;
        try {
            String json = eng.extractEndpointsJson(trunc(code, CHUNK_CHARS + PER_SOURCE_CHARS));
            if (json == null || json.isBlank()) return 0;
            JSONArray arr = new JSONArray(json);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o == null) continue;
                // SCHEMA-TOLERANT: at temp>0 the model often drifts from our {method,path,params} shape and names
                // the path "endpoint" or "url" (verified via TRACE — those replies were silently parsed to 0). Accept
                // the common aliases and normalize a full URL down to its path. Hallucinated externals (example.com,
                // a wrong host) still get filtered downstream by live-probing, so tolerance costs coverage nothing.
                String path = firstNonBlank(o.optString("path", ""), o.optString("endpoint", ""),
                        o.optString("url", ""), o.optString("route", ""), o.optString("uri", ""));
                path = normalizePath(path);
                if (path.isBlank() || STATIC.matcher(path).matches()) continue;
                String method = o.optString("method", o.optString("verb", "GET")).trim().toUpperCase();
                if (!method.equals("GET") && !method.equals("POST")) method = "GET";
                StringBuilder ps = new StringBuilder();
                // params can be a "params" array OR the keys of a "data"/"body"/"params" object (also seen at temp>0).
                JSONArray pj = o.optJSONArray("params");
                if (pj != null) {
                    for (int k = 0; k < pj.length(); k++) {
                        String pn = pj.optString(k, "").trim();
                        if (!pn.isBlank()) { if (ps.length() > 0) ps.append(','); ps.append(pn); }
                    }
                } else {
                    JSONObject pobj = o.optJSONObject("data");
                    if (pobj == null) pobj = o.optJSONObject("body");
                    if (pobj == null) pobj = o.optJSONObject("params");
                    if (pobj != null) for (String k : pobj.keySet()) {
                        if (!k.isBlank()) { if (ps.length() > 0) ps.append(','); ps.append(k); }
                    }
                }
                out.add(method + SEP + path + SEP + ps);   // dedup into the union set
                n++;                                       // count EVERY valid parsed entry (RAW, pre-dedup)
            }
        } catch (Exception ignore) { }
        return n;
    }

    static String firstNonBlank(String... vs) {
        if (vs != null) for (String v : vs) if (v != null && !v.trim().isEmpty()) return v.trim();
        return "";
    }

    /** Normalize a candidate path value into a server path: a full URL → its path; a bare "foo/bar" → "/foo/bar";
     *  placeholders with no '/' ("endpoint1") or host-only URLs ("http://target-http-address") → "" (rejected). */
    static String normalizePath(String v) {
        if (v == null) return "";
        v = v.trim();
        if (v.isEmpty()) return "";
        if (v.matches("(?i)^https?://.*")) {                    // full URL → path only (external host filtered by probing)
            try { String p = java.net.URI.create(v).getRawPath(); return p == null ? "" : p.trim(); }
            catch (Exception e) {
                int s = v.indexOf('/', v.indexOf("://") + 3);
                return s >= 0 ? v.substring(s).trim() : "";
            }
        }
        if (!v.contains("/")) return "";                        // "endpoint1" / "intercept-request" placeholder → reject
        return v.startsWith("/") ? v : "/" + v;
    }

    private static boolean looksLikeEndpoint(String p) {
        if (p.length() < 2) return false;
        int q = p.indexOf('?');
        String bare = q < 0 ? p : p.substring(0, q);
        boolean dynExt = bare.matches("(?i).*\\.(html|json|do|action|php|jsp|aspx?|api)$");
        boolean hasQuery = q >= 0;
        boolean hasSegment = bare.chars().filter(c -> c == '/').count() >= 1 && bare.length() > 3;
        return dynExt || hasQuery || hasSegment;
    }

    // ---- request building + probing ----

    // API-ish paths tend to consume JSON: /api/… /rest/… /graphql /v1/… or a .json endpoint.
    private static final Pattern API_ISH = Pattern.compile(
            "(?i).*/(api|rest|graphql|gql|v\\d+|services?)(/.*)?$|.*\\.json($|\\?).*");

    /**
     * Build the candidate request(s) to probe for a spec. GET → one URL-param request. POST → a
     * form-encoded variant plus, when the params are non-empty, a JSON-body variant; the JSON one is
     * tried FIRST on API-ish paths (most likely to be accepted) so we keep the shape the server wants.
     */
    private List<HttpRequest> buildVariants(String spec, String baseUrl) {
        List<HttpRequest> out = new ArrayList<>();
        try {
            String[] parts = spec.split(SEP, -1);
            String method = parts[0].trim();
            String path = parts.length > 1 ? parts[1].trim() : "";
            String params = parts.length > 2 ? parts[2].trim() : "";
            if (path.isEmpty()) return out;
            String abs = path.startsWith("http") ? path : URI.create(baseUrl).resolve(path).toString();

            if (!"POST".equals(method)) {
                HttpRequest get = HttpRequest.httpRequestFromUrl(abs).withMethod(method);
                get = addParams(get, params, HttpParameterType.URL, baseUrl);
                out.add(withSessionCookie(get));
                return out;
            }

            List<String> ps = paramList(params);
            HttpRequest form = HttpRequest.httpRequestFromUrl(abs).withMethod("POST")
                    .withAddedHeader("Content-Type", "application/x-www-form-urlencoded");
            form = addParams(form, params, HttpParameterType.BODY, baseUrl);
            HttpRequest json = ps.isEmpty() ? null : withSessionCookie(
                    HttpRequest.httpRequestFromUrl(abs).withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(jsonBody(ps)));
            form = withSessionCookie(form);

            if (json != null && API_ISH.matcher(abs).matches()) { out.add(json); out.add(form); }
            else if (json != null) { out.add(form); out.add(json); }
            else out.add(form);
        } catch (Exception ignore) { }
        return out;
    }

    // A parameter whose value is fetched/opened as a URL (SSRF surface). Seeding it with "1" makes the server's
    // http.Get("1") fail (502) so the endpoint is dropped as dead; a VALID absolute URL keeps it live so it
    // reaches the audit surface (and any OAST SSRF check). Generic by name, no app-specifics.
    // Package-private: also reused by SsrfProbe (single source of truth for the url-like-param heuristic).
    static final Pattern URL_PARAM = Pattern.compile(
            "(?i)^(url|uri|link|href|src|dest|destination|target|redirect|redirect_?uri|return|return_?url|"
            + "next|callback|webhook|feed|proxy|fetch|load|resource|endpoint|remote|host|site|image_?url|img)$");

    private String addParamSeed(String name, String baseUrl) {
        return (baseUrl != null && URL_PARAM.matcher(name).matches()) ? baseUrl : READ_SEED;
    }

    private HttpRequest addParams(HttpRequest req, String params, HttpParameterType type, String baseUrl) {
        for (String pn : params.split(",")) {
            pn = pn.trim();
            if (!pn.isEmpty()) req = req.withAddedParameters(HttpParameter.parameter(pn, addParamSeed(pn, baseUrl), type));
        }
        return req;
    }

    private HttpRequest withSessionCookie(HttpRequest req) {
        if (session != null && session.has()) req = req.withHeader("Cookie", session.cookieHeader());
        // Carry the bearer too — JWT/SPA apps (e.g. Juice) gate /rest/* behind Authorization, not a cookie,
        // so cookie-only probes 401 and never reach the authenticated surface (auth-details, basket, …).
        if (session != null && session.hasBearer()) req = req.withHeader("Authorization", "Bearer " + session.bearer());
        // Sign if the app is signature-gated (key captured at auth) — reaches /me/ + merchant data endpoints
        // that a bearer alone can't. Signing covers method/path/body only, so a later header add is harmless.
        if (session != null && session.hasSigningKey())
            req = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKey()).sign(req);
        return req;
    }

    private static List<String> paramList(String params) {
        List<String> out = new ArrayList<>();
        for (String pn : params.split(",")) { pn = pn.trim(); if (!pn.isEmpty()) out.add(pn); }
        return out;
    }

    /** {"p1":"1","p2":"1"} — a seeded JSON body so JSON insertion points have a non-empty value. */
    private static String jsonBody(List<String> params) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < params.size(); i++) {
            if (i > 0) sb.append(',');
            String p = params.get(i);
            sb.append('"').append(p.replace("\"", "\\\"")).append("\":");
            // Numeric-looking fields (product_id, quantity, amount, price, …) → a JSON NUMBER, not a string.
            // Two reasons: (1) a real product_id:1 yields a valid 2xx baseline (needed for the mass-assignment
            // oracle); (2) BodyMutatorProbe's numeric boundary mutation matches `"key":<number>` only — a quoted
            // "1" is never mutated, so crAPI's {quantity:-1000}→credit-grows mass-assignment would be missed.
            sb.append(NUM_KEY.matcher(p.toLowerCase()).matches() ? "1" : "\"1\"");
        }
        return sb.append('}').toString();
    }

    /** Rank probe statuses so we keep the most "accepted" variant: 2xx &gt; 3xx &gt; 4xx &gt; 5xx/none. */
    private static int liveRank(int st) {
        if (st >= 200 && st < 300) return 4;
        if (st >= 300 && st < 400) return 3;
        if (st >= 400 && st < 500) return 2;
        if (st >= 500) return 1;
        return 0;
    }

    private HttpRequestResponse probe(HttpRequest req) {
        try {
            HttpRequestResponse rr = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
            rr = AiScanner.decompress(rr);   // plain-text body so HTML/JS mining works behind a compressing proxy/CDN
            // Register DISCOVERED endpoints into the Target site map so they're visible for manual follow-up.
            // A non-404 response means the route actually exists (200/401/403/405/…); a 404 is a guess miss and
            // is left out so the map isn't flooded with negative probes. Signed requests register with their
            // X-Signature headers intact. sendRequest() does NOT auto-add to the site map — this is the hook.
            try {
                if (rr != null && rr.response() != null && rr.response().statusCode() != 404)
                    api.siteMap().add(rr);
            } catch (Exception ignore) { }
            return rr;
        } catch (Throwable t) {
            return null;
        }
    }

    // ---- collecting client code ----

    /** Returns "scheme://host[:port]/" for the host from any site-map entry, or null. */
    private String baseUrlFor(String host) {
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String url = rr.request().url();
            if (host.equalsIgnoreCase(hostOf(url))) {
                try {
                    URI u = URI.create(url);
                    String b = u.getScheme() + "://" + u.getHost();
                    if (u.getPort() != -1) b += ":" + u.getPort();
                    return b + "/";
                } catch (Exception ignore) { }
            }
        }
        return null;
    }

    /**
     * Gather the host's APP client-side sources (one entry per page/script: {url, body}), skipping
     * third-party libraries. Deeper/authenticated HTML pages (e.g. {@code /bank/account-activity.html})
     * are ordered FIRST so they get mined even if we hit the source/LLM-call caps — that's exactly
     * where the interesting authenticated AJAX endpoints live.
     */
    private List<String[]> gatherSources(String host) {
        List<String[]> html = new ArrayList<>();
        List<String[]> js = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        Set<String> scriptRefs = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null) continue;
            String url = rr.request().url();
            if (!host.equalsIgnoreCase(hostOf(url))) continue;
            String lower = url.toLowerCase();
            String ctype = "";
            try { if (rr.response().hasHeader("Content-Type")) ctype = rr.response().headerValue("Content-Type").toLowerCase(); } catch (Throwable ignore) { }
            boolean isJs = lower.contains(".js") || ctype.contains("javascript");
            // Classify HTML by CONTENT-TYPE too, not just extension: server-rendered pages carry a real extension
            // (.aspx/.php/.jsp/.do) so the extension heuristic skips them — yet they're exactly the pages whose inline
            // module-loader lists (headJS/RequireJS) reference the SPA bundles holding the real API. text/html → mine.
            boolean isHtml = lower.endsWith(".html") || lower.endsWith(".htm") || lower.endsWith("/")
                    || ctype.contains("text/html")
                    || !lower.matches(".*\\.[a-z0-9]{1,5}($|\\?).*");
            if (!isJs && !isHtml) continue;
            if (isJs && LIBRARY_JS.matcher(lower).matches()) continue;   // skip libs
            if (!seen.add(Net.stripQuery(url))) continue;
            // A/B: legacy head-truncation when -Daiscanner.legacyMining=true, else the regex-anchored excerpt.
            byte[] rb = rr.response().body().getBytes();
            String magic = rb.length >= 2 ? String.format("%02x%02x", rb[0] & 0xFF, rb[1] & 0xFF) : "";
            rr = AiScanner.decompress(rr);   // site-map re-reads can hand back the compressed body → force plain
            String raw = rr.response().bodyToString();
            if (isHtml) {
                int b0 = scriptRefs.size();
                collectScriptRefs(raw, url, host, scriptRefs);   // note the page's own <script>/preload JS
                scanLog.debug("mine-src " + url + " rawBytes=" + rb.length + " magic=" + magic
                        + " afterLen=" + raw.length() + " hasScript=" + raw.contains("<script")
                        + " newRefs=" + (scriptRefs.size() - b0));
            }
            String body = Boolean.getBoolean("aiscanner.legacyMining")
                    ? trunc(raw, PER_SOURCE_CHARS)
                    : endpointExcerpt(raw, PER_SOURCE_CHARS);
            if (body.isBlank()) continue;
            (isHtml ? html : js).add(new String[]{url, body});
        }
        // Actively FETCH the JS chunks a page references but the crawler never fetched — on an SPA the crawler
        // gets 0 requests, so the bundles holding the real API (login/signup/verify…) are otherwise mined only
        // by chance (run-to-run variance). Persisted to the site map so later passes reuse them, not re-fetch.
        int fetched = 0;
        for (String su : scriptRefs) {
            if (fetched >= MAX_FETCH_SCRIPTS) break;
            if (!seen.add(su)) continue;
            try {
                HttpRequestResponse fr = probe(withSessionCookie(HttpRequest.httpRequestFromUrl(su).withMethod("GET")));
                if (fr == null || fr.response() == null) continue;
                try { api.siteMap().add(fr); } catch (Exception ignore) { }
                String raw = fr.response().bodyToString();
                String body = Boolean.getBoolean("aiscanner.legacyMining") ? trunc(raw, PER_SOURCE_CHARS) : endpointExcerpt(raw, PER_SOURCE_CHARS);
                if (!body.isBlank()) { js.add(new String[]{ su, body }); fetched++; }
            } catch (Exception ignore) { }
        }
        scanLog.log("mining sources: " + html.size() + " html + " + js.size() + " js in site map; "
                + scriptRefs.size() + " referenced JS chunk(s), fetched " + fetched + " new.");
        // deepest paths first (authenticated app views before the public landing pages)
        html.sort((a, b) -> Integer.compare(pathDepth(b[0]), pathDepth(a[0])));
        List<String[]> out = new ArrayList<>();
        out.addAll(html);
        out.addAll(js);
        int maxSrc = Tuning.maxSources();
        return out.size() > maxSrc ? out.subList(0, maxSrc) : out;
    }

    /** Collect the same-host .js URLs a page references (script src / preload link href), resolved absolute. */
    private void collectScriptRefs(String rawHtml, String pageUrl, String host, Set<String> out) {
        if (rawHtml == null) return;
        // (a) <script src>/<link href> attributes — the classic case.
        addJsRefs(SCRIPT_REF.matcher(rawHtml), pageUrl, host, out);
        // (b) INLINE module-loader lists — headJS `head.load([{ "scripts/page.login.js": "…?_=v" }])`, RequireJS,
        //     System.import, etc. reference their real bundles as quoted `.js` STRING LITERALS inside an inline
        //     <script>, never as a src= attribute, so (a) misses them. On ASP.NET/SPA apps that's exactly where the
        //     page's own module (holding the login.aspx/* page-methods + rest/* API) lives. Generic: any quoted
        //     path-like `.js` literal, same-host, non-library. Bounded downstream by MAX_FETCH_SCRIPTS + dedup.
        addJsRefs(INLINE_JS_REF.matcher(rawHtml), pageUrl, host, out);
    }

    /** Resolve each regex-captured `.js` reference against the page URL and keep same-host, non-library ones. */
    private void addJsRefs(Matcher m, String pageUrl, String host, Set<String> out) {
        while (m.find()) {
            try {
                String su = URI.create(pageUrl).resolve(m.group(1)).toString();
                if (host.equalsIgnoreCase(hostOf(su)) && !LIBRARY_JS.matcher(su.toLowerCase()).matches())
                    out.add(Net.stripQuery(su));
            } catch (Exception ignore) { }
        }
    }

    /** Greedily pack source bodies (each prefixed with its URL) into ~CHUNK_CHARS blocks. */
    private static List<String> packChunks(List<String[]> sources) {
        List<String> chunks = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String[] src : sources) {
            String piece = "\n// === " + src[0] + " ===\n" + src[1] + "\n";
            if (cur.length() > 0 && cur.length() + piece.length() > CHUNK_CHARS) {
                chunks.add(cur.toString());
                cur = new StringBuilder();
            }
            cur.append(piece);
        }
        if (cur.length() > 0) chunks.add(cur.toString());
        return chunks;
    }

    private static int pathDepth(String url) {
        try {
            String p = URI.create(url).getPath();
            return (int) p.chars().filter(c -> c == '/').count();
        } catch (Exception e) { return 0; }
    }

    // ---- small helpers ----
    private static final Pattern JSON_KEY = Pattern.compile("\"([^\"]+)\"\\s*:");

    private static String paramSuffix(HttpRequest req) {
        // JSON body variant: parameters() won't see JSON fields, so list the keys and flag it.
        String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
        if (ct != null && ct.toLowerCase().contains("json")) {
            StringBuilder sb = new StringBuilder();
            Matcher m = JSON_KEY.matcher(req.bodyToString());
            while (m.find()) { if (sb.length() > 0) sb.append(", "); sb.append(m.group(1)); }
            return sb.length() == 0 ? "  [json]" : "  [json: " + sb + "]";
        }
        if (!req.hasParameters()) return "";
        StringBuilder sb = new StringBuilder();
        req.parameters().forEach(p -> {
            if (p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(p.name());
            }
        });
        return sb.length() == 0 ? "" : "  [" + sb + "]";
    }
    /** Stable content hash of a mined source (url + body) for the LLM dedup — a byte-identical body at the same URL
     *  hashes identically (skip re-mining); a changed body (anon → authenticated) hashes differently (re-mine). */
    private static String srcHash(String url, String body) {
        String s = (url == null ? "" : url) + "\n" + (body == null ? "" : body);
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (Throwable t) {
            return Integer.toHexString(s.hashCode());   // never on JDK17; safe fallback
        }
    }
    private static String hostOf(String url) { return Net.authority(url); }
    private static int statusOf(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; }
        catch (Throwable t) { return -1; }
    }
    private static String trunc(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    // Endpoint-bearing anchors in a page/script body: REST roots, relative api/rest/vN leaves, the JS calls
    // that reference server endpoints, form actions, and GraphQL. Universal web idioms, not app-specific.
    private static final Pattern SRC_ANCHOR = Pattern.compile(
            "(?i)(/(?:rest|api)/[A-Za-z0-9_./-]+"
          + "|[\"'](?:api|rest|v[0-9]+)/[a-z0-9][a-z0-9/_.-]{1,60}[\"']"
          + "|fetch\\s*\\(|XMLHttpRequest|\\.(?:get|post|put|patch|delete)\\s*\\("
          + "|\\burl\\s*[:=]|\\baction\\s*=|/graphql|endpoint)");

    /**
     * Lesson from Burp AT's {@code inspect_http_message} (regex-anchored windows, not head-truncation):
     * return an endpoint-RELEVANT excerpt of a body, capped at {@code cap} chars. If it fits, return whole.
     * Otherwise DON'T take the head — a minified bundle's first bytes are webpack boilerplate, so head-8k
     * truncation systematically missed endpoint strings deeper in the file (this is what hid /api/Users in a
     * lazy chunk). Instead extract regex-anchored windows around each endpoint-bearing match (merging
     * overlaps) so those regions survive. Falls back to a head slice only if nothing anchors.
     */
    static String endpointExcerpt(String body, int cap) {
        if (body == null) return "";
        if (body.length() <= cap) return body;
        final int BEFORE = 120, AFTER = 360;
        List<int[]> spans = new ArrayList<>();
        Matcher m = SRC_ANCHOR.matcher(body);
        while (m.find() && spans.size() < 5000) {
            int a = Math.max(0, m.start() - BEFORE);
            int b = Math.min(body.length(), m.end() + AFTER);
            if (!spans.isEmpty()) {
                int[] last = spans.get(spans.size() - 1);
                if (a <= last[1]) { last[1] = Math.max(last[1], b); continue; }   // merge overlapping windows
            }
            spans.add(new int[]{a, b});
        }
        if (spans.isEmpty()) return body.substring(0, cap) + "…";                 // no anchors → head fallback
        StringBuilder sb = new StringBuilder(cap + 32);
        for (int[] s : spans) {
            if (sb.length() >= cap) break;
            int take = Math.min(s[1] - s[0], cap - sb.length());
            if (sb.length() > 0) sb.append(" … ");
            sb.append(body, s[0], s[0] + take);
        }
        return sb.toString();
    }
}
