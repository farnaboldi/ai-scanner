package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.scan.flow.FlowEngine;
import com.ioactive.aiscanner.scan.flow.StepResult;
import com.ioactive.aiscanner.scan.sast.AgenticSourceAnalyzer;
import com.ioactive.aiscanner.scan.sast.CoarseSourceAnalyzer;
import com.ioactive.aiscanner.scan.sast.RepoFetcher;
import com.ioactive.aiscanner.scan.sast.RouteHarvester;
import com.ioactive.aiscanner.scan.sast.SourceAnalyzer;
import com.ioactive.aiscanner.scan.sast.SourceFindings;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI-driven <em>targeting</em> in front of Burp's <em>native</em> active audit.
 *
 * <p>The AI/tool does what Burp's crawler does poorly: it derives real
 * parameterized requests from HTML &lt;form&gt;s, inherits the captured
 * authenticated session, dedups, and pinpoints the app's own parameters. It then
 * hands each request — with {@link Range} markers restricting insertion to those
 * exact parameter values — to Burp's built-in active audit
 * ({@link BuiltInAuditConfiguration#LEGACY_ACTIVE_AUDIT_CHECKS}). Burp brings its
 * full, maintained payload library and its battle-tested oracles, and files the
 * findings as native Audit Issues under a Dashboard task.
 */
public final class AiScanner {

    private final MontoyaApi api;
    private final Supplier<AiEngine> engine; // reserved for triage; not used for injection
    private final ScanConfig config;
    private final ScanLog scanLog;
    private final SessionStore session;
    private final java.util.function.BooleanSupplier cancelled;  // true once the extension is unloaded
    /** host → local source-repo path (or null) — drives the optional SAST pass. null resolver = never. */
    private final java.util.function.Function<String, String> repoResolver;

    /** User-requested stop (the Agent-tab Stop button). Volatile: set from the UI thread, polled by the scan
     *  thread via {@link #cancelled()}. Reset at the start of each scan so a prior Stop never kills a new run. */
    private volatile boolean stopRequested = false;
    /** Ask the running scan to stop at the next cooperative checkpoint. Pair with interrupting the scan thread
     *  (the extension does that) so blocking calls unblock too. */
    public void requestStop() { stopRequested = true; }
    /** Clear the stop flag — called when a fresh scan starts. */
    public void resetStop() { stopRequested = false; }
    public boolean stopRequested() { return stopRequested; }

    /** Stop cooperatively when the extension has been unloaded (or the scan thread was interrupted). */
    private boolean cancelled() {
        // Burp AI credits ran out mid-scan → halt at the next checkpoint (the paid engine can't do more; running
        // the AI-driven flow on empty just wastes wall-clock). Override with -Daiscanner.haltOnCreditExhaustion=false
        // to keep the credit-free deterministic layer (auth + probes + native audit) running instead.
        if (com.ioactive.aiscanner.engine.MontoyaAiEngine.creditsExhausted()
                && !"false".equalsIgnoreCase(System.getProperty("aiscanner.haltOnCreditExhaustion", "true"))) {
            if (creditHaltLogged.compareAndSet(false, true))
                scanLog.log("[AI Scanner] halting scan — Burp AI credits exhausted (see the credit-exhaustion notice above). "
                        + "The partial report of what was already found is written. Top up Burp AI or use a local LLM to continue.");
            return true;
        }
        if (stopRequested) {
            if (stopLogged.compareAndSet(false, true))
                scanLog.log("[AI Scanner] scan stopped by user (Stop button). Writing the partial report of what was already found.");
            return true;
        }
        return (cancelled != null && cancelled.getAsBoolean()) || Thread.currentThread().isInterrupted();
    }
    // Per-audit-phase budget for LLM insertion-point suggestions. addLlmInsertionPoints() fires ONE (slow) model call
    // PER audited request — on a big surface that alone runs to tens of minutes with a 35B model and starves the native
    // audit (which does the actual fuzzing) of time. Deterministic ranges (params + JSON + path IDs) are ALWAYS added;
    // the LLM only surfaces non-obvious extras, so capping it costs almost no coverage but reclaims the time budget.
    private static final int LLM_INSERT_CAP = Integer.getInteger("aiscanner.llmInsertCap", 20);
    private final java.util.concurrent.atomic.AtomicInteger llmInsertBudget = new java.util.concurrent.atomic.AtomicInteger(0);
    private final java.util.concurrent.atomic.AtomicBoolean creditHaltLogged = new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.atomic.AtomicBoolean stopLogged = new java.util.concurrent.atomic.AtomicBoolean(false);

    private static final Pattern STATIC = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)$");
    // Param names that SELECT which operation a dispatcher endpoint runs (one URL → many operations). Their VALUE
    // is part of the endpoint identity, so it is folded into the audit-target dedup key (see addTarget). Generic
    // RPC/dispatcher convention (callType/call/action/op/cmd/method/…) — not tied to any one app.
    private static final Pattern SELECTOR_PARAM = Pattern.compile(
            "(?i)(call|call_?type|action|op|operation|cmd|command|method|verb|func|function|fn|rpc|service|do|mode|kind|task|event)");
    // Transport/handshake endpoints: their "params" (EIO/transport/t/sid, Engine.IO packet
    // prefixes) are framing, not attack surface — fuzzing them is pure noise.
    private static final Pattern NOISE = Pattern.compile("(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$");
    private static final Pattern FORM = Pattern.compile("(?is)<form\\b.*?</form>");
    private static final Pattern INPUT = Pattern.compile("(?is)<(input|textarea|select)\\b[^>]*>");

    public AiScanner(MontoyaApi api, Supplier<AiEngine> engine, ScanConfig config, ScanLog scanLog,
                     SessionStore session) {
        this(api, engine, config, scanLog, session, null, null);
    }

    public AiScanner(MontoyaApi api, Supplier<AiEngine> engine, ScanConfig config, ScanLog scanLog,
                     SessionStore session, java.util.function.BooleanSupplier cancelled) {
        this(api, engine, config, scanLog, session, cancelled, null);
    }

    public AiScanner(MontoyaApi api, Supplier<AiEngine> engine, ScanConfig config, ScanLog scanLog,
                     SessionStore session, java.util.function.BooleanSupplier cancelled,
                     java.util.function.Function<String, String> repoResolver) {
        this.api = api;
        this.engine = engine;
        this.config = config;
        this.scanLog = scanLog;
        this.session = session;
        this.cancelled = cancelled;
        this.repoResolver = repoResolver;
    }

    /** Re-authentication callback (set by the orchestrator). The captured session can go stale DURING the long
     *  probe battery — authenticated-only endpoints then bounce to login/302 and late probes silently miss them.
     *  Invoked once just before the authenticated reflected-XSS phase to refresh the session cookie. */
    private volatile Runnable reauth;
    public void setReauth(Runnable r) { this.reauth = r; }
    /** Callback that registers a SECOND identity B (set by the scan orchestrator). Invoked once at the start of the
     *  attack battery — where the primary auth has definitely settled — so the access-control probes get a true
     *  cross-user differential. No-op if already minted / not authenticated. */
    private volatile Runnable secondIdentityMinter;
    public void setSecondIdentityMinter(Runnable r) { this.secondIdentityMinter = r; }
    private void refreshSessionIfPossible(String why) {
        try {
            if (reauth != null && session != null && session.authenticated()) {
                scanLog.phase("Re-authenticating (" + why + ")");
                reauth.run();
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner] re-auth skipped: " + t); }
    }

    /** Wall-clock budget for a single slow probe phase (blind-SQLi time payloads sleep ~5s each), so one phase
     *  can't stall the sequential chain and starve the later probes. Overridable for big/slow targets. */
    private static final long PROBE_PHASE_BUDGET_MS =
            Long.getLong("aiscanner.probePhaseBudgetMs", 150_000L);

    /** The AI engine (or null) — lets the auth flow do model-driven OTP/verification extraction. */
    public AiEngine engine() { return engine != null ? engine.get() : null; }

    // ---- entry points ----

    /** Submit one request's real parameters to Burp's native active audit. */
    public Audit scanRequest(HttpRequest req) {
        List<HttpRequest> one = new ArrayList<>();
        one.add(req);
        return scanRequests(one, "selected request");
    }

    /** Submit a batch of requests as a single native audit task. Returns the Audit, or null if nothing was queued. */
    public Audit scanRequests(List<HttpRequest> reqs, String label) {
        try {
            Audit audit = newAudit();
            if (audit == null) {   // Community edition: no native audit — our own HTTP probes carry detection
                scanLog.log("[AI Scanner] Burp Community edition: native active audit unavailable — " + label
                        + " is covered by the extension's own HTTP probes + local-LLM discovery instead.");
                return null;
            }
            int added = 0;
            llmInsertBudget.set(LLM_INSERT_CAP);   // bound the per-request LLM insertion-point calls for THIS phase
            for (HttpRequest req : reqs) {
                if (addToAudit(audit, req)) added++;
            }
            if (added == 0) {
                audit.delete();
                scanLog.log("[AI Scanner] nothing to audit (" + label + "): no app parameters found.");
                return null;
            }
            scanLog.log("[AI Scanner] submitted " + added + " request(s) to Burp active audit ("
                    + label + ") — watch the Dashboard task for findings.");
            return audit;
        } catch (Throwable t) {
            api.logging().logToError("[AI Scanner] scanRequests error: " + t);
            return null;
        }
    }

    /** Mine login/auth requests from client code (pre-auth) so we can authenticate autonomously. */
    public List<HttpRequest> discoverAuthRequests(String host) {
        return new EndpointDiscovery(api, engine, session, scanLog).discoverAuthRequests(host);
    }

    /** Discover parameterized requests for a host (site map + form-derived) and audit them natively. */
    public Audit scanDiscovered(String host) {
        if (cancelled()) return null;                    // extension unloaded before we started
        if (!aiPreflight()) {                            // REQUIRED AI backend (local LLM) down → abort, don't degrade
            scanLog.log("[AI Scanner] scan aborted by preflight (required AI backend unusable).");
            return null;
        }
        // In Pro, Burp's native audit will test every target we submit — so defer Burp-covered classes (SQLi/XSS/…)
        // to Burp's own dashboard issue instead of raising a duplicate. (No-op / keeps our issues in Community.)
        scanLog.setBurpNativeAudit(!communityEdition());
        // NOTE: an untrusted/self-signed/expired server TLS certificate is a CLASSIC transport finding Burp Pro
        // already reports natively — we do NOT duplicate it (same call as CORS, removed build 167). We still
        // TOLERATE bad certs (dropped withUpstreamTLSVerification) so we can reach the target; that does not stop
        // Burp's own certificate evaluation from firing.
        Set<String> seen = new HashSet<>();
        List<HttpRequest> targets = new ArrayList<>();
        // SPA client-side-routing guard: a single-page app serves the SAME HTML shell (index.html) for ANY
        // unmatched path, so Burp's crawler records dozens of "endpoints" (e.g. /rest/movies, /user/{id}) that
        // are really just the shell — fuzzing their params only hits static HTML and manufactures phantom
        // coverage. We detect the catch-all ONCE (probe an improbable path: if the app answers 2xx HTML where
        // nothing can exist, it has a client-side-routing catch-all) and skip site-map entries that ARE that
        // shell. Generic + zero-FP: inert on any app that 404s unknown paths (server-rendered apps, real APIs);
        // real SPA endpoints still arrive via EndpointDiscovery's JS-mining, not the shell. spaShell == "" means
        // "checked, no catch-all"; null means "not checked yet".
        // Ingest SAME-SITE, not just exact-host. Burp's embedded-browser crawl RENDERS the SPA (executes
        // bundle.js) and records the runtime XHR/fetch calls it makes — including calls to a SIBLING origin
        // (SPA :3001 -> API :8080, or api.<domain>) that static JS-mining can't recover. Those land in the site
        // map on a different host/port, so an exact-host filter would drop the very API calls we want to audit.
        // sameSite() keeps the seed origin AND same-registrable-domain siblings (the user-approved scope) and
        // still excludes third-party origins (CDNs, telemetry, vendor domains) the page also talks to.
        Map<String, String> shellByOrigin = new HashMap<>();   // origin -> its catch-all shell ("" = none)
        int spaSkipped = 0, xorigin = 0;
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String rhost = hostOf(rr.request().url());
            if (!sameSite(host, rhost)) continue;
            String origin = originOf(rr.request().url());
            String shell = shellByOrigin.computeIfAbsent(origin, this::detectCatchAllShell);
            if (!shell.isEmpty() && matchesCatchAllShell(rr, shell)) { spaSkipped++; continue; }
            if (!host.equalsIgnoreCase(rhost)) xorigin++;   // a sibling-origin API call the browser observed
            addTarget(targets, seen, rr.request());
            for (HttpRequest f : deriveForms(rr)) addTarget(targets, seen, f);
        }
        if (spaSkipped > 0) scanLog.log("[AI Scanner] SPA client-side-routing catch-all detected — excluded "
                + spaSkipped + " phantom endpoint(s) that only echo the app shell (real API endpoints still come "
                + "from the embedded-browser crawl + JS-mining discovery).");
        if (xorigin > 0) scanLog.log("[AI Scanner] ingested " + xorigin + " same-site cross-origin request(s) the "
                + "embedded browser observed the SPA make (sibling API origin) — auditing them too.");

        // Source analysis (SAST): if a repo is associated with this host, run a coarse LLM pass that emits
        // testing DIRECTIVES (hidden endpoints, tainted params, sink types). These STEER discovery + the
        // probes + the flow engine below; a hint NEVER raises a finding on its own — the deterministic
        // oracles still decide every verdict, so a weak/blank pass costs coverage, never soundness.
        SourceFindings hints0 = SourceFindings.empty();
        String repoPath = repoResolver != null ? repoResolver.apply(host) : null;
        // Always surface the repo-association status on the Log page so it's obvious whether this run is
        // SAST-assisted or plain black-box (-Daiscanner.sastMode=agentic follows the child-process boundary).
        boolean agentic = "agentic".equalsIgnoreCase(System.getProperty("aiscanner.sastMode", "coarse"));
        if (repoPath != null && !repoPath.isBlank()) {
            scanLog.log("[AI Scanner] source repo associated with " + host + ": " + repoPath
                    + "  → SAST-assisted scan (mode=" + (agentic ? "agentic" : "coarse") + ")");
            try {
                // Local path → use it; git/GitHub URL → fetch it over HTTP (no git binary, no subprocess).
                String localRepo = RepoFetcher.ensureLocal(repoPath, scanLog);
                if (localRepo == null) {
                    scanLog.log("[AI Scanner] source could not be resolved to a local checkout — SAST skipped (black-box).");
                } else {
                    // DETERMINISTIC route/GraphQL-schema harvest — runs WITH OR WITHOUT an LLM, so a repo adds
                    // coverage even in no-AI mode. Steering only; discovery live-probes and the oracles decide.
                    SourceFindings harvested = RouteHarvester.harvest(localRepo);
                    if (!harvested.isEmpty())
                        scanLog.log("[AI Scanner] SAST(routes): " + harvested.size() + " route/GraphQL directive(s) harvested from source.");
                    // Optional LLM pass (taint-aware sinks) layered on top when an engine is configured.
                    SourceFindings llm = SourceFindings.empty();
                    AiEngine sastEng = engine != null ? engine.get() : null;
                    if (sastEng != null && sastEng.isConfigured()) {
                        scanLog.phase("Source analysis (SAST" + (agentic ? ", agentic" : "") + ")");
                        SourceAnalyzer analyzer = agentic
                                ? new AgenticSourceAnalyzer(sastEng, scanLog)
                                : new CoarseSourceAnalyzer(sastEng, scanLog);
                        llm = analyzer.analyze(host, localRepo);
                        scanLog.log("[AI Scanner] source analysis: " + llm.size() + " LLM hint(s) from " + localRepo);
                    } else {
                        scanLog.log("[AI Scanner] LLM engine not configured — using the deterministic route/GraphQL harvest only.");
                    }
                    hints0 = SourceFindings.combine(llm, harvested);
                    scanLog.log("[AI Scanner] source analysis total: " + hints0.size() + " directive(s).");
                }
            } catch (Throwable t) {
                scanLog.debug("[AI Scanner] source analysis skipped: " + t);
            }
        } else {
            scanLog.log("[AI Scanner] no source repo associated with " + host + " — black-box scan.");
        }
        final SourceFindings hints = hints0;   // effectively-final snapshot the data-driven attack lambdas capture

        // LLM + regex endpoint discovery: recover endpoints Burp's crawler can't reach
        // (JS-only AJAX/routes), probed live so nothing hallucinated gets audited.
        EndpointDiscovery disc = new EndpointDiscovery(api, engine, session, scanLog);
        disc.addSourceHints(hints);   // SAST-driven: probe source-named routes/params too (dead ones filtered)
        for (HttpRequest ep : disc.discover(host)) {
            addTarget(targets, seen, ep);
        }
        // SAST hint → CONCRETE request. Discovery adds hinted routes as specs, but seeds their params with
        // generic/empty values — so a sink that JSON.parse()s its param (xvna /getdata?id=) 500s on the empty
        // value and gets dropped as "not live", and command/eval sinks never get a param to mutate. Synthesize
        // one concrete request per hint with a CLASS-APPROPRIATE baseline (numeric "1"; a resolvable host for
        // command sinks) so the param-iterating probes (NoSql JSON-value, CommandInjection, Xss…) can fire.
        synthesizeHintTargets(host, hints, targets, seen);
        // Discovery-depth: synthesize POST creates from each REST collection's learned schema so
        // create/update endpoints (never POSTed during the crawl) get audited + probed.
        for (HttpRequest w : disc.synthesizeWrites(host)) {
            addTarget(targets, seen, w);
        }
        // Bridge: discovery already fetched these endpoints (Burp's crawler couldn't reach them). Add the
        // request+response pairs to the site map so the site-map-reading probes — IdorGetProbe, BflaProbe,
        // ChainReplayProbe — can see them too (they don't read the `targets` list). keep()'s guards ensure
        // only real, non-HTML-shell, handler-answered responses were stashed, so this adds no FP surface.
        int bridged = 0;
        for (HttpRequestResponse rr : disc.lastKeptResponses()) {
            try { api.siteMap().add(rr); bridged++; } catch (Exception ignore) { }
        }
        if (bridged > 0) scanLog.log("[AI Scanner] bridged " + bridged
                + " discovered endpoint(s) into the site map for IDOR/BFLA/chain probes.");

        // ABSTRACT authenticated SPA navigation. A static crawl never executes the app's JS, so a JS-driven app's
        // DATA surface (record lists / grids / detail views / searches loaded on demand behind menu→module→grid
        // navigation) never enters the site map and the battery never audits it. Now that EndpointDiscovery has
        // fetched the app's client JS into the site map, hand its OWN data-call JS + a running fetch-log to the
        // model and let it drive the data protocol deeper, read-only, REUSING ids the responses return. Each data
        // endpoint it reaches is registered BOTH in the site map (site-map probes) and as an audit target (the
        // full targets-iterating battery: BlindSqli/NoSql/BodyMutator/Xss/IDOR/BOLA…). Generic; no per-app rule.
        if (session != null && session.authenticated() && engine != null && engine.get() != null) {
            SpaNavigator spa = new SpaNavigator(api, scanLog, engine.get(), session);
            int nav = spa.navigate(host, session.landingUrl());
            if (nav > 0) {
                int navTargets = 0;
                for (HttpRequestResponse rr : spa.reachedResponses()) {
                    // Schema-aware: fold a fingerprint of the RESPONSE field-set into the dedup key, so two calls to the
                    // SAME operation that return DIFFERENT columns (e.g. a generic grid over table A vs table B — same
                    // request shape, only the source id differs) become DISTINCT audit targets and each table's unique
                    // (injectable) filter/column surface is probed, instead of collapsing to one.
                    if (rr != null && rr.request() != null && addTarget(targets, seen, rr.request(), responseSchemaSig(rr))) navTargets++;
                }
                scanLog.log("[AI Scanner] SPA navigator: " + navTargets + " data endpoint(s) registered as audit targets.");
            }
        }

        // AI-path-discovered HTML pages (e.g. an unlinked /admin/ console Burp's link-crawler never reached):
        // add each to the site map (so Burp + the site-map probes see it) and derive its forms as targets — so
        // an /admin/*-add form is CSRF-tested. deriveForms above ran only over the pre-discovery site map.
        int discPages = 0;
        for (HttpRequestResponse rr : disc.lastDiscoveredPages()) {
            try { api.siteMap().add(rr); } catch (Exception ignore) { }
            for (HttpRequest f : deriveForms(rr)) addTarget(targets, seen, f);
            discPages++;
        }
        if (discPages > 0) scanLog.log("[AI Scanner] surfaced " + discPages
                + " AI-discovered page(s) into the site map + form targets.");

        // TRACE: the exact audit surface the targets-iterating probes (BlindSqli/NoSql/BodyMutator) will
        // cover — so we can SEE whether e.g. validate-coupon{coupon_code} made it in, not infer it.
        scanLog.log("[AI Scanner] audit surface: " + targets.size() + " target(s) —");
        for (HttpRequest t : targets) {
            String body = t.bodyToString();
            String shape = (body != null && !body.isBlank() && body.length() < 200) ? " body=" + body
                    : " " + paramSummary(t);
            scanLog.log("[AI Scanner]   • " + t.method() + " " + stripQuery(t.url()) + shape);
        }

        // DISCOVERY-ONLY: dump the reachable attack surface and STOP before the (slow) probes + Burp audit.
        // Turns the "did the crawl reach the target forms?" question into a ~1-2 min run instead of a full
        // 20-30 min audit — the fast inner loop for tuning discovery/coverage. -Daiscanner.discoveryOnly=true.
        if (Boolean.getBoolean("aiscanner.discoveryOnly")) {
            scanLog.log("[AI Scanner] discovery-only mode: reached " + targets.size()
                    + " target(s) above; skipping probes + active audit.");
            return null;
        }

        if (cancelled()) { scanLog.log("[AI Scanner] scan cancelled (extension unloaded)."); return null; }

        // Agent-flow probe: reach an LLM-agent action surface (chat that drives privileged tools) by driving its
        // stateful rooms→run→turn flow, which endpoint mining alone can't (the run_id only exists at runtime).
        // Runs a canary-gated prompt-injection oracle AND — crucially — bridges every reached agent request into
        // the site map. This MUST run BEFORE the site-map-reading probes below (IDOR/BFLA/JWT/chain/secret-
        // exposure) so they actually analyse the newly-unlocked agent surface — otherwise the coverage-unlock is
        // wasted. When the assistant is gated, it asks the LLM to plan the unlock from the app's own discovered
        // writes (no app-specific knowledge in code). No-op when the app has no /agents/ surface.
        // DATA-DRIVEN BATTERY — the ScanPhases registry IS the battery: each attack module binds its action below
        // under the SAME key, and the loop at the end runs ScanPhases.attackModules() in order (title/enablement/
        // count all come from the registry). A probe cannot run without a registry entry, so the list can't drift.
        final java.util.List<String> injectionLeaks = new ArrayList<>();   // shared: NoSQL bypass leak -> create->consume chain
        final java.util.LinkedHashMap<String, Runnable> attackActions = new java.util.LinkedHashMap<>();

        attackActions.put("agentflow", () -> {
            AiEngine agentEng = engine != null ? engine.get() : null;   // used only to plan a generic unlock when gated
            AgentFlowProbe afp = new AgentFlowProbe(api, scanLog, agentEng);
            int hits = afp.probe(host, this::withSession);
            scanLog.log("[AI Scanner] agent-flow probe: " + hits + " LLM-agent finding(s).");
            // Feed the agent write requests it reached into the audit surface — so the targets-iterating probes
            // below AND the final Burp active audit fuzz the agent endpoints too (not just the site-map readers).
            int added = 0;
            for (HttpRequestResponse rr : afp.reached()) if (addTarget(targets, seen, rr.request())) added++;
            if (added > 0) scanLog.log("[AI Scanner] agent-flow: added " + added + " reached agent request(s) to the audit surface.");
        });

        // LLM-fuzz probe: fire the adversarial battery (unicode / prompt-injection / structural) at any single-
        // request LLM endpoint in the site map and judge replies with the local LLM (hybrid two-tier oracle). The
        // agent's async run→turn endpoints are fuzzed inside the agent-flow probe above; this covers plain chat/
        // completion endpoints. Generic — endpoint identification is structural (LlmEndpointDetector), no app paths.
        attackActions.put("llmfuzz", () -> {
            AiEngine fuzzEng = engine != null ? engine.get() : null;
            int hits = new LlmFuzzProbe(api, scanLog, fuzzEng).probe(host, this::withSession);
            scanLog.log("[AI Scanner] llm-fuzz probe: " + hits + " finding(s).");
        });

        // FAST, high-signal findings FIRST — CSRF + open-redirect are deterministic, cheap, and independent of
        // the (slow, per-target) injection fuzzing below, so the crit/high they find emit promptly even on a
        // high-latency target where Burp's async active audit is slow to complete. The CSRF probe is handed the
        // derived form POSTs directly, so it doesn't wait for the audit to push them into the site map.
        attackActions.put("csrf", () -> {
            int hits = new CsrfProbe(api, scanLog).probe(host, this::withSession, targets);
            scanLog.log("[AI Scanner] CSRF probe: " + hits + " state-changing form(s) accept a forged cross-site request.");
        });
        attackActions.put("redirect", () -> {
            OpenRedirectProbe orp = new OpenRedirectProbe(api, scanLog);
            int hits = 0;
            for (HttpRequest t : targets) if (orp.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] open-redirect probe: " + hits + " endpoint(s) redirect to an attacker host.");
        });
        attackActions.put("oauth", () -> {
            // OAuth authorization-server logic (redirect_uri validation → auth-code/token leak). Drives the
            // observed authorize flow with an off-origin sentinel redirect_uri; a leaked code/token to it = flaw.
            new OAuthLogicProbe(api, scanLog).probe(host, this::withSession);
        });

        // Blind-SQLi FIRST — its content oracle needs a stable target, so run it before the heavier
        // probes build up load (fragile/rate-limited targets can drop sessions under sustained scanning).
        attackActions.put("sqli", () -> {
            long deadline = System.currentTimeMillis() + PROBE_PHASE_BUDGET_MS;
            BlindSqliProbe bsp = new BlindSqliProbe(api, scanLog);   // stateless (final fields) → thread-safe to share
            bsp.setSourceHints(hints);   // SAST: source-tag the SQLi finding (provenance rides into the report)

            // Unit list = discovered audit targets + parameterless GET pages to mine for hidden params (sqli-labs
            // "input the ID" pages, /page.php?id= handlers). Collected sequentially (reads the site map). Each unit
            // is a self-contained READ-ONLY differential (its own baseline+legs stay coherent inside bsp.probe);
            // different units are independent → safe to run in parallel.
            java.util.List<HttpRequest> units = new java.util.ArrayList<>(targets);
            java.util.Set<String> minedPaths = new java.util.HashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (minedPaths.size() >= 80) break;
                if (rr == null || rr.response() == null) continue;
                HttpRequest r = rr.request();
                if (!"GET".equalsIgnoreCase(r.method()) || r.url().contains("?")) continue;
                if (STATIC.matcher(pathOf(r)).matches()) continue;
                try { if (!api.scope().isInScope(r.url())) continue; } catch (Throwable ignore) { }
                int st = rr.response().statusCode(); if (st < 200 || st >= 400) continue;
                String ct = rr.response().headerValue("Content-Type");
                if (ct == null || !ct.toLowerCase().contains("html")) continue;   // an HTML page that may hide a param
                // Normalize an extensionless path to a trailing slash: the crawler records the link "Less-1"
                // without the slash, but appending ?id= to /Less-1 makes Apache 301-redirect to /Less-1/ and DROP
                // the query — so the injected param never reaches the handler. /Less-1/ keeps it.
                String u = stripQuery(r.url());
                String lastSeg = u.substring(u.lastIndexOf('/') + 1);
                if (!u.endsWith("/") && !lastSeg.contains(".")) u = u + "/";
                if (!minedPaths.add(u)) continue;
                units.add(HttpRequest.httpRequestFromUrl(u).withMethod("GET"));
            }

            // READ-ONLY parallel slice behind -Daiscanner.concurrency (default 3): N units at once. One hung/slow
            // unit occupies ONE worker (bounded by the 12s per-request timeout), never the whole tool — the fix for
            // "one blocked request stalls the whole scan". Adaptive Throttle: on 429/503 it backs off + shrinks
            // toward sequential (no self-inflicted rate-limit lockout). concurrency=1 = the sequential outcome
            // baseline the benchmark's outcome-neutral gate compares against.
            int concurrency = Math.max(1, Integer.getInteger("aiscanner.concurrency", 3));
            java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
            if (concurrency <= 1) {
                for (HttpRequest u : units) {
                    if (System.currentTimeMillis() > deadline) break;
                    if (bsp.probe(withSession(u), deadline)) hits.incrementAndGet();
                }
            } else {
                Throttle throttle = new Throttle(concurrency, scanLog);
                bsp.withThrottle(throttle);
                java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(concurrency);
                for (HttpRequest u : units) {
                    pool.submit(() -> {
                        if (System.currentTimeMillis() > deadline) return;
                        try {
                            throttle.acquire();
                            try { if (bsp.probe(withSession(u), deadline)) hits.incrementAndGet(); }
                            finally { throttle.release(); }
                        } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                        catch (Throwable ignore) { }
                    });
                }
                pool.shutdown();
                try {
                    long grace = Math.max(0, deadline - System.currentTimeMillis()) + 30_000L;
                    if (!pool.awaitTermination(grace, java.util.concurrent.TimeUnit.MILLISECONDS)) pool.shutdownNow();
                } catch (InterruptedException ie) { pool.shutdownNow(); Thread.currentThread().interrupt(); }
            }
            int sqliN = bsp.emitCollapsed();   // emit now: 1 systemic finding if it's a shared-sink flood, else each
            scanLog.log("[AI Scanner] blind-SQLi probe: " + hits.get() + " endpoint(s) injectable ("
                    + minedPaths.size() + " parameterless page(s) mined; concurrency=" + concurrency
                    + (sqliN > 5 ? "; " + sqliN + " hits collapsed to 1 systemic SQLi (shared sink)" : "") + ").");
        });

        // Reflected XSS is left to Burp's native ACTIVE audit — it is the canonical owner of that class and we
        // feed it every discovered endpoint, so we NEVER duplicate it with our own reflected-XSS. EXCEPTION:
        // WAF-evasion mode, where Burp's canonical XSS payloads get blocked by the WAF — there a small evasion-only
        // probe tries obfuscated tag vectors Burp can't slip. That is COMPLEMENTARY (covers a case Burp fails at),
        // not duplication, and it runs ONLY when the toggle is on. (Burp Community has no active audit, so reflected
        // XSS is simply an edition limitation there — an honest Pro-scanner class, not something we re-implement.)
        attackActions.put("rxss", () -> {
            // WAF-evasion mode FIRST (only when the toggle is on): obfuscated tag vectors Burp's canonical XSS
            // payloads can't slip past a WAF — complementary to Burp's native reflected-XSS, not a duplicate.
            if (Evasion.enabled()) {
                EvasionXssProbe xss = new EvasionXssProbe(api, scanLog);
                int eh = 0;
                for (HttpRequest t : targets) if (xss.probe(withSession(t))) eh++;
                scanLog.log("[AI Scanner] evasion-XSS probe: " + eh + " endpoint(s) reflect an obfuscated tag past the WAF.");
            }
            // Deterministic reflected-XSS with CONTEXT-AWARE breakout: catches sinks Burp leaves at INFO (a
            // reflection landing in an HTML comment / <script> block). Zero-FP (unique marker into an executable
            // context + re-confirm). Runs always.
            ReflectedXssProbe rxss = new ReflectedXssProbe(api, scanLog);
            int hits = 0;
            for (HttpRequest t : targets) if (rxss.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] reflected-XSS probe: " + hits + " endpoint(s) with a breakout-confirmed reflected XSS.");
        });

        // (reflected-XSS — WAF-evasion + context-aware breakout — is folded into the "rxss" action above.)

        // Deterministic path-traversal oracle via path REFLECTION (generic; catches file-path params a JSON API
        // exposes with no /etc/passwd readback — the value flows into a server path echoed in an error, and a
        // ../<leaked-dir>/<value> up-and-back resolves like the baseline while a junk dir does not → CWE-22).
        attackActions.put("pathtrav", () -> {
            PathReflectionProbe prp = new PathReflectionProbe(api, scanLog);
            int hits = 0;
            for (HttpRequest t : targets) if (prp.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] path-reflection probe: " + hits + " endpoint(s) path-traversable.");
        });

        // Deterministic NoSQL oracle over the discovered surface (generic; Burp's NoSQL coverage is weak).
        // Records the records a bypass leaks so the create->consume chain below can replay them.
        attackActions.put("nosql", () -> {
            NoSqlProbe nosql = new NoSqlProbe(api, scanLog);
            nosql.setLeakSink(injectionLeaks);
            nosql.setSourceHints(hints);   // SAST: tag provenance when a source NoSQL sink matches
            if (session != null) nosql.setKnownUser(session.loginUser());   // valid user → clean auth-bypass check
            int hits = 0;
            for (HttpRequest t : targets) if (nosql.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] NoSQL probe: " + hits + " endpoint(s) look NoSQL-injectable.");
        });

        // OS command injection + server-side eval (SSJS/RCE). Deterministic (time-based sleep; arithmetic
        // eval oracle). SAST-hint-driven: synthesizes a concrete request per command/eval sink the source pins
        // (the exact route+param a JS-wired SPA hides from the crawler), plus a generic pass over discovered
        // targets. Neither oracle can false-positive (a real sleep-delay / a computed product must appear).
        attackActions.put("cmdi", () -> {
            CommandInjectionProbe cmdi = new CommandInjectionProbe(api, scanLog);
            cmdi.setSourceHints(hints);
            String base = targets.isEmpty() ? null : originOf(targets.get(0).url());
            int hits = cmdi.probeHints(host, this::withSession, base);
            for (HttpRequest t : targets) if (cmdi.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] command/eval probe: " + hits + " injectable point(s).");
        });

        // create->consume chain: replay a record an injection bypass leaked into sibling write endpoints
        // the crawler never reached (the UI only calls them after a valid value it doesn't possess), then
        // fuzz those sinks. Reaches chained vulns like a NoSQL leak feeding a SQL-backed apply endpoint.
        attackActions.put("ssti", () -> {
            SstiProbe ssti = new SstiProbe(api, scanLog);
            ssti.setSourceHints(hints);
            int hits = 0;
            for (HttpRequest t : targets) if (ssti.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] SSTI probe: " + hits + " endpoint(s) with server-side template injection.");
        });
        attackActions.put("chain", () -> {
            if (!injectionLeaks.isEmpty())
                new ChainReplayProbe(api, scanLog, this::withSession, injectionLeaks).run(host);
        });

        // Generic body-mutation probe (mass-assignment / empty-required / boundary / IDOR) over writes.
        attackActions.put("bodymut", () -> {
            BodyMutatorProbe bm = new BodyMutatorProbe(api, scanLog);
            for (HttpRequest t : targets) bm.probe(withSession(t));
        });

        // Generic poison-null-byte / extension-bypass fetch over sensitive served files.
        attackActions.put("fileserve", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new FileServePathProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] file-serve probe: " + hits + " sensitive file(s) exfiltrated via bypass.");
        });

        // Generic IDOR probe: re-request id-bearing GET paths with a neighboring id (cross-tenant access).
        attackActions.put("idor", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            String cookieB = session != null ? session.cookieHeaderB() : "";
            String bearerB = session != null ? session.bearerB() : "";
            String identityB = session != null ? session.identityB() : "";
            IdorGetProbe idor = new IdorGetProbe(api, scanLog);
            idor.setSourceHints(hints);   // SAST: widen enumeration on source-flagged object-refs + tag provenance
            int hits = idor.probe(host, cookie, bearer, cookieB, bearerB, identityB);
            boolean twoId = session != null && session.hasSecondIdentity();
            scanLog.log("[AI Scanner] IDOR probe: " + hits + " id-bearing GET(s) returned another tenant's record"
                    + (twoId ? " (two-identity cross-user differential enabled)." : "."));
        });

        // WRITE-side BOLA: mutate another identity's sub-resource (PUT /coll/{id}/{field}) with our session and
        // read the marker back — the cross-user WRITE (account-takeover-grade) IdorGetProbe can't reach (GET-only).
        // Zero-FP: victims sourced from the collection listing + require >= 2 distinct landed victims + restore.
        attackActions.put("bolawrite", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            String cookieB = session != null ? session.cookieHeaderB() : "";
            String bearerB = session != null ? session.bearerB() : "";
            String base = !targets.isEmpty() ? originOf(targets.get(0).url()) : siteMapOrigin(host);
            int hits = new BolaWriteProbe(api, scanLog).probe(host, hints, base, targets, cookie, bearer, cookieB, bearerB);
            scanLog.log("[AI Scanner] BOLA write probe: " + hits + " endpoint(s) allowed a confirmed cross-user write (CWE-639)"
                    + (session != null && session.hasSecondIdentity() ? " (second-identity witness enabled)." : "."));
        });

        // Mass-assignment / privilege-escalation-on-registration: register an account with injected privilege
        // fields, then prove the field elevated it via an admin-action differential (M allowed, our normal N
        // denied). Zero-FP (same request, only the injected field differs); deletes only our own throwaways.
        attackActions.put("massassign", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new MassAssignProbe(api, scanLog).probe(host, discoverAuthRequests(host), cookie, bearer);
            scanLog.log("[AI Scanner] Mass-assignment probe: " + hits + " privilege-escalation-on-registration confirmed (CWE-915).");
        });

        // Generic BFLA probe: role-segment substitution (…/user/… -> …/admin/…) then a non-destructive
        // three-request authz differential (unauth denied + our-session reaches a real handler that a
        // non-existent sibling route does not) — a non-admin invoking an admin-tier function.
        attackActions.put("bfla", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new BflaProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] BFLA probe: " + hits + " admin-tier function(s) reachable by a non-privileged user.");
        });

        // JWT implementation analysis: harvest tokens the app used, decode them, and run deterministic
        // oracle-gated checks (alg:none active replay, weak/known HMAC secret, missing exp, sensitive claims).
        attackActions.put("jwt", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new JwtAnalysisProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] JWT analysis probe: " + hits + " JWT implementation issue(s).");
        });

        // Unauthenticated-access probe: re-send each authenticated 2xx-JSON endpoint with the credential
        // stripped; fire only if it still returns the same data shape (auth not enforced). Reads the site map,
        // so it sees the discovered endpoints via the bridge above.
        attackActions.put("unauth", () -> {
            int hits = new UnauthAccessProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] unauth-access probe: " + hits + " protected endpoint(s) served data with no credential.");
        });

        // Webhook signature fail-open: inbound provider webhooks (payments/KYC/banking) must verify an HMAC
        // signature — a verifier that fails open lets an anonymous attacker forge provider events (fake a
        // deposit, flip a loan/KYC decision to approved). Deterministic: a bad/absent signature that is ACCEPTED
        // (2xx, not a signature rejection) proves verification isn't enforced. Generic; non-destructive ({} body).
        attackActions.put("webhook", () -> {
            int hits = new WebhookAuthProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] webhook-auth probe: " + hits + " webhook(s) accept an invalid/absent signature.");
        });

        // Privilege-parity (broken function-level authz): a privileged resource reachable through an ungated
        // sibling route. Reads the site map (a denied /admin/X twin proves the resource is privileged), then
        // confirms the open /X twin returns data to our session — crash-independent, passes a WAF unchanged.
        attackActions.put("privparity", () -> {
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new PrivilegeParityProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] privilege-parity probe: " + hits + " privileged resource(s) reachable via an ungated sibling.");
        });

        // (CSRF probe ran early — see the fast-findings block above.)

        // Response-side secret disclosure: a challenge served together with its own answer (CWE-345).
        // Reads the site map, so it sees the discovered endpoints via the bridge above.
        attackActions.put("secrets", () -> {
            int hits = new ResponseSecretExposureProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] response-secret probe: " + hits + " response(s) disclosed a challenge answer.");
        });

        // GraphQL: Burp DETECTS a /graphql endpoint but won't fuzz resolver ARGS without a valid query carrying
        // them as insertion points. Introspect the schema (info exposure if enabled), then inject each resolver's
        // String args via query variables with a deterministic echo-nonce oracle → catches unauth GraphQL RCE
        // (e.g. a getCommandResult(command) shell resolver) that our REST-only surface was blind to.
        attackActions.put("graphql", () -> {
            int hits = new GraphqlProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] graphql probe: done (" + hits + " finding(s)).");
        });

        // Insecure deserialization: DETECT a serialized-object cookie (Java/.NET/pickle/PHP), then VALIDATE it
        // black-box by replaying a discovered GET with the cookie's serialized stream corrupted — if the app 5xx's
        // only on the corrupt blob, it deserializes attacker data (CWE-502). Fires only on that dynamic delta.
        attackActions.put("deser", () -> {
            int hits = new InsecureDeserializationProbe(api, scanLog).probe(host, targets);
            scanLog.log("[AI Scanner] insecure-deserialization probe: " + hits + " endpoint(s) proven to deserialize a client-supplied object.");
        });

        // Out-of-band (blind) XXE via Burp Collaborator: inject an external-entity payload into XML endpoints
        // (discovered from the OpenAPI spec) and poll for a server-side callback. Catches blind XXE that has
        // no in-band oracle (constant response). Zero-FP: the callback is caused only by the server parsing us.
        attackActions.put("xxe", () -> {
            int hits = new XxeProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] XXE probe: " + hits + " endpoint(s) resolved an out-of-band external entity.");
        });

        // SAML SSO probe: reconstruct the SAML surface (SP metadata, ACS, SP-initiated endpoint) from the site
        // map by PROTOCOL signals (metadata content-type / <EntityDescriptor>, SAMLRequest/SAMLResponse params, a
        // `saml` path segment) — never by a vendor name or literal path — then run a zero-FP, non-destructive
        // battery: metadata-hardening reads (unsigned/unencrypted assertions, HTTP-Artifact binding), an ACS
        // stack-trace disclosure oracle (malformed SAMLResponse + strong markers, re-confirmed), OOB XXE at the
        // ACS via Collaborator (same mechanism as the XXE/SSRF probes), unsigned/forged-assertion acceptance
        // (fires only on a real authenticated signal — non-login 302 + fresh session cookie, re-confirmed), and a
        // RelayState/ReturnUrl open redirect. Runs once per host (discovers its own surface). No-op if no SAML.
        attackActions.put("saml", () -> {
            int hits = new SamlProbe(api, scanLog).probe(host, this::withSession);
            scanLog.log("[AI Scanner] SAML probe: " + hits + " SAML SSO finding(s).");
        });

        // Verbose-error / stack-trace disclosure probe: generic, host-wide. Passively scans the site map for strong
        // stack-trace markers and actively POSTs a malformed body to discovered ASP.NET page-method / service-handler
        // endpoints, firing ONCE per host (dedups with SamlProbe's SAML-route finding). Catches the systemic
        // customErrors-Off class Burp misses (it never sends the malformed page-method call). Zero-FP, non-destructive.
        attackActions.put("verberr", () -> {
            int hits = new VerboseErrorProbe(api, scanLog).probe(host, this::withSession);
            scanLog.log("[AI Scanner] verbose-error probe: " + hits + " host-wide disclosure finding(s).");
        });

        // NOTE: CORS misconfiguration is intentionally NOT a custom probe — Burp's native passive scanner
        // already reports it ("Cross-origin resource sharing: arbitrary origin trusted") with correct scope,
        // so a bespoke probe would only duplicate a built-in template.

        // Generic path-traversal / LFI probe (OS-file signature oracle; Burp's coverage is uneven).
        attackActions.put("lfi", () -> {
            PathTraversalProbe lfi = new PathTraversalProbe(api, scanLog);
            lfi.setSourceHints(hints);   // SAST: tag provenance when a source path/LFI sink matches
            int hits = 0;
            for (HttpRequest t : targets) if (lfi.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] path-traversal probe: " + hits + " endpoint(s) leaked an OS file.");
        });

        // OAST SSRF confirmation (Burp Collaborator) — DRIVEN BY THE SAST SSRF HINTS so it tests endpoints the
        // discovery surface dropped (e.g. a self-referential /import?url= that mirrors the app's catch-all page).
        // A callback proves the server fetched our attacker-controlled URL (CWE-918) — deterministic, zero-FP.
        attackActions.put("ssrf", () -> {
            SsrfProbe ssrf = new SsrfProbe(api, scanLog);
            ssrf.setSourceHints(hints);
            String base = targets.isEmpty() ? null : originOf(targets.get(0).url());
            int hits = ssrf.probe(base, targets, this::withSession);
            scanLog.log("[AI Scanner] SSRF probe: " + hits + " endpoint(s) made an out-of-band request (SSRF).");
        });

        // OAST Log4Shell / JNDI confirmation (Burp Collaborator). Sprays ${jndi:ldap://<collab>} into the headers
        // apps log (User-Agent/X-Api-Version/X-Forwarded-For/…) + params; a callback proves a vulnerable Log4j2
        // resolved the lookup (CVE-2021-44228, CWE-917) — unauthenticated RCE, deterministic + zero-FP.
        attackActions.put("log4shell", () -> {
            Log4ShellProbe log4j = new Log4ShellProbe(api, scanLog);
            // Header-only probe: hit the host root even when discovery found no auditable param (targets empty).
            String base = !targets.isEmpty() ? originOf(targets.get(0).url()) : siteMapOrigin(host);
            int hits = log4j.probe(base, targets, this::withSession);
            scanLog.log("[AI Scanner] Log4Shell probe: " + hits + " endpoint(s) resolved a ${jndi:…} out-of-band (Log4Shell RCE).");
        });

        // (Open-redirect probe ran early — see the fast-findings block above.)

        // Generic client-side-restriction bypass + parameter tampering (server-side enforcement of
        // client-only controls: option lists, maxlength, format regexes, computed totals, weak-password).
        attackActions.put("tamper", () -> {
            RestrictionBypassProbe rb = new RestrictionBypassProbe(api, scanLog);
            int hits = 0;
            for (HttpRequest t : targets) if (rb.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] restriction-bypass probe: " + hits + " form(s) accepted a restricted submission.");
        });

        // Cross-Site WebSocket Hijacking: replay each observed WS upgrade with a foreign Origin — a still-successful
        // upgrade on a cookie-authenticated socket means the server never validated Origin (CWE-1385). Reads the WS
        // handshakes the crawl opened (WsObservations + proxy history), so no HTTP target list is needed.
        attackActions.put("cswsh", () -> {
            int hits = new WebSocketCswshProbe(api, scanLog).probe(this::withSession);
            scanLog.log("[AI Scanner] WebSocket CSWSH probe: " + hits + " socket(s) upgrade cross-origin with ambient cookies.");
        });

        // ③ Agentic multi-step flow-engine — the LLM plans the next request from each response (targeting only),
        // every proposal is live-probed, oracle-decided. Reaches chains a single-shot fuzzer can't. LAST in the
        // registry (session primed, creates already POSTed so bodies carry ids/tokens).
        attackActions.put("flow", () -> {
            AiEngine eng = engine != null ? engine.get() : null;
            if (eng != null && eng.isConfigured()) {
                FlowEngine fe = new FlowEngine(eng, scanLog, this::withSession, this::sendAndMeasure);
                if (!hints.isEmpty()) fe.setSourceHintText(hints.hintText(8));   // SAST leads → planner targets them first
                int hits = fe.run(host, targets);
                scanLog.log("[AI Scanner] flow-engine: " + hits + " finding(s) from multi-step chains.");
                // Bridge LLM-reached 2xx endpoints into the site map + targets so the Burp active audit fuzzes them too.
                int added = 0;
                for (HttpRequestResponse rr : fe.reachedResponses()) {
                    try { api.siteMap().add(rr); } catch (Exception ignore) { }
                    if (addTarget(targets, seen, rr.request())) added++;
                }
                if (added > 0) scanLog.log("[AI Scanner] flow-engine: added " + added
                        + " LLM-reached endpoint(s) to the audit surface (site map + Burp active audit).");
            }
        });

        // ── RUN THE REGISTRY ── ScanPhases' attack list IS the battery: iterate it in order and dispatch each bound
        // action. Title, ordering, and module-filter enablement all come from ScanPhases (the single source); a probe
        // cannot run without a registry entry, and the consistency check below flags either side missing (no drift).
        {
            java.util.Set<String> keys = new java.util.HashSet<>();
            for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.attackModules()) keys.add(ph.key);
            for (String k : attackActions.keySet()) if (!keys.contains(k)) scanLog.log("[AI Scanner] WARN: attack action '" + k + "' has no ScanPhases entry (drift).");
            for (String k : keys) if (!attackActions.containsKey(k)) scanLog.log("[AI Scanner] WARN: ScanPhases module '" + k + "' has no bound action (drift).");
        }
        // Mint the SECOND identity B here — the auth flow has definitely settled by now (unlike a fixed point in the
        // crawl orchestration, which can race the async login), and this is the single chokepoint before every
        // access-control probe reads session.cookieHeaderB()/bearerB(). Best-effort + idempotent.
        if (secondIdentityMinter != null && session != null && session.authenticated() && !session.hasSecondIdentity()) {
            try { secondIdentityMinter.run(); } catch (Throwable t) { scanLog.debug("[AI Scanner] second-identity minter: " + t); }
        }
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.attackModules()) {
            if (cancelled()) return null;
            Runnable action = attackActions.get(ph.key);
            if (action == null) continue;
            try {
                scanLog.phase(ph);   // registry-sourced title + module filter + step count (throws PhaseSkipped/ScanStopped)
                action.run();
            } catch (Throwable t) {
                scanLog.debug("[AI Scanner] " + ph.key + " probe skipped: " + t);
            }
        }

        scanLog.log("[AI Scanner] discovery done: " + targets.size()
                + " parameterized request(s) for " + host + " — submitting to Burp active audit…");

        // User hit Stop during the probe battery (each probe swallowed the phase() ScanStopped) → don't now submit
        // the long native Burp audit; return what the probes already raised as live issues.
        if (cancelled()) return null;
        return scanRequests(targets, host);
    }

    /**
     * Audit the auth-flow pages (login/signin) in a SEPARATE audit — run this LAST, once the
     * authenticated /bank audit is done, because fuzzing the login endpoint invalidates the session.
     * Here that no longer matters, so we still get login SQLi / auth-bypass coverage without sabotage.
     */
    // Auth-flow pages for the load-free blind-SQLi pass. BROADER than SESSION_RESET (which excludes
    // signup/register) — the boolean/blind signup-SQLi lives on the registration endpoint.
    private static final java.util.regex.Pattern AUTH_PAGE = java.util.regex.Pattern.compile(
            "(?i)/(login|signin|sign-in|logon|signup|sign-up|register|registration|authenticate|auth)(/|$|\\.).*");

    public Audit auditAuthPages(String host) {
        // Robustness pass (runs LAST, target idle): re-run the custom blind-SQLi oracle over auth-flow
        // requests (login/signin/SIGNUP/register). The in-scan BlindSqli during scanDiscovered can be
        // starved when LLM synthesis adds probe load, and SESSION_RESET excludes signup — so anchoring
        // this coverage here (load-free) prevents the 2/8→1/8 regression on the signup-SQLi finding.
        try {
            BlindSqliProbe bsp = new BlindSqliProbe(api, scanLog);
            Set<String> bseen = new HashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                if (!host.equalsIgnoreCase(hostOf(req.url()))) continue;
                if (!AUTH_PAGE.matcher(stripQuery(req.url())).find()) continue;
                if (!hasFuzzable(req)) continue;
                if (!bseen.add(req.method() + " " + stripQuery(req.url()))) continue;
                bsp.probe(req);
            }
            bsp.emitCollapsed();   // flush collected auth-page SQLi (else they'd be recorded but never emitted)
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] auth-page blind-SQLi pass skipped: " + t);
        }

        Set<String> seen = new HashSet<>();
        List<HttpRequest> auth = new ArrayList<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpRequest req = rr.request();
            if (!host.equalsIgnoreCase(hostOf(req.url()))) continue;
            if (!AuthenticatedExplorer.SESSION_RESET.matcher(stripQuery(req.url())).matches()) continue;
            if (!hasFuzzable(req)) continue;
            StringBuilder key = new StringBuilder(req.method()).append(' ').append(stripQuery(req.url()));
            for (ParsedHttpParameter p : fuzzableParams(req)) key.append('|').append(p.name());
            if (!seen.add(key.toString())) continue;
            auth.add(req);
        }
        if (auth.isEmpty()) return null;
        try {
            Audit audit = newAudit();
            if (audit == null) return null;   // Community: no native audit (login SQLi still covered by BlindSqliProbe)
            int added = 0;
            for (HttpRequest req : auth) {
                HttpRequest r = seedEmptyJson(req);          // no session — login is pre-auth
                List<Range> ranges = fuzzableRanges(r);
                ranges.addAll(jsonBodyRanges(r));            // login SQLi/auth-bypass lives in JSON creds
                if (ranges.isEmpty()) continue;
                audit.addRequest(r, ranges);
                added++;
                scanLog.log("[AI Scanner]   audit (auth page, separate) @ " + r.method() + " "
                        + stripQuery(r.url()) + " → " + paramSummary(r));
            }
            if (added == 0) { audit.delete(); return null; }
            scanLog.log("[AI Scanner] submitted " + added + " login/signin request(s) to a SEPARATE audit "
                    + "(runs last; may end the session, which no longer matters).");
            return audit;
        } catch (Throwable t) {
            api.logging().logToError("[AI Scanner] auth-page audit error: " + t);
            return null;
        }
    }

    /**
     * PURE BURP-NATIVE BASELINE (no-extension equivalent). Audits ONLY what Burp's own crawler reached,
     * with Burp's built-in active checks — NO LLM preflight, NO guided discovery, NO auth injection, NO
     * probes. This is the faithful "what does Burp Pro find on its own" measurement: the extension is just
     * a headless harness here (start Burp's native audit + let AiTriage collect Burp's own FIRM/CERTAIN
     * issues into the report), it contributes zero detection of its own. Used for the benchmark's
     * no-extension baseline column via -Daiscanner.nativeOnly / AISCANNER_NATIVE_ONLY.
     */
    public Audit scanNativeBaseline(String host) {
        scanLog.setBurpNativeAudit(true);   // Burp owns every class; AiTriage counts its native issues (= "native" half)
        Audit audit = newAudit();
        if (audit == null) {                // Community edition has no native active audit → nothing to baseline
            scanLog.log("[AI Scanner] native baseline: Burp Community has no active audit — baseline is 0 by definition.");
            return null;
        }
        Set<String> seen = new HashSet<>();
        int added = 0;
        // Audit EVERY crawled request for this host, INCLUDING login/signin pages: with no session to protect
        // (native baseline never authenticates), auditing auth forms is exactly what a plain Burp crawl+audit
        // does, and it's where Burp finds login SQLi. Mirror auditAuthPages()'s range construction.
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpRequest req = rr.request();
            if (req == null || !host.equalsIgnoreCase(hostOf(req.url()))) continue;
            if (STATIC.matcher(pathOf(req)).matches()) continue;
            StringBuilder key = new StringBuilder(req.method()).append(' ').append(stripQuery(req.url()));
            for (ParsedHttpParameter p : fuzzableParams(req)) key.append('|').append(p.name());
            if (!seen.add(key.toString())) continue;
            List<Range> ranges = fuzzableRanges(req);
            ranges.addAll(jsonBodyRanges(req));
            if (ranges.isEmpty()) continue;
            try { audit.addRequest(req, ranges); added++; } catch (Throwable ignore) { }
        }
        scanLog.log("[AI Scanner] native baseline: submitted " + added + " crawled request(s) to Burp's built-in "
                + "active audit (no auth, no discovery, no probes — pure Burp).");
        if (added == 0) { try { audit.delete(); } catch (Throwable ignore) { } return null; }
        return audit;
    }

    /**
     * Wait for the native audit to wind down, then print a severity tally and list the
     * confirmed vulnerabilities (HIGH/MEDIUM first). Marks the pipeline idle. No AI triage.
     */
    public void summarize(Audit audit, String host) { summarize(audit, host, true); }

    /**
     * @param finalPhase true only for the LAST audit of a run (the separate login/signin audit). The full
     *   SCAN COMPLETE banner + site-map issue dump are emitted ONLY when finalPhase — so they print ONCE at
     *   the end instead of once per intermediate audit (the main authenticated audit prints a concise
     *   one-line completion instead). Both phases still WAIT for their audit to finish.
     */
    public void summarize(Audit audit, String host, boolean finalPhase) {
        try {
            if (audit == null) {
                scanLog.phase("Idle — scan complete (nothing to audit)");
                scanLog.log("[AI Scanner] === scan complete for " + host + ": no auditable parameters ===");
                // NOTE: Burp's PASSIVE findings (missing HSTS/CSP, version disclosure, cookie flags) are already
                // logged in real time — and captured to the report — by AiTriage's audit-issue handler as Burp
                // files them during the crawl. No separate harvest here (that double-logged them).
                logAiUsage();
                writeReport();
                return;   // exit is triggered ONCE by the caller after ALL audits (see crawlAndScan)
            }
            // Completion = both request count AND issue count quiet for QUIET_STEPS×5s. Using issue
            // count too matters: OOB/Collaborator findings can trickle in long after the last request,
            // so a request-only heuristic would declare "complete" before they arrive.
            // Completion = the audit has ACTUALLY started (requestCount grew past 0) and then both
            // request count AND issue count stay quiet for QUIET_STEPS×5s. We deliberately do NOT
            // trust Burp's statusMessage ("100%/complete" is reported the moment requests are sent,
            // long before OOB/Collaborator findings trickle in) — trusting it made this return early
            // and let the separate login audit run CONCURRENTLY, dropping the session mid-scan.
            // Poll once a MINUTE (not every few seconds) — the audit runs for minutes and a coarse,
            // readable heartbeat is what the user asked for. Completion = the audit actually started
            // (requestCount grew) and then request+issue counts stay flat for QUIET_STEPS polls.
            // NOTE: a single quiet minute was too aggressive — Burp's active audit has multi-minute gaps
            // between modules/confirmation passes where request+issue counts plateau, so QUIET_STEPS=1
            // declared "done" mid-audit and truncated a different tail of findings each run. Back to 2.
            final long POLL_MS = 60_000L;
            final int QUIET_STEPS = 4;    // 4 quiet minutes → done. 2 still truncated the separate login/signup
                                          // SQLi audit when LLM-synthesized endpoints add load (2/8→1/8);
                                          // Burp's own finish/complete status stays the primary signal, this is fallback.
            int lastReq = -1, lastIss = -1, stable = 0;
            boolean started = false;
            // NOTE: issues are logged in real-time (deduped) by AiTriage's audit-issue handler — we do NOT
            // re-log them here (that produced 2-3 duplicate lines per finding in two different formats).
            // 50-min cap: Burp's active audit of a many-module app (DVWA) is slow — dominated by time-based
            // SLEEP payloads (~35 req/min) — and a 30-min cap cut it off MID-audit, landing a different
            // partial finding-subset each run. Give it room; the real stop is Burp's own "finished" status.
            long deadline = System.currentTimeMillis() + Long.getLong("aiscanner.auditDeadlineMinutes", 50L) * 60 * 1000L;
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(POLL_MS);
                // A transient error from Burp's audit API (e.g. querying it right after startAudit)
                // must NOT abort the wait — otherwise summarize() returns early and the separate
                // login audit runs CONCURRENTLY, dropping the session. Ride past per-iteration errors.
                try {
                    int c = audit.requestCount();
                    int ic = hostIssues(host).size();
                    if (c > 0) started = true;
                    String sm = safeStatus(audit);
                    // AUTHORITATIVE completion: Burp itself reports the audit finished. This is the accurate
                    // signal for these targets (no OOB/Collaborator checks → no late trickle), and it lets a
                    // slow audit run to TRUE completion instead of being cut by a quiet-timeout or the
                    // deadline while still scanning (which truncated findings).
                    if (started && sm.toLowerCase().matches("(?s).*(finish|complete|abandon|cancel).*")) {
                        scanLog.log("[AI Scanner] audit finished (Burp status: " + trunc(sm, 60) + ")");
                        break;
                    }
                    if (c == lastReq && ic == lastIss) {
                        if (started && ++stable >= QUIET_STEPS) break;   // fallback: quiet if status never says finished
                    } else {
                        stable = 0; lastReq = c; lastIss = ic;
                    }
                    scanLog.log("[AI Scanner] auditing… requests: " + c + ", findings: " + scanLog.findingCount()
                            + ", quiet: " + stable + "m"
                            + (sm.isBlank() ? "" : "  [" + trunc(sm, 80) + "]"));
                } catch (Throwable t) {
                    scanLog.debug("[AI Scanner] audit monitor tick error (continuing): " + t);
                }
            }

            List<AuditIssue> issues = hostIssues(host);
            int high = 0, medium = 0, low = 0, info = 0;
            for (AuditIssue i : issues) {
                switch (i.severity()) {
                    case HIGH: high++; break;
                    case MEDIUM: medium++; break;
                    case LOW: low++; break;
                    default: info++; break;
                }
            }

            // Intermediate audit (the main authenticated audit): concise one-liner only. The full banner +
            // site-map dump + report are emitted once, by the FINAL (auth-page) summarize, so they don't double.
            if (!finalPhase) {
                scanLog.log("[AI Scanner] main audit complete: " + scanLog.findingCount() + " confirmed finding(s), "
                        + audit.requestCount() + " request(s), " + audit.errorCount() + " error(s).");
                logAiUsage();
                writeReport();
                return;
            }

            String authWith = session == null ? "no"
                    : session.hasBearer() ? "yes (bearer token)"
                    : session.has() ? "yes (session cookie)"
                    : "no";
            scanLog.phase("Idle — scan complete");
            scanLog.log("[AI Scanner] ===================== SCAN COMPLETE (" + host + ") =====================");
            logBenchmarkTally();   // copy-pasteable, matches the harness metric() exactly (no report file needed)
            scanLog.log("[AI Scanner] authenticated: " + authWith
                    + "   |   audit requests: " + audit.requestCount() + "   |   errors: " + audit.errorCount());
            if (!issues.isEmpty()) {
                scanLog.log("[AI Scanner] issues: " + issues.size()
                        + "  →  HIGH: " + high + " | MEDIUM: " + medium + " | LOW: " + low + " | INFO: " + info);
            } else {
                // audit.issues() is unsupported on this Burp build — report the live count instead of a
                // misleading "0". The findings themselves were logged above as they were confirmed.
                scanLog.log("[AI Scanner] confirmed findings (reported live above): " + scanLog.findingCount()
                        + "   (per-audit severity tally unavailable on this Burp build)");
            }
            // (No per-finding recap here — each finding was already logged ONCE, in real time, by AiTriage.
            // Re-listing them added duplicate lines to the log AND the report; the count tally above suffices.)
            scanLog.log("[AI Scanner] ==========================================================================");
            emitManualNextSteps();   // analyst hand-off: what the scanner does NOT auto-confirm → test by hand
            // DIAGNOSTIC: are our own AI issues actually in the site map (Target→Issues)? audit.issues()
            // above only lists the active-audit TASK's issues; our probe/flow findings are added via
            // siteMap().add(). Confirm they landed so we know if "not on dashboard" is a display nuance.
            try {
                List<AuditIssue> sm = api.siteMap().issues();
                long ai = sm.stream().filter(i -> i.name() != null && i.name().startsWith("AI:")).count();
                scanLog.log("[AI Scanner] site-map issues: " + sm.size() + " total, " + ai + " AI-raised");
                sm.stream().filter(i -> i.name() != null && i.name().startsWith("AI:")).limit(10)
                        .forEach(i -> scanLog.log("[AI Scanner]    AI issue in site map: " + i.name() + " @ " + i.baseUrl()));
            } catch (Throwable t) { scanLog.log("[AI Scanner] site-map issue query failed: " + t); }
            logAiUsage();    // estimated Burp AI credit burn for this scan (Burp AI is paid — keep it visible)
            writeReport();   // machine-readable findings for the benchmark harness (-Daiscanner.report / AISCANNER_REPORT)
            // NOTE: exitOnComplete is NOT triggered here — summarize() runs once PER audit (main + login), and
            // exiting after the first one killed Burp while the login audit was still sending requests (NPEs on a
            // null api.http()). The caller (crawlAndScan) calls exitIfRequested() ONCE after ALL audits finish.
        } catch (InterruptedException ie) {
            // Interrupt = extension unloaded / thread cancelled — do NOT exit Burp on this path.
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            scanLog.log("[AI Scanner] summary failed (visible so it's not silent): " + t);
            api.logging().logToError("[AI Scanner] summary failed: " + t);
        }
    }

    /** True when -Daiscanner.exitOnComplete / AISCANNER_EXIT_ON_COMPLETE is set to a truthy value. */
    private static boolean exitOnComplete() {
        String v = System.getProperty("aiscanner.exitOnComplete");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_EXIT_ON_COMPLETE");
        return v != null && (v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes"));
    }

    /**
     * When {@code -Daiscanner.exitOnComplete} is set (an unattended CLI/CI run — OFF by default), shut Burp down
     * cleanly via the sanctioned {@code api.burpSuite().shutdown()} so the foreground process returns and a
     * wrapper can assert pass/fail. We deliberately never hard-kill the JVM — an extension must not terminate
     * the process (BApp store rule); shutdown() is the only supported path, and if it is unavailable we simply
     * log and let the caller/CI time out.
     */
    public void exitIfRequested() {
        if (!exitOnComplete()) return;   // default: never triggers — normal GUI use is unaffected
        scanLog.log("[AI Scanner] exitOnComplete set — requesting a clean Burp shutdown so the CLI run can return.");
        try { Thread.sleep(1500L); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }  // let the final log/report flush
        try {
            api.burpSuite().shutdown();
        } catch (Throwable t) {
            scanLog.log("[AI Scanner] burpSuite().shutdown() unavailable (" + t + ") — leaving Burp running; close it manually.");
        }
    }

    private volatile Boolean aiUsable = null;   // memoized preflight verdict (a REAL endpoint test costs a round-trip)

    /**
     * REAL preflight: actually pings the selected AI backend (a tiny live call, not just "is a URL set?"). Returns
     * whether the scan may proceed. Returns FALSE only when the user explicitly selected a self-hosted LLM
     * ({@link AiEngine#requiresReachableEndpoint()}) that is unconfigured or NOT answering — the caller then ABORTS
     * instead of running a silently-degraded, AI-less scan. Memoized so we test the endpoint once per run.
     */
    public boolean aiPreflight() {
        if (aiUsable != null) return aiUsable;
        try {
            AiEngine e = engine != null ? engine.get() : null;
            if (e == null) return aiUsable = true;
            boolean required = e.requiresReachableEndpoint();
            if (!e.isConfigured()) {
                if (required) {
                    if (exitOnComplete()) {   // headless/Docker: fail fast
                        scanLog.log("[AI Scanner] !! " + e.name() + " is NOT configured (base URL/key missing) — ABORTING (headless). "
                                + "The local LLM was selected but has no endpoint; set -Daiscanner.baseUrl / AISCANNER_BASE_URL.");
                        return aiUsable = false;
                    }
                    scanLog.log("[AI Scanner] !! " + e.name() + " is NOT configured (base URL/key missing) — continuing "
                            + "WITHOUT AI: deterministic probes + auth + native audit still run; LLM discovery/triage skipped.");
                    return aiUsable = true;
                }
                scanLog.log("[AI Scanner] AI preflight → engine=" + e.name() + " not configured — targeting/triage will degrade. "
                        + "For Burp AI: turn on Settings → AI, reload this extension, and approve its AI-access prompt. "
                        + "Or use a local LLM (AI Scanner Settings) — no Burp AI needed.");
                return aiUsable = true;
            }
            boolean reachable = e.testConnection();
            scanLog.log("[AI Scanner] AI preflight → engine=" + e.name() + ", reachable=" + reachable);
            if (!reachable && required) {
                String err = e.lastError();
                String tail = (err == null || err.isEmpty() ? "" : " (" + err + ")");
                if (exitOnComplete()) {   // headless/Docker: fail fast — a silently AI-less report is worse than none
                    scanLog.log("[AI Scanner] !! " + e.name() + " endpoint did NOT answer the health check" + tail
                            + " — ABORTING (headless): the local LLM was selected but is down. Fix the endpoint or use -Daiscanner.provider=BURP_AI.");
                    return aiUsable = false;
                }
                // interactive: degrade, don't abort — the deterministic layer (auth, identity sweep, probes,
                // exercise-writes, native audit) still delivers findings without the LLM.
                scanLog.log("[AI Scanner] !! " + e.name() + " endpoint did NOT answer the health check" + tail
                        + " — continuing WITHOUT AI: deterministic probes + auth + native audit still run; LLM-assisted discovery/triage is skipped.");
                return aiUsable = true;
            }
            if (!reachable)
                scanLog.log("[AI Scanner] !! AI backend not reachable — continuing; targeting/triage will degrade.");
            return aiUsable = true;
        } catch (Throwable t) {
            scanLog.log("[AI Scanner] AI preflight error (continuing): " + t);
            return aiUsable = true;   // a preflight bug must never block a run
        }
    }

    /** Log the estimated Burp AI credit burn for this scan (Burp AI is paid; the tally is text-length-estimated). */
    private void logAiUsage() {
        try {
            long calls = com.ioactive.aiscanner.engine.MontoyaAiEngine.totalCalls();
            if (calls <= 0) return;   // LOCAL_LLM run (or no AI calls) — nothing to bill
            // NOTE: no token estimate — chars/4 was unreliable, so we report only the EXACT call count. Real credit
            // cost comes from Burp's balance (below), which lags its cache.
            scanLog.log("[AI Scanner] ===== Burp AI usage this scan: " + calls + " call(s) =====");
            // REAL credits: start (snapshotted on the first call) vs end (Burp's last-synced balance).
            String start = com.ioactive.aiscanner.engine.MontoyaAiEngine.scanStartCredits();
            String end = com.ioactive.aiscanner.engine.MontoyaAiEngine.readCreditBalance();
            if (start != null)
                scanLog.log("[AI Scanner] Burp AI credits available (start of scan): "
                        + com.ioactive.aiscanner.engine.MontoyaAiEngine.displayBalance(start));
            if (end != null) {
                // Burp's cached balance (WorkspaceConfig.json) only refreshes on sync/exit, so end==start is the
                // COMMON case even after 100s of billed calls → a "spent: 0.0000" reading would be flat-out wrong.
                // Only report a credit delta when the balance ACTUALLY dropped; otherwise say it hasn't reflected
                // yet and point at the token estimate (the true in-scan spend signal).
                String note;
                try {
                    double delta = start != null ? Double.parseDouble(start) - Double.parseDouble(end) : 0;
                    if (start != null && delta > 0.00005)
                        note = String.format("  |  spent this scan: %.4f credits", delta);
                    else
                        note = "  |  spent this scan: NOT yet reflected — Burp's cached balance lags (refreshes on "
                             + "sync/exit); " + calls + " billed call(s) this scan (see above)";
                } catch (NumberFormatException e) { note = ""; }
                scanLog.log("[AI Scanner] Burp AI credits available (end of scan): "
                        + com.ioactive.aiscanner.engine.MontoyaAiEngine.displayBalance(end) + note);
            }
        } catch (Throwable ignore) { }
    }

    /**
     * Analyst hand-off: at the end of a run, surface what the scanner did NOT (and deliberately does not)
     * auto-confirm, so the pentester knows exactly where to take over manually. Emitted to the log (the analyst
     * reads it live) and to a sibling "<report>.manual.txt" when a report path is set — NEVER into the scored
     * findings report (class names there would pollute the benchmark's substring scoring). Fully generic.
     */
    private void emitManualNextSteps() {
        try {
            java.util.List<String> out = new java.util.ArrayList<>();
            out.add("MANUAL NEXT STEPS — analyst hand-off (what the scanner does not auto-confirm)");
            // 1) advisories the tool flagged for human verification (soft / LLM-judged, NOT deterministic)
            java.util.List<String> adv = new java.util.ArrayList<>();
            for (String f : scanLog.findingsReport()) {
                if (f.toLowerCase().contains("needs review") || f.contains("ADVISORY")) adv.add(f);
            }
            if (adv.isEmpty()) {
                out.add("  Advisories to verify: none flagged this run.");
            } else {
                out.add("  Advisories to verify by hand (" + adv.size() + " — LLM-suspected, not deterministically confirmed):");
                for (String a : adv) out.add("    - " + a);
            }
            // 2) classes we deliberately DO NOT auto-confirm (no deterministic oracle of intent) — test by hand
            out.add("  Classes not auto-confirmed (require human judgment) — probe these by hand where the surface fits:");
            String[] manual = {
                "Business logic / workflow abuse (price, quantity, negative values, step-skipping) — no generic oracle of intent",
                "Complex / multi-step authorization (app-specific role & tenant policy beyond the IDOR/BFLA differential)",
                "Multi-step exploit chains (create -> consume, state-dependent flows)",
                "Client-side / DOM-only issues (DOM XSS, postMessage, prototype pollution) — need a rendering browser + interaction",
                "File-upload business rules (allowed type/size/path logic beyond generic traversal/type checks)",
                "Rate-limit / anti-automation / CAPTCHA robustness"
            };
            for (String m : manual) out.add("    - " + m);

            for (String line : out) scanLog.log("[AI Scanner] " + line);

            String path = System.getProperty("aiscanner.report");
            if (path == null || path.isBlank()) path = System.getenv("AISCANNER_REPORT");
            if (path != null && !path.isBlank()) {
                String mp = path.replaceAll("\\.report\\.txt$", "").replaceAll("\\.txt$", "") + ".manual.txt";
                try { java.nio.file.Files.write(java.nio.file.Path.of(mp), out); } catch (Throwable ignore) { }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] manual-next-steps emit failed: " + t);
        }
    }

    /** Write the run's findings to -Daiscanner.report / AISCANNER_REPORT so the benchmark harness can score. */
    /** Log a copy-pasteable BENCHMARK tally that mirrors the harness {@code metric()} EXACTLY (count of report
     *  lines starting with VULNERABILITY: / HIGH / MED). Printed at scan end so a GUI run (no report file) can be
     *  scored from the log alone — paste it and the score is the number on the header line. */
    private void logBenchmarkTally() {
        try {
            // Decompose the score by SOURCE, because the two halves have very different run-to-run stability:
            //   • deterministic-oracle — OUR probes (logged "VULNERABILITY: …"): fixed payloads + deterministic
            //     oracles → should be REPEATABLE run-to-run on an identical target.
            //   • native-Burp-audit  — Burp's own FIRM/CERTAIN issues (logged "HIGH/MED (CONF) …"): async +
            //     time-bounded + confidence-upgrade churn → the VARIABLE half.
            // Splitting them shows exactly which half moves when a re-measure differs (and the deterministic
            // half is the zero-FP number to compare models on).
            java.util.List<String> det = new java.util.ArrayList<>();
            java.util.List<String> nat = new java.util.ArrayList<>();
            for (String s : scanLog.findingsReport()) {
                String t = s == null ? "" : s.trim();
                if (t.startsWith("VULNERABILITY:")) det.add(t);
                else if (t.startsWith("HIGH ") || t.startsWith("MED ")) nat.add(t);
            }
            int total = det.size() + nat.size();
            scanLog.log("[AI Scanner] ===== BENCHMARK SCORE (VULNERABILITY + HIGH + MED) = " + total
                    + "   →   deterministic-oracle: " + det.size() + " | native-Burp-audit: " + nat.size()
                    + "   |   time: " + scanLog.scanElapsed() + " (" + scanLog.scanElapsedSeconds() + "s) =====");
            // Breakdown by CRITICALITY + CATEGORY (over the scored findings) — so the benchmark compares not just a
            // raw count but the severity mix and which vuln classes each model/config surfaced.
            java.util.List<String> all = new java.util.ArrayList<>(det); all.addAll(nat);
            java.util.Map<String,Integer> bySev = new java.util.LinkedHashMap<>();
            for (String s : new String[]{"HIGH","MEDIUM","LOW","INFO"}) bySev.put(s, 0);
            java.util.Map<String,Integer> byCat = new java.util.TreeMap<>();
            for (String c : all) {
                String sev = sevOf(c), cat = catOf(c);
                bySev.merge(sev, 1, Integer::sum);
                byCat.merge(cat, 1, Integer::sum);
            }
            scanLog.log("[AI Scanner]   by criticality:  HIGH: " + bySev.get("HIGH") + " | MEDIUM: " + bySev.get("MEDIUM")
                    + " | LOW: " + bySev.get("LOW") + " | INFO: " + bySev.get("INFO"));
            // …and split by SOURCE (deterministic probes vs Burp-native), the exact rows the benchmark table uses.
            int[] ds = sevCounts(det), ns = sevCounts(nat);
            scanLog.log("[AI Scanner]   by criticality — deterministic:  HIGH: " + ds[0] + " | MEDIUM: " + ds[1] + " | LOW: " + ds[2]);
            scanLog.log("[AI Scanner]   by criticality — native:         HIGH: " + ns[0] + " | MEDIUM: " + ns[1] + " | LOW: " + ns[2]);
            StringBuilder cats = new StringBuilder();
            for (java.util.Map.Entry<String,Integer> e : byCat.entrySet())
                cats.append(cats.length() > 0 ? " | " : "").append(e.getKey()).append(": ").append(e.getValue());
            scanLog.log("[AI Scanner]   by category (" + byCat.size() + " classes):  " + cats);
            int i = 1;
            scanLog.log("[AI Scanner]   -- deterministic-oracle (" + det.size() + ") — our probes, repeatable --");
            for (String c : det) scanLog.log("[AI Scanner]   " + (i++) + ". [" + sevOf(c) + "] " + (c.length() > 175 ? c.substring(0, 175) + "…" : c));
            scanLog.log("[AI Scanner]   -- native-Burp-audit (" + nat.size() + ") — Burp FIRM/CERTAIN, variable --");
            for (String c : nat) scanLog.log("[AI Scanner]   " + (i++) + ". [" + sevOf(c) + "] " + (c.length() > 175 ? c.substring(0, 175) + "…" : c));
            String llm = com.ioactive.aiscanner.engine.LlmTiming.summary();
            if (llm != null) scanLog.log("[AI Scanner]   " + llm + "  (LLM wait is part of the total time above)");
            scanLog.log("[AI Scanner] ===== END BENCHMARK SCORE (" + total + " = " + det.size() + " det + " + nat.size() + " native) =====");
        } catch (Throwable t) { scanLog.debug("[AI Scanner] benchmark tally failed: " + t); }
    }

    /** [HIGH, MEDIUM, LOW] counts for a list of report lines (INFO folded out — never scored). */
    private static int[] sevCounts(java.util.List<String> lines) {
        int h = 0, m = 0, l = 0;
        for (String s : lines) {
            switch (sevOf(s)) {
                case "HIGH": h++; break;
                case "MEDIUM": m++; break;
                case "LOW": l++; break;
                default: break;
            }
        }
        return new int[]{h, m, l};
    }

    /** Criticality of a report line. Native lines carry it as a prefix; our "VULNERABILITY:" lines
     *  get it from IssueLibrary (the same class→severity map that raiseAiIssue() files with). */
    private static String sevOf(String line) {
        String t = line == null ? "" : line.trim();
        if (t.startsWith("HIGH ")) return "HIGH";
        if (t.startsWith("MED ")) return "MEDIUM";
        if (t.startsWith("LOW ")) return "LOW";
        if (t.startsWith("INFO ")) return "INFO";
        if (t.startsWith("VULNERABILITY:")) {
            try {
                burp.api.montoya.scanner.audit.issues.AuditIssueSeverity s = IssueLibrary.describe(catOf(t)).severity;
                if (s == burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH) return "HIGH";
                if (s == burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM) return "MEDIUM";
                if (s == burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW) return "LOW";
                return "INFO";
            } catch (Throwable e) { return "HIGH"; }  // our probe findings are actionable by construction
        }
        return "INFO";
    }

    /** Vuln category/class of a report line, stripped of the severity/confidence prefix and the URL tail. */
    private static String catOf(String line) {
        String t = line == null ? "" : line.trim();
        if (t.startsWith("VULNERABILITY:")) {
            String c = t.substring("VULNERABILITY:".length()).trim();
            int at = c.indexOf("  @"); if (at < 0) at = c.indexOf(" @");
            if (at > 0) c = c.substring(0, at);
            return c.trim();
        }
        String c = t.replaceFirst("^(HIGH|MED|LOW|INFO)\\s+\\([A-Za-z]+\\)\\s*", "")
                    .replaceFirst("^(HIGH|MED|LOW|INFO)\\s+", "");
        int at = c.indexOf(" @"); if (at > 0) c = c.substring(0, at);
        return c.trim();
    }

    /** Machine-readable '#'-prefixed summary lines prepended to the report: elapsed scan time and the severity
     *  mix (total, deterministic vs native split, HIGH/MED/LOW/INFO). The e2e matrix parses these for its
     *  comparative table; metric() ignores '#' lines so the score is unchanged. */
    private java.util.List<String> reportSummaryHeader() {
        java.util.List<String> h = new java.util.ArrayList<>();
        try {
            java.util.List<String> det = new java.util.ArrayList<>();
            java.util.List<String> nat = new java.util.ArrayList<>();
            for (String s : scanLog.findingsReport()) {
                String t = s == null ? "" : s.trim();
                if (t.startsWith("VULNERABILITY:")) det.add(t);
                else if (t.startsWith("HIGH ") || t.startsWith("MED ")) nat.add(t);
            }
            java.util.List<String> scored = new java.util.ArrayList<>(det); scored.addAll(nat);
            int[] all = sevCounts(scored);   // [HIGH, MEDIUM, LOW] over scored lines (INFO folded out)
            int info = 0;
            for (String s : scanLog.findingsReport()) if (s != null && s.trim().startsWith("INFO ")) info++;
            int[] ds = sevCounts(det), ns = sevCounts(nat);
            h.add("# AI Scanner report — build " + com.ioactive.aiscanner.AiScannerExtension.BUILD);
            h.add("# time_seconds=" + scanLog.scanElapsedSeconds() + "  time_hms=" + scanLog.scanElapsed());
            h.add("# findings_total=" + scored.size() + "  deterministic=" + det.size() + "  native=" + nat.size());
            h.add("# severity  HIGH=" + all[0] + "  MEDIUM=" + all[1] + "  LOW=" + all[2] + "  INFO=" + info);
            h.add("# severity_deterministic  HIGH=" + ds[0] + "  MEDIUM=" + ds[1] + "  LOW=" + ds[2]);
            h.add("# severity_native  HIGH=" + ns[0] + "  MEDIUM=" + ns[1] + "  LOW=" + ns[2]);
        } catch (Throwable t) {
            h.add("# report summary unavailable: " + t);
        }
        return h;
    }

    private void writeReport() {
        String path = System.getProperty("aiscanner.report");
        if (path == null || path.isBlank()) path = System.getenv("AISCANNER_REPORT");
        if (path == null || path.isBlank()) return;
        try {
            // Self-recording summary header so the report is self-contained for the benchmark harness: elapsed
            // scan time + severity mix + det/native split, without having to parse the (often overwritten) log.
            // All header lines start with '#', which the harness metric() (^VULNERABILITY:/^HIGH /^MED ) ignores,
            // so scoring is unchanged; the e2e matrix can read '# time_seconds=' / '# severity ' for its table.
            java.util.List<String> out = new java.util.ArrayList<>(reportSummaryHeader());
            out.addAll(scanLog.findingsReport());
            java.nio.file.Files.write(java.nio.file.Path.of(path), out);
            scanLog.log("[AI Scanner] findings report written → " + path);
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] report write failed: " + t);
        }
    }

    /** Pre-scan Burp-AI credit gate. When Burp AI is the active engine, refuse to start a scan unless the cached
     *  balance is &gt; 1 credit (a scan that begins with ≤1 credit would immediately exhaust mid-run). Returns a
     *  human reason string when the scan MUST be blocked, or null when it's OK to proceed. Only applies to Burp AI:
     *  a local LLM / no-AI run has no credits, so it always returns null (never blocked). An unreadable balance is
     *  treated as "unknown" and does NOT block (we can't prove exhaustion — the reactive error-signature halt still
     *  covers a true mid-scan run-out). The &gt;1 threshold is overridable via -Daiscanner.minCredits. */
    public String creditGateReason() {
        AiEngine eng = engine();
        if (eng == null || eng.name() == null || !eng.name().toLowerCase().contains("burp ai")) return null;
        if (com.ioactive.aiscanner.engine.MontoyaAiEngine.creditsExhausted())
            return "Burp AI credits already exhausted this session";
        double min = 1.0;
        try { min = Double.parseDouble(System.getProperty("aiscanner.minCredits", "1")); } catch (Exception ignore) { }
        double bal = com.ioactive.aiscanner.engine.MontoyaAiEngine.readCreditBalanceValue();
        if (Double.isNaN(bal)) return null;                       // unknown → don't block (reactive halt still applies)
        if (bal > min) return null;                               // enough credits → proceed
        return "Burp AI credit balance (" + Math.round(bal) + ") is not > " + Math.round(min);
    }

    /** Write a report marking the cell as SKIPPED (no scan run), so the benchmark harness records the cell as a
     *  deliberate 0 with a machine-readable reason rather than a missing/errored file. */
    public void writeSkipReport(String reason) {
        String path = System.getProperty("aiscanner.report");
        if (path == null || path.isBlank()) path = System.getenv("AISCANNER_REPORT");
        if (path == null || path.isBlank()) return;
        try {
            java.util.List<String> out = new java.util.ArrayList<>();
            out.add("# AI Scanner report — build " + com.ioactive.aiscanner.AiScannerExtension.BUILD);
            out.add("# SKIPPED: " + (reason == null ? "credit gate" : reason));
            out.add("# time_seconds=0  time_hms=0s");
            out.add("# findings_total=0  deterministic=0  native=0");
            out.add("# severity  HIGH=0  MEDIUM=0  LOW=0  INFO=0");
            java.nio.file.Files.write(java.nio.file.Path.of(path), out);
            scanLog.log("[AI Scanner] skip report written → " + path);
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] skip report write failed: " + t);
        }
    }

    // ---- native audit plumbing ----

    /** True on Burp Community edition (no Scanner API: no native active audit, crawl, or Collaborator). The
     *  extension then runs its own HTTP-based deterministic probes + local-LLM discovery only; Pro/Enterprise
     *  get the full native path. Public so the crawl launcher can gate startCrawl on it too. */
    public boolean communityEdition() {
        try { return api.burpSuite().version().edition() == burp.api.montoya.core.BurpSuiteEdition.COMMUNITY_EDITION; }
        catch (Throwable t) { return false; }
    }

    /** Native active audit — Pro/Enterprise only. Returns null on Community; callers then rely on own probes. */
    private Audit newAudit() {
        if (communityEdition()) return null;
        return api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
    }

    /**
     * Add a request to the audit, restricting Burp's insertion points to the value
     * offsets of the app's own URL/body parameters (so it doesn't waste payloads on
     * headers/cookies/path). Applies the captured session cookie first.
     */
    private boolean addToAudit(Audit audit, HttpRequest req) {
        if (audit == null) return false;   // Community edition — no native audit
        if (STATIC.matcher(pathOf(req)).matches()) return false;
        if (NOISE.matcher(req.url()).matches()) {
            scanLog.debug("[AI Scanner]   skip audit (transport/handshake noise): " + stripQuery(req.url()));
            return false;
        }
        // Never audit login/signin/logout: Burp firing payloads at them = login attempts that
        // invalidate our authenticated session mid-audit, making every /bank/* request bounce to
        // login. Those pages add no injection value (creds/cleartext already covered separately).
        if (AuthenticatedExplorer.SESSION_RESET.matcher(stripQuery(req.url())).matches()) {
            scanLog.debug("[AI Scanner]   skip audit (auth page, would drop session): " + stripQuery(req.url()));
            return false;
        }
        HttpRequest base = withSession(req);
        boolean any = submitToAudit(audit, base, true);
        // Empty-valued params give Burp a zero-length insertion point whose appended
        // payloads never reach value-dependent sinks (e.g. LIKE '%<v>%'). Audit an
        // extra copy with empty params seeded — WITHOUT dropping the original, since
        // some params must legitimately stay empty. Burp's consolidateIssues dedups.
        HttpRequest seeded = seedEmptyJson(seedEmptyParams(base));
        if (seeded != base) any |= submitToAudit(audit, seeded, false);
        return any;
    }

    /** Submit one request to the audit over its fuzzable ranges. {@code llm} adds LLM-suggested
     *  insertion points (skipped on the seeded twin to avoid a duplicate model call). */
    private boolean submitToAudit(Audit audit, HttpRequest finalReq, boolean llm) {
        List<Range> ranges = fuzzableRanges(finalReq);
        ranges.addAll(jsonBodyRanges(finalReq));   // JSON body fields Montoya's parameters() misses
        ranges.addAll(pathSegmentRanges(finalReq)); // id-looking URL path segments (NoSQL/SQLi/XSS/IDOR)
        int paramCount = ranges.size();
        int extra = llm ? addLlmInsertionPoints(finalReq, ranges) : 0;
        if (ranges.isEmpty()) return false;
        audit.addRequest(finalReq, ranges);
        scanLog.addInsertionPoints(paramCount + extra);
        scanLog.log("[AI Scanner]   audit @ " + finalReq.method() + " " + stripQuery(finalReq.url())
                + " → " + paramSummary(finalReq)
                + (extra > 0 ? " [+" + extra + " AI insertion point(s)]" : "")
                + " (" + (paramCount + extra) + " point(s))");
        return true;
    }

    /**
     * Ask the LLM for non-obvious insertion points (JSON fields, path IDs, custom
     * headers) and add byte-offset {@link Range}s for any that don't overlap the
     * app-parameter ranges already collected. Returns how many were added.
     */
    private int addLlmInsertionPoints(HttpRequest req, List<Range> ranges) {
        AiEngine eng = engine != null ? engine.get() : null;
        if (eng == null || !eng.isConfigured()) return 0;
        if (llmInsertBudget.getAndDecrement() <= 0) return 0;   // phase budget spent — deterministic ranges only from here
        String text = req.toString();
        List<String> values;
        try {
            values = eng.suggestInsertionValues(trunc(text, 4000), 6);
        } catch (Throwable t) {
            return 0;
        }
        int added = 0;
        for (String v : values) {
            if (v == null || v.isBlank()) continue;
            int start = text.indexOf(v);
            if (start < 0) continue; // must be verbatim, else we can't locate it
            int end = start + v.length();
            if (overlapsAny(ranges, start, end)) continue;
            ranges.add(Range.range(start, end));
            added++;
            scanLog.log("[AI Scanner]     + AI insertion point: " + trunc(v, 60));
        }
        return added;
    }

    private static boolean overlapsAny(List<Range> ranges, int start, int end) {
        for (Range r : ranges) {
            if (start < r.endIndexExclusive() && r.startIndexInclusive() < end) return true;
        }
        return false;
    }

    /**
     * Probe an improbable path under the same origin to learn a SPA's client-side-routing catch-all. Returns the
     * shell body (trimmed) when the app answers a real (2xx) HTML page for a path that cannot exist — the tell of
     * a single-page app that serves index.html for every route. Returns "" (never null) when there is no catch-all
     * (404/redirect/non-HTML), so the caller treats "" as "checked, none". Uses the session so an authenticated
     * SPA still returns its shell rather than a login gate. Fully generic — the probe path is app-independent.
     */
    private String detectCatchAllShell(String sampleUrl) {
        try {
            URI u = URI.create(sampleUrl);
            String origin = u.getScheme() + "://" + u.getAuthority();
            // an app-independent path that no real router should have a handler for
            String probe = origin + "/aiscanner-nonexistent-" + Integer.toHexString(("probe" + sampleUrl).hashCode());
            HttpRequestResponse r = api.http().sendRequest(
                    withSession(HttpRequest.httpRequestFromUrl(probe).withMethod("GET")),
                    RequestOptions.requestOptions().withResponseTimeout(12000L));
            if (r == null || r.response() == null) return "";
            int st = r.response().statusCode();
            String ct = r.response().headerValue("Content-Type");
            boolean html = ct != null && ct.toLowerCase().contains("text/html");
            if (st >= 200 && st < 300 && html) {
                String body = r.response().bodyToString();
                return body == null ? "" : body.trim();
            }
        } catch (Exception ignore) { }
        return "";
    }

    /** True when this site-map response IS the SPA catch-all shell (a phantom endpoint), not a real handler. */
    private static boolean matchesCatchAllShell(HttpRequestResponse rr, String shell) {
        if (rr == null || rr.response() == null || shell.isEmpty()) return false;
        int st = rr.response().statusCode();
        if (st < 200 || st >= 300) return false;   // a real 3xx/4xx/5xx handler ran — not the shell
        String ct = rr.response().headerValue("Content-Type");
        if (ct == null || !ct.toLowerCase().contains("text/html")) return false;   // real API JSON etc. — keep it
        String b = rr.response().bodyToString();
        if (b == null) return false;
        b = b.trim();
        if (b.equals(shell)) return true;                 // byte-identical shell → definitively phantom
        // tolerate a per-request nonce/csrf in an otherwise-static shell: near-identical length is enough only
        // when both are the same HTML document — keeps this zero-FP (a genuinely different page differs in size).
        int d = Math.abs(b.length() - shell.length());
        return d <= Math.max(48, shell.length() / 50);
    }

    /** Add a fuzzable request to the audit surface. Returns true iff it was newly added (not static/unfuzzable/dup). */
    private boolean addTarget(List<HttpRequest> targets, Set<String> seen, HttpRequest req) {
        return addTarget(targets, seen, req, null);
    }

    /** As {@link #addTarget(List,Set,HttpRequest)}, plus an optional response-schema fingerprint folded into the dedup
     *  key so two same-shape requests that return DIFFERENT field-sets are treated as distinct targets. */
    private boolean addTarget(List<HttpRequest> targets, Set<String> seen, HttpRequest req, String schemaVariant) {
        // Honor Burp's configured scope — the central chokepoint for EVERY audit target. A page can carry a form
        // or link to an external host (e.g. mutillidae's PayPal donate form POSTing to www.paypal.com); harvesting
        // it as a target would send attack payloads to a third party (scope violation + guaranteed false positive:
        // an external service's response varies by its own params, which fools differential oracles). Skip anything
        // Burp says is out of scope. Generic — respects whatever scope the operator/launcher set.
        try { if (!api.scope().isInScope(req.url())) { scanLog.debug("[AI Scanner]   skip out-of-scope: " + stripQuery(req.url())); return false; } }
        catch (Throwable ignore) { }
        // NEVER put login/logout/signin in the probe surface: a probe fuzzing them submits credentials / hits the
        // logout, which INVALIDATES our authenticated session mid-battery — every authenticated endpoint tested
        // afterwards then bounces to login (302) and its sink is missed (observed: reflected-XSS on Zero Bank's
        // /bank/* went from 5→0 in a full run because a prior probe fuzzed /signin.html and logged us out). Login
        // SQLi / weak-creds are covered separately by the auth phase + auditAuthPages() (run in isolation, after).
        if (AuthenticatedExplorer.SESSION_RESET.matcher(stripQuery(req.url())).matches()) {
            scanLog.debug("[AI Scanner]   skip auth page (would drop session if fuzzed): " + stripQuery(req.url()));
            return false;
        }
        if (STATIC.matcher(pathOf(req)).matches()) return false;
        if (!hasFuzzable(req)) return false;
        StringBuilder key = new StringBuilder(req.method()).append(' ').append(hostOf(req.url())).append(pathTemplate(req));
        for (ParsedHttpParameter p : fuzzableParams(req)) {
            key.append('|').append(p.type()).append(':').append(p.name());
            // DISPATCHER endpoints route by a SELECTOR param's VALUE (callType/call/action/op/cmd/…): ONE url, MANY
            // logical operations. Keying only on param NAMES collapses them to a single target (observed: 39 reached
            // dispatcher ops → 1 probed target), so every operation but one goes un-audited. Fold the selector VALUE
            // into the key so each operation is a DISTINCT target. Generic (RPC/dispatcher pattern); only short
            // identifier-like values (an operation name, not free text / an id / a GUID) so it can't explode targets.
            if (SELECTOR_PARAM.matcher(p.name()).matches()) {
                String val = p.value();
                if (val != null && val.length() <= 40 && val.matches("[A-Za-z][A-Za-z0-9_./-]*"))
                    key.append('=').append(val);
            }
        }
        if (schemaVariant != null && !schemaVariant.isEmpty()) key.append("|schema:").append(schemaVariant);
        if (seen.add(key.toString())) {
            targets.add(req);
            scanLog.scanned(req.url(), paramSummary(req));
            scanLog.log("[AI Scanner]   found params @ " + req.method() + " " + stripQuery(req.url())
                    + " → " + paramSummary(req));
            return true;
        }
        return false;
    }

    /** A stable fingerprint of a response's FIELD-SET (record/object keys) — two responses with different columns
     *  hash differently, so the SAME operation over different datasources/tables becomes distinct audit targets. */
    private String responseSchemaSig(HttpRequestResponse rr) {
        try {
            String body = rr.response() == null ? null : rr.response().bodyToString();
            if (body == null || body.isEmpty()) return "";
            // collect distinct JSON key names ("key": ), which characterise the schema regardless of row values/ids
            java.util.TreeSet<String> keys = new java.util.TreeSet<>();
            Matcher m = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:").matcher(body);
            while (m.find() && keys.size() < 120) keys.add(m.group(1));
            if (keys.isEmpty()) return "";
            return Integer.toHexString(String.join(",", keys).hashCode());
        } catch (Throwable t) { return ""; }
    }

    /** Build a concrete, baseline-seeded request for every SAST hint that names a route + param, and add it to
     *  the audit surface. This bridges "source knows the route/param" → "a real request the probes can mutate",
     *  using class-appropriate seeds so JSON.parse/mongo sinks return a valid baseline instead of erroring out. */
    private void synthesizeHintTargets(String host, SourceFindings hints, List<HttpRequest> targets, Set<String> seen) {
        if (hints == null || hints.isEmpty() || targets.isEmpty()) return;
        String base = originOf(targets.get(0).url());
        if (base == null) return;
        int added = 0;
        for (com.ioactive.aiscanner.scan.sast.StaticHint h : hints.all()) {
            if (!h.hasEndpoint() || !h.hasParam()) continue;
            try {
                String path = h.path.replaceAll("\\{[^}]*}", "1");
                if (!path.startsWith("/")) path = "/" + path;
                String method = h.method.isBlank() ? "GET" : h.method.toUpperCase();
                String abs = base.replaceFirst("/+$", "") + path;
                List<String> ps = new ArrayList<>();
                ps.add(h.paramName);
                for (String p : h.params) if (!ps.contains(p) && !p.isBlank()) ps.add(p);
                HttpRequest req;
                if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                    StringBuilder sb = new StringBuilder("{");
                    for (int i = 0; i < ps.size(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append('"').append(ps.get(i)).append("\":\"").append(hintSeed(ps.get(i))).append('"');
                    }
                    req = HttpRequest.httpRequestFromUrl(abs).withMethod(method)
                            .withAddedHeader("Content-Type", "application/json").withBody(sb.append('}').toString());
                } else {
                    req = HttpRequest.httpRequestFromUrl(abs).withMethod(method);
                    for (String p : ps) req = req.withAddedParameters(HttpParameter.urlParameter(p, hintSeed(p)));
                }
                if (!host.equalsIgnoreCase(hostOf(req.url()))) continue;
                if (addTarget(targets, seen, req)) added++;
            } catch (Throwable ignore) { }
        }
        if (added > 0) scanLog.log("[AI Scanner] SAST: synthesized " + added
                + " concrete hint-target(s) (route+param+baseline) into the audit surface.");
    }

    /** Baseline value for a synthesized hint param: a resolvable host for command/host-lookup sinks (so the
     *  time-based command oracle has a valid base), else a harmless numeric "1" (valid for id/JSON.parse sinks). */
    private static String hintSeed(String name) {
        String n = name == null ? "" : name.toLowerCase();
        if (n.matches(".*(host|ip|addr|ping|target|dns|url|domain).*")) return "127.0.0.1";
        return "1";
    }

    /** Send one request and measure it, computing the flow-engine's anti-hallucination {@code live} gate. */
    StepResult sendAndMeasure(HttpRequest req) {
        long t0 = System.nanoTime();
        HttpRequestResponse r;
        try { r = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)); }
        catch (Throwable t) { return StepResult.dead((System.nanoTime() - t0) / 1_000_000L); }
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        if (r == null || r.response() == null) return StepResult.dead(ms);
        int st = r.response().statusCode();
        boolean live = (st >= 200 && st < 400) || st == 401 || st == 403;   // real endpoint even if authz-blocked
        return new StepResult(st, r.response().bodyToString(), ms, r, live);
    }

    private HttpRequest withSession(HttpRequest req) {
        HttpRequest r = req;
        if (session != null && session.has()) r = r.withHeader("Cookie", session.cookieHeader());
        // Token/JWT auth (OpenAPI/SPA style): attach the captured bearer to every audited request
        // so authenticated-only endpoints are actually reachable. Generic — driven by capture, not host.
        if (session != null && session.hasBearer()) r = r.withHeader("Authorization", "Bearer " + session.bearer());
        // Request-signature gate: if the app handed us a signing key at auth time, sign each request (last, so
        // the signature covers the final method/path/body) — otherwise the protected API returns "Missing
        // request signature" and every authenticated probe is wasted. No-op when no signing key was captured.
        if (session != null && session.hasSigningKey())
            r = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKey()).sign(r);
        return r;
    }

    /** As {@link #withSession} but authenticates as the SECOND identity B (for true cross-user access-control
     *  differentials). Falls back to the request unchanged when no second identity was minted. */
    private HttpRequest withSessionB(HttpRequest req) {
        HttpRequest r = req;
        if (session == null || !session.hasSecondIdentity()) return r;
        if (!session.cookieHeaderB().isBlank()) r = r.withHeader("Cookie", session.cookieHeaderB());
        if (session.hasBearerB()) r = r.withHeader("Authorization", "Bearer " + session.bearerB());
        if (session.hasSigningKeyB())
            r = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKeyB()).sign(r);
        return r;
    }

    /**
     * Return a response with an UNCOMPRESSED body. Burp's sendRequest() returns the raw response, so a
     * gzip/deflate body (any compressing proxy/CDN — ngrok, Cloudflare, nginx gzip) reaches bodyToString() as
     * compressed bytes, and HTML/JS mining then finds 0 &lt;script src&gt;/endpoints. Decompressing at the fetch
     * source (so the site-map entry is plain text) fixes every downstream reader without wrapping any of them.
     * No-op when the body isn't compressed or the codec is one the JDK lacks (brotli).
     */
    public static burp.api.montoya.http.message.responses.HttpResponse decompress(
            burp.api.montoya.http.message.responses.HttpResponse resp) {
        try {
            if (resp == null) return resp;
            byte[] raw = resp.body().getBytes();
            if (raw == null || raw.length < 2) return resp;
            String enc = resp.hasHeader("Content-Encoding") ? resp.headerValue("Content-Encoding") : null;
            String el = enc == null ? "" : enc.toLowerCase();
            int b0 = raw[0] & 0xFF, b1 = raw[1] & 0xFF;
            // Detect the codec by MAGIC BYTES, not just the header: Burp can hand back a compressed body with the
            // Content-Encoding header stripped, so a header-only check misses it. gzip=1f8b; zlib/deflate=78 xx.
            // Generic — works for ngrok/CDN/nginx compression whether or not the header survives.
            boolean gzip    = (b0 == 0x1f && b1 == 0x8b) || el.contains("gzip");
            boolean zlib    = b0 == 0x78 && (b1 == 0x01 || b1 == 0x9c || b1 == 0xda);
            boolean deflate = !gzip && (zlib || el.contains("deflate"));
            if (!gzip && !deflate) return resp; // plain, or brotli (no JDK codec) — leave as-is
            byte[] out;
            if (gzip) out = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(raw)).readAllBytes();
            else {
                // zlib-wrapped inflates directly; a raw (headerless) deflate stream needs nowrap=true — try both.
                try { out = new java.util.zip.InflaterInputStream(new java.io.ByteArrayInputStream(raw)).readAllBytes(); }
                catch (Throwable t) {
                    out = new java.util.zip.InflaterInputStream(new java.io.ByteArrayInputStream(raw),
                            new java.util.zip.Inflater(true)).readAllBytes();
                }
            }
            burp.api.montoya.http.message.responses.HttpResponse r =
                    resp.withBody(burp.api.montoya.core.ByteArray.byteArray(out));
            if (enc != null) r = r.withRemovedHeader("Content-Encoding");
            return r;
        } catch (Throwable t) { return resp; }
    }

    /** Convenience: decompress the response inside an HttpRequestResponse (keeps the original request). */
    public static HttpRequestResponse decompress(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return rr;
        return HttpRequestResponse.httpRequestResponse(rr.request(), decompress(rr.response()));
    }

    // ---- JSON body insertion points (Montoya doesn't parse JSON into parameters()) ----

    /** True when the request carries a non-empty JSON body (any Content-Type containing "json"). */
    private static boolean isJsonBody(HttpRequest req) {
        try {
            String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
            return ct != null && ct.toLowerCase().contains("json") && !req.bodyToString().isBlank();
        } catch (Throwable t) { return false; }
    }

    // RHS scalar of  "key": <value>  — a JSON string ("...") or number. Group 1 = the value token.
    // The string body is the UNROLLED form  [^"\\]*(?:\\.[^"\\]*)*  — NOT  (?:[^"\\]|\\.)*  : the latter iterates
    // the group once PER CHARACTER and recurses in java.util.regex, overflowing the stack on a long JSON value
    // (dvws /api/v2/passphrase). The unrolled form matches the bulk in one iterative char-class pass (no recursion).
    private static final Pattern JSON_SCALAR = Pattern.compile(
            "\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"\\s*:\\s*(\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|-?\\d+(?:\\.\\d+)?)");

    /** Byte-offset ranges of each JSON scalar VALUE in the body (inside the quotes for strings). */
    private static List<Range> jsonBodyRanges(HttpRequest req) {
        List<Range> out = new ArrayList<>();
        if (!isJsonBody(req)) return out;
        String body = req.bodyToString();
        if (body.length() > 500_000) return out;   // pathological body → skip value-range synthesis (audit still runs)
        int base = req.bodyOffset();
        Matcher m = JSON_SCALAR.matcher(body);
        while (m.find()) {
            int s = m.start(1), e = m.end(1);
            if (body.charAt(s) == '"') { s++; e--; }   // insert inside the quotes for string values
            if (e > s) out.add(Range.range(base + s, base + e));   // empties handled by seedEmptyJson
        }
        return out;
    }

    // A path segment that is a real IDENTIFIER: pure numeric, a UUID, or a long hex string. This is
    // where REST injection/IDOR lives (/rest/track-order/<uuid>, /api/Products/<n>, /rest/basket/<n>).
    // Deliberately strict — excludes route words (i18n, web3), versioned names, and filenames (dots) —
    // so we don't waste the audit on non-ids. Generic, no hardcoded paths.
    private static final Pattern ID_SEG = Pattern.compile(
            "^(?:[0-9]+|[0-9a-fA-F]{12,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$");

    /** Byte-offset ranges of id-looking PATH segments — Montoya's parameters() never exposes these. */
    private static List<Range> pathSegmentRanges(HttpRequest req) {
        List<Range> out = new ArrayList<>();
        try {
            if (STATIC.matcher(pathOf(req)).matches()) return out;   // never fuzz static asset paths
            String path = req.pathWithoutQuery();
            if (path == null || path.isEmpty()) return out;
            int base = req.method().length() + 1;   // request-line: METHOD<sp>request-target<sp>HTTP
            int i = 0;
            while (i < path.length()) {
                if (path.charAt(i) == '/') { i++; continue; }
                int s = i;
                while (i < path.length() && path.charAt(i) != '/') i++;
                if (ID_SEG.matcher(path.substring(s, i)).matches()) out.add(Range.range(base + s, base + i));
            }
        } catch (Throwable t) { /* best-effort */ }
        return out;
    }

    /** Path with id-looking segments replaced by {id}, so /x/5 and /x/6 dedup to one audit target. */
    private static String pathTemplate(HttpRequest req) {
        try {
            String[] segs = req.pathWithoutQuery().split("/");
            for (int k = 0; k < segs.length; k++) if (ID_SEG.matcher(segs[k]).matches()) segs[k] = "{id}";
            return String.join("/", segs);
        } catch (Throwable t) { return stripQuery(req.url()); }
    }

    /** Empty JSON string values ("k":"") give Burp a zero-length point; seed them to "1" (see seedEmptyParams). */
    private static HttpRequest seedEmptyJson(HttpRequest req) {
        if (!isJsonBody(req)) return req;
        String body = req.bodyToString();
        String seeded = body.replaceAll("(\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"\\s*:\\s*)\"\"", "$1\"1\"");
        return seeded.equals(body) ? req : req.withBody(seeded);
    }

    /** A request is worth auditing if it has form/URL params, an injectable JSON body, or an id path segment. */
    private static boolean hasFuzzable(HttpRequest req) {
        return !fuzzableParams(req).isEmpty() || isJsonBody(req) || !pathSegmentRanges(req).isEmpty();
    }

    /** Value offsets of the app's own URL/body parameters, for use as audit insertion points. */
    /**
     * A param discovered with an EMPTY value gives Burp a zero-length insertion point:
     * its payloads get appended to nothing, so a bare {@code '} lands as {@code q='} —
     * which in a {@code LIKE '%<v>%'} context parses clean and never trips the error-based
     * SQLi/XSS sink (proven on Juice Shop: {@code q='} → 200, {@code q=1'} → SQLITE_ERROR).
     * Seed empty URL/BODY params with a benign non-empty token so payloads become
     * {@code <seed><payload>} and actually exercise the value-dependent code path.
     */
    private static HttpRequest seedEmptyParams(HttpRequest req) {
        if (!req.hasParameters()) return req;
        List<HttpParameter> updates = new ArrayList<>();
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
            if (p.value() == null || p.value().isEmpty()) {
                updates.add(HttpParameter.parameter(p.name(), "1", p.type()));
            }
        }
        return updates.isEmpty() ? req : req.withUpdatedParameters(updates.toArray(new HttpParameter[0]));
    }

    private static List<Range> fuzzableRanges(HttpRequest req) {
        List<Range> out = new ArrayList<>();
        for (ParsedHttpParameter p : fuzzableParams(req)) {
            Range r = p.valueOffsets();
            if (r != null) out.add(r);
        }
        return out;
    }

    private static String paramSummary(HttpRequest req) {
        StringBuilder sb = new StringBuilder();
        for (ParsedHttpParameter p : fuzzableParams(req)) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p.name()).append(" (").append(p.type()).append(')');
        }
        int json = jsonBodyRanges(req).size();
        if (json > 0) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(json).append(" JSON field(s)");
        }
        int pathIds = pathSegmentRanges(req).size();
        if (pathIds > 0) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(pathIds).append(" path id(s)");
        }
        return sb.toString();
    }

    // ---- form derivation ----
    private List<HttpRequest> deriveForms(HttpRequestResponse pageRr) {
        List<HttpRequest> out = new ArrayList<>();
        if (pageRr.response() == null) return out;
        String html = pageRr.response().bodyToString();
        String pageUrl = pageRr.request().url();
        HttpService svc = pageRr.request().httpService();
        Matcher fm = FORM.matcher(html);
        while (fm.find()) {
            try {
                String form = fm.group();
                String formTag = form.substring(0, form.indexOf('>') + 1);
                String method = attr(formTag, "method");
                boolean post = method != null && method.equalsIgnoreCase("post");
                String action = attr(formTag, "action");
                String actionUrl = (action == null || action.isBlank()) ? pageUrl
                        : URI.create(pageUrl).resolve(action).toString();

                List<HttpParameter> ps = new ArrayList<>();
                Matcher im = INPUT.matcher(form);
                while (im.find()) {
                    String tag = im.group();
                    String name = attr(tag, "name");
                    if (name == null || name.isBlank()) continue;
                    String value = attr(tag, "value");
                    String v = (value == null || value.isBlank()) ? "test" : value;
                    ps.add(HttpParameter.parameter(name, v, post ? HttpParameterType.BODY : HttpParameterType.URL));
                }
                if (ps.isEmpty()) continue;

                HttpRequest req = HttpRequest.httpRequestFromUrl(actionUrl).withMethod(post ? "POST" : "GET");
                if (req.httpService() == null && svc != null) req = req.withService(svc);
                if (post) req = req.withAddedHeader("Content-Type", "application/x-www-form-urlencoded");
                req = req.withAddedParameters(ps);
                out.add(req);
            } catch (Exception ignore) { }
        }
        return out;
    }

    // ---- helpers ----
    private static List<ParsedHttpParameter> fuzzableParams(HttpRequest req) {
        List<ParsedHttpParameter> out = new ArrayList<>();
        if (!req.hasParameters()) return out;
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY) out.add(p);
        }
        return out;
    }

    private static String pathOf(HttpRequest req) {
        try { return req.pathWithoutQuery(); } catch (Exception e) { return req.url(); }
    }
    private static String stripQuery(String url) {
        int i = url.indexOf('?'); return i < 0 ? url : url.substring(0, i);
    }
    /** scheme://authority (host[:port]) for {@code url}, or "" — the request's origin, used to key catch-all shells. */
    private static String originOf(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getAuthority(); } catch (Exception e) { return ""; }
    }

    /**
     * True when {@code other} is the same host as the seed, or a sibling on the same registrable domain
     * the user-approved cross-origin scope. Port is irrelevant here
     * ({@link #hostOf} already drops it, so localhost:3001 and localhost:8080 are the SAME host). Third-party
     * origins (different registrable domain — CDNs, telemetry, vendor APIs) are excluded. Bare single-label
     * hosts (localhost) require an exact match. Generic: registrable domain = the last two DNS labels, so this
     * is app-independent and hardcodes nothing.
     */
    static boolean sameSite(String seed, String other) {
        if (seed == null || other == null || other.isEmpty()) return false;
        if (seed.equalsIgnoreCase(other)) return true;
        String rd = registrableDomain(seed);
        if (rd == null) return false;                       // single-label seed (localhost) -> exact only
        return other.equalsIgnoreCase(rd) || other.toLowerCase().endsWith("." + rd.toLowerCase());
    }

    /** The last two DNS labels ("a.b.whatever.com" -> "whatever.com"), or null when there is no dot (e.g. "localhost"). */
    private static String registrableDomain(String hostname) {
        if (hostname == null) return null;
        String[] p = hostname.split("\\.");
        if (p.length < 2) return null;
        return p[p.length - 2] + "." + p[p.length - 1];
    }

    private static String hostOf(String url) {
        try { return URI.create(url).getHost(); } catch (Exception e) { return ""; }
    }
    /** Full origin (scheme://authority incl. port) for {@code host} from the site map — lets a header-only OAST
     *  probe (Log4Shell) hit the root even when discovery surfaced no auditable parameter (targets list empty). */
    private String siteMapOrigin(String host) {
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = rr.request().url();
                if (host.equalsIgnoreCase(hostOf(u))) return originOf(u);
            }
        } catch (Throwable ignore) { }
        return null;
    }
    /** audit.statusMessage() is UnsupportedOperationException on some Burp builds and is polled in a loop; like
     *  {@link #safeIssues} we latch it off after the first unsupported hit so Burp doesn't print a stack trace on
     *  every poll (that was the repeated trace in the headless stacktrace). */
    private static volatile boolean statusSupported = true;
    private static String safeStatus(Audit a) {
        if (!statusSupported) return "";
        try { String s = a.statusMessage(); return s == null ? "" : s; }
        catch (UnsupportedOperationException u) { statusSupported = false; return ""; }
        catch (Throwable t) { return ""; }
    }
    /** Issues Burp has recorded for this HOST, read from the SITE MAP. We NEVER call {@code audit.issues()}: it is
     *  UnsupportedOperationException on current Burp builds and — even when caught — makes Burp print a proxy stack
     *  trace on the FIRST call. {@code siteMap().issues()} is supported and covers the same findings (our probe/flow
     *  issues are added via siteMap().add(); Burp's native audit issues land there too). Returns [] on any error. */
    private List<AuditIssue> hostIssues(String host) {
        try {
            List<AuditIssue> out = new ArrayList<>();
            for (AuditIssue i : api.siteMap().issues()) {
                if (host == null || host.equalsIgnoreCase(hostOf(i.baseUrl()))) out.add(i);
            }
            return out;
        } catch (Throwable t) { return java.util.Collections.emptyList(); }
    }

    private static String trunc(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }
    private static String attr(String tag, String name) {
        Matcher m = Pattern.compile("(?is)\\b" + Pattern.quote(name)
                + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").matcher(tag);
        if (!m.find()) return null;
        if (m.group(2) != null) return m.group(2);
        if (m.group(3) != null) return m.group(3);
        return m.group(4);
    }
}
