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
        return (cancelled != null && cancelled.getAsBoolean()) || Thread.currentThread().isInterrupted();
    }
    private final java.util.concurrent.atomic.AtomicBoolean creditHaltLogged = new java.util.concurrent.atomic.AtomicBoolean(false);

    private static final Pattern STATIC = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)$");
    // Transport/handshake endpoints: their "params" (EIO/transport/t/sid, Engine.IO packet
    // prefixes) are framing, not attack surface — fuzzing them is pure noise.
    private static final Pattern NOISE = Pattern.compile("(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$");
    private static final Pattern FORM = Pattern.compile("(?is)<form\\b.*?</form>");
    private static final Pattern INPUT = Pattern.compile("(?is)<(input|textarea|select)\\b[^>]*>");

    public AiScanner(MontoyaApi api, Supplier<AiEngine> engine, ScanConfig config, ScanLog scanLog,
                     SessionStore session) {
        this(api, engine, config, scanLog, session, null);
    }

    public AiScanner(MontoyaApi api, Supplier<AiEngine> engine, ScanConfig config, ScanLog scanLog,
                     SessionStore session, java.util.function.BooleanSupplier cancelled) {
        this.api = api;
        this.engine = engine;
        this.config = config;
        this.scanLog = scanLog;
        this.session = session;
        this.cancelled = cancelled;
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
            int added = 0;
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

        // LLM + regex endpoint discovery: recover endpoints Burp's crawler can't reach
        // (JS-only AJAX/routes), probed live so nothing hallucinated gets audited.
        EndpointDiscovery disc = new EndpointDiscovery(api, engine, session, scanLog);
        for (HttpRequest ep : disc.discover(host)) {
            addTarget(targets, seen, ep);
        }
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
        try {
            scanLog.phase("Agent-flow probe (LLM agent)");
            AiEngine agentEng = engine != null ? engine.get() : null;   // used only to plan a generic unlock when gated
            AgentFlowProbe afp = new AgentFlowProbe(api, scanLog, agentEng);
            int hits = afp.probe(host, this::withSession);
            scanLog.log("[AI Scanner] agent-flow probe: " + hits + " LLM-agent finding(s).");
            // Feed the agent write requests it reached into the audit surface — so the targets-iterating probes
            // below AND the final Burp active audit fuzz the agent endpoints too (not just the site-map readers).
            int added = 0;
            for (HttpRequestResponse rr : afp.reached()) if (addTarget(targets, seen, rr.request())) added++;
            if (added > 0) scanLog.log("[AI Scanner] agent-flow: added " + added + " reached agent request(s) to the audit surface.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] agent-flow probe skipped: " + t);
        }

        // LLM-fuzz probe: fire the adversarial battery (unicode / prompt-injection / structural) at any single-
        // request LLM endpoint in the site map and judge replies with the local LLM (hybrid two-tier oracle). The
        // agent's async run→turn endpoints are fuzzed inside the agent-flow probe above; this covers plain chat/
        // completion endpoints. Generic — endpoint identification is structural (LlmEndpointDetector), no app paths.
        try {
            AiEngine fuzzEng = engine != null ? engine.get() : null;
            scanLog.phase("LLM-fuzz probe (payloads vs target LLM)");
            int hits = new LlmFuzzProbe(api, scanLog, fuzzEng).probe(host, this::withSession);
            scanLog.log("[AI Scanner] llm-fuzz probe: " + hits + " finding(s).");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] llm-fuzz probe skipped: " + t);
        }

        // FAST, high-signal findings FIRST — CSRF + open-redirect are deterministic, cheap, and independent of
        // the (slow, per-target) injection fuzzing below, so the crit/high they find emit promptly even on a
        // high-latency target where Burp's async active audit is slow to complete. The CSRF probe is handed the
        // derived form POSTs directly, so it doesn't wait for the audit to push them into the site map.
        {
            try {
                scanLog.phase("CSRF probe");
                int hits = new CsrfProbe(api, scanLog).probe(host, this::withSession, targets);
                scanLog.log("[AI Scanner] CSRF probe: " + hits + " state-changing form(s) accept a forged cross-site request.");
            } catch (Throwable t) { scanLog.debug("[AI Scanner] CSRF probe skipped: " + t); }
            try {
                scanLog.phase("Open-redirect probe");
                OpenRedirectProbe orp = new OpenRedirectProbe(api, scanLog);
                int hits = 0;
                for (HttpRequest t : targets) if (orp.probe(withSession(t))) hits++;
                scanLog.log("[AI Scanner] open-redirect probe: " + hits + " endpoint(s) redirect to an attacker host.");
            } catch (Throwable t) { scanLog.debug("[AI Scanner] open-redirect probe skipped: " + t); }
        }

        if (cancelled()) { scanLog.log("[AI Scanner] scan cancelled (extension unloaded)."); return null; }

        // Blind-SQLi FIRST — its content oracle needs a stable target, so run it before the heavier
        // probes build up load (fragile/rate-limited targets can drop sessions under sustained scanning).
        try {
            scanLog.phase("Blind SQLi probe");
            BlindSqliProbe bsp = new BlindSqliProbe(api, scanLog);
            int hits = 0, done = 0;
            // Wall-clock budget: each time-based payload sleeps ~5s, so a large signed surface × params can run
            // for many minutes and STALL the whole sequential probe chain (IDOR/BFLA/mass-assignment never run).
            // Bound the phase and log what was skipped — never silently truncate.
            long deadline = System.currentTimeMillis() + PROBE_PHASE_BUDGET_MS;
            for (HttpRequest t : targets) {
                if (System.currentTimeMillis() > deadline) {
                    scanLog.log("[AI Scanner] blind-SQLi probe: time budget hit — audited " + done + "/"
                            + targets.size() + " target(s), " + (targets.size() - done) + " skipped (Burp's native audit still covers them).");
                    break;
                }
                if (bsp.probe(withSession(t))) hits++;
                done++;
            }
            scanLog.log("[AI Scanner] blind-SQLi probe: " + hits + " endpoint(s) blind-injectable.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] blind-SQLi probe skipped: " + t);
        }

        // Reflected XSS is normally left to Burp's native audit (richer evidence; we feed it every discovered
        // endpoint). EXCEPTION: in WAF-evasion mode, Burp's canonical XSS payloads get blocked by the WAF, so
        // a small evasion-only probe tries obfuscated tag vectors to slip the WAF (runs ONLY when the toggle
        // is on → no duplication of Burp on normal scans).
        try {
            EvasionXssProbe xss = new EvasionXssProbe(api, scanLog);
            if (Evasion.enabled()) {
                scanLog.phase("Reflected-XSS probe (WAF-evasion)");
                int hits = 0;
                for (HttpRequest t : targets) if (xss.probe(withSession(t))) hits++;
                scanLog.log("[AI Scanner] evasion-XSS probe: " + hits + " endpoint(s) reflect an obfuscated tag past the WAF.");
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] evasion-XSS probe skipped: " + t);
        }

        // Deterministic NoSQL oracle over the discovered surface (generic; Burp's NoSQL coverage is weak).
        // Records the records a bypass leaks so the create->consume chain below can replay them.
        List<String> injectionLeaks = new ArrayList<>();
        try {
            scanLog.phase("NoSQL injection probe");
            NoSqlProbe nosql = new NoSqlProbe(api, scanLog);
            nosql.setLeakSink(injectionLeaks);
            if (session != null) nosql.setKnownUser(session.loginUser());   // valid user → clean auth-bypass check
            int hits = 0;
            for (HttpRequest t : targets) if (nosql.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] NoSQL probe: " + hits + " endpoint(s) look NoSQL-injectable.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] NoSQL probe skipped: " + t);
        }

        // create->consume chain: replay a record an injection bypass leaked into sibling write endpoints
        // the crawler never reached (the UI only calls them after a valid value it doesn't possess), then
        // fuzz those sinks. Reaches chained vulns like a NoSQL leak feeding a SQL-backed apply endpoint.
        try {
            if (!injectionLeaks.isEmpty()) {
                scanLog.phase("Create->consume chain (leak replay)");
                new ChainReplayProbe(api, scanLog, this::withSession, injectionLeaks).run(host);
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] chain-replay probe skipped: " + t);
        }

        // Generic body-mutation probe (mass-assignment / empty-required / boundary / IDOR) over writes.
        try {
            scanLog.phase("Body-mutation probe");
            BodyMutatorProbe bm = new BodyMutatorProbe(api, scanLog);
            for (HttpRequest t : targets) bm.probe(withSession(t));
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] body-mutation probe skipped: " + t);
        }

        // Generic poison-null-byte / extension-bypass fetch over sensitive served files.
        try {
            scanLog.phase("File-serve bypass probe");
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new FileServePathProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] file-serve probe: " + hits + " sensitive file(s) exfiltrated via bypass.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] file-serve probe skipped: " + t);
        }

        // Generic IDOR probe: re-request id-bearing GET paths with a neighboring id (cross-tenant access).
        try {
            scanLog.phase("IDOR probe");
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new IdorGetProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] IDOR probe: " + hits + " id-bearing GET(s) returned another tenant's record.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] IDOR probe skipped: " + t);
        }

        // Generic BFLA probe: role-segment substitution (…/user/… -> …/admin/…) then a non-destructive
        // three-request authz differential (unauth denied + our-session reaches a real handler that a
        // non-existent sibling route does not) — a non-admin invoking an admin-tier function.
        try {
            scanLog.phase("BFLA probe");
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new BflaProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] BFLA probe: " + hits + " admin-tier function(s) reachable by a non-privileged user.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] BFLA probe skipped: " + t);
        }

        // JWT implementation analysis: harvest tokens the app used, decode them, and run deterministic
        // oracle-gated checks (alg:none active replay, weak/known HMAC secret, missing exp, sensitive claims).
        try {
            scanLog.phase("JWT analysis probe");
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new JwtAnalysisProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] JWT analysis probe: " + hits + " JWT implementation issue(s).");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] JWT analysis probe skipped: " + t);
        }

        // Unauthenticated-access probe: re-send each authenticated 2xx-JSON endpoint with the credential
        // stripped; fire only if it still returns the same data shape (auth not enforced). Reads the site map,
        // so it sees the discovered endpoints via the bridge above.
        try {
            scanLog.phase("Unauthenticated-access probe");
            int hits = new UnauthAccessProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] unauth-access probe: " + hits + " protected endpoint(s) served data with no credential.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] unauth-access probe skipped: " + t);
        }

        // Webhook signature fail-open: inbound provider webhooks (payments/KYC/banking) must verify an HMAC
        // signature — a verifier that fails open lets an anonymous attacker forge provider events (fake a
        // deposit, flip a loan/KYC decision to approved). Deterministic: a bad/absent signature that is ACCEPTED
        // (2xx, not a signature rejection) proves verification isn't enforced. Generic; non-destructive ({} body).
        try {
            scanLog.phase("Webhook signature fail-open probe");
            int hits = new WebhookAuthProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] webhook-auth probe: " + hits + " webhook(s) accept an invalid/absent signature.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] webhook-auth probe skipped: " + t);
        }

        // Privilege-parity (broken function-level authz): a privileged resource reachable through an ungated
        // sibling route. Reads the site map (a denied /admin/X twin proves the resource is privileged), then
        // confirms the open /X twin returns data to our session — crash-independent, passes a WAF unchanged.
        try {
            scanLog.phase("Privilege-parity probe");
            String cookie = session != null ? session.cookieHeader() : "";
            String bearer = session != null ? session.bearer() : "";
            int hits = new PrivilegeParityProbe(api, scanLog).probe(host, cookie, bearer);
            scanLog.log("[AI Scanner] privilege-parity probe: " + hits + " privileged resource(s) reachable via an ungated sibling.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] privilege-parity probe skipped: " + t);
        }

        // (CSRF probe ran early — see the fast-findings block above.)

        // Response-side secret disclosure: a challenge served together with its own answer (CWE-345).
        // Reads the site map, so it sees the discovered endpoints via the bridge above.
        try {
            scanLog.phase("Response secret-exposure probe");
            int hits = new ResponseSecretExposureProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] response-secret probe: " + hits + " response(s) disclosed a challenge answer.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] response-secret probe skipped: " + t);
        }

        // GraphQL: Burp DETECTS a /graphql endpoint but won't fuzz resolver ARGS without a valid query carrying
        // them as insertion points. Introspect the schema (info exposure if enabled), then inject each resolver's
        // String args via query variables with a deterministic echo-nonce oracle → catches unauth GraphQL RCE
        // (e.g. a getCommandResult(command) shell resolver) that our REST-only surface was blind to.
        try {
            scanLog.phase("GraphQL probe");
            int hits = new GraphqlProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] graphql probe: done (" + hits + " finding(s)).");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] graphql probe skipped: " + t);
        }

        // Insecure deserialization: DETECT a serialized-object cookie (Java/.NET/pickle/PHP), then VALIDATE it
        // black-box by replaying a discovered GET with the cookie's serialized stream corrupted — if the app 5xx's
        // only on the corrupt blob, it deserializes attacker data (CWE-502). Fires only on that dynamic delta.
        try {
            scanLog.phase("Insecure-deserialization probe");
            int hits = new InsecureDeserializationProbe(api, scanLog).probe(host, targets);
            scanLog.log("[AI Scanner] insecure-deserialization probe: " + hits + " endpoint(s) proven to deserialize a client-supplied object.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] insecure-deserialization probe skipped: " + t);
        }

        // Out-of-band (blind) XXE via Burp Collaborator: inject an external-entity payload into XML endpoints
        // (discovered from the OpenAPI spec) and poll for a server-side callback. Catches blind XXE that has
        // no in-band oracle (constant response). Zero-FP: the callback is caused only by the server parsing us.
        try {
            scanLog.phase("Blind XXE (OOB) probe");
            int hits = new XxeProbe(api, scanLog).probe(host);
            scanLog.log("[AI Scanner] XXE probe: " + hits + " endpoint(s) resolved an out-of-band external entity.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] XXE probe skipped: " + t);
        }

        // NOTE: CORS misconfiguration is intentionally NOT a custom probe — Burp's native passive scanner
        // already reports it ("Cross-origin resource sharing: arbitrary origin trusted") with correct scope,
        // so a bespoke probe would only duplicate a built-in template.

        // Generic path-traversal / LFI probe (OS-file signature oracle; Burp's coverage is uneven).
        try {
            scanLog.phase("Path traversal / LFI probe");
            PathTraversalProbe lfi = new PathTraversalProbe(api, scanLog);
            int hits = 0;
            for (HttpRequest t : targets) if (lfi.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] path-traversal probe: " + hits + " endpoint(s) leaked an OS file.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] path-traversal probe skipped: " + t);
        }

        // (Open-redirect probe ran early — see the fast-findings block above.)

        // Generic client-side-restriction bypass + parameter tampering (server-side enforcement of
        // client-only controls: option lists, maxlength, format regexes, computed totals, weak-password).
        try {
            scanLog.phase("Restriction-bypass / tampering probe");
            RestrictionBypassProbe rb = new RestrictionBypassProbe(api, scanLog);
            int hits = 0;
            for (HttpRequest t : targets) if (rb.probe(withSession(t))) hits++;
            scanLog.log("[AI Scanner] restriction-bypass probe: " + hits + " form(s) accepted a restricted submission.");
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] restriction-bypass probe skipped: " + t);
        }

        scanLog.log("[AI Scanner] discovery done: " + targets.size()
                + " parameterized request(s) for " + host + " — submitting to Burp active audit…");

        // ③ Agentic multi-step flow-engine — the LLM plans the next request from each response (targeting
        // only), every proposal is live-probed, and a deterministic oracle decides the verdict. Reaches
        // chains a single-shot fuzzer can't: create->consume, IDOR, mass-assignment, token flows, lessons.
        // Runs AFTER the probes (session primed, creates already POSTed so bodies carry ids/tokens).
        try {
            AiEngine eng = engine != null ? engine.get() : null;
            if (eng != null && eng.isConfigured()) {
                scanLog.phase("Flow-engine (agentic multi-step)");
                FlowEngine fe = new FlowEngine(eng, scanLog, this::withSession, this::sendAndMeasure);
                int hits = fe.run(host, targets);
                scanLog.log("[AI Scanner] flow-engine: " + hits + " finding(s) from multi-step chains.");
                // The flow-engine reaches 2xx endpoints the crawl/mining never did. Bridge them into the site map
                // (Burp UI + any later site-map reader) and add them to `targets` so the Burp active audit below
                // fuzzes them too — otherwise everything the LLM reached here stays siloed to the flow oracles.
                int added = 0;
                for (HttpRequestResponse rr : fe.reachedResponses()) {
                    try { api.siteMap().add(rr); } catch (Exception ignore) { }
                    if (addTarget(targets, seen, rr.request())) added++;
                }
                if (added > 0) scanLog.log("[AI Scanner] flow-engine: added " + added
                        + " LLM-reached endpoint(s) to the audit surface (site map + Burp active audit).");
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] flow-engine skipped: " + t);
        }

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
            scanLog.log("[AI Scanner] ===== Burp AI usage (estimated) this scan: " + calls + " calls, ~"
                    + com.ioactive.aiscanner.engine.MontoyaAiEngine.totalTokens() + " tokens"
                    + " (~" + com.ioactive.aiscanner.engine.MontoyaAiEngine.totalInTokens() + " in / ~"
                    + com.ioactive.aiscanner.engine.MontoyaAiEngine.totalOutTokens() + " out) =====");
            // REAL credits: start (snapshotted on the first call) vs end (Burp's last-synced balance).
            String start = com.ioactive.aiscanner.engine.MontoyaAiEngine.scanStartCredits();
            String end = com.ioactive.aiscanner.engine.MontoyaAiEngine.readCreditBalance();
            if (start != null)
                scanLog.log("[AI Scanner] Burp AI credits available (start of scan): " + start);
            if (end != null) {
                String spent = "";
                if (start != null) {
                    try { spent = String.format("  |  spent this scan: %.4f credits",
                            Double.parseDouble(start) - Double.parseDouble(end)); }
                    catch (NumberFormatException ignore) { }
                }
                scanLog.log("[AI Scanner] Burp AI credits available (end of scan): " + end + spent
                        + " (end balance is Burp's last sync — may lag the final calls)");
            }
        } catch (Throwable ignore) { }
    }

    /** Write the run's findings to -Daiscanner.report / AISCANNER_REPORT so the benchmark harness can score. */
    private void writeReport() {
        String path = System.getProperty("aiscanner.report");
        if (path == null || path.isBlank()) path = System.getenv("AISCANNER_REPORT");
        if (path == null || path.isBlank()) return;
        try {
            java.nio.file.Files.write(java.nio.file.Path.of(path), scanLog.findingsReport());
            scanLog.log("[AI Scanner] findings report written → " + path);
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] report write failed: " + t);
        }
    }

    // ---- native audit plumbing ----

    private Audit newAudit() {
        return api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
    }

    /**
     * Add a request to the audit, restricting Burp's insertion points to the value
     * offsets of the app's own URL/body parameters (so it doesn't waste payloads on
     * headers/cookies/path). Applies the captured session cookie first.
     */
    private boolean addToAudit(Audit audit, HttpRequest req) {
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
                    RequestOptions.requestOptions());
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
        if (STATIC.matcher(pathOf(req)).matches()) return false;
        if (!hasFuzzable(req)) return false;
        StringBuilder key = new StringBuilder(req.method()).append(' ').append(hostOf(req.url())).append(pathTemplate(req));
        for (ParsedHttpParameter p : fuzzableParams(req)) key.append('|').append(p.type()).append(':').append(p.name());
        if (seen.add(key.toString())) {
            targets.add(req);
            scanLog.scanned(req.url(), paramSummary(req));
            scanLog.log("[AI Scanner]   found params @ " + req.method() + " " + stripQuery(req.url())
                    + " → " + paramSummary(req));
            return true;
        }
        return false;
    }

    /** Send one request and measure it, computing the flow-engine's anti-hallucination {@code live} gate. */
    StepResult sendAndMeasure(HttpRequest req) {
        long t0 = System.nanoTime();
        HttpRequestResponse r;
        try { r = api.http().sendRequest(req, RequestOptions.requestOptions()); }
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

    // ---- JSON body insertion points (Montoya doesn't parse JSON into parameters()) ----

    /** True when the request carries a non-empty JSON body (any Content-Type containing "json"). */
    private static boolean isJsonBody(HttpRequest req) {
        try {
            String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
            return ct != null && ct.toLowerCase().contains("json") && !req.bodyToString().isBlank();
        } catch (Throwable t) { return false; }
    }

    // RHS scalar of  "key": <value>  — a JSON string ("...") or number. Group 1 = the value token.
    private static final Pattern JSON_SCALAR = Pattern.compile(
            "\"(?:[^\"\\\\]|\\\\.)*\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|-?\\d+(?:\\.\\d+)?)");

    /** Byte-offset ranges of each JSON scalar VALUE in the body (inside the quotes for strings). */
    private static List<Range> jsonBodyRanges(HttpRequest req) {
        List<Range> out = new ArrayList<>();
        if (!isJsonBody(req)) return out;
        String body = req.bodyToString();
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
        String seeded = body.replaceAll("(\"(?:[^\"\\\\]|\\\\.)*\"\\s*:\\s*)\"\"", "$1\"1\"");
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
