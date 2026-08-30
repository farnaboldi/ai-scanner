package com.ioactive.aiscanner.scan.flow;
import com.ioactive.aiscanner.scan.Net;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.scan.RequestContext;
import com.ioactive.aiscanner.ui.ScanLog;
import com.ioactive.aiscanner.vulns.Signal;
import com.ioactive.aiscanner.vulns.VulnClass;
import com.ioactive.aiscanner.vulns.VulnClasses;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ③ The agentic multi-step flow-engine. For each seed request it runs a bounded
 * OBSERVE → PLAN → ACT → VERIFY → FEEDBACK loop: the LLM proposes the next request from the observed
 * response (targeting only), every proposal is live-probed (anti-hallucination), and a DETERMINISTIC
 * oracle — the generic {@link VulnClasses} body oracles plus a few differential chain checks — decides
 * broke/not-broke. The LLM never decides a verdict. Bounded by a step budget + anti-loop; entirely
 * generic (no per-app rules); reports via {@link ScanLog#found}.
 */
public final class FlowEngine {

    private static final int MAX_SEEDS = 12;
    private static final int MAX_STEPS_PER_SEED = 6;
    private static final int MAX_PLATEAU = 2;   // consecutive no-progress / dead / dup / off-host steps

    private final AiEngine engine;
    private final ScanLog scanLog;
    private final Function<HttpRequest, HttpRequest> sessionizer;   // AiScanner::withSession (Cookie + Bearer)
    private final Function<HttpRequest, StepResult> sender;         // AiScanner::sendAndMeasure (live gate)
    // 2xx endpoints the LLM REACHED that the crawl/mining never did — exposed so the caller can bridge them into
    // the site map + targets, so the specialized probes + Burp active audit cover them too (not siloed here).
    private final List<HttpRequestResponse> reached = new ArrayList<>();
    /** Optional source-analysis leads appended to the planner goal (targeting only; oracle still confirms). */
    private volatile String sourceHintText = "";

    public FlowEngine(AiEngine engine, ScanLog scanLog,
                      Function<HttpRequest, HttpRequest> sessionizer,
                      Function<HttpRequest, StepResult> sender) {
        this.engine = engine;
        this.scanLog = scanLog;
        this.sessionizer = sessionizer;
        this.sender = sender;
    }

    /** Feed compact SAST leads (endpoints/params/classes) so the planner targets them first. Blank = no-op. */
    public void setSourceHintText(String s) { this.sourceHintText = s == null ? "" : s.trim(); }

    // Bearer token dynamically acquired mid-chain (e.g. login step returns a JWT → used for subsequent steps).
    // Volatile so it's visible across method calls; reset per-run so chains don't bleed across seeds.
    private volatile String chainBearer = null;

    /** Run the bounded loop over each seed. Returns the number of oracle-confirmed findings. */
    public int run(String host, List<HttpRequest> seeds) {
        if (engine == null || !engine.isConfigured() || seeds == null || seeds.isEmpty()) return 0;

        final String goal =
                "Advance a multi-step chain from the observed request/response: consume any id or token the "
                + "response returned; try a neighbour id (IDOR); if a role/privilege field appears, resend the body "
                + "with it elevated (mass-assignment); submit the exact answer a lesson/assignment asks. Canaries to "
                + "embed when probing — XSS: " + VulnClasses.XSS_CANARY + ", SSTI: " + VulnClasses.SSTI_INPUT
                + " (=> " + VulnClasses.SSTI_RESULT + "). "
                // SSRF→credential→reauth chain: if a response body field contains base64-encoded JSON with a
                // password (e.g. image_base64 = base64({"password":"..."})), decode it, then POST /token (or
                // equivalent login endpoint) with those credentials to obtain a new JWT, then retry any endpoint
                // that was returning 403. Use the new JWT in the Authorization header of subsequent requests.
                // CREDENTIAL EXTRACTION (highest priority): If the observation contains the section
                // '[Auto-decoded base64 fields]' with a password/secret/credential field, your IMMEDIATE next
                // step MUST be to authenticate: find the login/token endpoint (POST /token, POST /login, etc.)
                // and submit those credentials. Do NOT do IDOR or any other step first.
                + "CRITICAL RULE: If the observation includes '[Auto-decoded base64 fields]' showing a "
                + "password, secret, or credential value, your VERY NEXT step must be to authenticate using "
                + "those credentials (POST /token or equivalent login endpoint with the discovered username "
                + "and password). After obtaining an access_token, use it as Bearer for endpoints that "
                + "returned 403 earlier (privilege escalation via credential chain). "
                // URL-typed field injection: if SAST leads mention a url-typed field for an endpoint,
                // include it in PUT/POST JSON bodies pointing to internal credential/reset endpoints.
                + "If SAST leads mention a url-typed field (image_url, url, link, redirect) for any endpoint, "
                + "add that field to the JSON body of PUT/POST requests to the same path, pointing to internal "
                + "password-reset or credential-vending endpoints (paths containing 'reset', 'password', "
                + "'credential', 'secret') to retrieve credentials via SSRF."
                + (sourceHintText.isBlank() ? ""
                        : " SOURCE-CODE LEADS from static analysis (prioritize reaching these endpoints/params; "
                          + "they must still be confirmed dynamically): " + sourceHintText);

        Set<String> visited = new LinkedHashSet<>();   // anti-loop across all seeds
        int findings = 0, seedCount = 0;
        chainBearer = null;   // reset per run
        long deadlineMs = System.currentTimeMillis() + Long.getLong("aiscanner.flowBudgetMs", 240_000L);

        for (HttpRequest seed : seeds) {
            if (seedCount++ >= MAX_SEEDS) break;
            if (System.currentTimeMillis() >= deadlineMs) {
                scanLog.debug("  flow: time budget reached — stopping after " + (seedCount - 1) + " seed(s)");
                break;
            }

            StepResult obs0 = safeSend(applySession(seed));   // OBSERVE step-0: un-mutated, authenticated
            if (obs0 == null || !obs0.live()) continue;
            String baselineBody = obs0.body() == null ? "" : obs0.body();
            HttpRequestResponse cursor = obs0.rr();
            String feedback = null;
            int plateau = 0;

            for (int step = 1; step <= MAX_STEPS_PER_SEED; step++) {
                if (System.currentTimeMillis() >= deadlineMs) break;
                String observation = RequestContext.of(cursor).forLlm();
                String carriedId = firstIdOrToken(cursor);                 // from the REAL response bytes

                String rawJson = engine.planNextRequest(goal, observation, feedback);   // PLAN
                PlannedRequest p = PlannedRequest.parse(rawJson);
                if (p == null) break;

                if (!visited.add(p.signature())) {
                    feedback = "already tried " + p.method() + " " + p.url() + "; pick a different endpoint/param";
                    if (++plateau >= MAX_PLATEAU) break; else continue;
                }
                if (!sameHost(p.url(), host)) {
                    feedback = "off-host url rejected: " + p.url();
                    if (++plateau >= MAX_PLATEAU) break; else continue;
                }

                StepResult act = safeSend(applySession(p.toHttpRequest()));   // ACT
                if (act == null || !act.live()) {
                    feedback = "planned " + p.method() + " " + p.url() + " not real (HTTP "
                            + (act == null ? 0 : act.status()) + ") — do not reuse it";
                    if (++plateau >= MAX_PLATEAU) break; else continue;
                }
                scanLog.debug("  flow step " + step + ": " + p.method() + " " + p.url()
                        + (p.intent().isBlank() ? "" : " (" + p.intent() + ")") + " -> HTTP " + act.status());

                if (act.ok2xx() && act.rr() != null && act.rr().response() != null) reached.add(act.rr());

                // Mid-chain credential upgrade: if a step returns a new access_token (e.g. POST /token with
                // escalated credentials), capture it so subsequent steps in this chain use the new session.
                String freshToken = extractAccessToken(act.body());
                if (freshToken != null && !freshToken.equals(chainBearer)) {
                    chainBearer = freshToken;
                    scanLog.debug("  flow: mid-chain bearer updated (step " + step + ")");
                }

                if (verify(p, baselineBody, act, carriedId)) {
                    findings++;
                    break;
                }

                boolean progressed = act.body() != null && !act.body().equals(baselineBody);
                feedback = "sent " + p.method() + " " + p.url() + " -> HTTP " + act.status()
                        + (progressed ? " (new state)" : " (no change)");
                plateau = progressed ? 0 : plateau + 1;
                if (plateau >= MAX_PLATEAU) break;
                cursor = act.rr();
            }
        }
        chainBearer = null;   // clean up
        return findings;
    }

    /** Apply session — uses a mid-chain bearer when one was obtained, else falls back to the initial sessionizer. */
    private HttpRequest applySession(HttpRequest req) {
        if (chainBearer != null) {
            // Apply the upgraded bearer; keep any cookies from the initial sessionizer.
            HttpRequest withInitialCookies = sessionizer.apply(req);
            return withInitialCookies.withHeader("Authorization", "Bearer " + chainBearer);
        }
        return sessionizer.apply(req);
    }

    /** Extract a freshly-issued auth token from a JSON response body — the common OAuth2/JWT field names, so a
     *  login/refresh step's new session is picked up regardless of which of the standard keys the app uses. */
    private static final Pattern ACCESS_TOKEN = Pattern.compile(
            "\"(?:access_?token|auth_?token|id_?token|token|jwt|bearer)\"\\s*:\\s*\"([A-Za-z0-9_\\-\\.]{20,512})\"");
    private static String extractAccessToken(String body) {
        if (body == null || body.isEmpty()) return null;
        Matcher m = ACCESS_TOKEN.matcher(body);
        return m.find() ? m.group(1) : null;
    }

    /** 2xx requests the LLM reached that the crawl/mining didn't — for the caller to bridge into site map + targets. */
    public List<HttpRequestResponse> reachedResponses() { return reached; }

    // ---- VERIFY: deterministic only. vulnClassHint routes which check runs; the comparison is the verdict. ----

    private boolean verify(PlannedRequest p, String baselineBody, StepResult act, String carriedId) {
        String body = act.body() == null ? "" : act.body();
        String url = act.rr().request().url();

        // Channel A — the four generic body-signature oracles, verbatim (SQLi/XSS/SSTI/traversal).
        for (VulnClass vc : VulnClasses.all()) {
            Signal s = vc.oracle.detect(baselineBody, body, act.elapsedMs(), p.body());
            if (s.hit) { report(vc.id, url, s.evidence); return true; }
        }

        // NOTE: NO create→consume oracle. "an id/token minted earlier is echoed in a later 2xx" is just
        // normal read-after-write of YOUR OWN resource (create a post → read it back) or a login echoing
        // the JWT it just issued (the constant header "eyJhbGci…"). Proving a BROKEN object-level chain
        // needs a SECOND identity (create as user A, consume as user B) — which this single-identity engine
        // does not have — so a single-identity "echoed id" check only manufactures false positives (same
        // unsoundness as the removed loose IDOR oracle that FP'd on Juice's public /api/Products). Real
        // path-id IDOR stays covered deterministically by IdorGetProbe. Reintroduce a SOUND create→consume
        // oracle only once the engine can act under two identities.
        // mass-assignment — an elevated role/privilege now echoed that the baseline did not carry.
        if (act.ok2xx() && echoesElevatedRole(body) && !echoesElevatedRole(baselineBody)) {
            report("Improper input validation / mass assignment", url,
                    "response now echoes an elevated role/privilege the baseline did not");
            return true;
        }
        // lesson/challenge solved — the universal completion field flipped true.
        if (solvedFlag(body) && !solvedFlag(baselineBody)) {
            report("Lesson/challenge solved", url, "server confirmed completion");
            return true;
        }
        return false;
    }

    private void report(String cls, String url, String evidence) {
        scanLog.found("AI: " + cls, url, evidence);
        scanLog.incFinding();
    }

    // ---- generic helpers (no per-app rules) ----

    private static final Pattern ID_JSON = Pattern.compile(
            "(?i)\"(?:_?id|token|uuid|guid|order[_]?id|session|access[_]?token)\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{1,64})\"?");
    private static final Pattern ID_PATH = Pattern.compile(".*/([A-Za-z0-9][A-Za-z0-9_\\-]{3,63})/?$");
    private static final Pattern LOC_ID = Pattern.compile("([A-Za-z0-9_\\-]{6,64})");
    private static final Pattern ELEVATED = Pattern.compile(
            "(?i)\"(?:role|roles|authority|privilege|group|type)\"\\s*:\\s*\"?(admin|administrator|superuser|root|owner)\"?"
            + "|\"(?:is[_]?admin|admin|superuser|elevated)\"\\s*:\\s*true");

    /** Carry-forward id/token from the REAL prior response: first id/token JSON value, else a Location id,
     *  else a trailing id-looking path segment. Generic — no app-specific field names. */
    private static String firstIdOrToken(HttpRequestResponse rr) {
        try {
            if (rr.response() != null) {
                Matcher m = ID_JSON.matcher(rr.response().bodyToString());
                if (m.find()) return m.group(1);
                if (rr.response().hasHeader("Location")) {
                    Matcher lm = LOC_ID.matcher(rr.response().headerValue("Location"));
                    if (lm.find()) return lm.group(1);
                }
            }
            Matcher pm = ID_PATH.matcher(rr.request().pathWithoutQuery());
            if (pm.matches()) return pm.group(1);
        } catch (Throwable ignore) { }
        return null;
    }

    private static boolean echoesElevatedRole(String body) {
        return body != null && ELEVATED.matcher(body).find();
    }

    private static boolean solvedFlag(String body) {
        if (body == null) return false;
        String b = body.replaceAll("\\s+", "");
        return b.contains("\"lessonCompleted\":true") || b.contains("\"solved\":true") || b.contains("\"complete\":true");
    }

    private static boolean sameHost(String url, String host) {
        try { return host.equalsIgnoreCase(Net.authority(url)); } catch (Exception e) { return false; }
    }

    private StepResult safeSend(HttpRequest req) {
        try { return sender.apply(req); } catch (Throwable t) { return StepResult.dead(0); }
    }
}
