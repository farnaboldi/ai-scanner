package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.scan.sast.SourceFindings;
import com.ioactive.aiscanner.scan.sast.StaticHint;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Deterministic OS-command-injection and server-side-eval (SSJS/RCE) oracle. Burp's active checks cover these,
 * but a param whose value is concatenated into a shell {@code exec()} or a JS {@code eval()} is only reached
 * when the scanner (a) knows the exact route+param and (b) sends the right shape — precisely where a black-box
 * crawl of a JS-wired SPA falls short. This probe is SAST-hint-driven: for every source hint that pins a
 * command/eval sink it SYNTHESIZES a concrete request (route + param + a sane baseline value) and confirms with
 * two zero-FP oracles:
 * <ul>
 *   <li><b>OS command — time-based</b>: inject a {@code sleep N} behind a shell separator; a response delayed by
 *       ~N s (vs a fast baseline) proves the injected command ran. No output parsing, so it survives any output
 *       shape.</li>
 *   <li><b>eval / SSJS — arithmetic</b>: inject a distinctive product ({@code 8161*7919}); the exact result
 *       ({@code 64626559}) appearing in the response — and absent from the literal-string baseline — proves the
 *       expression was evaluated, not echoed.</li>
 * </ul>
 * Both are differential and self-evidencing. Hints only steer WHICH endpoint/param/value; the oracle alone
 * decides — a wrong hint costs a couple of requests, never a false finding.
 */
public final class CommandInjectionProbe extends Probe {

    private SourceFindings sourceHints;

    public CommandInjectionProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    // ~5s sleep behind every common shell separator (Unix + Windows). SLEEP_S kept low to bound scan time while
    // staying well above network jitter.
    private static final int SLEEP_S = 5;
    private static final long DELAY_THRESHOLD_MS = 3800;   // must be < SLEEP_S*1000, > realistic jitter
    private static final String[] CMD_SEPARATORS = {
            "; sleep " + SLEEP_S, " && sleep " + SLEEP_S, " | sleep " + SLEEP_S, " & sleep " + SLEEP_S,
            "$(sleep " + SLEEP_S + ")", "`sleep " + SLEEP_S + "`", " && timeout " + SLEEP_S   // Windows fallback
    };
    // Distinctive multiplicand pair — product 64626559 is unlikely to occur naturally in a response.
    private static final long EV_A = 8161, EV_B = 7919, EV_PRODUCT = EV_A * EV_B;   // 64,626,559
    private static final String[] EVAL_EXPRS = { EV_A + "*" + EV_B, EV_A + "*" + EV_B + "//x", "(" + EV_A + "*" + EV_B + ")" };

    // Param names that plausibly feed a shell/host lookup (used to bound the expensive time-based test on the
    // generic, hint-less target sweep — hint-driven runs test regardless of name).
    private static final Pattern CMDISH = Pattern.compile(
            "(?i)(^|[_-])(cmd|command|exec|ping|host|hostname|ip|addr|address|target|url|domain|dns|nslookup|"
            + "file|path|name|arg|args|option|opt|id)([_-]|$)");

    // Echo-canary separators for stdout-reflection oracle (ordered: least-filtered first).
    private static final String[] ECHO_SEPS = { "; echo ", " && echo ", "\necho ", "| echo " };
    // Sequential nonce to guarantee echo-canary uniqueness across invocations.
    private static final java.util.concurrent.atomic.AtomicInteger NONCE = new java.util.concurrent.atomic.AtomicInteger();
    // Common API-prefix variants to retry when the synthesised path returns 404.
    private static final String[] API_PREFIXES = { "/api", "/api/v1", "/api/v2", "/v1", "/v2" };
    // Common single-key wrappers that apps use around their payload (e.g. {"body":{…}}).
    private static final String[] WRAP_KEYS = { "body", "data", "request", "params", "input", "payload" };

    /** Hint-driven pass: synthesize a concrete request for every command/eval sink the source pins, and confirm. */
    public int probeHints(String host, Function<HttpRequest, HttpRequest> withSession, String base) {
        if (sourceHints == null || base == null) return 0;
        int hits = 0;
        for (StaticHint h : sourceHints.all()) {
            if (!isCmdOrEval(h) || !h.hasEndpoint() || !h.hasParam()) continue;
            HttpRequest req = synthesize(h, base);
            if (req == null) continue;
            try { req = withSession.apply(req); } catch (Throwable ignore) { }

            // Path-prefix retry: SAST extracts bare paths (/debug) but APIs often live under /api/debug.
            // If the synthesised path gets a 404, probe common prefix variants before giving up.
            HttpRequestResponse probe0 = send(req);
            if (probe0 != null && probe0.response() != null && probe0.response().statusCode() == 404) {
                String rawPath = java.net.URI.create(req.url()).getPath();
                HttpRequest found = null;
                for (String pfx : API_PREFIXES) {
                    String candidate = req.url().replace(rawPath, pfx + rawPath);
                    HttpRequest cr = req.withPath(java.net.URI.create(candidate).getPath());
                    HttpRequestResponse pr = send(cr);
                    if (pr != null && pr.response() != null && pr.response().statusCode() != 404) {
                        found = cr;
                        try { found = withSession.apply(found); } catch (Throwable ignore) { }
                        break;
                    }
                }
                if (found != null) req = found;
            }

            // Body-wrapper retry: synthesise builds flat {"command":"1"} but many APIs expect {"body":{"command":"1"}}.
            // If the flat body is rejected (4xx), probe each common wrapper key with multiple seeds — the endpoint
            // may also whitelist/validate the VALUE (not just the structure), so "1" may be rejected while
            // "uptime" is accepted. Both wrapper key and seed must be found together.
            final String synBody = req.bodyToString();
            if (synBody != null && synBody.trim().startsWith("{")) {
                HttpRequestResponse cur = send(req);
                if (cur != null && cur.response() != null && cur.response().statusCode() >= 400) {
                    boolean wrappedTested = false;
                    String[] wrapSeeds = { seed(h.paramName), "uptime", "ls", "id", "whoami", "dir", "" };
                    wrapSearch:
                    for (String wk : WRAP_KEYS) {
                        for (String ws : wrapSeeds) {
                            String wrapped = "{\"" + wk + "\":{\"" + h.paramName + "\":\"" + ws + "\"}}";
                            HttpRequest wr = req.withBody(wrapped);
                            HttpRequestResponse pr = send(wr);
                            if (pr != null && pr.response() != null && pr.response().statusCode() < 400) {
                                final String wkFinal = wk; final HttpRequest wrFinal = wr; final String wsFinal = ws;
                                String wlabel = h.paramName + " @ " + h.path
                                        + " (in \"" + wk + "\" wrapper)  " + h.provenance();
                                if (confirmWith(wrFinal,
                                        v -> setNestedBodyParam(wrFinal, wkFinal, h.paramName, v),
                                        wsFinal, wlabel, true)) hits++;
                                wrappedTested = true;
                                break wrapSearch;
                            }
                        }
                    }
                    if (wrappedTested) continue;   // found a valid wrapper — skip flat confirm
                    continue;   // no wrapper worked either — endpoint fully rejects our params
                }
            }

            String label = h.paramName + " @ " + h.path + "  " + h.provenance();
            if (confirm(req, h.paramName, label, true)) hits++;
        }
        return hits;
    }

    /** Generic pass over an already-discovered request: test its params (arithmetic always; time-based only on
     *  command-ish names to bound cost). Also drills one level into single-key JSON wrappers so params like
     *  {"body":{"command":"…"}} are reached even when the top-level key is not command-ish. */
    public boolean probe(HttpRequest req) {
        try {
            if (req == null) return false;
            // Top-level params (URL + BODY)
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                boolean timeBased = CMDISH.matcher(p.name()).find();
                if (confirm(req, p.name(), p.name() + " (" + p.type() + ")", timeBased)) return true;
            }
            // Nested JSON drilling: {"wrapper":{"command":"…"}} — top-level key is not command-ish but inner is.
            String body = req.bodyToString();
            if (body != null && body.trim().startsWith("{")) {
                try {
                    org.json.JSONObject top = new org.json.JSONObject(body);
                    if (top.length() == 1) {
                        String wrapKey = top.keys().next();
                        Object wrapVal = top.opt(wrapKey);
                        if (wrapVal instanceof org.json.JSONObject) {
                            org.json.JSONObject inner = (org.json.JSONObject) wrapVal;
                            for (String k : inner.keySet()) {
                                if (!CMDISH.matcher(k).find()) continue;
                                String label = k + " (nested in \"" + wrapKey + "\") (BODY)";
                                if (confirmWith(req, v -> setNestedBodyParam(req, wrapKey, k, v),
                                        seed(k), label, true)) return true;
                            }
                        }
                    }
                } catch (Throwable ignore) { }
            }
            return false;
        } catch (Throwable t) { scanLog.debug("cmdi probe error: " + t); return false; }
    }

    // Fallback seeds for whitelisted/restricted command endpoints (tried when the primary seed is blocked).
    // "uptime" heads the list because many security CTFs/labs whitelist it specifically.
    private static final String[] CMD_SEEDS = { "uptime", "ls", "id", "whoami", "dir", "echo 1", "" };

    /** Run all oracles on one param via a supplied value-injector:
     *  (1) eval/SSJS arithmetic (always) — cheapest, no delay;
     *  (2) echo-canary stdout-reflection (command-ish only) — no delay, works when timing is filtered;
     *  (3) time-based sleep (command-ish only) — definitive even without stdout reflection. */
    private boolean confirmWith(HttpRequest baseReq, Function<String, HttpRequest> inject,
                                String seedVal, String label, boolean timeBased) {
        try {
            HttpRequest seedReq = inject.apply(seedVal);
            if (seedReq == null) return false;
            HttpRequestResponse baseRR = send(seedReq);
            if (baseRR == null || baseRR.response() == null) return false;
            String baseBody = baseRR.response().bodyToString();

            // Seed-fallback: if the initial seed is rejected (4xx — whitelist, validation, etc.),
            // probe common command values until one is accepted. This lets the echo-canary and
            // time-based oracles run even against endpoints that whitelist specific commands
            // (e.g. {"whitelist":{"commands":["uptime"]}}).
            if (timeBased && baseRR.response().statusCode() >= 400) {
                String foundSeed = null;
                HttpRequestResponse foundRR = null;
                for (String alt : CMD_SEEDS) {
                    if (alt.equals(seedVal)) continue;
                    HttpRequest ar = inject.apply(alt);
                    if (ar == null) continue;
                    HttpRequestResponse ar2 = send(ar);
                    if (ar2 != null && ar2.response() != null && ar2.response().statusCode() < 400) {
                        foundSeed = alt; foundRR = ar2; break;
                    }
                }
                if (foundSeed == null) return false;   // every seed blocked — not injectable via this oracle
                seedVal  = foundSeed;
                baseRR   = foundRR;
                baseBody = foundRR.response().bodyToString();
            }

            // --- oracle 1: eval / SSJS arithmetic ---
            if (baseBody == null || !baseBody.contains(String.valueOf(EV_PRODUCT))) {
                for (String expr : EVAL_EXPRS) {
                    HttpRequest er = inject.apply(expr);
                    if (er == null) continue;
                    HttpRequestResponse r = send(er);
                    if (r == null || r.response() == null) continue;
                    String b = r.response().bodyToString();
                    if (b != null && b.contains(String.valueOf(EV_PRODUCT))) {
                        scanLog.found("Server-side code injection (eval)", baseReq.url(),
                                label + " — injected `" + expr + "` evaluated to " + EV_PRODUCT
                                + " in the response (arithmetic oracle: the value was computed, not echoed).", r);
                        scanLog.incFinding();
                        return true;
                    }
                }
            }

            if (timeBased) {
                // --- oracle 2: echo-canary stdout-reflection (faster than sleep; run before time-based) ---
                // Canary: fixed prefix + nonce. Lowercase hex avoids shell quoting issues.
                String canary = "cmdi" + Integer.toHexString(NONCE.incrementAndGet() & 0xFFFF) + "ok";
                for (String sep : ECHO_SEPS) {
                    HttpRequest cr = inject.apply(seedVal + sep + canary);
                    if (cr == null) continue;
                    HttpRequestResponse r = send(cr);
                    if (r == null || r.response() == null) continue;
                    String rb = r.response().bodyToString();
                    if (rb != null && rb.contains(canary)) {
                        scanLog.found("OS command injection", baseReq.url(),
                                label + " — echo canary \"" + canary + "\" appeared verbatim in the response "
                                + "after injection via `" + sep.trim() + "`. The shell executed the injected "
                                + "command (stdout-reflection oracle, zero false-positive).", r);
                        scanLog.incFinding();
                        return true;
                    }
                }

                // --- oracle 3: time-based sleep ---
                for (String sep : CMD_SEPARATORS) {
                    long t0 = System.nanoTime();
                    HttpRequest tr = inject.apply(seedVal + sep);
                    if (tr == null) continue;
                    HttpRequestResponse r = send(tr);
                    long dt = (System.nanoTime() - t0) / 1_000_000;
                    if (r != null && r.response() != null && dt >= DELAY_THRESHOLD_MS) {
                        long c0 = System.nanoTime();
                        send(inject.apply(seedVal));
                        long cdt = (System.nanoTime() - c0) / 1_000_000;
                        if (cdt < DELAY_THRESHOLD_MS) {
                            scanLog.found("OS command injection", baseReq.url(),
                                    label + " — payload `" + sep.trim() + "` delayed the response " + dt
                                    + "ms (baseline " + cdt + "ms); the injected sleep executed.", r);
                            scanLog.incFinding();
                            return true;
                        }
                    }
                }
            }
        } catch (Throwable t) { scanLog.debug("cmdi confirm error: " + t); }
        return false;
    }

    /** Convenience wrapper: top-level param injection (existing surface). */
    private boolean confirm(HttpRequest req, String param, String label, boolean timeBased) {
        String sv = firstValue(req, param);
        if (sv == null || sv.isBlank()) sv = seed(param);
        final String seedVal = sv;
        return confirmWith(req, v -> setParam(req, param, v), seedVal, label, timeBased);
    }

    /** Build a request with {@code innerKey} updated inside a single-key JSON wrapper
     *  (e.g. {@code {"body":{"command":"PAYLOAD"}}}). Returns null on any parse failure. */
    private static HttpRequest setNestedBodyParam(HttpRequest req, String wrapKey, String innerKey, String value) {
        try {
            String body = req.bodyToString();
            org.json.JSONObject top = (body != null && body.trim().startsWith("{"))
                    ? new org.json.JSONObject(body) : new org.json.JSONObject();
            org.json.JSONObject inner = top.optJSONObject(wrapKey);
            if (inner == null) inner = new org.json.JSONObject();
            inner.put(innerKey, value);
            top.put(wrapKey, inner);
            return req.withBody(top.toString()).withHeader("Content-Type", "application/json");
        } catch (Throwable t) { return null; }
    }

    // ---- request synthesis from a hint ----

    private HttpRequest synthesize(StaticHint h, String base) {
        try {
            String path = h.path.replaceAll("\\{[^}]*}", "1");
            if (!path.startsWith("/")) path = "/" + path;
            String method = h.method.isBlank() ? "GET" : h.method.toUpperCase();
            String abs = base.replaceFirst("/+$", "") + path;
            List<String> allParams = new ArrayList<>();
            allParams.add(h.paramName);
            for (String p : h.params) if (!allParams.contains(p)) allParams.add(p);
            if ("POST".equals(method) || "PUT".equals(method)) {
                StringBuilder sb = new StringBuilder("{");
                for (int i = 0; i < allParams.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append('"').append(allParams.get(i)).append("\":\"").append(seed(allParams.get(i))).append('"');
                }
                sb.append('}');
                return HttpRequest.httpRequestFromUrl(abs).withMethod(method)
                        .withAddedHeader("Content-Type", "application/json").withBody(sb.toString());
            }
            HttpRequest req = HttpRequest.httpRequestFromUrl(abs).withMethod(method);
            for (String p : allParams) req = req.withAddedParameters(HttpParameter.urlParameter(p, seed(p)));
            return req;
        } catch (Throwable t) { scanLog.debug("cmdi synth error for " + h.path + ": " + t); return null; }
    }

    /** A benign baseline value for a param — a resolvable host for command sinks, else a harmless "1". */
    private static String seed(String name) {
        return CMDISH.matcher(name == null ? "" : name).find() && name.toLowerCase().matches(".*(host|ip|addr|ping|target|dns|url|domain).*")
                ? "127.0.0.1" : "1";
    }

    private static boolean isCmdOrEval(StaticHint h) {
        // Include paramName: a param literally named "command"/"cmd"/"exec" is always a CMDI candidate
        // even if the LLM didn't assign a command/eval vulnClass to the hint.
        String v = (h.vulnClass + " " + h.sinkType + " " + h.paramName).toLowerCase();
        return v.contains("command") || v.contains("cmd") || v.contains("rce")
                || v.contains("eval") || v.contains("code") || v.contains("exec");
    }

    // ---- helpers ----

    private HttpRequest setParam(HttpRequest req, String name, String value) {
        HttpParameterType t = HttpParameterType.URL;
        for (ParsedHttpParameter p : req.parameters())
            if (p.name().equals(name) && (p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY)) { t = p.type(); break; }
        return req.withUpdatedParameters(HttpParameter.parameter(name, value, t));
    }

    private static String firstValue(HttpRequest req, String name) {
        for (ParsedHttpParameter p : req.parameters()) if (p.name().equals(name)) return p.value();
        return null;
    }

    protected HttpRequestResponse send(HttpRequest req) {   // overrides Probe.send(req): custom sleep-tied timeout
        politeness();   // ScanConfig politeness delay
        // Response timeout must exceed the injected sleep so a successful delay is OBSERVED, not cut off.
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout((SLEEP_S + 8) * 1000L)); }
        catch (Throwable t) { return null; }
    }
}
