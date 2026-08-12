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

import java.net.URI;
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
public final class CommandInjectionProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private SourceFindings sourceHints;

    public CommandInjectionProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
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

    /** Hint-driven pass: synthesize a concrete request for every command/eval sink the source pins, and confirm. */
    public int probeHints(String host, Function<HttpRequest, HttpRequest> withSession, String base) {
        if (sourceHints == null || base == null) return 0;
        int hits = 0;
        for (StaticHint h : sourceHints.all()) {
            if (!isCmdOrEval(h) || !h.hasEndpoint() || !h.hasParam()) continue;
            HttpRequest req = synthesize(h, base);
            if (req == null) continue;
            try { req = withSession.apply(req); } catch (Throwable ignore) { }
            String label = h.paramName + " @ " + h.path + "  " + h.provenance();
            if (confirm(req, h.paramName, label, true)) hits++;
        }
        return hits;
    }

    /** Generic pass over an already-discovered request: test its params (arithmetic always; time-based only on
     *  command-ish names to bound cost). Complements the hint pass for surface the crawler DID reach. */
    public boolean probe(HttpRequest req) {
        try {
            if (req == null) return false;
            boolean any = false;
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                boolean timeBased = CMDISH.matcher(p.name()).find();
                if (confirm(req, p.name(), p.name() + " (" + p.type() + ")", timeBased)) { any = true; break; }
            }
            return any;
        } catch (Throwable t) { scanLog.debug("[AI Scanner] cmdi probe error: " + t); return false; }
    }

    /** Run the eval (always) + time-based (when enabled) oracles on one param of one request. */
    private boolean confirm(HttpRequest req, String param, String label, boolean timeBased) {
        try {
            HttpRequestResponse base = send(req);
            if (base == null || base.response() == null) return false;
            String baseBody = base.response().bodyToString();
            // --- eval / SSJS: arithmetic oracle (cheap; run first) ---
            if (baseBody == null || !baseBody.contains(String.valueOf(EV_PRODUCT))) {   // product must NOT be in baseline
                for (String expr : EVAL_EXPRS) {
                    HttpRequestResponse r = send(setParam(req, param, expr));
                    if (r == null || r.response() == null) continue;
                    String b = r.response().bodyToString();
                    if (b != null && b.contains(String.valueOf(EV_PRODUCT))) {
                        scanLog.found("Server-side code injection (eval)", req.url(),
                                label + " — injected `" + expr + "` evaluated to " + EV_PRODUCT
                                + " in the response (arithmetic oracle: the value was computed, not echoed).", r);
                        scanLog.incFinding();
                        return true;
                    }
                }
            }
            // --- OS command: time-based oracle ---
            if (timeBased) {
                String seed = firstValue(req, param);
                if (seed == null || seed.isBlank()) seed = "127.0.0.1";
                for (String sep : CMD_SEPARATORS) {
                    long t0 = System.nanoTime();
                    HttpRequestResponse r = send(setParam(req, param, seed + sep));
                    long dt = (System.nanoTime() - t0) / 1_000_000;
                    if (r != null && r.response() != null && dt >= DELAY_THRESHOLD_MS) {
                        // confirm it's the injection (not a one-off network stall): a benign re-request is fast
                        long c0 = System.nanoTime();
                        send(setParam(req, param, seed));
                        long cdt = (System.nanoTime() - c0) / 1_000_000;
                        if (cdt < DELAY_THRESHOLD_MS) {
                            scanLog.found("OS command injection", req.url(),
                                    label + " — payload `" + sep.trim() + "` delayed the response " + dt
                                    + "ms (baseline " + cdt + "ms); the injected sleep executed.", r);
                            scanLog.incFinding();
                            return true;
                        }
                    }
                }
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner] cmdi confirm error: " + t); }
        return false;
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
        } catch (Throwable t) { scanLog.debug("[AI Scanner] cmdi synth error for " + h.path + ": " + t); return null; }
    }

    /** A benign baseline value for a param — a resolvable host for command sinks, else a harmless "1". */
    private static String seed(String name) {
        return CMDISH.matcher(name == null ? "" : name).find() && name.toLowerCase().matches(".*(host|ip|addr|ping|target|dns|url|domain).*")
                ? "127.0.0.1" : "1";
    }

    private static boolean isCmdOrEval(StaticHint h) {
        String v = (h.vulnClass + " " + h.sinkType).toLowerCase();
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

    private HttpRequestResponse send(HttpRequest req) {
        // Response timeout must exceed the injected sleep so a successful delay is OBSERVED, not cut off.
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout((SLEEP_S + 8) * 1000L)); }
        catch (Throwable t) { return null; }
    }
}
