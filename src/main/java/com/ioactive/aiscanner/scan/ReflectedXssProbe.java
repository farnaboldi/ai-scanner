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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Deterministic reflected-XSS probe with CONTEXT-AWARE breakout. Complements Burp's native reflected-XSS check,
 * which is conservative about reflections that land in a non-live context (an HTML comment, a script string): it
 * reports them only as INFO "input returned reflected" and never escalates — so a real, exploitable reflected XSS
 * whose sink is an HTML comment (e.g. Zero Bank's Find-Transactions "description", echoed into a
 * {@code <!-- Transaction filter was: description - X -->} debug comment) is silently missed.
 *
 * <p>Method (zero-FP): (1) send a bare unique canary and locate where it reflects; (2) classify the reflection
 * CONTEXT — plain HTML, inside an HTML comment, inside a &lt;script&gt;, or inside a tag/attribute; (3) send the
 * breakout payload for that context ({@code --> …} for a comment, {@code </script> …} for a script, {@code "> …}
 * for an attribute, bare tag for plain HTML) carrying a unique {@code <svg onload=MK>} marker; (4) confirm the
 * marker tag reflects VERBATIM (unencoded) into an HTML response AND lands in an EXECUTABLE context (not still
 * inside a comment/script) — then re-confirm. Only then is it a real, browser-executable reflected XSS (CWE-79).
 */
public final class ReflectedXssProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private static final AtomicInteger SEQ = new AtomicInteger();
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public ReflectedXssProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            // NEVER fuzz login/logout/signin pages: hitting them with the live session logs us OUT, so every
            // authenticated endpoint tested AFTER bounces to login (302) and its reflected sink is missed. Mirror
            // the other probes' SESSION_RESET guard. Generic — no app-specific paths.
            if (AuthenticatedExplorer.SESSION_RESET.matcher(stripQ(req.url())).matches()) return false;
            boolean any = false;
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                if (fire(req, v -> req.withUpdatedParameters(HttpParameter.parameter(p.name(), v, p.type())),
                        p.name() + " (" + p.type() + ")")) any = true;
            }
            return any;
        } catch (Throwable t) {
            scanLog.debug("reflected-XSS probe error: " + t);
            return false;
        }
    }

    private boolean fire(HttpRequest req, Function<String, HttpRequest> build, String label) {
        // 1) bare canary → find WHERE and HOW it reflects.
        String canary = "axr" + SEQ.incrementAndGet() + "z";
        HttpRequestResponse rr0 = send(build.apply(canary));
        if (!isHtml(rr0)) {
            int st = rr0 != null && rr0.response() != null ? rr0.response().statusCode() : -1;
            // GENERIC: a 3xx here means the (authenticated) request bounced — usually to login → session not accepted.
            if (st >= 300 && st < 400)
                scanLog.debug("  rxss " + label + ": HTTP " + st + " redirect → "
                        + rr0.response().headerValue("Location") + " (session not accepted for this request?)");
            else scanLog.trace("  rxss " + label + ": response not HTML (HTTP " + st + ")");
            return false;
        }
        String body0 = rr0.response().bodyToString();
        int at = body0.indexOf(canary);
        if (at < 0) {
            // GENERIC: reflected nowhere. If it looks like a login page, the session was lost for this request.
            String lb = body0.toLowerCase();
            if (lb.contains("password") && (lb.contains("login") || lb.contains("sign in")))
                scanLog.debug("  rxss " + label + ": canary NOT reflected — LOGIN page (session lost for this request?)");
            else scanLog.trace("  rxss " + label + ": canary not reflected");
            return false;
        }

        // 2) classify the reflection context from what precedes the canary.
        boolean inComment = inComment(body0, at);
        boolean inScript  = inScript(body0, at);
        boolean inTag     = inTag(body0, at);
        scanLog.debug("  rxss " + label + ": canary REFLECTED (context: "
                + (inComment ? "comment" : inScript ? "script" : inTag ? "tag/attr" : "html") + ") — attempting breakout");

        // 3) build context-appropriate breakout payloads (ordered: the most specific first). Each carries a
        //    unique <svg onload=MK> so a confirmed verbatim reflection is unambiguously OUR injection.
        String mk = "xr" + SEQ.incrementAndGet();
        String tag = "<svg onload=" + mk + ">";
        java.util.List<String> payloads = new java.util.ArrayList<>();
        if (inComment) payloads.add("--><" + "svg onload=" + mk + "><!--");   // close the comment, inject, reopen
        if (inScript)  payloads.add("</script><svg onload=" + mk + "><script>");
        if (inTag)   { payloads.add("\"><svg onload=" + mk + ">"); payloads.add("'><svg onload=" + mk + ">"); }
        payloads.add(tag);                                                    // plain HTML context (also a fallback)

        for (String pl : payloads) {
            HttpRequestResponse rr = send(build.apply(pl));
            boolean present = rr != null && rr.response() != null && rr.response().bodyToString().contains(tag);
            boolean exec = executes(rr, tag);
            scanLog.debug("  rxss " + label + ": payload " + pl + " → tagPresent=" + present + " executes=" + exec);
            if (!exec) continue;
            HttpRequestResponse rr2 = send(build.apply(pl));                  // re-confirm (zero-FP)
            if (!executes(rr2, tag)) continue;
            String ctx = inComment ? "an HTML comment" : inScript ? "a <script> block"
                    : inTag ? "a tag/attribute" : "HTML text";
            // DEFER the dashboard issue to Burp's native audit. Once our form-exercise submits the POST form to
            // Burp's active audit, Burp DOES reach the sink and raises its own HIGH "Cross-site scripting (reflected)"
            // (verified on the dashboard: a single native issue with all instances). Raising our own "AI: …" issue
            // too would DUPLICATE it on the dashboard. Our finding + provenance still go to the log + AI report + the
            // benchmark count. (deferToBurp already no-ops in Community edition, where there IS no native audit.)
            boolean forceRaise = false;
            scanLog.found("Cross-site scripting (reflected)", req.url(),
                    label + " reflects unsanitized into " + ctx + "; the payload " + pl + " breaks out and injects "
                    + tag + " UNENCODED into an executable HTML context — runs in the browser (CWE-79).", forceRaise, rr);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    /** Confirmed = the injected marker tag appears VERBATIM (unencoded) in an HTML response AND is NOT trapped
     *  inside a comment or a script block (i.e. the breakout worked and the tag is in a live, executable position). */
    private static boolean executes(HttpRequestResponse rr, String tag) {
        if (!isHtml(rr)) return false;
        String body = rr.response().bodyToString();
        int i = body.indexOf(tag);
        if (i < 0) return false;
        return !inComment(body, i) && !inScript(body, i);
    }

    private static String trunc(String s) { return s == null ? "(none)" : s.length() > 60 ? s.substring(0, 60) + "…" : s; }
    private static String stripQ(String u) { int q = u == null ? -1 : u.indexOf('?'); return q < 0 ? u : u.substring(0, q); }

    private static boolean isHtml(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String ct = rr.response().headerValue("Content-Type");
        String body = rr.response().bodyToString();
        return (ct != null && ct.toLowerCase().contains("html"))
                || (body != null && (body.trim().regionMatches(true, 0, "<!doctype", 0, 9) || body.trim().startsWith("<")));
    }

    /** The position sits inside an HTML comment: the last "<!--" before it is not yet closed by a "-->". */
    private static boolean inComment(String body, int idx) {
        String b = body.substring(0, idx);
        return b.lastIndexOf("<!--") > b.lastIndexOf("-->");
    }

    /** The position sits inside a &lt;script&gt; body: last "<script" opens after the last "</script" closes. */
    private static boolean inScript(String body, int idx) {
        String b = body.substring(0, idx).toLowerCase();
        return b.lastIndexOf("<script") > b.lastIndexOf("</script");
    }

    /** The position sits inside an (unclosed) tag: last "<" after the last ">" before it. */
    private static boolean inTag(String body, int idx) {
        String b = body.substring(0, idx);
        return b.lastIndexOf('<') > b.lastIndexOf('>');
    }

    /** Force Burp's project cookie jar to match the request's OWN Cookie header for this host. On
     *  api.http().sendRequest, a stale JSESSIONID in the jar (e.g. an unauthenticated one the native crawler set)
     *  can OVERRIDE our explicit authenticated Cookie header — the server then sees the unauth session and 302s to
     *  login. Aligning the jar first makes the authenticated cookie win. No-op if the request carries no Cookie. */
    private void syncJar(HttpRequest req) {
        try {
            String cookie = req.headerValue("Cookie");
            if (cookie == null || cookie.isBlank()) return;
            String host = URI.create(req.url()).getHost();
            for (String pair : cookie.split(";")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                api.http().cookieJar().setCookie(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim(),
                        "/", host, java.time.ZonedDateTime.now().plusDays(1));
            }
        } catch (Throwable ignore) { }
    }

    private HttpRequestResponse send(HttpRequest req) {
        try {
            syncJar(req);
            HttpRequestResponse rr = AiScanner.decompress(
                    api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)));
            // Authenticated POSTs can bounce through an interstitial (Zero Bank redirects to /auth/accept-certs.html
            // when the session needs re-priming) — a 302 whose empty body has no reflection. Walk the interstitial
            // carrying our session cookie, then RE-SEND the original request once so its params actually reach the
            // sink. Only fires on a 3xx (bounded); returns the re-sent response. Generic (no app-specific paths).
            if (rr != null && rr.response() != null) {
                int st = rr.response().statusCode();
                String loc = st >= 300 && st < 400 ? rr.response().headerValue("Location") : null;
                // GENERIC diagnostic (no app-specific paths): an authenticated request that REDIRECTS (3xx) likely
                // bounced to login → the session isn't being accepted for it. Log where it went + the cookie sent
                // vs any Set-Cookie the server returned, so a lost/rotated session is visible. debug-level only.
                boolean dbg = loc != null;
                if (dbg) {
                    String setc = String.join(" | ", rr.response().headers().stream()
                            .filter(h -> h.name().equalsIgnoreCase("Set-Cookie")).map(h -> h.value()).toList());
                    scanLog.debug("  rxss " + req.method() + " " + stripQ(req.url()) + " → HTTP " + st
                            + " Location: " + loc + " | sent-Cookie=" + trunc(req.headerValue("Cookie"))
                            + (setc.isBlank() ? "" : " | Set-Cookie=" + trunc(setc)));
                }
                if (loc != null && !loc.isBlank()) {
                    try {
                        String abs = URI.create(req.url()).resolve(loc).toString().replaceFirst("^https://", "http://");
                        HttpRequest walk = HttpRequest.httpRequestFromUrl(abs).withMethod("GET");
                        String cookie = req.headerValue("Cookie");
                        if (cookie != null) walk = walk.withHeader("Cookie", cookie);
                        HttpRequestResponse wr = api.http().sendRequest(walk, RequestOptions.requestOptions().withResponseTimeout(12000L));
                        if (dbg && wr != null && wr.response() != null)
                            scanLog.debug("  rxss walk GET " + abs + " → HTTP " + wr.response().statusCode()
                                    + (wr.response().statusCode() >= 300 && wr.response().statusCode() < 400 ? " Location: " + wr.response().headerValue("Location") : ""));
                    } catch (Exception ignore) { }
                    syncJar(req);   // the interstitial walk-GET may have re-polluted the jar — realign before re-send
                    rr = AiScanner.decompress(
                            api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)));
                    if (dbg && rr != null && rr.response() != null)
                        scanLog.debug("  rxss re-POST → HTTP " + rr.response().statusCode());
                }
            }
            return rr;
        } catch (Throwable t) { return null; }
    }
}
