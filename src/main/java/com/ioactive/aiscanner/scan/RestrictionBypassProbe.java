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
import java.util.List;
import java.util.regex.Pattern;

/**
 * Deterministic client-side-restriction-bypass + parameter-tampering probe — fully generic. A browser's
 * client-side controls (option lists, maxlength, format regexes, read-only/hidden fields, computed
 * totals) only constrain the honest user; a scanner submits raw bytes. For each discovered form this
 * re-submits it with values a client would BLOCK:
 * <ul>
 *   <li><b>bypass</b>: every text field gets an over-length, mixed-charset, special-char value that
 *       violates length limits, format regexes, and fixed option/radio/checkbox choices;</li>
 *   <li><b>tamper</b>: every number-looking field gets a boundary value (0 / a large value) — the
 *       classic price/quantity/total tamper.</li>
 * </ul>
 * Oracle: the server ACCEPTS the restricted submission — a generic success signal appears that the
 * baseline lacked. No app knowledge, no field names, no per-target payloads. (On lesson/challenge apps
 * the acceptance is also recorded server-side, which is what the benchmark counts.)
 */
public final class RestrictionBypassProbe extends Probe {

    // api + scanLog inherited from Probe

    // A value a client would block yet is safe server-side: long + mixed-charset + special char, so it
    // violates length<=5, ^[a-z]{3}$, ^[0-9]{3}$, ^[a-zA-Z0-9 ]*$ (the '!'), fixed option/on/off/"change"
    // choices — AND is high-entropy enough to also pass a "strong password" server check (zxcvbn>=4).
    private static final String BYPASS = "Aisc9!Byp4ss#Xz7wQ2rT";
    // A field is "numeric" (keep it parseable / tamper it, don't inject a string) by value or by name.
    private static final Pattern NUMERIC_VAL = Pattern.compile("-?\\d+(?:\\.\\d+)?");
    private static final Pattern NUMERIC_NAME = Pattern.compile(
            "(?i).*(qty|quantity|amount|total|price|cost|count|num|number|error|balance|sum|score|age|year).*");
    private static final Pattern SUCCESS = Pattern.compile(
            "(?i)\"lessonCompleted\"\\s*:\\s*true|\"solved\"\\s*:\\s*true|\"success\"\\s*:\\s*true"
            + "|congratulation|well done|you (?:have )?(?:just )?(?:solved|completed|passed|bought)"
            + "|assignment (?:solved|completed)");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public RestrictionBypassProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    /** Probe one form (already carrying the authenticated session). Returns true if the server accepted a restricted submission. */
    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            List<ParsedHttpParameter> params = formParams(req);
            if (params.isEmpty()) return false;

            String baseBody = body(send(req));
            if (SUCCESS.matcher(baseBody).find()) return false;   // already "solved" in the baseline → not us

            // Variant 1 — bypass: every field gets the restriction-violating BYPASS string. Only fields the
            // SERVER binds as a number (name looks numeric, e.g. an "error"/"count" flag) go to a safe "0" —
            // a string there would 400 on int binding. A field whose *value* merely looks numeric (a
            // maxlength'd default like "12345") is exactly the client restriction we must violate, so it
            // still gets BYPASS. Keying off name (not value) is what lets a numeric-defaulted text field
            // (shortInput) be over-lengthened instead of shrunk to "0".
            if (accepted(mutate(req, params, p -> nameNumeric(p) ? "0" : BYPASS), baseBody,
                    "bypass client-side field restrictions", req.url())) return true;

            // Variant 2 — tamper: number-looking fields pushed to boundary values (undercut totals/prices).
            if (params.stream().anyMatch(RestrictionBypassProbe::isNumeric)) {
                for (String boundary : new String[]{"999999999", "0", "-1"}) {
                    final String b = boundary;
                    if (accepted(mutate(req, params, p -> isNumeric(p) ? b : safe(p.value())), baseBody,
                            "tampered numeric field to " + boundary, req.url())) return true;
                }
            }

            // Variant 3 — field-name tamper: some servers validate by EXACT field name (e.g. a
            // containsKey("secQuestion0") guard) yet accept any number of same-family fields. Renaming the
            // indexed/array-style fields (name ends in a digit) to novel names slips past that name-keyed
            // validation WITHOUT knowing any secret answer. Keys off param-name STRUCTURE only — never an app
            // value — and fires only on the success oracle, so false-positive risk stays low.
            if (params.stream().anyMatch(RestrictionBypassProbe::indexed)) {
                if (accepted(mutateNames(req, params), baseBody,
                        "renamed indexed field names (server validated by exact name)", req.url())) return true;
            }
        } catch (Throwable t) {
            scanLog.debug("restriction-bypass probe error: " + t);
        }
        return false;
    }

    private boolean accepted(HttpRequest mutated, String baseBody, String how, String url) {
        HttpRequestResponse rr = send(mutated);
        if (rr == null || rr.response() == null) return false;
        String b = rr.response().bodyToString();
        if (SUCCESS.matcher(b).find() && !SUCCESS.matcher(baseBody).find()) {
            scanLog.found("Client-side restriction bypass / parameter tampering", url,
                    how + " → server accepted it (attached: the tampered request the server accepted)", rr);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    /** Tamper targeting: a field is numeric if its value OR name looks numeric (price/qty/total to boundary). */
    private static boolean isNumeric(ParsedHttpParameter p) {
        String v = p.value();
        return (v != null && !v.isBlank() && NUMERIC_VAL.matcher(v.trim()).matches()) || nameNumeric(p);
    }

    /** Bypass gating: only a field the server binds as a number (by NAME) must stay a valid integer. A
     *  merely numeric-looking value is a client restriction to violate, not a reason to send "0". */
    private static boolean nameNumeric(ParsedHttpParameter p) {
        return NUMERIC_NAME.matcher(p.name()).matches();
    }

    // An indexed/array-style field name — ends in a digit (secQuestion0, field1, items2...). These are the
    // fields a name-keyed server check tends to whitelist by exact name and thus can be renamed to bypass it.
    private static final Pattern INDEXED_NAME = Pattern.compile(".*\\d$");
    private static boolean indexed(ParsedHttpParameter p) { return INDEXED_NAME.matcher(p.name()).matches(); }

    private static List<ParsedHttpParameter> formParams(HttpRequest req) {
        List<ParsedHttpParameter> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        if (!req.hasParameters()) return out;
        for (ParsedHttpParameter p : req.parameters())
            // dedupe by name — a radio/checkbox group repeats a name, and passing it twice to
            // withUpdatedParameters throws, silently aborting the whole probe on that form.
            if ((p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY) && seen.add(p.name()))
                out.add(p);
        return out;
    }

    /** Rebuild the request with mutated values. Rebuilds the form body / query directly instead of using
     *  withUpdatedParameters, which throws when a form repeats a param name (radio/checkbox groups). */
    private static HttpRequest mutate(HttpRequest req, List<ParsedHttpParameter> params,
                                      java.util.function.Function<ParsedHttpParameter, String> valueFn) {
        HttpRequest r = req;
        StringBuilder body = new StringBuilder();
        boolean hasBody = false;
        for (ParsedHttpParameter p : params) {
            if (p.type() != HttpParameterType.BODY) continue;
            hasBody = true;
            if (body.length() > 0) body.append('&');
            body.append(enc(p.name())).append('=').append(enc(valueFn.apply(p)));
        }
        if (hasBody) r = r.withBody(body.toString());
        List<HttpParameter> urlUpdates = new ArrayList<>();
        for (ParsedHttpParameter p : params)
            if (p.type() == HttpParameterType.URL) urlUpdates.add(HttpParameter.parameter(p.name(), valueFn.apply(p), HttpParameterType.URL));
        if (!urlUpdates.isEmpty()) { try { r = r.withUpdatedParameters(urlUpdates.toArray(new HttpParameter[0])); } catch (Throwable ignore) { } }
        return r;
    }

    /** Rebuild the request renaming indexed/array-style BODY fields (name ends in a digit) with a suffix,
     *  keeping their values and every other param intact — a generic field-name-tampering mutation. Other
     *  params (incl. required non-indexed ones like userId) are left untouched so the request still binds. */
    private static HttpRequest mutateNames(HttpRequest req, List<ParsedHttpParameter> params) {
        StringBuilder body = new StringBuilder();
        boolean hasBody = false;
        for (ParsedHttpParameter p : params) {
            if (p.type() != HttpParameterType.BODY) continue;
            hasBody = true;
            String name = indexed(p) ? p.name() + "z" : p.name();
            if (body.length() > 0) body.append('&');
            body.append(enc(name)).append('=').append(enc(safe(p.value())));
        }
        return hasBody ? req.withBody(body.toString()) : req;
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s == null ? "" : s, java.nio.charset.StandardCharsets.UTF_8);
    }
    private static String safe(String s) { return s == null ? "" : s; }

    // send(HttpRequest) inherited from Probe (politeness + configured request timeout).

    private static String body(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : ""; }
        catch (Throwable t) { return ""; }
    }
}
