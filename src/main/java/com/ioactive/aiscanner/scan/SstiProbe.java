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


/**
 * Deterministic Server-Side Template Injection (SSTI, CWE-1336) — the gap left by {@link CommandInjectionProbe},
 * which only injects BARE arithmetic ({@code 8161*7919}) that a template engine won't evaluate outside its
 * delimiters. This probe injects a distinctive product WRAPPED in every major engine's delimiters and confirms
 * with an arithmetic canary: if the COMPUTED product appears in the response — but the literal payload does NOT
 * (so it wasn't merely reflected) and it was absent from the baseline — the engine evaluated our expression.
 * Zero-FP: a unique product that only server-side evaluation could produce. SSTI is routinely escalatable to RCE.
 *
 * <p>Generic: it fuzzes discovered request parameters (and SAST-flagged template sinks); no app-specific paths.
 * Covers Jinja2/Twig/Nunjucks ({@code {{}}}), FreeMarker/JSP-EL/Thymeleaf/Velocity/JS ({@code ${}}), Ruby/Thymeleaf
 * ({@code #{}}), ERB/EJS ({@code <%= %>}) and bare-brace engines.</p>
 */
public final class SstiProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private SourceFindings sourceHints;

    // Distinctive operands (separate from CommandInjectionProbe's so findings don't collide); the product is
    // COMPUTED from them — never a hand-typed literal — so the oracle value can't drift from the payload.
    private static final long A = 73331L, B = 24499L;
    private static final long PRODUCT = A * B;
    private static final String EXPR = A + "*" + B;
    private static final String[] PAYLOADS = {
            "{{" + EXPR + "}}",        // Jinja2 / Twig / Nunjucks / Django
            "${" + EXPR + "}",         // FreeMarker / JSP-EL / Thymeleaf / Velocity / JS template literal
            "#{" + EXPR + "}",         // Ruby (Slim/ERB attr) / Thymeleaf
            "<%= " + EXPR + " %>",     // ERB / EJS
            "{" + EXPR + "}",          // bare-brace (some engines / format-string)
            "${{" + EXPR + "}}",       // Spring/Handlebars polyglot
    };

    public SstiProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    /** Test each URL/BODY parameter of a discovered request for SSTI. Returns true on the first confirmed hit. */
    public boolean probe(HttpRequest req) {
        try {
            if (req == null || !req.hasParameters()) return false;
            HttpRequestResponse base = send(req);
            String baseBody = base != null && base.response() != null ? base.response().bodyToString() : null;
            if (baseBody != null && baseBody.contains(String.valueOf(PRODUCT))) return false;   // product already present → FP guard
            String prov = prov(req.url());
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                for (String payload : PAYLOADS) {
                    HttpRequestResponse r = send(setParam(req, p.name(), p.type(), payload));
                    if (r == null || r.response() == null) continue;
                    String b = r.response().bodyToString();
                    if (b == null) continue;
                    // COMPUTED (product present) but NOT merely reflected (literal payload absent) ⇒ the engine ran it.
                    if (b.contains(String.valueOf(PRODUCT)) && !b.contains(payload)) {
                        scanLog.found("Server-Side Template Injection (SSTI)", req.url(),
                                "Parameter '" + p.name() + "' is evaluated by a server-side template engine: injecting "
                              + payload + " returned the COMPUTED product " + PRODUCT + " (the literal payload was NOT "
                              + "reflected, and the product was absent from the baseline) — the engine executed our "
                              + "expression (CWE-1336), routinely escalatable to RCE. Deterministic: a unique arithmetic "
                              + "product computed server-side." + prov, r);
                        scanLog.incFinding();
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] SSTI probe error: " + t);
        }
        return false;
    }

    private HttpRequest setParam(HttpRequest req, String name, HttpParameterType type, String value) {
        return req.withUpdatedParameters(HttpParameter.parameter(name, value, type));
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)); }
        catch (Throwable t) { return null; }
    }

    /** Provenance suffix when a source-analysis SSTI/template sink matches this url (else empty). */
    private String prov(String url) {
        if (sourceHints == null) return "";
        for (StaticHint h : sourceHints.all())
            if (("SSTI".equalsIgnoreCase(h.vulnClass) || "template".equalsIgnoreCase(h.sinkType))
                    && (!h.hasEndpoint() || h.matchesUrl(url))) return "  " + h.provenance();
        return "";
    }
}
