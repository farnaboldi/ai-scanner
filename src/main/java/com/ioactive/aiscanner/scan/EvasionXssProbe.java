package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Reflected-XSS probe that runs ONLY in WAF-evasion mode ({@link Evasion#enabled()}). On a normal (no-WAF)
 * scan Burp's native active audit already detects reflected XSS with richer evidence, so we don't duplicate
 * it there. But behind a signature WAF, Burp's canonical XSS payloads get blocked — so in evasion mode we
 * try OBFUSCATED tag vectors (mixed case, alternate tags/handlers) that slip common XSS signatures, and fire
 * only if the tag reflects UNENCODED into an HTML-context response. Zero-FP: unique canary + raw-tag +
 * HTML-content-type + re-confirmation.
 */
public final class EvasionXssProbe extends Probe {

    // api + scanLog inherited from Probe
    private static final AtomicInteger SEQ = new AtomicInteger();
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public EvasionXssProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    public boolean probe(HttpRequest req) {
        if (!Evasion.enabled()) return false;        // evasion-mode only — Burp owns XSS on normal scans
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                if (fire(req, v -> req.withUpdatedParameters(HttpParameter.parameter(p.name(), v, p.type())),
                        p.name() + " (" + p.type() + ")")) return true;
            }
        } catch (Throwable t) {
            scanLog.debug("evasion-XSS probe error: " + t);
        }
        return false;
    }

    private boolean fire(HttpRequest req, Function<String, HttpRequest> build, String label) {
        String mk = "aixev" + SEQ.incrementAndGet() + "z";
        // WAF-evasion tag vectors: mixed case + a less-signatured element/handler than <script>. The exact
        // tag string is echoed unchanged by a reflecting endpoint, so we match it verbatim.
        String[] vectors = {
                "<sVg/onload=" + mk + ">",
                "<iMg src=x onerror=" + mk + ">",
                "<deTails/open/ontoggle=" + mk + ">",
        };
        for (String tag : vectors) {
            HttpRequestResponse rr = send(build.apply(tag));
            if (!reflectedUnencodedInHtml(rr, tag)) continue;
            HttpRequestResponse rr2 = send(build.apply(tag));      // confirm
            if (!reflectedUnencodedInHtml(rr2, tag)) continue;
            scanLog.found("Cross-site scripting (reflected, WAF-evasion)", req.url(),
                    label + " reflected an obfuscated HTML tag UNENCODED into an HTML response (" + tag
                    + ") — executes in the browser and slipped the WAF's XSS signatures (CWE-79).", rr);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    private static boolean reflectedUnencodedInHtml(HttpRequestResponse rr, String tag) {
        if (rr == null || rr.response() == null) return false;
        String ct = rr.response().headerValue("Content-Type");
        String body = rr.response().bodyToString();
        boolean html = (ct != null && ct.toLowerCase().contains("html"))
                || (body != null && body.trim().regionMatches(true, 0, "<!doctype", 0, 9))
                || (body != null && body.trim().startsWith("<"));
        return html && body != null && body.contains(tag);
    }

    // send(HttpRequest) inherited from Probe (politeness + configured request timeout).
}
