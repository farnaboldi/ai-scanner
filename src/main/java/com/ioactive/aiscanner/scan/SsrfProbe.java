package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * Out-of-band SSRF confirmation via Burp Collaborator. For every url-like / SSRF-hinted parameter it submits a
 * unique Collaborator URL as the value, then polls for a callback: an HTTP/DNS interaction proves the server
 * fetched our attacker-controlled URL (CWE-918) — deterministic and zero-FP by construction.
 *
 * <p>Crucially it is <b>driven by the SAST SSRF hints</b>, not just the discovered targets: an SSRF endpoint
 * like {@code /import?url=} is often dropped from the audit surface (a self-referential seed mirrors the app's
 * catch-all page), so this probe builds the request straight from the hint (base + path + param) to test it.</p>
 */
public final class SsrfProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private SourceFindings sourceHints;
    // url-like-param heuristic (SSRF surface) is shared with EndpointDiscovery.URL_PARAM — single source of truth.

    public SsrfProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    /**
     * @param baseUrl scheme://authority of the target (for building hint-derived requests), or null
     * @param targets discovered audit targets (their url-like params are also tested)
     */
    public int probe(String baseUrl, List<HttpRequest> targets, UnaryOperator<HttpRequest> withSession) {
        CollaboratorClient collab;
        try { collab = api.collaborator().createClient(); }
        catch (Throwable t) { scanLog.debug("[AI Scanner]   ssrf: Collaborator unavailable — OAST SSRF skipped"); return 0; }

        Map<String, String[]> tagToPoint = new LinkedHashMap<>();   // tag -> {url, point-label}
        Map<String, HttpRequestResponse> tagToRr = new LinkedHashMap<>();   // tag -> the request that carried the payload
        Set<String> seen = new LinkedHashSet<>();
        int[] idx = {0};

        // (1) hint-driven: build the request from each SSRF hint (covers endpoints discovery dropped, e.g. /import).
        if (sourceHints != null && baseUrl != null) {
            for (StaticHint h : sourceHints.all()) {
                if (!"SSRF".equalsIgnoreCase(h.vulnClass) || !h.hasEndpoint()) continue;
                String pname = !h.paramName.isBlank() ? h.paramName : (h.params.isEmpty() ? null : h.params.get(0));
                if (pname == null || pname.isBlank()) continue;
                String abs = baseUrl.replaceAll("/+$", "") + (h.path.startsWith("/") ? h.path : "/" + h.path);
                if (!seen.add(pathKey(abs) + "|" + pname)) continue;
                fire(collab, tagToPoint, tagToRr, idx, abs, h.method.isBlank() ? "GET" : h.method, pname,
                        HttpParameterType.URL, withSession, "SSRF hint " + h.path);
            }
        }

        // (2) target-driven: any url-like param on a discovered target (belt and suspenders).
        if (targets != null) {
            for (HttpRequest req : targets) {
                for (ParsedHttpParameter p : req.parameters()) {
                    if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
                    if (!isSsrfParam(req.url(), p.name())) continue;
                    if (!seen.add(pathKey(req.url()) + "|" + p.name())) continue;
                    fireOn(collab, tagToPoint, tagToRr, idx, req, p.name(), p.type(), withSession);
                }
            }
        }

        if (tagToPoint.isEmpty()) return 0;
        scanLog.debug("[AI Scanner]   ssrf: fired " + tagToPoint.size() + " OAST payload(s); polling Collaborator…");
        return poll(collab, tagToPoint, tagToRr);
    }

    private boolean isSsrfParam(String url, String name) {
        if (EndpointDiscovery.URL_PARAM.matcher(name).matches()) return true;
        if (sourceHints != null) for (StaticHint h : sourceHints.all())
            if ("SSRF".equalsIgnoreCase(h.vulnClass) && h.paramName.equalsIgnoreCase(name)
                    && (!h.hasEndpoint() || h.matchesUrl(url))) return true;
        return false;
    }

    /** Build a fresh request at {@code abs} with {@code param}=<collab-url> and send it. */
    private void fire(CollaboratorClient collab, Map<String, String[]> tagToPoint, Map<String, HttpRequestResponse> tagToRr,
                      int[] idx, String abs, String method, String param, HttpParameterType type,
                      UnaryOperator<HttpRequest> withSession, String why) {
        try {
            String tag = "ssrf" + (idx[0]++);
            CollaboratorPayload cp = collab.generatePayload(tag);
            String payload = "http://" + cp.toString() + "/" + tag;
            HttpRequest req = HttpRequest.httpRequestFromUrl(abs).withMethod(method)
                    .withAddedParameters(HttpParameter.parameter(param, payload, type));
            HttpRequestResponse rr = send(req, withSession);
            tagToPoint.put(tag, new String[]{ abs, param + " (" + type + ") [" + why + "]" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
    }

    /** Inject a collab URL into an existing parameter of {@code req} and send it. */
    private void fireOn(CollaboratorClient collab, Map<String, String[]> tagToPoint, Map<String, HttpRequestResponse> tagToRr,
                        int[] idx, HttpRequest req, String param, HttpParameterType type, UnaryOperator<HttpRequest> withSession) {
        try {
            String tag = "ssrf" + (idx[0]++);
            CollaboratorPayload cp = collab.generatePayload(tag);
            String payload = "http://" + cp.toString() + "/" + tag;
            HttpRequest m = req.withUpdatedParameters(HttpParameter.parameter(param, payload, type));
            HttpRequestResponse rr = send(m, withSession);
            tagToPoint.put(tag, new String[]{ req.url(), param + " (" + type + ")" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
    }

    /** Send the payload request and return the request/response so it can be attached to the finding as proof.
     *  On a transport error we still return a request-only record — for an OAST hit the request itself is the proof. */
    private HttpRequestResponse send(HttpRequest req, UnaryOperator<HttpRequest> withSession) {
        HttpRequest s = withSession != null ? withSession.apply(req) : req;
        try {
            return api.http().sendRequest(s, RequestOptions.requestOptions().withResponseTimeout(15000L));
        } catch (Throwable t) {
            try { return HttpRequestResponse.httpRequestResponse(s, null); } catch (Throwable ignore) { return null; }
        }
    }

    private int poll(CollaboratorClient collab, Map<String, String[]> tagToPoint, Map<String, HttpRequestResponse> tagToRr) {
        int hits = 0;
        Set<String> fired = new LinkedHashSet<>();
        try {
            for (int round = 0; round < 6; round++) {           // ~15s total — enough for a synchronous fetch
                Thread.sleep(2500);
                List<Interaction> interactions;
                try { interactions = collab.getAllInteractions(); } catch (Throwable t) { break; }
                if (interactions == null || interactions.isEmpty()) continue;
                for (Interaction it : interactions) {
                    String tag = it.customData().orElse(null);
                    String[] pt = tag == null ? null : tagToPoint.get(tag);
                    if (pt == null || !fired.add(tag)) continue;
                    scanLog.found("Server-side request forgery (SSRF)", pt[0],
                            pt[1] + " → the server fetched our Collaborator URL (" + it.type()
                          + " interaction) — an attacker-controlled outbound request (CWE-918), proven out-of-band"
                          + prov(pt[0]),
                            tagToRr.get(tag));
                    scanLog.incFinding();
                    hits++;
                }
            }
        } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        catch (Throwable t) { scanLog.debug("[AI Scanner]   ssrf: poll error: " + t); }
        return hits;
    }

    private String prov(String url) {
        if (sourceHints == null) return "";
        for (StaticHint h : sourceHints.all())
            if ("SSRF".equalsIgnoreCase(h.vulnClass) && (!h.hasEndpoint() || h.matchesUrl(url)))
                return "  " + h.provenance();
        return "";
    }

    private static String pathKey(String u) {
        try { URI x = URI.create(u); return (x.getScheme() + "://" + x.getAuthority() + x.getPath()).toLowerCase(); }
        catch (Exception e) { return u == null ? "" : u.toLowerCase(); }
    }
}
