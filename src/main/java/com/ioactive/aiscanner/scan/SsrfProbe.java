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
public final class SsrfProbe extends Probe {

    private SourceFindings sourceHints;
    // url-like-param heuristic (SSRF surface) is shared with EndpointDiscovery.URL_PARAM — single source of truth.

    public SsrfProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    public void setSourceHints(SourceFindings hints) { this.sourceHints = hints; }

    /**
     * @param baseUrl scheme://authority of the target (for building hint-derived requests), or null
     * @param targets discovered audit targets (their url-like params are also tested)
     */
    // Hostnames used by the local listener: loopback for non-Docker targets, Docker-Desktop bridge for containers.
    private static final String[] LOCAL_HOSTS = { "127.0.0.1", "host.docker.internal" };

    public int probe(String baseUrl, List<HttpRequest> targets, UnaryOperator<HttpRequest> withSession) {
        // Start a local HTTP listener for SSRF callbacks — works without an external Collaborator server and
        // covers localhost/Docker targets where outbound DNS callbacks are unreachable.
        LocalSsrfListener localListener = LocalSsrfListener.start();
        if (localListener != null) scanLog.debug("  ssrf: local listener started on port " + localListener.port());

        CollaboratorClient collab;
        try { collab = api.collaborator().createClient(); }
        catch (Throwable t) {
            collab = null;
            if (localListener == null) { scanLog.debug("  ssrf: Collaborator unavailable and local listener failed — SSRF skipped"); return 0; }
            scanLog.debug("  ssrf: Collaborator unavailable — using local listener only.");
        }

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
                String method = h.method.isBlank() ? "GET" : h.method;
                if (collab != null) fire(collab, tagToPoint, tagToRr, idx, abs, method, pname,
                        HttpParameterType.URL, withSession, "SSRF hint " + h.path);
                if (localListener != null) for (String lh : LOCAL_HOSTS)
                    fireLocal(localListener, lh, tagToPoint, tagToRr, idx, abs, method, pname,
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
                    if (collab != null) fireOn(collab, tagToPoint, tagToRr, idx, req, p.name(), p.type(), withSession);
                    if (localListener != null) for (String lh : LOCAL_HOSTS)
                        fireLocalOn(localListener, lh, tagToPoint, tagToRr, idx, req, p.name(), p.type(), withSession);
                }
            }
        }

        // (3) JSON BODY fields — a url/path/dispatch value inside a JSON body (e.g. {"theUrl":"page/Viewer/Search"})
        // is NOT a Montoya parameter, so arms (1)/(2) never see it. A field whose NAME is url-ish (theUrl/redirectUrl/
        // endpoint…) OR whose VALUE is an app-relative path / absolute URL is a dispatch/SSRF sink: inject a
        // Collaborator/local URL and poll. Generic — no app paths.
        if (targets != null) {
            for (HttpRequest req : targets) {
                String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
                String body = req.bodyToString();
                if (body == null || body.indexOf('{') < 0) continue;
                if (ct != null && !ct.isBlank() && !ct.toLowerCase().contains("json") && body.indexOf('"') < 0) continue;
                java.util.regex.Matcher jm = JSON_STR.matcher(body);
                java.util.LinkedHashSet<String> doneKeys = new java.util.LinkedHashSet<>();
                while (jm.find()) {
                    String key = jm.group(1), val = jm.group(2);
                    if (!doneKeys.add(key)) continue;
                    if (!(NAME_URLISH.matcher(key).find() || looksPathOrUrl(val))) continue;
                    if (!seen.add(pathKey(req.url()) + "|json:" + key)) continue;
                    if (collab != null) fireJsonField(collab, tagToPoint, tagToRr, idx, req, body, key, withSession);
                    if (localListener != null) for (String lh : LOCAL_HOSTS)
                        fireLocalJson(localListener, lh, tagToPoint, tagToRr, idx, req, body, key, withSession);
                }
            }
        }

        // (4) BODY-ADD on write endpoints — a url-typed field named by an SSRF hint is often OPTIONAL and thus
        // ABSENT from a discovered PUT/POST/PATCH target's baseline body; arm (3) only rewrites keys that are
        // PRESENT, so it never fires. Take a discovered write target that already carries a VALID JSON body (the
        // required sibling fields the endpoint validates, synthesized during discovery) and ADD the hinted url
        // field pointing at our listener. This reaches url-fetch-on-create/update sinks generically
        // (avatar-by-URL, import-from-URL, image_url → server-side fetch), independent of the hint's HTTP method
        // (the SAST LLM often mislabels the route method as the sink's requests.get()).
        if (targets != null && sourceHints != null) {
            for (StaticHint h : sourceHints.all()) {
                if (!h.hasEndpoint()) continue;
                // A url-typed field on a write endpoint is an SSRF candidate BY STRUCTURE — don't depend on the
                // LLM having labelled the hint vulnClass=SSRF (it often mislabels the sink). Gate on the field NAME.
                java.util.LinkedHashSet<String> urlFields = new java.util.LinkedHashSet<>();
                if (!h.paramName.isBlank() && NAME_URLISH.matcher(h.paramName).find()) urlFields.add(h.paramName);
                for (String p : h.params) if (p != null && NAME_URLISH.matcher(p).find()) urlFields.add(p);
                if (urlFields.isEmpty()) continue;
                for (HttpRequest req : targets) {
                    String m = req.method();
                    if (!("POST".equalsIgnoreCase(m) || "PUT".equalsIgnoreCase(m) || "PATCH".equalsIgnoreCase(m))) continue;
                    if (!pathMatchesHint(req.url(), h)) continue;
                    String body = req.bodyToString();
                    if (body == null || body.indexOf('{') < 0) continue;                  // JSON-body write only
                    for (String f : urlFields) {
                        if (body.matches("(?s).*\"" + java.util.regex.Pattern.quote(f) + "\"\\s*:.*")) continue; // present → arm(3)
                        if (!seen.add(pathKey(req.url()) + "|bodyadd:" + f)) continue;
                        if (collab != null) fireBodyAdd(collab, null, null, tagToPoint, tagToRr, idx, req, body, f, withSession);
                        if (localListener != null) for (String lh : LOCAL_HOSTS)
                            fireBodyAdd(null, localListener, lh, tagToPoint, tagToRr, idx, req, body, f, withSession);
                    }
                }
            }
        }

        if (tagToPoint.isEmpty()) { if (localListener != null) localListener.close(); return 0; }
        int fired = tagToPoint.size();
        scanLog.debug("  ssrf: fired " + fired + " payload(s)"
                + (collab != null ? " (Collaborator)" : "")
                + (localListener != null ? " + local listener :" + localListener.port() : "")
                + "; polling…");
        int hits = collab != null ? poll(collab, tagToPoint, tagToRr) : 0;
        if (localListener != null) hits += pollLocal(localListener, tagToPoint, tagToRr);
        return hits;
    }

    /** Fire a local-listener URL into a fresh request — SSRF confirmed when the listener receives the tag. */
    private void fireLocal(LocalSsrfListener ll, String host, Map<String, String[]> tagToPoint,
                           Map<String, HttpRequestResponse> tagToRr, int[] idx,
                           String abs, String method, String param, HttpParameterType type,
                           UnaryOperator<HttpRequest> withSession, String why) {
        try {
            String tag = "ssrfl" + (idx[0]++);
            String payload = "http://" + host + ":" + ll.port() + "/" + ll.nonce() + "/" + tag;
            HttpRequest req = HttpRequest.httpRequestFromUrl(abs).withMethod(method)
                    .withAddedParameters(HttpParameter.parameter(param, payload, type));
            HttpRequestResponse rr = send(req, withSession);
            tagToPoint.put(tag, new String[]{ abs, param + " (" + type + ") [" + why + "]" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
    }

    private void fireLocalOn(LocalSsrfListener ll, String host, Map<String, String[]> tagToPoint,
                             Map<String, HttpRequestResponse> tagToRr, int[] idx,
                             HttpRequest req, String param, HttpParameterType type,
                             UnaryOperator<HttpRequest> withSession) {
        try {
            String tag = "ssrfl" + (idx[0]++);
            String payload = "http://" + host + ":" + ll.port() + "/" + ll.nonce() + "/" + tag;
            HttpRequest m = req.withUpdatedParameters(HttpParameter.parameter(param, payload, type));
            HttpRequestResponse rr = send(m, withSession);
            tagToPoint.put(tag, new String[]{ req.url(), param + " (" + type + ")" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
    }

    private void fireLocalJson(LocalSsrfListener ll, String host, Map<String, String[]> tagToPoint,
                               Map<String, HttpRequestResponse> tagToRr, int[] idx,
                               HttpRequest req, String body, String key,
                               UnaryOperator<HttpRequest> withSession) {
        try {
            String tag = "ssrfl" + (idx[0]++);
            String payload = "http://" + host + ":" + ll.port() + "/" + ll.nonce() + "/" + tag;
            String mbody = body.replaceFirst(
                    "(\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*\")[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*(\")",
                    "$1" + java.util.regex.Matcher.quoteReplacement(payload) + "$2");
            HttpRequestResponse rr = send(req.withBody(mbody), withSession);
            tagToPoint.put(tag, new String[]{ req.url(), key + " (JSON)" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
    }

    /** Add a url-typed field to a write endpoint's VALID JSON body (keeping its required siblings) and send it —
     *  reaches url-fetch-on-create/update SSRF sinks where the field was optional/absent from the baseline body.
     *  Exactly one of {collab, ll} is non-null (Collaborator payload vs local-listener payload). */
    private void fireBodyAdd(CollaboratorClient collab, LocalSsrfListener ll, String host,
                             Map<String, String[]> tagToPoint, Map<String, HttpRequestResponse> tagToRr,
                             int[] idx, HttpRequest req, String body, String field,
                             UnaryOperator<HttpRequest> withSession) {
        try {
            String tag, payload;
            if (ll != null) {
                tag = "ssrfl" + (idx[0]++);
                payload = "http://" + host + ":" + ll.port() + "/" + ll.nonce() + "/" + tag;
            } else {
                tag = "ssrf" + (idx[0]++);
                payload = "http://" + collab.generatePayload(tag).toString() + "/" + tag;
            }
            org.json.JSONObject o = new org.json.JSONObject(body);   // valid baseline (has the required siblings)
            o.put(field, payload);                                    // ADD the url-typed field
            HttpRequest m = req.withBody(o.toString());
            if (!m.hasHeader("Content-Type")) m = m.withAddedHeader("Content-Type", "application/json");
            HttpRequestResponse rr = send(m, withSession);
            tagToPoint.put(tag, new String[]{ req.url(), field + " (JSON body-add)" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
    }

    /** Same-path-family match: the target URL's path equals the hint path or is a child of it (/menu ~ /menu/1). */
    private static boolean pathMatchesHint(String url, StaticHint h) {
        if (h == null || !h.hasEndpoint()) return false;
        try {
            String tp = java.net.URI.create(url).getPath();
            if (tp == null) return false;
            String hp = h.path.replaceAll("\\{[^}]*}", "").replaceAll("\\?.*$", "").replaceAll("/+$", "");
            tp = tp.replaceAll("/+$", "");
            if (hp.isEmpty()) return false;
            return tp.equals(hp) || tp.startsWith(hp + "/") || hp.startsWith(tp + "/");
        } catch (Exception e) { return false; }
    }

    /** Poll the local listener for tag hits (brief wait for async callbacks, then check). Catches BOTH:
     *  (a) BLIND SSRF — the target's outbound request reached the listener (tag recorded); and
     *  (b) REFLECTED SSRF — the target fetched the listener URL and echoed the canary body back in its OWN
     *      response (raw or base64-wrapped, e.g. an image_base64 field). Both are deterministic and zero-FP:
     *      the tag/canary are 128-bit random, so neither a chance collision nor a stray LAN request can forge one. */
    private int pollLocal(LocalSsrfListener ll, Map<String, String[]> tagToPoint,
                          Map<String, HttpRequestResponse> tagToRr) {
        try { Thread.sleep(2000); } catch (InterruptedException ignore) { }
        int hits = 0;
        // Precompute the canary in the encodings a reflecting app might wrap it in.
        String canary = ll.canary();
        java.util.List<String> canaryForms = canaryForms(canary);
        for (Map.Entry<String, String[]> e : tagToPoint.entrySet()) {
            String tag = e.getKey(); if (!tag.startsWith("ssrfl")) continue;
            String[] pt = e.getValue();
            HttpRequestResponse ev = tagToRr.get(tag);
            if (ll.received(tag)) {                                   // (a) blind / OOB callback
                scanLog.found("SSRF", pt[0],
                        "Server made an outbound HTTP request to the scanner-controlled listener (blind SSRF "
                        + "callback confirmed). Injection point: " + pt[1] + " — the server fetched a URL the "
                        + "scanner supplied (CWE-918).",
                        ev != null ? new HttpRequestResponse[]{ ev } : new HttpRequestResponse[0]);
                scanLog.incFinding(); hits++;
                continue;
            }
            // (b) reflected / returned-content: the fetched canary appears in the app's own response body.
            if (ev != null && ev.response() != null) {
                String rb = ev.response().bodyToString();
                if (rb != null && !rb.isEmpty()) {
                    String form = firstContained(rb, canaryForms);
                    if (form != null) {
                        scanLog.found("SSRF", pt[0],
                                "Server fetched the scanner-controlled URL and reflected the fetched content back "
                                + "in its own response (" + form + "-encoded canary present) — returned-content SSRF "
                                + "(CWE-918). Injection point: " + pt[1] + ".",
                                new HttpRequestResponse[]{ ev });
                        scanLog.incFinding(); hits++;
                    }
                }
            }
        }
        ll.close();
        return hits;
    }

    /** The canary in the forms a reflecting server might wrap it in: raw, and base64 (std + url-safe, padded/not). */
    private static java.util.List<String> canaryForms(String canary) {
        java.util.List<String> out = new java.util.ArrayList<>();
        out.add(canary);                                              // raw
        byte[] cb = canary.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String std = java.util.Base64.getEncoder().encodeToString(cb);
        out.add(std);                                                 // standard base64 (padded)
        out.add(std.replace("=", ""));                                // unpadded
        String url = java.util.Base64.getUrlEncoder().encodeToString(cb);
        out.add(url);                                                 // url-safe base64 (padded)
        out.add(url.replace("=", ""));                                // unpadded
        return out;
    }

    /** Return the label of the first canary form contained in {@code body}, or null. */
    private static String firstContained(String body, java.util.List<String> forms) {
        // forms order: [raw, b64, b64-nopad, b64url, b64url-nopad]
        if (body.contains(forms.get(0))) return "raw";
        for (int i = 1; i < forms.size(); i++) if (body.contains(forms.get(i))) return "base64";
        return null;
    }

    // A JSON "key":"value" string field; a url-ish field NAME (substring, so camelCase theUrl/redirectUrl match); and
    // a value that looks like an app-relative path or absolute URL (the dispatch/SSRF surface inside a JSON body).
    private static final java.util.regex.Pattern JSON_STR =
            java.util.regex.Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
    private static final java.util.regex.Pattern NAME_URLISH = java.util.regex.Pattern.compile(
            "(?i)(url|uri|link|href|redirect|return|callback|webhook|proxy|fetch|endpoint|remote|\\bsite\\b|\\bpath\\b|dest|target)");
    private static boolean looksPathOrUrl(String v) {
        if (v == null || v.isEmpty() || v.length() > 200 || v.indexOf(' ') >= 0) return false;
        return v.matches("(?i)^(https?://\\S+|//\\S+|/[\\w./%-]+|[\\w.-]+/[\\w./%-]+)$");
    }

    /** Inject a Collaborator URL into a JSON body field (by key) and send it — for a url/path dispatch sink. */
    private void fireJsonField(CollaboratorClient collab, Map<String, String[]> tagToPoint, Map<String, HttpRequestResponse> tagToRr,
                               int[] idx, HttpRequest req, String body, String key, UnaryOperator<HttpRequest> withSession) {
        try {
            String tag = "ssrf" + (idx[0]++);
            CollaboratorPayload cp = collab.generatePayload(tag);
            String payload = "http://" + cp.toString() + "/" + tag;
            String mbody = body.replaceFirst(
                    "(\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*\")[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*(\")",
                    "$1" + java.util.regex.Matcher.quoteReplacement(payload) + "$2");
            HttpRequestResponse rr = send(req.withBody(mbody), withSession);
            tagToPoint.put(tag, new String[]{ req.url(), key + " (JSON)" });
            if (rr != null) tagToRr.put(tag, rr);
        } catch (Throwable ignore) { }
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
        politeness();   // ScanConfig politeness delay
        HttpRequest s = withSession != null ? withSession.apply(req) : req;
        try {
            return api.http().sendRequest(s, RequestOptions.requestOptions().withResponseTimeout(requestTimeoutMs()));
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
        catch (Throwable t) { scanLog.debug("  ssrf: poll error: " + t); }
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
