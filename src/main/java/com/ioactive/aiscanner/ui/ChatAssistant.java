package com.ioactive.aiscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.scan.ScanScope;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The chat brain (no UI). Every reply is grounded in the scan: the prompt carries what's IN SCOPE
 * (endpoints Burp captured for the scanned hosts), the SCAN LOG itself, the finding count, and the
 * running conversation. The UI (ScanLog's chat row) just feeds it text and logs the reply, so chat
 * and scan log interleave in one stream.
 */
public final class ChatAssistant {

    private final Supplier<AiEngine> engine;
    private final MontoyaApi api;
    private final ScanScope scope;
    private final ScanLog scanLog;
    private final List<String> history = new ArrayList<>();

    /** Wired by the extension to menuProvider.startScan() — null means scan launch is unavailable. */
    private volatile java.util.function.Consumer<String> scanHandler;
    public void setScanHandler(java.util.function.Consumer<String> h) { this.scanHandler = h; }

    /** Wired by the extension to launchParallel() — CONCURRENT multi-target DAST+SAST. Each String[] = {url, repoOrNull}. */
    private volatile java.util.function.Consumer<java.util.List<String[]>> batchScanHandler;
    public void setBatchScanHandler(java.util.function.Consumer<java.util.List<String[]>> h) { this.batchScanHandler = h; }

    /** Wired by the extension: run ONE probe module on demand against an ALREADY-scanned host, reusing the warm
     *  site map (no re-crawl). String[] = {host, moduleKey}. Null → on-demand module run unavailable. */
    private volatile java.util.function.Consumer<String[]> moduleHandler;
    public void setModuleHandler(java.util.function.Consumer<String[]> h) { this.moduleHandler = h; }

    /** On-demand single-module command: "test|run|probe|fuzz <module> [rest…]" (e.g. "test SQLi on the current
     *  scan"). Group 2 is the module alias; a URL after the verb (a scan intent) is NOT matched (no bare word). */
    private static final java.util.regex.Pattern MODULE_CMD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:test|run|probe|fuzz)\\s+([a-z0-9][a-z0-9_-]*)\\b.*$");

    /** Resolve a loose module alias to a ScanPhases attack-module key. The set of VALID keys is read from
     *  {@link com.ioactive.aiscanner.scan.ScanPhases#attackModules()} — the SINGLE registry — so a newly added
     *  module (e.g. {@code wsfuzz}) is reachable here automatically with no edit and can never drift. We only map
     *  spoken SYNONYMS that differ from the canonical key; the exact key is then confirmed against the registry.
     *  Null if it isn't a known module. */
    private static String resolveModuleKey(String alias) {
        if (alias == null || alias.isBlank()) return null;
        String x = alias.toLowerCase().replaceAll("[^a-z0-9]", "");
        switch (x) {   // spoken synonym → canonical key (ONLY where the word differs from the ScanPhases key)
            case "sql": case "sqlinjection":                 x = "sqli"; break;
            case "xss": case "reflectedxss":                 x = "rxss"; break;
            case "storedxss":                                x = "sxss"; break;
            case "bola": case "idorget":                     x = "idor"; break;
            case "massassignment":                           x = "massassign"; break;
            case "rce": case "command": case "commandinjection": x = "cmdi"; break;
            case "template": case "templateinjection":       x = "ssti"; break;
            case "jndi": case "log4j":                       x = "log4shell"; break;
            case "websocket": case "ws":                     x = "cswsh"; break;
            case "websocketfuzz": case "wsfuzzing": case "wsinjection": x = "wsfuzz"; break;
            case "xml":                                      x = "xxe"; break;
            case "deserialization":                          x = "deser"; break;
            case "pathtraversal": case "traversal": case "fileinclusion": x = "lfi"; break;
            case "openredirect":                             x = "redirect"; break;
            default: break;
        }
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase p : com.ioactive.aiscanner.scan.ScanPhases.attackModules())
            if (p.key.equalsIgnoreCase(x)) return p.key;   // authoritative: keys come from the ONE registry
        return null;
    }

    /** Matches "scan / escanea / audit / crawl / test" followed by a URL or bare hostname. */
    private static final java.util.regex.Pattern SCAN_CMD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:scan|escanea|audit(?:ar)?|crawl|test)\\s+(https?://\\S+|[\\w.-]+\\.[a-z]{2,}(?:/\\S*)?)\\s*$");

    /** Leading scan/audit/… keyword (so we only multi-parse an explicit scan intent). */
    private static final java.util.regex.Pattern SCAN_KEYWORD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:scan|escanea|audit(?:ar)?|crawl|test)\\b");

    /** One `URL (REPO)` occurrence: an http(s) URL, then an OPTIONAL parenthesized repo (git URL / URL / local path). */
    private static final java.util.regex.Pattern TARGET_WITH_REPO = java.util.regex.Pattern.compile(
            "(https?://\\S+?)(?:\\s*\\(\\s*(\\S+?)\\s*\\))?(?=\\s*(?:,|\\band\\b|$)|\\s+https?://)",
            java.util.regex.Pattern.CASE_INSENSITIVE);

    public ChatAssistant(Supplier<AiEngine> engine, MontoyaApi api, ScanScope scope, ScanLog scanLog) {
        this.engine = engine;
        this.api = api;
        this.scope = scope;
        this.scanLog = scanLog;
    }

    /**
     * Parse an ordered list of (url, repoOrNull) pairs from a `scan URL1 (REPO1) and URL2 (REPO2) …` message.
     * Only http(s) URLs are matched; each URL may carry an OPTIONAL parenthesized SAST source (git URL / URL /
     * local path). Returns an empty list if no URL is found (so callers fall through to normal handling).
     */
    static java.util.List<String[]> parseTargets(String msg) {
        java.util.List<String[]> out = new java.util.ArrayList<>();
        if (msg == null) return out;
        String s = msg.trim();
        java.util.regex.Matcher kw = SCAN_KEYWORD.matcher(s);
        if (!kw.find()) return out;   // require an explicit scan/audit/… intent
        String body = s.substring(kw.end());
        java.util.regex.Matcher m = TARGET_WITH_REPO.matcher(body);
        while (m.find()) {
            String url = m.group(1);
            if (url == null || url.isBlank()) continue;
            url = url.replaceAll("[),;]+$", "");   // trim trailing punctuation the URL regex may have swallowed
            String repo = m.group(2);
            if (repo != null) { repo = repo.trim(); if (repo.isBlank()) repo = null; }
            out.add(new String[]{ url, repo });
        }
        return out;
    }

    /** Produce a reply to the user's message, grounded in scope + log + conversation. Blocking. */
    public String reply(String userMsg) {
        // --- multi-target scan intent: `scan URL1 (REPO1) and URL2 (REPO2)` → CONCURRENT DAST+SAST scans ---
        if (userMsg != null && userMsg.trim().toLowerCase().startsWith("scan ")) {
            java.util.List<String[]> pairs = parseTargets(userMsg);
            // Only take the batch path for a genuine multi-target OR a URL-with-repo request; a lone `scan <url>`
            // with no repo keeps the EXISTING single-URL behavior below (backward compat).
            boolean batchWorthy = pairs.size() > 1 || (pairs.size() == 1 && pairs.get(0)[1] != null);
            if (batchWorthy) {
                java.util.function.Consumer<java.util.List<String[]>> bh = batchScanHandler;
                if (bh == null) return "(parallel scan not available — batch handler not wired)";
                final java.util.List<String[]> targets = pairs;
                new Thread(() -> bh.accept(targets), "chat-scan-batch").start();
                StringBuilder desc = new StringBuilder();
                for (int i = 0; i < targets.size(); i++) {
                    String[] t = targets.get(i);
                    String host; try { host = new java.net.URI(t[0]).getAuthority(); } catch (Exception ex) { host = t[0]; }
                    if (host == null || host.isBlank()) host = t[0];
                    desc.append(host);
                    if (t[1] != null) desc.append(" (").append(t[1]).append(')');
                    if (i < targets.size() - 1) desc.append(", ");
                }
                String reply = "launching " + targets.size() + " parallel scan(s): " + desc
                        + ". Watch the log tab for progress.";
                history.add("User: " + userMsg);
                history.add("Assistant: " + reply);
                return reply;
            }
        }
        // --- single-URL scan intent: deterministic, no LLM tokens needed ---
        java.util.regex.Matcher m = SCAN_CMD.matcher(userMsg.trim());
        if (m.matches()) {
            java.util.function.Consumer<String> h = scanHandler;
            if (h == null) return "(scan launch not available — use 'Crawl and scan this host' from the context menu)";
            String raw = m.group(1);
            String url = raw.matches("(?i)https?://.*") ? raw : "https://" + raw;
            try { new java.net.URI(url); } catch (Exception ex) { return "(invalid URL: " + url + ")"; }
            new Thread(() -> h.accept(url), "chat-scan").start();
            String reply = "Starting scan on " + url + ". Watch the log tab for progress.";
            history.add("User: " + userMsg);
            history.add("Assistant: " + reply);
            return reply;
        }
        // --- on-demand single-module run against an already-scanned host (reuses the warm site map) ---
        java.util.regex.Matcher mod = MODULE_CMD.matcher(userMsg.trim());
        if (mod.matches()) {
            String key = resolveModuleKey(mod.group(1));
            if (key != null) {   // a known module — otherwise fall through (it was ordinary chat/scan text)
                java.util.function.Consumer<String[]> mh = moduleHandler;
                if (mh == null) return "(on-demand module run not available)";
                Set<String> hosts = scope.hosts();
                if (hosts.isEmpty()) return "(nothing scanned yet — scan a host first, then 'test " + key + "')";
                final String host = hosts.iterator().next();   // the scanned host (reuse its discovered surface)
                // A scan already running → the handler ENQUEUES the module into it (ticks the checkbox, rewrites the
                // live only= filter, status bar +1) instead of starting a second scan. No scan → fresh scoped re-scan.
                boolean live = scanLog.isScanActive();
                new Thread(() -> mh.accept(new String[]{ host, key }), "chat-module").start();
                String reply = live
                        ? "Queued '" + key + "' into the running scan's attack modules — it'll run when the battery "
                          + "reaches that phase (if it hasn't passed it yet). The Modules checkbox ticks and the "
                          + "status-bar phase count goes +1; no second scan is started."
                        : "Running the '" + key + "' module on " + host + " — reusing the discovered surface "
                          + "(no re-crawl). Watch the log tab for findings.";
                history.add("User: " + userMsg);
                history.add("Assistant: " + reply);
                return reply;
            }
        }
        AiEngine e = engine.get();
        if (e == null || !e.isConfigured())
            return "(AI not available — in the AI Scanner Settings tab, select Local LLM and set its Base "
                    + "URL/Model, or pick Burp AI after turning on Settings → AI and reloading this extension)";
        history.add("User: " + userMsg);
        String sys = "You are the AI Scanner assistant embedded in a Burp Suite extension. Answer the "
                + "pentester concisely and concretely, grounded in the scan data below (in-scope captured "
                + "endpoints, the scan log, findings). You may reason about which endpoints look "
                + "injectable/interesting and suggest next steps.\n\n"
                + "=== IN SCOPE (captured this session) ===\n" + scopeContext()
                + "\n\n=== SCAN LOG ===\n" + scanLog.recentLog(200)
                + "\n\n=== findings so far: " + scanLog.findingCount() + " ===";
        String reply;
        try {
            reply = e.chat(sys, String.join("\n", history) + "\nAssistant:");
        } catch (Throwable t) {
            reply = "(error: " + t.getMessage() + ")";
        }
        if (reply == null || reply.isBlank()) reply = "(no response — " + e.lastError() + ")";
        reply = reply.trim();
        history.add("Assistant: " + reply);
        return reply;
    }

    /** Distinct METHOD path [status] the browser/scan captured for in-scope hosts, from Burp's site map. */
    private String scopeContext() {
        Set<String> hosts = scope.hosts();
        if (hosts.isEmpty()) return "(nothing scanned yet — run 'Crawl and scan this host' first)";
        StringBuilder sb = new StringBuilder("Hosts: ").append(String.join(", ", hosts)).append('\n');
        Set<String> seen = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String url = rr.request().url();
            if (!scope.contains(url)) continue;
            int st = rr.response() != null ? rr.response().statusCode() : 0;
            String line = rr.request().method() + " " + stripQuery(url) + (st > 0 ? " [" + st + "]" : "");
            if (seen.add(line)) sb.append(line).append('\n');
            if (seen.size() >= 250) { sb.append("… (truncated at 250)\n"); break; }
        }
        return sb.toString();
    }

    private static String stripQuery(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getAuthority() + (u.getRawPath() == null ? "" : u.getRawPath()); }
        catch (Exception e) { int i = url.indexOf('?'); return i < 0 ? url : url.substring(0, i); }
    }
}
