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

    /** Matches a REAL-fetch command: `fetch|curl|get|request|hit <url-or-host>` and nothing else. Deterministic
     *  so the Agent issues a genuine request through Burp instead of fabricating a response. Natural-language
     *  phrases like "can you get the headers of x?" do NOT match (they carry extra words). */
    private static final java.util.regex.Pattern FETCH_CMD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:fetch|curl|get|request|hit)\\s+(https?://\\S+|/\\S*|[\\w.-]+\\.[a-z]{2,}(?:/\\S*)?)\\s*$");

    /** On-demand port/web-app discovery: a scan verb, anything, then the word ports/puertos. The whole phrase
     *  is handed to the LLM to resolve into a concrete port list (the model picks, code sanitizes+gates+probes).
     *  An optional trailing `on|en|against|contra <host>` overrides the default (the in-scope scanned host). */
    private static final java.util.regex.Pattern PORTSCAN_CMD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:"
          + "(?:port-?scan|nmap)\\b.*"                          // explicit verb: "ports" optional
          + "|(?:scan|probe|check)\\b.*\\bports?\\b.*"          // generic verb + ports
          + ")$");

    /** Send a REAL captured request to Burp Repeater: a send-verb + "repeater", or "repeater …". The LLM picks
     *  WHICH captured (in-scope) request matches; code sends the actual bytes — never a synthesized guess. */
    private static final java.util.regex.Pattern REPEATER_CMD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:(?:send|add|push|throw|move|copy)\\b.*\\brepeater\\b.*|repeater\\b.*)$");

    /** Send a REAL captured request to Burp Intruder with payload positions. The LLM picks WHICH request and
     *  WHICH parameters to fuzz; code marks those params' value offsets as insertion points. */
    private static final java.util.regex.Pattern INTRUDER_CMD = java.util.regex.Pattern.compile(
            "(?i)^\\s*(?:(?:send|add|push|throw|move|copy|fuzz)\\b.*\\bintruder\\b.*|intruder\\b.*)$");

    /** Hard cap on ports probed per run (user-set). Also the max the LLM is asked for. */
    private static final int PORTSCAN_MAX = 100;

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
        // --- /clear: wipe the chat transcript visually (no model call, no fabrication). ---
        if (userMsg != null && userMsg.trim().equalsIgnoreCase("/clear")) {
            scanLog.clearChat();
            return null;   // null → appendChat is skipped by the caller, nothing appended after the clear
        }
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
        // --- on-demand port / web-app discovery: `scan <…> ports [on <host>]`. The LLM resolves WHICH ports
        //     from the phrase; the CODE sanitizes+caps, hard-gates the HOST (in-scope only, never private/
        //     metadata), then probes HTTP/S in parallel through Burp. Results are real, never fabricated. ---
        if (PORTSCAN_CMD.matcher(userMsg.trim()).matches()) {
            String reply = portScan(userMsg.trim());
            history.add("User: " + userMsg);
            history.add("Assistant: (ran a port/web-app probe)");
            return reply;
        }
        // --- real HTTP fetch: `fetch|curl|get|request|hit <url>` → issue a GENUINE request through Burp and
        //     show the true raw bytes. Deterministic, no LLM — so it can never fabricate a response. ---
        java.util.regex.Matcher fx = FETCH_CMD.matcher(userMsg.trim());
        if (fx.matches()) {
            String raw = fx.group(1);
            String url;
            if (raw.matches("(?i)https?://.*")) url = raw;
            else if (raw.startsWith("/")) {                      // bare path → resolve against the in-scope host
                String host = fetchHostForPath(raw);
                if (host == null)
                    return "(no in-scope host to resolve `" + raw + "` against — scan a host first, or give a full URL)";
                url = "https://" + host + raw;
            } else url = "https://" + raw;                       // bare domain
            String reply = fetchRaw(url);
            history.add("User: " + userMsg);
            history.add("Assistant: (issued a real fetch of " + url + ")");   // keep history compact
            return reply;
        }
        // --- send a REAL captured request to Repeater: the LLM picks which in-scope request matches; code
        //     sends the actual bytes Burp holds (no fabricated request). ---
        if (REPEATER_CMD.matcher(userMsg.trim()).matches()) {
            String reply = sendToRepeater(userMsg.trim());
            history.add("User: " + userMsg);
            history.add("Assistant: (sent a captured request to Repeater)");
            return reply;
        }
        // --- send a REAL captured request to Intruder, marking chosen params as payload positions ---
        if (INTRUDER_CMD.matcher(userMsg.trim()).matches()) {
            String reply = sendToIntruder(userMsg.trim());
            history.add("User: " + userMsg);
            history.add("Assistant: (sent a captured request to Intruder)");
            return reply;
        }
        AiEngine e = engine.get();
        if (e == null || !e.isConfigured())
            return "(AI not available — in the AI Scanner Settings tab, select Local LLM and set its Base "
                    + "URL/Model, or pick Burp AI after turning on Settings → AI and reloading this extension)";
        history.add("User: " + userMsg);
        String sys = "You are the AI Scanner Agent embedded in a Burp Suite extension. Answer the user's ACTUAL "
                + "question directly and concisely, grounded ONLY in the scan data below (scope, SCAN STATE, log, "
                + "findings). Do NOT pad replies with canned calls-to-action, and do NOT suggest starting or "
                + "re-running a scan unless the user explicitly asks how to start one. `scan this host` is a "
                + "right-click context-menu action, NOT a chat command — never tell the user to type it.\n"
                + "IMPORTANT: To get real data from a URL, reply with a SINGLE line `FETCH: <url>` and NOTHING "
                + "else. The tool performs the REAL HTTP request through Burp and returns the response for you to "
                + "analyze on your NEXT turn; then you answer. Prefer public sources that need no API key. NEVER "
                + "fabricate HTTP responses, headers, status codes, cookies, or scan results — if you don't have "
                + "the data, FETCH it (or say plainly you can't). The ONLY chat commands you may mention (and only "
                + "when the user actually needs them) are: `scan <url>` (start a scan on a NEW target), "
                + "`scan <which> ports`, `send <which> to repeater`, `send <which> to intruder to fuzz <params>`. "
                + "Those run THROUGH Burp — never simulate their results or invent a request.\n\n"
                + "=== SCAN STATE (authoritative — trust THIS over your own reading of the phase list) ===\n"
                + (scanLog.isScanActive()
                    ? "A scan is ACTIVE right now on the scoped host(s). The phases shown as 'done' below are "
                    + "COMPLETED STEPS of THIS running scan — they do NOT mean the scan finished or is idle. Do NOT "
                    + "tell the user to start or re-run a scan; answer about the live scan (progress, findings, "
                    + "what phase is next)."
                    : "No scan is active right now (idle). Only if the user asks to test a target, tell them the "
                    + "right-click menu action or `scan <url>`.")
                + "\n\n=== In Scope captured this session ===\n" + scopeContext()
                + "\n\n=== Scan phases (COMPLETED steps of the current run — NOT proof the scan is idle) ===\n" + scanLog.phaseContext()
                + "\n\n=== Scan Log (last 200 lines) ===\n" + scanLog.recentLog(200)
                + "\n\n=== Findings so far: " + scanLog.findingCount() + " ===";
        // Agentic FETCH tool-loop: the model may reply `FETCH: <url>` to have the CODE perform a REAL request
        // (through Burp) and feed the bytes back — so it can answer a natural-language "fetch/look this up" ask
        // itself instead of telling the user to type the command. The LLM-CHOSEN url is SSRF-gated (agentFetch):
        // public hosts only, never loopback/private/link-local/metadata, so target-influenced context can't pivot
        // the fetch inward. The operator-typed `fetch <url>` command stays ungated (explicit human intent).
        String convo = String.join("\n", history) + "\nAssistant:";
        String reply = "";
        int fetches = 0;
        for (int step = 0; step < 5; step++) {
            try {
                reply = e.chat(sys, convo);
            } catch (Throwable t) { reply = "(error: " + t.getMessage() + ")"; break; }
            reply = reply == null ? "" : reply.trim();
            String url = fetchDirective(reply);
            if (url == null) break;                       // no fetch requested → this reply is the final answer
            if (fetches++ >= 3) {                          // budget: bound auto-fetch so one turn can't runaway
                convo += "\n" + reply + "\n[system: auto-fetch budget reached — answer with what you have]\nAssistant:";
                continue;
            }
            String result = agentFetch(url);               // gated REAL fetch (or a refusal/error string)
            convo += "\n" + reply + "\n[FETCH RESULT for " + url + "]\n" + result + "\nAssistant:";
        }
        if (fetchDirective(reply) != null)                 // ran out of steps still asking to fetch
            reply = "(couldn't finish fetching + analyzing in time — run it directly with `fetch <url>`)";
        if (reply == null || reply.isBlank()) reply = "(no response — " + e.lastError() + ")";
        reply = reply.trim();
        history.add("Assistant: " + reply);
        return reply;
    }

    /** Parse an agentic `FETCH: <url>` directive (on its own line) from the model's reply; null if none. Normalizes
     *  a bare host to https:// and resolves a bare /path against the in-scope host. Only used to TRIGGER a real,
     *  code-performed fetch — the model never fabricates the bytes. */
    private String fetchDirective(String reply) {
        if (reply == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(?im)^\\s*FETCH:\\s*(https?://\\S+|/\\S*|[\\w.-]+\\.[a-z]{2,}(?:/\\S*)?)\\s*$").matcher(reply);
        if (!m.find()) return null;
        String u = m.group(1).replaceAll("[),.;]+$", "");
        if (u.matches("(?i)https?://.*")) return u;
        if (u.startsWith("/")) { String h = fetchHostForPath(u); return h == null ? null : "https://" + h + u; }
        return "https://" + u;
    }

    /** Perform a REAL fetch the LLM requested, SSRF-gated to public hosts. Returns the response (status + truncated
     *  body) to feed back to the model, or a refusal/error string. Distinct from {@link #fetchRaw} (the operator-
     *  typed `fetch` command, deliberately ungated): here the URL is LLM-chosen, so a target-influenced prompt-
     *  injection could try to steer it — {@link #fetchGate} blocks internal/reserved ranges. */
    private String agentFetch(String url) {
        String deny = fetchGate(url);
        if (deny != null) { scanLog.log("[agent] auto-fetch REFUSED " + url + " — " + deny); return "[fetch refused: " + deny + "]"; }
        try {
            burp.api.montoya.http.message.requests.HttpRequest req =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse rr = api.http().sendRequest(req,
                    burp.api.montoya.http.RequestOptions.requestOptions().withResponseTimeout(15000L));
            rr = com.ioactive.aiscanner.scan.AiScanner.decompress(rr);
            int code = rr.response() == null ? -1 : rr.response().statusCode();
            scanLog.log("[agent] auto-fetch " + url + " → " + (code < 0 ? "no response" : code));
            if (rr.response() == null) return "[no response from " + url + " — connection failed or timed out]";
            String body = rr.response().bodyToString();
            if (body == null) body = "";
            int full = body.length();
            if (full > 6000) body = body.substring(0, 6000) + "\n… [truncated, " + full + " bytes total]";
            return "HTTP " + code + "\n" + body;
        } catch (Throwable t) { return "[fetch failed: " + t.getMessage() + "]"; }
    }

    /** SSRF host gate for the LLM-chosen agentic fetch: refuse an empty/unresolvable host and any address that
     *  resolves to loopback / private / link-local / metadata (169.254.169.254) — reuses {@link #isForbiddenAddress}.
     *  Returns a denial reason, or null if the host may be fetched. NO Burp-scope requirement (a public URL the user
     *  asked about is fine); only INTERNAL/reserved ranges are blocked, so scan context can't pivot the fetch inward. */
    private String fetchGate(String url) {
        String host;
        try { host = new java.net.URI(url).getHost(); } catch (Exception ex) { return "invalid URL"; }
        if (host == null || host.isBlank()) return "no host in URL";
        try {
            for (java.net.InetAddress a : java.net.InetAddress.getAllByName(host))
                if (isForbiddenAddress(a))
                    return host + " resolves to a private/reserved address (" + a.getHostAddress() + ")";
        } catch (Throwable t) { return "cannot resolve " + host; }
        return null;
    }

    /** Issue a REAL GET through Burp's HTTP stack and return the true raw request + response as fenced code
     *  blocks. Deterministic (no LLM), so the Agent presents genuine bytes instead of fabricating them. The
     *  request goes through Burp, so it is logged/visible like any Repeater request. */
    private String fetchRaw(String url) {
        try { new java.net.URI(url); } catch (Exception ex) { return "(invalid URL: " + url + ")"; }
        try {
            burp.api.montoya.http.message.requests.HttpRequest req =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse rr = api.http().sendRequest(req,
                    burp.api.montoya.http.RequestOptions.requestOptions().withResponseTimeout(15000L));
            rr = com.ioactive.aiscanner.scan.AiScanner.decompress(rr);   // ungzip so the body is readable
            String rawReq  = rr.request()  == null ? "(no request)"  : rr.request().toString();
            String rawResp = rr.response() == null
                    ? "(no response — connection failed or timed out)"
                    : rr.response().toString();
            // Neutralize any ``` inside the payload so it can't prematurely close our fenced block (ZWSP is
            // invisible and gets stripped on copy).
            rawReq  = rawReq.replace("```", "``​`");
            rawResp = rawResp.replace("```", "``​`");
            if (rawReq.length()  > 1500) rawReq  = rawReq.substring(0, 1500) + "\n… [request truncated]";
            if (rawResp.length() > 6000) rawResp = rawResp.substring(0, 6000)
                    + "\n… [response truncated, " + rawResp.length() + " bytes total]";
            scanLog.log("[agent] real fetch " + url + " → "
                    + (rr.response() == null ? "no response" : rr.response().statusCode()));
            return "Real request issued through Burp to " + url + ":\n"
                    + "```\n" + rawReq + "\n```\nResponse:\n```\n" + rawResp + "\n```";
        } catch (Throwable t) {
            return "(fetch failed: " + t.getMessage() + ")";
        }
    }

    /** Resolve a bare "/path" to an in-scope host: prefer the host that already has that exact path captured;
     *  else the in-scope host with the richest captured surface (the app host over an auth host); else the
     *  first scanned host. */
    private String fetchHostForPath(String path) {
        java.util.Set<String> scanned = scope.hosts();
        if (scanned.isEmpty()) return null;
        if (scanned.size() == 1) return scanned.iterator().next();
        int q = path.indexOf('?');
        String p = q >= 0 ? path.substring(0, q) : path;
        java.util.Map<String, Integer> counts = new java.util.LinkedHashMap<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.request() == null) continue;
            String u = rr.request().url();
            if (u == null || !scope.contains(u)) continue;
            try {
                java.net.URI ur = new java.net.URI(u);
                String host = ur.getAuthority();
                if (host == null) continue;
                if (p.equals(ur.getPath())) return host;   // exact path → the definitive host
                counts.merge(host, 1, Integer::sum);
            } catch (Exception ignore) { }
        }
        String best = null; int bestN = -1;
        for (java.util.Map.Entry<String, Integer> en : counts.entrySet())
            if (en.getValue() > bestN) { bestN = en.getValue(); best = en.getKey(); }
        return best != null ? best : scanned.iterator().next();
    }

    // ---------------------------------------------------------------------------------------------------
    // "Send to Repeater" skill: the LLM chooses WHICH captured request matches the user's intent (e.g. "the
    // most likely vulnerable endpoint"), reasoning over the in-scope site map (paths + parameter names) plus
    // recent scan-log context. CODE then sends the REAL captured request bytes to Burp Repeater — never a
    // synthesized/guessed request. So what lands in Repeater is exactly what Burp observed.
    // ---------------------------------------------------------------------------------------------------
    private String sendToRepeater(String message) {
        java.util.LinkedHashMap<String, HttpRequestResponse> rrByKey = new java.util.LinkedHashMap<>();
        java.util.LinkedHashMap<String, java.util.LinkedHashSet<String>> paramsByKey = new java.util.LinkedHashMap<>();
        collectInScopeCandidates(rrByKey, paramsByKey);
        if (rrByKey.isEmpty())
            return "(nothing captured in scope yet — crawl or browse the app first, then I can send a real request)";
        java.util.List<String> keys = new java.util.ArrayList<>(rrByKey.keySet());
        if (keys.size() > 150) keys = keys.subList(0, 150);   // bound the prompt
        AiEngine e = engine.get();
        if (e == null || !e.isConfigured()) return "(AI not configured — needed to pick which captured request)";
        String sys = "Choose the ONE captured request that best matches the user's intent, and reply with ONLY "
                + "its leading number (an integer). These are REAL requests Burp captured (method, path, and the "
                + "parameter names). For 'most likely vulnerable/injectable', prefer endpoints carrying "
                + "user-controlled parameters (search, q, id, filter, url, redirect, file, path…) and anything "
                + "the scan log flagged. No words, just the number.\n\n=== Captured in-scope requests ===\n"
                + candidateList(keys, paramsByKey)
                + "\n=== Recent scan log (for 'found so far' context) ===\n" + scanLog.recentLog(60);
        String out;
        try { out = e.chat(sys, message); } catch (Throwable t) { return "(pick failed: " + t.getMessage() + ")"; }
        int idx = firstInt(out);
        if (idx < 0 || idx >= keys.size())
            return "(couldn't map that to a captured request — try naming the path, e.g. `send POST /api/login to repeater`)";
        String key = keys.get(idx);
        HttpRequestResponse chosen = rrByKey.get(key);
        try {
            api.repeater().sendToRepeater(chosen.request(), repeaterTab(key));
            scanLog.log("[agent] sent to Repeater: " + key);
            java.util.LinkedHashSet<String> ps = paramsByKey.get(key);
            return "Sent the **real captured** request to Repeater → `" + key + "`"
                    + (ps != null && !ps.isEmpty() ? " (params: " + String.join(", ", ps) + ")" : "")
                    + ". These are the exact bytes Burp holds — open the Repeater tab to edit/replay.";
        } catch (Throwable t) { return "(send to Repeater failed: " + t.getMessage() + ")"; }
    }

    /** Send the chosen captured request to Intruder, marking the LLM-chosen params' value offsets as payload
     *  positions (Intruder auto-positions when none matched). Real captured bytes — never synthesized. */
    private String sendToIntruder(String message) {
        java.util.LinkedHashMap<String, HttpRequestResponse> rrByKey = new java.util.LinkedHashMap<>();
        java.util.LinkedHashMap<String, java.util.LinkedHashSet<String>> paramsByKey = new java.util.LinkedHashMap<>();
        collectInScopeCandidates(rrByKey, paramsByKey);
        if (rrByKey.isEmpty()) return "(nothing captured in scope yet — crawl or browse the app first)";
        java.util.List<String> keys = new java.util.ArrayList<>(rrByKey.keySet());
        if (keys.size() > 150) keys = keys.subList(0, 150);
        AiEngine e = engine.get();
        if (e == null || !e.isConfigured()) return "(AI not configured — needed to pick the request/params)";
        String sys = "Pick the ONE captured request to send to Intruder AND which of its parameters to fuzz "
                + "(mark as payload positions). Reply ONLY strict JSON {\"index\": <int>, \"fuzz\": [\"name\", …]} "
                + "— index = the leading number; fuzz = parameter names from that request's [params: …] list to "
                + "fuzz (empty = let Intruder auto-position). No prose, no code fences.\n\n"
                + "=== Captured in-scope requests ===\n" + candidateList(keys, paramsByKey)
                + "\n=== Recent scan log ===\n" + scanLog.recentLog(60);
        String out;
        try { out = e.chat(sys, message); } catch (Throwable t) { return "(pick failed: " + t.getMessage() + ")"; }
        int idx = -1;
        java.util.Set<String> want = new java.util.LinkedHashSet<>();
        try {
            String json = out.substring(out.indexOf('{'), out.lastIndexOf('}') + 1);
            org.json.JSONObject o = new org.json.JSONObject(json);
            idx = o.optInt("index", -1);
            org.json.JSONArray fa = o.optJSONArray("fuzz");
            if (fa != null) for (int i = 0; i < fa.length(); i++) {
                String n = fa.optString(i, "").trim(); if (!n.isEmpty()) want.add(n);
            }
        } catch (Throwable ignore) { idx = firstInt(out); }
        if (idx < 0 || idx >= keys.size())
            return "(couldn't map that to a captured request — name the path, e.g. `send POST /api/login to intruder`)";
        String key = keys.get(idx);
        HttpRequestResponse chosen = rrByKey.get(key);
        java.util.List<burp.api.montoya.core.Range> ranges = new java.util.ArrayList<>();
        java.util.List<String> marked = new java.util.ArrayList<>();
        try {
            for (burp.api.montoya.http.message.params.ParsedHttpParameter p : chosen.request().parameters())
                if (want.contains(p.name())) { ranges.add(p.valueOffsets()); marked.add(p.name()); }
        } catch (Throwable ignore) { }
        try {
            String tab = repeaterTab(key);
            if (!ranges.isEmpty()) {
                burp.api.montoya.intruder.HttpRequestTemplate tmpl =
                        burp.api.montoya.intruder.HttpRequestTemplate.httpRequestTemplate(chosen.request(), ranges);
                api.intruder().sendToIntruder(chosen.request().httpService(), tmpl, tab);
                scanLog.log("[agent] sent to Intruder: " + key + " fuzz=" + marked);
                return "Sent the **real captured** request to Intruder → `" + key + "` with payload position(s) on **"
                        + String.join(", ", marked) + "**. Open the Intruder tab to set payloads and attack.";
            }
            api.intruder().sendToIntruder(chosen.request(), tab);
            scanLog.log("[agent] sent to Intruder: " + key + " (auto positions)");
            return "Sent the **real captured** request to Intruder → `" + key + "` (no named param matched — "
                    + "Intruder auto-marked positions). Open the Intruder tab to adjust.";
        } catch (Throwable t) { return "(send to Intruder failed: " + t.getMessage() + ")"; }
    }

    /** In-scope captured requests, deduped by METHOD+path, keeping the RICHEST capture (most params). Fills
     *  rrByKey (key→request) and paramsByKey (key→injectable param names). Shared by Repeater/Intruder. */
    private void collectInScopeCandidates(java.util.LinkedHashMap<String, HttpRequestResponse> rrByKey,
                                          java.util.LinkedHashMap<String, java.util.LinkedHashSet<String>> paramsByKey) {
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.request() == null) continue;
            String url = rr.request().url();
            if (url == null || !scope.contains(url)) continue;
            String key = rr.request().method() + " " + stripQuery(url);
            java.util.LinkedHashSet<String> pnames = new java.util.LinkedHashSet<>();
            try {
                for (burp.api.montoya.http.message.params.ParsedHttpParameter p : rr.request().parameters()) {
                    burp.api.montoya.http.message.params.HttpParameterType ty = p.type();
                    if (ty == burp.api.montoya.http.message.params.HttpParameterType.URL
                     || ty == burp.api.montoya.http.message.params.HttpParameterType.BODY
                     || ty == burp.api.montoya.http.message.params.HttpParameterType.JSON
                     || ty == burp.api.montoya.http.message.params.HttpParameterType.XML) pnames.add(p.name());
                }
            } catch (Throwable ignore) { }
            java.util.LinkedHashSet<String> prev = paramsByKey.get(key);
            if (prev == null || pnames.size() > prev.size()) { rrByKey.put(key, rr); paramsByKey.put(key, pnames); }
        }
    }

    /** Numbered candidate list (with [params: …]) for the picker prompt. */
    private static String candidateList(java.util.List<String> keys,
                                        java.util.Map<String, java.util.LinkedHashSet<String>> paramsByKey) {
        StringBuilder list = new StringBuilder();
        for (int i = 0; i < keys.size(); i++) {
            java.util.LinkedHashSet<String> ps = paramsByKey.get(keys.get(i));
            list.append(i).append(": ").append(keys.get(i));
            if (ps != null && !ps.isEmpty()) list.append("  [params: ").append(String.join(", ", ps)).append(']');
            list.append('\n');
        }
        return list.toString();
    }

    /** First integer in a string, or -1. */
    private static int firstInt(String s) {
        if (s == null) return -1;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\d+").matcher(s);
        if (m.find()) { try { return Integer.parseInt(m.group()); } catch (NumberFormatException ignore) { } }
        return -1;
    }

    /** Short Repeater tab label from a "METHOD /path" key. */
    private static String repeaterTab(String key) {
        String t = key.replaceFirst("(?i)^https?://", "");
        return "AI " + (t.length() > 22 ? t.substring(0, 22) : t);
    }

    // ---------------------------------------------------------------------------------------------------
    // On-demand port / web-app discovery skill.
    //   LLM   → decides WHICH ports from the user's phrase (no hardcoded list, no guaranteed seed).
    //   CODE  → sanitizes + caps at PORTSCAN_MAX, hard-gates the HOST (in-scope only; never private/
    //           loopback/link-local/metadata, re-checked after DNS), probes HTTP+HTTPS in PARALLEL through
    //           Burp, and reports REAL results. It detects HTTP(S) web apps — not arbitrary open TCP ports.
    // ---------------------------------------------------------------------------------------------------

    private String portScan(String message) {
        Set<String> scanned = scope.hosts();   // used only as the DEFAULT host(s) when the user names none
        AiEngine e = engine.get();
        if (e == null || !e.isConfigured())
            return "(AI not configured — the model parses which host(s) and ports to probe)";

        // ONE LLM call parses the whole request into {hosts, ports}. The model handles ALL the natural-language
        // interpretation (which host, which ports, "all/both/our targets", "the 100 most common web ports") — no
        // brittle phrasing regexes. The CODE keeps the safety: hosts are IP-gated (loopback/private/metadata
        // refused in hostGate) and ports are sanitized + capped. The Burp-scope constraint was removed, so the
        // operator can name any host; the address gate still blocks internal/reserved ranges.
        String sys = "Parse a port-scan request into strict JSON. "
                + (scanned.isEmpty() ? "" : "Already-scanned host(s) — the DEFAULT when the user names none:\n"
                    + String.join("\n", scanned) + "\n")
                + "Return ONLY {\"hosts\":[...],\"ports\":[...]} — no prose, no code fences. "
                + "hosts: the host(s) the user means — the one they name (ANY host, in scope or not), or the "
                + "already-scanned host(s) for 'all'/'both'/'our targets'/no explicit host. ports: the TCP ports "
                + "to probe as integers; resolve descriptions like 'the 100 most common web ports' into real "
                + "port numbers, at most " + PORTSCAN_MAX + ".";
        String raw;
        try { raw = e.chat(sys, message); } catch (Throwable t) { return "(port parse failed: " + t.getMessage() + ")"; }

        java.util.List<String> hosts = new java.util.ArrayList<>();
        java.util.LinkedHashSet<Integer> portSet = new java.util.LinkedHashSet<>();
        try {
            String json = raw.substring(raw.indexOf('{'), raw.lastIndexOf('}') + 1);
            org.json.JSONObject o = new org.json.JSONObject(json);
            org.json.JSONArray ph = o.optJSONArray("hosts");
            if (ph != null) for (int i = 0; i < ph.length(); i++) {
                String h = stripToHost(ph.optString(i, ""));   // accept ANY host the operator named (scope gate removed)
                if (!h.isEmpty() && !hosts.contains(h)) hosts.add(h);
            }
            org.json.JSONArray pp = o.optJSONArray("ports");
            if (pp != null) for (int i = 0; i < pp.length() && portSet.size() < PORTSCAN_MAX; i++) {
                int p = pp.optInt(i, -1);
                if (p >= 1 && p <= 65535) portSet.add(p);
            }
        } catch (Throwable ignore) { /* malformed JSON → fall through to the safe defaults below */ }

        if (hosts.isEmpty()) hosts.addAll(scanned);   // no explicit host → default to the already-scanned host(s)
        if (hosts.isEmpty())
            return "(no host to probe — name one, e.g. `scan ports on example.com`)";
        if (portSet.isEmpty()) return "(couldn't determine which ports to probe from: \"" + message + "\")";
        int[] ports = new int[portSet.size()];
        { int i = 0; for (int p : portSet) ports[i++] = p; }

        // Gate hosts, then probe EVERY (host, port) concurrently in ONE pool, with a HARD total deadline
        // (invokeAll timeout). CRITICAL: the pool is sized to the task count (no queue) so every port actually
        // STARTS — otherwise filtered ports hogging a smaller pool would starve queued ports, and the deadline
        // would cancel them unstarted (dropping real open ports). With no queue, the deadline only cancels the
        // ports still HANGING at ~12s — which are filtered/no-app (a real web app answers in well under 1s), so
        // nothing useful is lost. Both targets probe together (no sequential per-host wait).
        StringBuilder sb = new StringBuilder();
        java.util.List<String> targets = new java.util.ArrayList<>();
        for (String host : hosts) {
            String deny = hostGate(host);
            if (deny != null) sb.append(deny).append("\n\n"); else targets.add(host);
        }
        java.util.Map<String, java.util.List<String[]>> byHost = new java.util.LinkedHashMap<>();
        for (String host : targets) byHost.put(host, new java.util.ArrayList<>());
        java.util.List<java.util.concurrent.Callable<String[]>> tasks = new java.util.ArrayList<>();
        for (String host : targets) {
            final String h = host;
            for (int p : ports) { final int port = p; tasks.add(() -> probeOnePort(h, port)); }
        }
        if (!tasks.isEmpty()) {
            scanLog.log("[agent] port probe " + targets.size() + " host(s) × " + ports.length
                    + " port(s) = " + tasks.size() + " task(s), parallel");
            // Pool = task count (no queue) so no port is left unstarted; capped at 200 = PORTSCAN_MAX(100) × 2
            // targets, the realistic max. They are short-lived, mostly-blocked I/O threads.
            java.util.concurrent.ExecutorService pool =
                    java.util.concurrent.Executors.newFixedThreadPool(Math.min(200, Math.max(1, tasks.size())));
            try {
                for (java.util.concurrent.Future<String[]> f
                        : pool.invokeAll(tasks, 12, java.util.concurrent.TimeUnit.SECONDS)) {
                    try { String[] r = f.get(); if (r != null) byHost.get(r[0]).add(r); }
                    catch (Throwable ignore) { /* cancelled at the deadline / failed → treated as no response */ }
                }
            } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            finally { pool.shutdownNow(); }
        }
        for (String host : targets) {
            java.util.List<String[]> open = byHost.get(host);   // rows: {host,port,scheme,status,time,size,type,server,title}
            open.sort((a, b) -> Integer.compare(Integer.parseInt(a[1]), Integer.parseInt(b[1])));   // by port
            sb.append("Probed **").append(ports.length).append("** port(s) on `").append(host)
              .append("` in parallel through Burp (HTTP+HTTPS). ");
            if (open.isEmpty()) {
                sb.append("**No HTTP(S) web app answered.**\n\n");
            } else {
                sb.append("**").append(open.size()).append("** responded:\n\n");
                sb.append("| Port | Scheme | Status | Time | Size | Type | Server | Location | Title |\n")
                  .append("|---|---|---|---|---|---|---|---|---|\n");
                for (String[] r : open)   // r = {host,port,scheme,status,time,size,type,server,location,title}
                    sb.append("| ").append(r[1]).append(" | ").append(r[2]).append(" | ").append(r[3])
                      .append(" | ").append(r[4]).append(" | ").append(r[5]).append(" | ").append(r[6])
                      .append(" | ").append(r[7]).append(" | ").append(r[8]).append(" | ").append(r[9]).append(" |\n");
                sb.append('\n');
            }
        }
        return sb.toString().trim();
    }

    /** One port: try HTTPS then HTTP. Returns a result row {port,scheme,status,time,size,type,server,title}
     *  if a web app answered, else null. Latency is measured around the request; for a 3xx with no page
     *  title the redirect Location goes in the last cell. */
    private String[] probeOnePort(String host, int port) {
        for (String scheme : new String[]{ "https", "http" }) {
            try {
                String url = scheme + "://" + host + ":" + port + "/";
                burp.api.montoya.http.message.requests.HttpRequest req =
                        burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url);
                long t0 = System.nanoTime();
                HttpRequestResponse rr = api.http().sendRequest(req,
                        burp.api.montoya.http.RequestOptions.requestOptions().withResponseTimeout(5000L));
                long ms = (System.nanoTime() - t0) / 1_000_000L;
                if (rr.response() == null) continue;
                String status = String.valueOf(rr.response().statusCode());
                int size = 0;
                try { if (rr.response().body() != null) size = rr.response().body().length(); } catch (Throwable ignore) { }
                String type   = shortType(headerVal(rr, "Content-Type"));
                String server = sanitizeCell(headerVal(rr, "Server"));
                String loc    = headerVal(rr, "Location");
                String location = (loc != null && !loc.isBlank()) ? sanitizeCell(loc) : "-";
                String title  = titleOrDash(rr.response().bodyToString());
                return new String[]{ host, String.valueOf(port), scheme, status, ms + "ms", humanSize(size), type, server, location, title };
            } catch (Throwable ignore) { /* refused / TLS mismatch / timeout → try the other scheme */ }
        }
        return null;
    }

    /** First matching header value, or null. */
    private static String headerVal(HttpRequestResponse rr, String name) {
        try {
            for (burp.api.montoya.http.message.HttpHeader h : rr.response().headers())
                if (h.name().equalsIgnoreCase(name)) return h.value();
        } catch (Throwable ignore) { }
        return null;
    }

    /** Content-Type without the "; charset=…" tail. */
    private static String shortType(String ct) {
        if (ct == null || ct.isBlank()) return "-";
        int semi = ct.indexOf(';');
        return sanitizeCell(semi >= 0 ? ct.substring(0, semi).trim() : ct.trim());
    }

    /** Compact human-readable byte size for a table cell. */
    private static String humanSize(int n) {
        if (n <= 0) return "0";
        if (n < 1024) return n + "B";
        if (n < 1024 * 1024) return String.format(java.util.Locale.ROOT, "%.1fKB", n / 1024.0);
        return String.format(java.util.Locale.ROOT, "%.1fMB", n / (1024.0 * 1024.0));
    }

    private static String titleOrDash(String body) {
        if (body == null) return "-";
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(?is)<title[^>]*>(.*?)</title>").matcher(body);
        return m.find() ? sanitizeCell(m.group(1).trim()) : "-";
    }

    /** Keep a table cell one-line and short (strip pipes/newlines that would break the markdown table). */
    private static String sanitizeCell(String s) {
        if (s == null || s.isBlank()) return "-";
        s = s.replaceAll("[\\r\\n|]+", " ").trim();
        return s.length() > 60 ? s.substring(0, 60) + "…" : s;
    }

    /** Reduce a user-supplied host/URL to a bare hostname (drop scheme, path, port, credentials). */
    private static String stripToHost(String s) {
        if (s == null) return "";
        String h = s.trim();
        h = h.replaceFirst("(?i)^[a-z]+://", "");
        int at = h.indexOf('@'); if (at >= 0) h = h.substring(at + 1);
        int slash = h.indexOf('/'); if (slash >= 0) h = h.substring(0, slash);
        int colon = h.indexOf(':'); if (colon >= 0) h = h.substring(0, colon);
        return h.trim();
    }

    /** Deterministic HOST gate. Returns a denial message, or null if the host may be probed. The LLM never
     *  reaches this decision — it is pure code so the skill cannot be steered into scanning internal ranges. */
    private String hostGate(String host) {
        if (host == null || host.isBlank()) return "(no target host)";
        String h = stripToHost(host).toLowerCase();
        if (h.isEmpty()) return "(no target host)";
        if (h.equals("localhost") || h.endsWith(".localhost") || h.equals("localhost.localdomain"))
            return "(refused: " + h + " is loopback — the port skill will not probe the local machine)";
        try {
            java.net.InetAddress[] addrs = java.net.InetAddress.getAllByName(h);
            for (java.net.InetAddress a : addrs)
                if (isForbiddenAddress(a))
                    return "(refused: " + h + " resolves to a private/reserved address (" + a.getHostAddress()
                            + ") — the port skill will not probe internal ranges)";
        } catch (Throwable t) {
            return "(refused: cannot resolve " + h + ")";
        }
        return null;
    }

    /** True for loopback / link-local (incl. 169.254.169.254 metadata) / site-local / any-local / multicast. */
    private static boolean isForbiddenAddress(java.net.InetAddress a) {
        if (a == null) return true;
        if (a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress()
                || a.isAnyLocalAddress() || a.isMulticastAddress()) return true;
        byte[] b = a.getAddress();
        if (b != null && b.length == 4) {
            int o0 = b[0] & 0xff, o1 = b[1] & 0xff;
            if (o0 == 100 && o1 >= 64 && o1 <= 127) return true;   // 100.64/10 CGNAT
            if (o0 == 169 && o1 == 254) return true;               // link-local / cloud metadata
            if (o0 == 192 && o1 == 0)  return true;                // 192.0.0.0/24 IETF
        }
        return false;
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
