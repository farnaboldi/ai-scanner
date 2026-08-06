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

    public ChatAssistant(Supplier<AiEngine> engine, MontoyaApi api, ScanScope scope, ScanLog scanLog) {
        this.engine = engine;
        this.api = api;
        this.scope = scope;
        this.scanLog = scanLog;
    }

    /** Produce a reply to the user's message, grounded in scope + log + conversation. Blocking. */
    public String reply(String userMsg) {
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
