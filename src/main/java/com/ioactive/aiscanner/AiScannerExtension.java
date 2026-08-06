package com.ioactive.aiscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.engine.EngineConfig;
import com.ioactive.aiscanner.engine.LlmHttp;
import com.ioactive.aiscanner.engine.MontoyaLlmHttp;
import com.ioactive.aiscanner.engine.LocalAiEngine;
import com.ioactive.aiscanner.engine.MontoyaAiEngine;
import com.ioactive.aiscanner.menu.AiContextMenuProvider;
import com.ioactive.aiscanner.scan.AiScanner;
import com.ioactive.aiscanner.scan.AiTriage;
import com.ioactive.aiscanner.scan.ScanConfig;
import com.ioactive.aiscanner.scan.ScanScope;
import com.ioactive.aiscanner.scan.SessionStore;
import com.ioactive.aiscanner.ui.ScanLog;
import com.ioactive.aiscanner.ui.SettingsTab;
import org.json.JSONObject;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.FlowLayout;

public class AiScannerExtension implements BurpExtension {

    public static final String EXT_NAME = "AI Scanner";
    /** Internal build number — bump on every rebuild so the load line tells you which jar is live. */
    public static final int BUILD = 314;
    private static final String PREF_KEY = "aiscanner.settings";

    private MontoyaApi api;
    private LlmHttp http;
    private ScanLog scanLog;
    private final ScanConfig scanConfig = new ScanConfig();
    private final SessionStore session = new SessionStore();
    private final ScanScope scanScope = new ScanScope();
    private volatile EngineConfig engineConfig;
    private volatile AiEngine engine;
    private volatile boolean unloaded = false;

    /** True once Burp has unloaded the extension — long-running loops check this to stop promptly. */
    public boolean isUnloaded() { return unloaded; }

    /**
     * Opt into Burp's built-in AI. Burp queries this default method AT LOAD TIME (before initialize); without
     * declaring AI_FEATURES here, every {@code api.ai()} call is rejected and {@link MontoyaAiEngine} silently
     * degrades to "AI not enabled". Must live on the class, not inside initialize().
     */
    @Override
    public java.util.Set<EnhancedCapability> enhancedCapabilities() {
        return java.util.Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        // Route ALL LLM traffic through Burp's own HTTP engine (visible in Logger, honors the user's network
        // config, avoids the java.net.http h2c body-drop). This is the only transport — BApp-compliant.
        this.http = new MontoyaLlmHttp(api);
        this.scanLog = new ScanLog(s -> api.logging().logToOutput(s));
        // Surface the AI Scanner's OWN findings (probes + flow-engine + auth) as Burp AuditIssues so they
        // appear on the dashboard / site-map issues, not only in our log. Scope-gated to hosts we scan.
        scanLog.setIssueSink(this::raiseAiIssue);
        scanLog.log("[AI Scanner] build " + BUILD + " loaded.");

        loadSettings();
        applyLaunchOverrides();          // -Daiscanner.baseUrl/-Daiscanner.model/-Daiscanner.apiKey (or AISCANNER_* env)
        scanLog.setVerbose(engineConfig.verbose);

        api.extension().setName(EXT_NAME);
        AiScanner scanner = new AiScanner(api, this::getEngine, scanConfig, scanLog, session, this::isUnloaded);
        api.scanner().registerAuditIssueHandler(new AiTriage(scanLog, scanScope));
        AiContextMenuProvider menuProvider = new AiContextMenuProvider(api, scanLog, session, scanner, scanScope);
        api.userInterface().registerContextMenuItemsProvider(menuProvider);
        // Suite tab: nav bar (Log / Settings) switching a CardLayout. No Dashboard tab — Burp's own
        // Dashboard already shows the scan task/issues; ours was redundant.
        // HEADLESS GUARD: registering a Swing Suite tab throws HeadlessException with no display. In an
        // unattended/container run (autoscan via -Daiscanner.*), skip the whole UI — the scan needs no GUI.
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            api.logging().logToOutput("[" + EXT_NAME + "] headless — Suite tab/UI skipped (scan runs via -Daiscanner.autoscan; config via -Daiscanner.* flags).");
        } else {
        SettingsTab settingsTab = new SettingsTab(this);

        // Chat with the local model, grounded in scope + the scan log. Replies interleave with the log.
        com.ioactive.aiscanner.ui.ChatAssistant chat =
                new com.ioactive.aiscanner.ui.ChatAssistant(this::getEngine, api, scanScope, scanLog);
        scanLog.enableChat(msg -> {
            scanLog.log("[you] " + msg);
            new Thread(() -> scanLog.log("[ai] " + chat.reply(msg)), "ais-chat").start();
        });

        CardLayout cards = new CardLayout();
        JPanel content = new JPanel(cards);
        content.add(scanLog.component(), "log");
        content.add(settingsTab.component(), "settings");

        JPanel nav = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        // toggle buttons in a group → the active view stays visibly "pressed"
        javax.swing.JToggleButton bLog = new javax.swing.JToggleButton("Agent");
        javax.swing.JToggleButton bSet = new javax.swing.JToggleButton("Settings");
        javax.swing.ButtonGroup group = new javax.swing.ButtonGroup();
        group.add(bLog); group.add(bSet);
        bLog.addActionListener(e -> cards.show(content, "log"));
        bSet.addActionListener(e -> { cards.show(content, "settings"); settingsTab.focusBaseUrl(); });
        nav.add(bLog);
        nav.add(bSet);

        JPanel tab = new JPanel(new BorderLayout());
        tab.add(nav, BorderLayout.NORTH);
        tab.add(content, BorderLayout.CENTER);
        // Default view: if the LLM is already configured, open on Log (you just want to watch it run);
        // otherwise open on Settings so you configure it first.
        AiEngine cfgEngine = getEngine();
        boolean llmSet = cfgEngine != null && cfgEngine.isConfigured();
        if (llmSet) {
            bLog.setSelected(true);
            cards.show(content, "log");
        } else {
            bSet.setSelected(true);
            cards.show(content, "settings");
            settingsTab.focusBaseUrl();
        }
        api.userInterface().registerSuiteTab(EXT_NAME, tab);
        }  // end headless guard

        // BApp requirement (clean unloading): stop our background work when the user unloads the extension.
        // Set a flag long-running scan loops poll, and interrupt our named worker threads (scan / autoscan /
        // chat) so blocking sleeps/HTTP waits abort promptly instead of leaking after unload.
        api.extension().registerUnloadingHandler(() -> {
            unloaded = true;
            for (Thread t : Thread.getAllStackTraces().keySet()) {
                String n = t.getName();
                if (n != null && (n.startsWith("ais-") || n.startsWith("aiscanner-"))) t.interrupt();
            }
            api.logging().logToOutput("[" + EXT_NAME + "] unloaded — background scans signalled to stop.");
        });

        api.logging().logToOutput("[" + EXT_NAME + "] loaded (build " + BUILD + "). Configure your local model in the '"
                + EXT_NAME + "' tab, then right-click a host/request → " + EXT_NAME + ".");

        // CLI-driven "Strix for Burp": -Daiscanner.autoscan=<url[,url2,…]> (or AISCANNER_AUTOSCAN) → kick off
        // crawl-and-scan automatically once Burp is up, then leave the GUI interactive. A comma/space/newline-
        // separated LIST runs SEQUENTIALLY in this one Burp session (session + findings reset between targets).
        String target = launchArg("aiscanner.autoscan", "AISCANNER_AUTOSCAN");
        if (target != null) {
            final String[] targets = target.split("[\\s,]+");
            final String reportDir = launchArg("aiscanner.reportDir", "AISCANNER_REPORT_DIR");
            final boolean batch = targets.length > 1;
            scanLog.log("[AI Scanner] auto-scan requested for " + targets.length + " target(s) — starting in ~5s…");
            new Thread(() -> {
                try { Thread.sleep(5000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                int done = 0;
                for (int i = 0; i < targets.length; i++) {
                    if (unloaded) return;
                    String url = normalizeTarget(targets[i]);
                    if (url == null) continue;
                    if (batch) {
                        scanLog.log("[AI Scanner] ===== BATCH target " + (i + 1) + "/" + targets.length + ": " + url + " =====");
                        session.reset();          // no cookie/bearer/login bleed between different hosts
                        scanLog.clearFindings();  // each target's report holds only its own findings
                    }
                    // Per-target report file when a report DIR is given (batch) — else the single -Daiscanner.report.
                    if (reportDir != null && !reportDir.isBlank())
                        System.setProperty("aiscanner.report", reportDir.replaceAll("/+$", "") + "/" + reportFileName(url));
                    try { menuProvider.startScanAndWait(url); done++; }
                    catch (Throwable t) { scanLog.log("[AI Scanner] target failed (" + url + "): " + t + " — continuing."); }
                }
                if (batch) scanLog.log("[AI Scanner] ===== BATCH complete: " + done + "/" + targets.length + " target(s) scanned =====");
            }, "aiscanner-autoscan").start();
        }
    }

    /** Add a scheme if the target is a bare host (dev/uat hosts are given without http(s)://). Defaults to https. */
    private static String normalizeTarget(String t) {
        if (t == null || t.isBlank()) return null;
        t = t.trim();
        return t.matches("(?i)^https?://.*") ? t : "https://" + t;
    }

    /** A filesystem-safe per-target report filename derived from the URL's host. */
    private static String reportFileName(String url) {
        String h = url.replaceFirst("(?i)^https?://", "").replaceFirst("[/:?#].*$", "");
        if (h.isBlank()) h = "target";
        return h.replaceAll("[^A-Za-z0-9._-]", "_") + ".report.txt";
    }

    /** A launch parameter from a JVM system property, falling back to an env var. null if unset/blank. */
    private static String launchArg(String prop, String env) {
        String v = System.getProperty(prop);
        if (v == null || v.isBlank()) v = System.getenv(env);
        return (v == null || v.isBlank()) ? null : v.trim();
    }

    /** Raise one of the AI Scanner's own findings as a Burp AuditIssue so it appears on the dashboard /
     *  site-map issues (probes + flow-engine + auth findings otherwise only reach our log). Scope-gated to
     *  the hosts we are scanning. Named "AI: …" so {@link AiTriage} knows not to re-log/re-count it. */
    private void raiseAiIssue(String vulnClass, String url, String detail, HttpRequestResponse... evidence) {
        try {
            if (url == null || !scanScope.contains(url)) return;   // only hosts WE are scanning
            // keep only the non-null req/resp pairs — a finding may attach several (e.g. BFLA's unauth /
            // our-session / control probes) so Burp shows the full proof across multiple request tabs.
            java.util.List<HttpRequestResponse> ev = new java.util.ArrayList<>();
            if (evidence != null) for (HttpRequestResponse e : evidence) if (e != null && e.response() != null) ev.add(e);
            String name = vulnClass == null ? "AI: finding" : (vulnClass.startsWith("AI:") ? vulnClass : "AI: " + vulnClass);
            String cls = vulnClass == null ? "finding" : vulnClass.replaceFirst("(?i)^AI:\\s*", "");
            // Full Burp-issue shape so these export cleanly alongside Burp's own issues: instance-specific
            // detail (what we did + the evidence), plus per-class background + remediation from IssueLibrary.
            com.ioactive.aiscanner.scan.IssueLibrary.Info info = com.ioactive.aiscanner.scan.IssueLibrary.describe(cls);
            // Neutral preamble: the specific METHOD (active proof, offline crack, static decode, differential…) is
            // stated in the per-finding Evidence detail below, so we don't over-claim an active "proof payload"
            // for passive/analysis findings (e.g. a JWT claim decode). The attached request/response is the proof.
            String detailHtml = "<p>The AI Scanner reported <b>" + escapeHtml(cls) + "</b> at this location.</p>"
                    + (detail == null || detail.isBlank() ? "" : "<p><b>Evidence:</b> " + escapeHtml(detail) + "</p>")
                    + (ev.isEmpty() ? "<p><i>No single request/response is attached — this finding is derived from "
                            + "observed traffic/artifacts; see the Evidence above.</i></p>"
                            : "<p>See the attached request/response for the observed artifact.</p>");
            // Mirror a native Burp issue's four fields: instance detail + remediation detail (this location),
            // class-level background + remediation background (the vuln class). All non-null — Montoya's
            // auditIssue() rejects a null remediation, which was silently thrown+swallowed here so findings
            // never reached the dashboard. Attach the offending req/resp when a probe gave us one.
            String remediationDetail = "<p>Apply the guidance in the remediation background to this endpoint/token.</p>";
            AuditIssue issue = !ev.isEmpty()
                    ? AuditIssue.auditIssue(name, detailHtml, remediationDetail, url, info.severity, AuditIssueConfidence.FIRM,
                            info.background, info.remediation, info.severity, ev.toArray(new HttpRequestResponse[0]))
                    : AuditIssue.auditIssue(name, detailHtml, remediationDetail, url, info.severity, AuditIssueConfidence.FIRM,
                            info.background, info.remediation, info.severity);
            api.siteMap().add(issue);
            scanLog.debug("[AI Scanner] dashboard issue raised: " + name + " @ " + url);
        } catch (Throwable t) {
            scanLog.log("[AI Scanner] could not raise dashboard issue for " + vulnClass + " @ " + url + ": " + t);
        }
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Override engine base URL / model / API key from launch args so a CLI invocation is self-configuring. */
    private void applyLaunchOverrides() {
        String provider = launchArg("aiscanner.provider", "AISCANNER_PROVIDER");
        String base = launchArg("aiscanner.baseUrl", "AISCANNER_BASE_URL");
        String model = launchArg("aiscanner.model", "AISCANNER_MODEL");
        String key = launchArg("aiscanner.apiKey", "AISCANNER_API_KEY");
        String think = launchArg("aiscanner.disableThinking", "AISCANNER_DISABLE_THINKING");
        String maxTok = launchArg("aiscanner.maxTokens", "AISCANNER_MAX_TOKENS");
        String verbose = launchArg("aiscanner.verbose", "AISCANNER_VERBOSE");
        if (provider == null && base == null && model == null && key == null && think == null && maxTok == null && verbose == null) return;
        EngineConfig c = engineConfig;
        int mt = c.maxTokens;
        if (maxTok != null) try { mt = Integer.parseInt(maxTok.trim()); } catch (NumberFormatException ignore) { }
        boolean vb = verbose != null ? Boolean.parseBoolean(verbose) : c.verbose;
        // Use the 9-arg constructor so a launch override does NOT collapse the provider to LOCAL_LLM (the
        // 8-arg back-compat ctor hardcodes it). -Daiscanner.provider=BURP_AI selects Burp's built-in AI from
        // the CLI. When no provider is given but a baseUrl override IS (the local-LLM launcher / Docker flow),
        // INFER LOCAL_LLM — a baseUrl is meaningless for BURP_AI, and otherwise the fresh-install BURP_AI
        // default silently ignores the endpoint and degrades. Else keep the current/saved provider.
        EngineConfig.Provider prov = provider != null ? parseProvider(provider.trim())
                : (base != null && !base.isBlank() ? EngineConfig.Provider.LOCAL_LLM : c.provider);
        engineConfig = new EngineConfig(
                prov,
                base != null ? base : c.baseUrl,
                model != null ? model : c.model,
                key != null ? key : c.apiKey,
                c.temperature, mt,
                think != null ? Boolean.parseBoolean(think) : c.disableThinking,
                c.timeoutSeconds, vb);
        scanLog.setVerbose(vb);   // -Daiscanner.verbose: show discovery/fetch traces without code edits
        this.engine = engineFor(engineConfig);
        scanLog.log("[AI Scanner] launch override → provider=" + engineConfig.provider
                + (engineConfig.provider == EngineConfig.Provider.LOCAL_LLM ? ", baseUrl=" + engineConfig.baseUrl : "")
                + (model != null ? ", model=" + model : "")
                + (key != null ? ", apiKey=***" : ""));
    }

    // ---- accessors ----
    public MontoyaApi api() { return api; }
    public AiEngine getEngine() { return engine; }
    public EngineConfig engineConfig() { return engineConfig; }
    public ScanConfig scanConfig() { return scanConfig; }

    /** Rebuild the engine from a new config and persist everything. Called by the settings tab. */
    public void applyEngineConfig(EngineConfig cfg) {
        this.engineConfig = cfg;
        this.engine = engineFor(cfg);
        scanLog.setVerbose(cfg.verbose);
        persist();
    }

    /** Build a throwaway engine from unsaved UI values (for "Test connection"). */
    public AiEngine buildEngine(EngineConfig cfg) {
        return engineFor(cfg);
    }

    /** Pick the engine implementation for a config's provider (Burp built-in AI vs a local OpenAI-compatible server). */
    private AiEngine engineFor(EngineConfig cfg) {
        return cfg.provider == EngineConfig.Provider.BURP_AI
                ? new MontoyaAiEngine(api, cfg, scanLog::log)
                : new LocalAiEngine(cfg, http, scanLog::log);
    }

    private static EngineConfig.Provider parseProvider(String s) {
        try { return EngineConfig.Provider.valueOf(s); } catch (Exception e) { return EngineConfig.Provider.LOCAL_LLM; }
    }

    public void persist() {
        JSONObject o = new JSONObject();
        EngineConfig c = engineConfig;
        o.put("provider", c.provider.name())
         .put("baseUrl", c.baseUrl).put("model", c.model).put("apiKey", c.apiKey)
         .put("temperature", c.temperature).put("maxTokens", c.maxTokens)
         .put("disableThinking", c.disableThinking).put("timeoutSeconds", c.timeoutSeconds)
         .put("verbose", c.verbose);
        o.put("rounds", scanConfig.rounds).put("payloadsPerRound", scanConfig.payloadsPerRound)
         .put("delayMs", scanConfig.delayMs);
        api.persistence().extensionData().setString(PREF_KEY, o.toString());
    }

    private void loadSettings() {
        // verbose defaults OFF: the log shows phases + real vulnerabilities; INFO findings and
        // diagnostic chatter (scanning/LLM echo/mining) appear only when the user enables verbose.
        // Fresh install defaults to Burp's built-in AI (App-Store preferred); the local base URL is pre-filled
        // so switching to the Local-LLM provider is one radio click away.
        EngineConfig def = new EngineConfig(EngineConfig.Provider.BURP_AI,
                "http://127.0.0.1:8000/v1/", "", "", 0.3, 512, true, 120, false);
        String raw = api.persistence().extensionData().getString(PREF_KEY);
        if (raw == null || raw.isBlank()) {
            this.engineConfig = def;
            this.engine = engineFor(def);
            return;
        }
        try {
            JSONObject o = new JSONObject(raw);
            // A saved config that predates the provider selector was a local LLM → default the missing key to
            // LOCAL_LLM so existing users aren't silently switched to Burp AI.
            this.engineConfig = new EngineConfig(
                    parseProvider(o.optString("provider", "LOCAL_LLM")),
                    o.optString("baseUrl", def.baseUrl),
                    o.optString("model", def.model),
                    o.optString("apiKey", def.apiKey),
                    o.optDouble("temperature", def.temperature),
                    o.optInt("maxTokens", def.maxTokens),
                    o.optBoolean("disableThinking", def.disableThinking),
                    o.optInt("timeoutSeconds", def.timeoutSeconds),
                    o.optBoolean("verbose", def.verbose));
            scanConfig.rounds = o.optInt("rounds", scanConfig.rounds);
            scanConfig.payloadsPerRound = o.optInt("payloadsPerRound", scanConfig.payloadsPerRound);
            scanConfig.delayMs = o.optInt("delayMs", scanConfig.delayMs);
        } catch (Exception e) {
            this.engineConfig = def;
        }
        this.engine = engineFor(engineConfig);
    }
}
