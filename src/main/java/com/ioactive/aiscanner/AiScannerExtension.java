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
import com.ioactive.aiscanner.engine.LogLevel;
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
    public static final int BUILD = 703;
    private static final String PREF_KEY = "aiscanner.settings";

    private MontoyaApi api;
    private LlmHttp http;
    private ScanLog scanLog;
    private final ScanConfig scanConfig = new ScanConfig();
    private final SessionStore session = new SessionStore();
    private final ScanScope scanScope = new ScanScope();
    /** -Daiscanner.sourceRepo / AISCANNER_SOURCE_REPO — a LOCAL repo path applied to every autoscan target. */
    private volatile String launchSourceRepo;
    /** host → local source-repo path (from the context-menu popup / settings); persisted across sessions. */
    private final java.util.Map<String, String> hostRepoMap = new java.util.concurrent.ConcurrentHashMap<>();
    private volatile EngineConfig engineConfig;
    /** Persisted log level (INFO/DEBUG/TRACE) from settings; null until loaded. Applied at init after legacy flags. */
    private volatile LogLevel logLevelSetting;
    private volatile AiEngine engine;
    private volatile boolean unloaded = false;
    /** Scanner-wide identity guard — promoted to a field so {@link #launchParallel} (a method) can register
     *  each parallel target's SessionStore with it. Set in {@link #initialize}. */
    private volatile com.ioactive.aiscanner.scan.SelfAccountProtector selfAccountProtector;
    /** The log mirror (Burp output + optional -Daiscanner.logFile) — promoted to a field so per-target
     *  {@link ScanLog}s built in {@link #launchParallel} share the same sink. Set in {@link #initialize}. */
    private volatile java.util.function.Consumer<String> logMirror;
    /** Race-free guard: at most ONE on-demand "test &lt;module&gt;" run at a time (it sets a GLOBAL -Daiscanner.only
     *  around a scan, so a concurrent run would corrupt that property AND double the target load). */
    private final java.util.concurrent.atomic.AtomicBoolean onDemandModuleRunning = new java.util.concurrent.atomic.AtomicBoolean(false);

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
        // CLI scan-mode override is applied AFTER loadSettings() (below) so it wins over the persisted value.
        // Route ALL LLM traffic through Burp's own HTTP engine (visible in Logger, honors the user's network
        // config, avoids the java.net.http h2c body-drop). This is the only transport — BApp-compliant.
        this.http = new MontoyaLlmHttp(api);
        // Burp Output is the always-on sink. File logging (both -Daiscanner.logFile and the Settings "Log to
        // file" toggle) is handled uniformly by ScanLog.setLogFile — one live-toggleable code path, and it
        // captures the chat too (which the old logMirror-wrapping FileWriter did not).
        java.util.function.Consumer<String> logMirror = s -> api.logging().logToOutput(s);
        this.logMirror = logMirror;   // field ref so launchParallel() can build per-target mirrors
        this.scanLog = new ScanLog(logMirror);
        String logFileProp = System.getProperty("aiscanner.logFile");
        if (logFileProp != null && !logFileProp.isBlank()) scanLog.setLogFile(logFileProp);   // CLI flag → same path
        // Surface the AI Scanner's OWN findings (probes + flow-engine + auth) as Burp AuditIssues so they
        // appear on the dashboard / site-map issues, not only in our log. Scope-gated to hosts we scan.
        scanLog.setIssueSink(this::raiseAiIssue);
        scanLog.log("build " + BUILD + " loaded.");

        loadSettings();
        applyLaunchOverrides();          // -Daiscanner.baseUrl/-Daiscanner.model/-Daiscanner.apiKey (or AISCANNER_* env)
        // -Daiscanner.sourceRepo (or AISCANNER_SOURCE_REPO): a LOCAL repo path to drive SAST-assisted testing
        // for every autoscan target (the launcher clones a URL and passes a path). null → black-box only.
        launchSourceRepo = launchArg("aiscanner.sourceRepo", "AISCANNER_SOURCE_REPO");
        if (launchSourceRepo != null) scanLog.log("source repo (launch): " + launchSourceRepo);
        // Unified log level (INFO/DEBUG/TRACE) — the ONE knob for verbosity, selectable from Settings and the CLI
        // (-Daiscanner.logLevel / AISCANNER_LOG_LEVEL). CLI wins over the persisted setting; nothing else feeds it.
        String cli = launchArg("aiscanner.logLevel", "AISCANNER_LOG_LEVEL");
        if (cli != null && !cli.isBlank()) LogLevel.set(LogLevel.parse(cli));
        else if (logLevelSetting != null)  LogLevel.set(logLevelSetting);
        scanLog.log("log level: " + LogLevel.current());
        // CLI scan-mode override: wins over any persisted value (loadSettings already ran).
        // Applied here so the SettingsTab that's built next reads the correct mode from scanConfig.
        String scanModeInit = launchArg("aiscanner.scanMode", "AISCANNER_SCAN_MODE");
        if (scanModeInit != null && !scanModeInit.isBlank()) {
            try { scanConfig.scanMode = com.ioactive.aiscanner.scan.ScanConfig.ScanMode.valueOf(scanModeInit.trim().toUpperCase());
                  scanLog.log("scan mode override from CLI: " + scanConfig.scanMode); }
            catch (Exception ignore) { scanLog.log("[warn] unknown AISCANNER_SCAN_MODE='" + scanModeInit + "'"); }
        }

        api.extension().setName(EXT_NAME);
        // Scanner-wide session self-preservation: neutralize any phase's state-changing request to OUR OWN account
        // (path carries the authenticated identity) → a harmless GET, so no probe/audit can reset/delete our creds
        // mid-scan and bounce the deep authenticated surface to /login. Generic; other identities untouched.
        final com.ioactive.aiscanner.scan.SelfAccountProtector protector =
                new com.ioactive.aiscanner.scan.SelfAccountProtector(api, session, scanLog);
        this.selfAccountProtector = protector;   // field ref so launchParallel() can register per-target sessions
        AiScanner scanner = new AiScanner(api, this::getEngine, scanConfig, scanLog, session, this::isUnloaded, this::repoForHost);
        // Agent-tab Stop button. Root mechanism (no per-probe checkpoints): (1) scanLog.phase() throws once
        // stopRequested, so the probe battery drains from a single point since every probe calls phase() first;
        // (2) interrupting the named scan threads unblocks any in-flight crawl / discovery / SAST / native-audit
        // wait. Wired before the headless guard so the stop-check is always live (the button lives in the UI).
        scanLog.setStopCheck(scanner::stopRequested);
        scanLog.setStopHandler(() -> {
            scanLog.log("Stop requested by user — cancelling the current scan…");
            scanner.requestStop();
            for (Thread t : Thread.getAllStackTraces().keySet()) {
                String n = t.getName();
                if (n != null && (n.startsWith("ais-") || n.startsWith("aiscanner-"))) t.interrupt();
            }
        });
        api.scanner().registerAuditIssueHandler(new AiTriage(scanLog, scanScope));
        // Collect every WebSocket upgrade the crawl/proxied-browser opens so the CSWSH probe knows the app's real
        // WS surface (WsObservations). Skip our OWN extension-initiated sockets (the probe's replays) to avoid a
        // feedback loop. Pure Montoya websocket API — no external deps.
        try {
            api.websockets().registerWebSocketCreatedHandler(created -> {
                try {
                    if (created.toolSource() != null
                            && created.toolSource().isFromTool(burp.api.montoya.core.ToolType.EXTENSIONS)) return;
                    com.ioactive.aiscanner.scan.WsObservations.add(created.upgradeRequest());
                } catch (Throwable ignore) { }
            });
        } catch (Throwable t) {
            api.logging().logToOutput("[" + EXT_NAME + "] websocket-observation handler not registered: " + t);
        }
        AiContextMenuProvider menuProvider = new AiContextMenuProvider(api, scanLog, session, scanner, scanScope,
                this::repoForHost, this::setRepoForHost);
        api.userInterface().registerContextMenuItemsProvider(menuProvider);
        scanLog.setRescanHandler(url -> menuProvider.startScan(url));
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            api.logging().logToOutput("[" + EXT_NAME + "] headless — Suite tab/UI skipped (scan runs via -Daiscanner.autoscan; config via -Daiscanner.* flags).");
        } else {
        SettingsTab settingsTab = new SettingsTab(this);
        menuProvider.setSettingsTab(settingsTab);   // wire after creation so CLI scan-mode overrides sync the UI
        settingsTab.hookPhaseChanges(scanLog);   // keep module checkboxes enabled/disabled in sync with scan phase

        // Chat with the local model, grounded in scope + the scan log. Replies interleave with the log.
        com.ioactive.aiscanner.ui.ChatAssistant chat =
                new com.ioactive.aiscanner.ui.ChatAssistant(this::getEngine, api, scanScope, scanLog);
        chat.setScanHandler(url -> menuProvider.startScan(url));
        // Multi-target chat command: `scan URL1 (REPO1) and URL2 (REPO2)` → CONCURRENT DAST+SAST scans, one
        // per-target unit each. Fire-and-forget (Burp stays open); NEVER touches aiscanner.exitOnComplete.
        chat.setBatchScanHandler(pairs -> launchParallel(pairs, null, /*exitWhenDone=*/false));
        // On-demand single-module "test <module>" from the Agent tab. TWO cases:
        //   • A scan is ALREADY running → ENQUEUE the module into it (do NOT start a second scan). Ticking its
        //     checkbox rewrites -Daiscanner.only, which the attack loop reads LIVE per phase, so the module runs when
        //     the battery reaches its phase (if not already passed) and the status-bar denominator grows by one — no
        //     re-crawl, no racing a second scan against a fragile target.
        //   • No scan running → fresh re-scan restricted to that ONE probe (transient only=), reusing the warm site
        //     map so discovery is fast. Race-free single-flight so a double "test" can't launch two.
        chat.setModuleHandler(hostKey -> {
            String host = hostKey[0], key = hostKey[1];
            if (scanLog.isScanActive()) {   // ENQUEUE into the in-flight scan
                boolean known = settingsTab.selectModuleBox(key);   // tick checkbox + rewrite only= (read live per phase)
                String warn = scanLog.attackPhasePassed(key)
                        ? " — WARNING: its phase may already have run this scan (queued anyway; it'll apply next scan)"
                        : " — it'll run when the attack battery reaches that phase";
                scanLog.appendChat("ai", known ? "queued '" + key + "' into the running scan's attack modules" + warn
                                           : "unknown module '" + key + "' — not queued");
                return;
            }
            // No scan running → fresh re-scan scoped to this ONE module (warm site map), race-free single-flight.
            if (!onDemandModuleRunning.compareAndSet(false, true)) {
                scanLog.appendChat("ai", "on-demand module run ignored — one is already starting.");
                return;
            }
            String prev = System.getProperty("aiscanner.only");
            System.setProperty("aiscanner.only", key);
            scanLog.appendChat("ai", "on-demand module '" + key + "' on " + host + " (only=" + key + ", warm site map)");
            try { menuProvider.startScanAndWait(host.matches("(?i)^https?://.*") ? host : "http://" + host + "/"); }
            catch (Throwable t) { scanLog.appendChat("ai", "on-demand module run error: " + t); }
            finally {
                if (prev == null) System.clearProperty("aiscanner.only"); else System.setProperty("aiscanner.only", prev);
                onDemandModuleRunning.set(false);
            }
        });
        // Build the chat (Agent) panel — standalone, no longer a split of the log.
        javax.swing.JPanel agentPanel = scanLog.buildChatPanel(msg -> {
            scanLog.appendChat("you", msg);
            new Thread(() -> { String r = chat.reply(msg); if (r != null) scanLog.appendChat("ai", r); }, "ais-chat").start();
        });

        // Three-tab structure: Settings | Log | Agent
        javax.swing.JTabbedPane tabs = new javax.swing.JTabbedPane();
        tabs.addTab("Settings", settingsTab.component());
        tabs.addTab("Log",     scanLog.component());
        tabs.addTab("Agent",   agentPanel);

        // Default: if LLM configured open on Log; else Settings.
        AiEngine cfgEngine = getEngine();
        boolean llmSet = cfgEngine != null && cfgEngine.isConfigured();
        tabs.setSelectedIndex(llmSet ? 1 : 0);
        if (!llmSet) settingsTab.focusBaseUrl();

        // Snap to Log when a scan is running and the user opens the suite tab.
        tabs.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0
                    && tabs.isShowing() && scanLog.isScanActive()) {
                tabs.setSelectedIndex(1);
                scanLog.scrollToBottom();
            }
        });
        api.userInterface().registerSuiteTab(EXT_NAME, tabs);
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
            // Filesystem hygiene: remove any source archives we downloaded+extracted to temp this session
            // (never a user-supplied local checkout — those are used in place and not tracked for deletion).
            int wiped = 0;
            try { wiped = com.ioactive.aiscanner.scan.sast.RepoFetcher.cleanup(); } catch (Throwable ignore) { }
            api.logging().logToOutput("[" + EXT_NAME + "] unloaded — background scans signalled to stop"
                    + (wiped > 0 ? "; removed " + wiped + " fetched source checkout(s) from temp." : "."));
        });

        api.logging().logToOutput("[" + EXT_NAME + "] loaded (build " + BUILD + "). Configure your local model in the '"
                + EXT_NAME + "' tab, then right-click a host/request → " + EXT_NAME + ".");

        // CLI-driven "Strix for Burp": -Daiscanner.autoscan=<url[,url2,…]> (or AISCANNER_AUTOSCAN) → kick off
        // crawl-and-scan automatically once Burp is up, then leave the GUI interactive. A comma/space/newline-
        // separated LIST runs SEQUENTIALLY in this one Burp session (session + findings reset between targets).
        String target = launchArg("aiscanner.autoscan", "AISCANNER_AUTOSCAN");
        if (target != null) {
            final String[] targets = target.split("[\\s,]+");
            // Optional PER-TARGET SAST source repos, aligned index-wise with the autoscan URLs (comma-separated,
            // empty slots allowed → that target stays black-box). Lets a headless parallel run drive DAST+SAST with a
            // DIFFERENT repo per target — the CLI equivalent of the Agent-tab `scan <url> (<repo>) and …` command.
            // Generic; falls back to the launch-wide sourceRepo when absent.
            final String reposArg = launchArg("aiscanner.autoscanRepos", "AISCANNER_AUTOSCAN_REPOS");
            final String[] autoscanRepos = (reposArg == null || reposArg.isBlank()) ? new String[0] : reposArg.split(",", -1);
            final String reportDir = launchArg("aiscanner.reportDir", "AISCANNER_REPORT_DIR");
            // Pre-seed an authenticated session from a launch cookie (AISCANNER_COOKIE / -Daiscanner.cookie) — for apps
            // whose login the scanner CANNOT replicate (client-side-crypto login, SSO, MFA): paste a live browser
            // Cookie header and the scan runs authenticated with no login step. Optional AISCANNER_LANDING = the
            // post-login entry URL the explorer should seed. Generic — no app-specific logic.
            final String seedCookie = launchArg("aiscanner.cookie", "AISCANNER_COOKIE");
            final String seedLanding = launchArg("aiscanner.landing", "AISCANNER_LANDING");
            final boolean batch = targets.length > 1;
            String parFlag = launchArg("aiscanner.parallel", "AISCANNER_PARALLEL");
            final boolean parallel = batch && parFlag != null && !"false".equalsIgnoreCase(parFlag) && !"0".equals(parFlag);
            scanLog.log("auto-scan requested for [" + String.join(",", targets) + "] — starting in ~5s…");
            new Thread(() -> {
                try { Thread.sleep(5000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                if (parallel) {
                    // CLI parallel autoscan: reuse the shared parallel engine. Per-target SAST repo comes from
                    // -Daiscanner.autoscanRepos (index-aligned with the URLs); absent slots fall back to the
                    // launch-wide sourceRepo (via repoForHost). exitWhenDone honors -Daiscanner.exitOnComplete.
                    boolean wantExit = System.getProperty("aiscanner.exitOnComplete") != null
                            && !"false".equalsIgnoreCase(System.getProperty("aiscanner.exitOnComplete"));
                    java.util.List<String[]> pairs = new java.util.ArrayList<>();
                    for (int i = 0; i < targets.length; i++) {
                        String url = normalizeTarget(targets[i]);
                        if (url == null) continue;
                        String repo = (i < autoscanRepos.length && !autoscanRepos[i].isBlank()) ? autoscanRepos[i].trim() : null;
                        pairs.add(new String[]{ url, repo });
                    }
                    launchParallel(pairs, reportDir, wantExit);
                    return;
                }
                int done = 0;
                for (int i = 0; i < targets.length; i++) {
                    if (unloaded) return;
                    String url = normalizeTarget(targets[i]);
                    if (url == null) continue;
                    if (batch) {
                        scanLog.log("===== BATCH target " + (i + 1) + "/" + targets.length + ": " + url + " =====");
                        session.reset();          // no cookie/bearer/login bleed between different hosts
                        scanLog.clearFindings();  // each target's report holds only its own findings
                    }
                    // Per-target report file when a report DIR is given (batch) — else the single -Daiscanner.report.
                    if (reportDir != null && !reportDir.isBlank())
                        System.setProperty("aiscanner.report", reportDir.replaceAll("/+$", "") + "/" + reportFileName(url));
                    // Seed the authenticated session (cookie in SessionStore + Burp's cookie jar so the native crawl is
                    // authenticated too) BEFORE the scan starts, so the login flow is a no-op and the deep surface opens.
                    if (seedCookie != null && !seedCookie.isBlank()) {
                        session.set(seedCookie);
                        session.setAdopted(true);   // operator-provided session → suppress auto-registration
                        session.setLandingUrl(seedLanding != null && !seedLanding.isBlank() ? seedLanding : url);
                        seedCookieJar(seedCookie, url);
                        scanLog.log("pre-seeded authenticated session from launch cookie — login skipped (names: "
                                + seedCookie.replaceAll("=[^;]*", "=…") + ")");
                    }
                    try { menuProvider.startScanAndWait(url); done++; }
                    catch (Throwable t) { scanLog.log("target failed (" + url + "): " + t + " — continuing."); }
                }
                if (batch) scanLog.log("===== BATCH complete: " + done + "/" + targets.length + " target(s) scanned =====");
            }, "aiscanner-autoscan").start();
        }
    }

    /**
     * TRUE-CONCURRENT multi-target scan engine, shared by the CLI parallel autoscan and the chat batch command.
     * Each target gets its OWN {SessionStore, ScanLog (tagged mirror + per-target findings/report), AiScanner,
     * AiContextMenuProvider} so auth/logs/scores don't cross-contaminate; the self-account protector guards every
     * identity; LLM timeouts scale by N.
     *
     * @param targets      each String[] = {url, repoOrNull}. url is the DAST target; repoOrNull is the per-target
     *                     SAST source (git URL / URL / local path) — applied via {@link #setRepoForHost} BEFORE the
     *                     unit is built so AiScanner's SAST picks it up (RepoFetcher downloads git URLs as a ZIP).
     * @param reportDir    optional directory for per-target report files (one per host); null → no report path set.
     * @param exitWhenDone true (CLI): join all threads, then shut Burp down. false (chat): fire-and-forget — start
     *                     the threads and RETURN immediately; NEVER touch aiscanner.exitOnComplete; Burp stays open.
     */
    void launchParallel(java.util.List<String[]> targets, String reportDir, boolean exitWhenDone) {
        if (targets == null || targets.isEmpty()) return;
        // First pass: normalize + apply per-target source repos, and count real targets so PARALLELISM is accurate.
        java.util.List<String[]> valid = new java.util.ArrayList<>();
        for (String[] t : targets) {
            if (t == null || t.length == 0) continue;
            String url = normalizeTarget(t[0]);
            if (url == null) continue;
            String repo = t.length > 1 ? t[1] : null;
            if (repo != null && !repo.isBlank()) {
                String host; try { host = com.ioactive.aiscanner.scan.Net.authority(url); } catch (Exception ex) { host = null; }
                if (host != null && !host.isBlank()) setRepoForHost(host, repo.trim());   // SAST picked up via repoForHost
            }
            valid.add(new String[]{ url, repo });
        }
        if (valid.isEmpty()) return;
        // LLM timeouts scale by the LIVE concurrent-scan count — each scan increments/decrements it in
        // crawlAndScan, so it's correct even when THESE targets are added to scans already running (chat "at will").
        boolean wantExit = exitWhenDone;
        if (wantExit) System.clearProperty("aiscanner.exitOnComplete");   // no per-unit self-shutdown; exit centrally after ALL join
        java.util.List<Thread> pthreads = new java.util.ArrayList<>();
        for (String[] t : valid) {
            final String url = t[0];
            String auth; try { auth = java.net.URI.create(url).getAuthority(); } catch (Exception ex) { auth = null; }
            final String tag = (auth != null && !auth.isBlank()) ? auth : url;
            final String rp = (reportDir != null && !reportDir.isBlank())
                    ? reportDir.replaceAll("/+$", "") + "/" + reportFileName(url) : null;
            final ScanLog plog = new ScanLog(logMirror);   // per-line [host] tag comes from ScanLog.TARGET_TAG
            plog.setUiMirror(scanLog);   // keep the shared UI status bar live (tagged) during the parallel run
            plog.setIssueSink(this::raiseAiIssue);
            final SessionStore psess = new SessionStore();
            final AiScanner psc = new AiScanner(api, this::getEngine, scanConfig, plog, psess, this::isUnloaded, this::repoForHost);
            // Parallel isolation: tell THIS scan about the OTHER concurrent co-targets so it won't pull them in
            // (Burp scope is additive). Excludes only the known co-target authorities — legit siblings unaffected.
            for (String[] other : valid) if (!other[0].equals(url)) psc.addSiblingTarget(other[0]);
            psc.setSelfExitAllowed(false);   // parallel: NO per-unit self-shutdown (env AISCANNER_EXIT_ON_COMPLETE
                                             // survives clearProperty); launchParallel shuts down centrally after join
            if (rp != null) psc.setReportPath(rp);
            if (selfAccountProtector != null) selfAccountProtector.addSession(psess);   // protect THIS target's own identity too
            final AiContextMenuProvider pmp = new AiContextMenuProvider(api, plog, psess, psc, scanScope,
                    this::repoForHost, this::setRepoForHost);
            pthreads.add(new Thread(() -> {
                ScanLog.TARGET_TAG.set("[" + tag + "] ");   // every line this scan's thread-lineage emits is tagged
                try { pmp.startScanAndWait(url); }
                catch (Throwable ex) { plog.log("target failed (" + url + "): " + ex); }
            }, "ais-par-" + tag));
        }
        for (Thread th : pthreads) th.start();
        if (!wantExit) {
            // Chat / fire-and-forget: threads run in the background; return immediately so Burp stays interactive.
            scanLog.log("===== launched " + pthreads.size() + " new scan(s) — total concurrent shown in the status bar =====");
            return;
        }
        for (Thread th : pthreads) { try { th.join(); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; } }
        scanLog.log("===== PARALLEL complete: " + pthreads.size() + " target(s) scanned =====");
        try { api.burpSuite().shutdown(); } catch (Throwable th) { scanLog.log("shutdown unavailable: " + th); }
    }

    /** Add a scheme if the target is a bare host (dev/uat hosts are given without http(s)://). Defaults to https. */
    private static String normalizeTarget(String t) {
        if (t == null || t.isBlank()) return null;
        t = t.trim();
        return t.matches("(?i)^https?://.*") ? t : "https://" + t;
    }

    /** A filesystem-safe per-target report filename derived from the URL's host. */
    private static String reportFileName(String url) {
        // Use the port-aware authority (host[:port]) so two CONCURRENT localhost targets on different ports get
        // DISTINCT report files — the old host-only name collapsed localhost:1337 + localhost:9500 to one
        // "localhost.report.txt" and the second scan's report overwrote the first. Default ports stay elided
        // (prod https target → "example.com.report.txt", unchanged). ':' is not filesystem-safe → '_'.
        String a = com.ioactive.aiscanner.scan.Net.authority(url);
        if (a == null || a.isBlank()) a = "target";
        return a.replaceAll("[^A-Za-z0-9._-]", "_") + ".report.txt";
    }

    /** Resolve the LOCAL source-repo path for a host: per-host mapping first, else the launch-wide repo, else null. */
    public String repoForHost(String host) {
        String h = host == null ? "" : host.toLowerCase().trim();
        String r = hostRepoMap.get(h);
        return (r != null && !r.isBlank()) ? r : launchSourceRepo;
    }

    /** Associate a local repo path with a host (from the context-menu popup); persisted. Blank/null clears it. */
    public void setRepoForHost(String host, String repoPath) {
        if (host == null || host.isBlank()) return;
        String h = host.toLowerCase().trim();
        if (repoPath == null || repoPath.isBlank()) hostRepoMap.remove(h);
        else hostRepoMap.put(h, repoPath.trim());
        persist();
    }

    /** Populate Burp's cookie jar from a raw "n1=v1; n2=v2" Cookie header for {@code url}'s host, so the NATIVE
     *  crawl/audit is authenticated (not just our own withSession requests). Best-effort; unparseable pairs skipped. */
    private void seedCookieJar(String cookie, String url) {
        try {
            String host = java.net.URI.create(url).getHost();
            if (host == null || host.isBlank()) {
                scanLog.log("[warn] cookie-seed: no host in " + url + " — Burp's native crawl will NOT be authenticated.");
                return;
            }
            int seeded = 0, attempted = 0;
            for (String kv : cookie.split(";")) {
                int eq = kv.indexOf('=');
                if (eq <= 0) continue;
                String n = kv.substring(0, eq).trim(), v = kv.substring(eq + 1).trim();
                if (n.isEmpty()) continue;
                attempted++;
                try { api.http().cookieJar().setCookie(n, v, "/", host, java.time.ZonedDateTime.now().plusDays(1)); seeded++; }
                catch (Throwable e) { scanLog.debug("cookie-seed: setCookie failed for " + n + ": " + e); }
            }
            // A silent failure here would leave OUR probes authenticated (SessionStore) but Burp's native crawl NOT —
            // a partially-tested surface that masquerades as full auth. Surface it loudly instead of hiding it.
            if (seeded == 0 && attempted > 0)
                scanLog.log("[warn] cookie-seed: 0/" + attempted + " cookies reached Burp's jar — the native "
                        + "crawl/audit will run UNAUTHENTICATED (our own probes are still authenticated via SessionStore).");
        } catch (Throwable e) {
            scanLog.log("[warn] cookie-seed: jar seeding failed (" + e + ") — Burp's native crawl may be unauthenticated.");
        }
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
            // keep evidence that carries a request OR a response — a finding may attach several (e.g. BFLA's
            // unauth / our-session / control probes) so Burp shows the full proof across multiple request tabs.
            // We keep a request with a null response too: for an out-of-band finding (OAST SSRF) the request
            // that triggered the interaction IS the proof, so it must render even though no response came back.
            java.util.List<HttpRequestResponse> ev = new java.util.ArrayList<>();
            if (evidence != null) for (HttpRequestResponse e : evidence) if (e != null && (e.request() != null || e.response() != null)) ev.add(e);
            String name = vulnClass == null ? "AI: finding" : (vulnClass.startsWith("AI:") ? vulnClass : "AI: " + vulnClass);
            String cls = vulnClass == null ? "finding" : vulnClass.replaceFirst("(?i)^AI:\\s*", "");
            // Full Burp-issue shape so these export cleanly alongside Burp's own issues: instance-specific
            // detail (what we did + the evidence), plus per-class background + remediation from IssueLibrary.
            com.ioactive.aiscanner.scan.IssueLibrary.Info info = com.ioactive.aiscanner.scan.IssueLibrary.describe(cls);
            // Neutral preamble: the specific METHOD (active proof, offline crack, static decode, differential…) is
            // stated in the per-finding Evidence detail below, so we don't over-claim an active "proof payload"
            // for passive/analysis findings (e.g. a JWT claim decode). The attached request/response is the proof.
            // If the probe already supplied HTML (contains a tag), embed it directly; otherwise escape plain text.
            // This lets probes use <p>/<br>/<b> for structured evidence while plain-text probes stay safe.
            String detailEncoded = (detail == null || detail.isBlank()) ? ""
                    : detail.contains("<") ? detail : escapeHtml(detail).replace("\n", "<br>");
            String detailHtml = "<p>The AI Scanner reported <b>" + escapeHtml(cls) + "</b> at this location.</p>"
                    + (detailEncoded.isBlank() ? "" : "<p><b>Evidence:</b> " + detailEncoded + "</p>")
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
            scanLog.debug("dashboard issue raised: " + name + " @ " + url);
        } catch (Throwable t) {
            scanLog.log("could not raise dashboard issue for " + vulnClass + " @ " + url + ": " + t);
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
        // -Daiscanner.temperature / AISCANNER_TEMPERATURE: sampling temperature for the LLM. Set to 0 for a
        // DETERMINISTIC benchmark run — at temp>0 the discovery LLM returns different endpoint candidates each
        // run, so the reachable surface (and thus the deterministic-oracle finding count) varies run-to-run.
        // (Log verbosity is handled separately by LogLevel in initialize(), not here.)
        String temp = launchArg("aiscanner.temperature", "AISCANNER_TEMPERATURE");
        // -Daiscanner.noAi / AISCANNER_NO_AI is a hard deterministic-only switch. Reflect it in the provider enum
        // so the Settings radio and the launch-override log SHOW "No AI" (otherwise the radio still reads the
        // launcher's default LOCAL_LLM even though getEngine() returns null — honest at runtime, misleading in UI).
        boolean forceNoAi = noAi();
        if (!forceNoAi && provider == null && base == null && model == null && key == null && think == null && maxTok == null && temp == null) return;
        EngineConfig c = engineConfig;
        int mt = c.maxTokens;
        if (maxTok != null) try { mt = Integer.parseInt(maxTok.trim()); } catch (NumberFormatException ignore) { }
        double tp = c.temperature;
        if (temp != null) try { tp = Double.parseDouble(temp.trim()); } catch (NumberFormatException ignore) { }
        // Use the 9-arg constructor so a launch override does NOT collapse the provider to LOCAL_LLM (the
        // 8-arg back-compat ctor hardcodes it). -Daiscanner.provider=BURP_AI selects Burp's built-in AI from
        // the CLI. When no provider is given but a baseUrl override IS (the local-LLM launcher / Docker flow),
        // INFER LOCAL_LLM — a baseUrl is meaningless for BURP_AI, and otherwise the fresh-install BURP_AI
        // default silently ignores the endpoint and degrades. Else keep the current/saved provider.
        EngineConfig.Provider prov = forceNoAi ? EngineConfig.Provider.NO_AI
                : provider != null ? parseProvider(provider.trim())
                : (base != null && !base.isBlank() ? EngineConfig.Provider.LOCAL_LLM : c.provider);
        engineConfig = new EngineConfig(
                prov,
                base != null ? base : c.baseUrl,
                model != null ? model : c.model,
                key != null ? key : c.apiKey,
                tp, mt,
                think != null ? Boolean.parseBoolean(think) : c.disableThinking,
                c.timeoutSeconds);
        this.engine = engineFor(engineConfig);
        scanLog.log("launch override → provider=" + engineConfig.provider
                + (engineConfig.provider == EngineConfig.Provider.LOCAL_LLM ? ", baseUrl=" + engineConfig.baseUrl : "")
                + (model != null ? ", model=" + model : "")
                + (key != null ? ", apiKey=***" : "")
                + ", temperature=" + engineConfig.temperature);
    }

    // ---- accessors ----
    public MontoyaApi api() { return api; }
    // NO-AI baseline: with -Daiscanner.noAi / AISCANNER_NO_AI the LLM is fully disabled — getEngine() returns
    // null so EVERY LLM path (discovery synthesis, agentic unlock, fuzz payloads, flow-engine, SAST, triage of
    // our own findings) is skipped by its existing `engine != null` guard, while the deterministic layer (auth,
    // identity sweep, probes, exercise-writes, Burp's native audit) still runs. This measures the extension's
    // NON-LLM capability, headless-safe (aiPreflight() returns true on a null engine, no endpoint required).
    private static boolean noAi() {
        String v = System.getProperty("aiscanner.noAi");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_NO_AI");
        return v != null && (v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes"));
    }
    public AiEngine getEngine() {
        // null → deterministic-only: the -Daiscanner.noAi/AISCANNER_NO_AI flag OR the NO_AI provider (Settings).
        return (noAi() || engineConfig.provider == EngineConfig.Provider.NO_AI) ? null : engine;
    }
    public EngineConfig engineConfig() { return engineConfig; }
    public ScanConfig scanConfig() { return scanConfig; }
    public ScanLog scanLog() { return scanLog; }

    /** Rebuild the engine from a new config and persist everything. Called by the settings tab. */
    public void applyEngineConfig(EngineConfig cfg) {
        this.engineConfig = cfg;
        this.engine = engineFor(cfg);
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
        // Fall back to the App-Store default (Burp AI) on an unknown/corrupt value. Legacy back-compat — a saved
        // config predating the provider selector — is preserved by the caller passing "LOCAL_LLM" explicitly (loadSettings).
        try { return EngineConfig.Provider.valueOf(s); } catch (Exception e) { return EngineConfig.Provider.BURP_AI; }
    }

    public void persist() {
        JSONObject o = new JSONObject();
        EngineConfig c = engineConfig;
        o.put("provider", c.provider.name())
         .put("baseUrl", c.baseUrl).put("model", c.model).put("apiKey", c.apiKey)
         .put("temperature", c.temperature).put("maxTokens", c.maxTokens)
         .put("disableThinking", c.disableThinking).put("timeoutSeconds", c.timeoutSeconds)
         .put("logLevel", LogLevel.current().name());
        o.put("rounds", scanConfig.rounds).put("payloadsPerRound", scanConfig.payloadsPerRound)
         .put("delayMs", scanConfig.delayMs).put("requestTimeoutMs", scanConfig.requestTimeoutMs)
         .put("logToFile", scanConfig.logToFile).put("logFilePath", scanConfig.logFilePath)
         .put("scanMode", scanConfig.scanMode.name());
        if (!hostRepoMap.isEmpty()) o.put("hostRepoMap", new JSONObject(hostRepoMap));
        api.persistence().extensionData().setString(PREF_KEY, o.toString());
    }

    private void loadSettings() {
        // verbose defaults OFF: the log shows phases + real vulnerabilities; INFO findings and
        // diagnostic chatter (scanning/LLM echo/mining) appear only when the user enables verbose.
        // Fresh install defaults to Burp's built-in AI (App-Store preferred); the local base URL is pre-filled
        // so switching to the Local-LLM provider is one radio click away.
        EngineConfig def = new EngineConfig(EngineConfig.Provider.BURP_AI,
                "http://127.0.0.1:8000/v1/", "", "", 0.3, 2048, true, 120);
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
                    o.optInt("timeoutSeconds", def.timeoutSeconds));
            String savedLvl = o.optString("logLevel", "");
            if (!savedLvl.isBlank()) logLevelSetting = LogLevel.parse(savedLvl);
            else if (o.optBoolean("verbose", false)) logLevelSetting = LogLevel.TRACE;   // migrate old verbose setting
            scanConfig.rounds = o.optInt("rounds", scanConfig.rounds);
            scanConfig.payloadsPerRound = o.optInt("payloadsPerRound", scanConfig.payloadsPerRound);
            scanConfig.delayMs = o.optInt("delayMs", scanConfig.delayMs);
            scanConfig.requestTimeoutMs = o.optInt("requestTimeoutMs", scanConfig.requestTimeoutMs);
            scanConfig.logToFile = o.optBoolean("logToFile", scanConfig.logToFile);
            scanConfig.logFilePath = o.optString("logFilePath", scanConfig.logFilePath);
            try { scanConfig.scanMode = com.ioactive.aiscanner.scan.ScanConfig.ScanMode.valueOf(o.optString("scanMode", "DAST_SAST")); } catch (Exception ignore) {}
            JSONObject rm = o.optJSONObject("hostRepoMap");
            if (rm != null) for (String k : rm.keySet()) {
                String v = rm.optString(k, "");
                if (!v.isBlank()) hostRepoMap.put(k.toLowerCase(), v);
            }
        } catch (Exception e) {
            this.engineConfig = def;
        }
        this.engine = engineFor(engineConfig);
    }
}
