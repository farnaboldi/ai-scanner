package com.ioactive.aiscanner.ui;

import com.ioactive.aiscanner.AiScannerExtension;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.engine.EngineConfig;
import com.ioactive.aiscanner.engine.LogLevel;
import com.ioactive.aiscanner.scan.ScanConfig;

import javax.swing.*;
import java.awt.*;
import java.awt.event.HierarchyEvent;

/** Configuration tab: AI provider (Burp built-in vs local LLM) + adaptive-loop tunables + a connection test. */
public final class SettingsTab {

    private final AiScannerExtension ext;
    private final JPanel panel = new JPanel(new GridBagLayout());

    // Scan mode selector
    private final JRadioButton dastRadio     = new JRadioButton("DAST — black-box crawl + all extension probes (no source)");
    private final JRadioButton sastRadio     = new JRadioButton("SAST — source route discovery → Burp active audit only (no extension probes)");
    private final JRadioButton dastSastRadio = new JRadioButton("DAST+SAST — full pipeline: SAST hints + crawl + all extension probes (Recommended)");

    // AI provider selector
    private final JRadioButton burpAiRadio = new JRadioButton("Burp AI (built-in)");
    private final JRadioButton localRadio  = new JRadioButton("Local / self-hosted LLM (OpenAI-compatible)");
    private final JRadioButton noAiRadio   = new JRadioButton("No AI — deterministic only (auth + probes + native audit; no LLM)");
    private final JLabel burpAiStatus = new JLabel();

    // Local-LLM connection fields (enabled only when "Local LLM" is selected)
    private final JTextField urlField = new JTextField(34);
    private final JTextField modelField = new JTextField(34);
    private final JPasswordField keyField = new JPasswordField(34);
    private final JToggleButton eyeBtn = new JToggleButton("👁");  // 👁
    private final JTextField tempField = new JTextField(6);
    private final JTextField maxTokField = new JTextField(6);
    private final JTextField timeoutField = new JTextField(6);
    private final JCheckBox thinkBox = new JCheckBox("Disable model thinking (Qwen/vLLM: enable_thinking=false)");
    private final JLabel urlLabel = new JLabel("Base URL (…/v1):");
    private final JLabel modelLabel = new JLabel("Model:");
    private final JLabel keyLabel = new JLabel("API key (blank = none):");
    private final JLabel maxTokLabel = new JLabel("Max tokens:");
    private final JLabel timeoutLabel = new JLabel("Timeout (s):");

    // Single verbosity knob: INFO (phases + vulns) / DEBUG (+ diagnostics + per-LLM-call metadata) / TRACE (+ full
    // request/response bodies). Replaces the old verbose + debug checkboxes.
    private final JComboBox<String> logLevelCombo = new JComboBox<>(new String[]{"INFO", "DEBUG", "TRACE"});
    private final JCheckBox wafEvasionBox = new JCheckBox("WAF evasion mode (obfuscate probe payloads to bypass a WAF)");
    private final JTextField roundsField = new JTextField(6);
    private final JTextField payloadsField = new JTextField(6);
    private final JTextField delayField = new JTextField(6);
    private final JTextField reqTimeoutField = new JTextField(6);   // probe→target per-request response timeout (ms)
    // Read-only parallel probe slice: N blind-SQLi units at once (adaptive throttle backs off on 429). 1 = sequential.
    private final JTextField concurrencyField = new JTextField(6);
    // Crawl & Discovery reach + Timeouts — coverage/latency knobs (backed by Tuning / LLM-transport system props).
    private final JTextField crawlDepthField     = new JTextField(6);
    private final JTextField crawlPagesField      = new JTextField(6);
    private final JTextField discRoundsField      = new JTextField(6);
    private final JTextField maxSourcesField      = new JTextField(6);
    private final JTextField maxCandidatesField   = new JTextField(6);
    private final JTextField crawlWaitField       = new JTextField(6);
    private final JTextField llmRespTimeoutField  = new JTextField(6);
    private final JTextField llmHardDeadlineField = new JTextField(6);
    // Which SAST analyzer runs when a scan has a source repo associated (mirrors -Daiscanner.sastMode). A named
    // mode, not a boolean — so it's a dropdown, and leaves room for future modes beyond coarse/agentic.
    private final JComboBox<String> sastModeCombo = new JComboBox<>(new String[]{"coarse", "agentic", "iterative"});
    // "Log to file": mirror the scan log + chat to a file, live (the UI equivalent of -Daiscanner.logFile).
    private final JCheckBox logToFileBox = new JCheckBox();
    private final JTextField logFileField = new JTextField(34);   // match urlField/modelField width so the path is legible + aligned
    private final JTextArea status = new JTextArea(3, 40);

    public SettingsTab(AiScannerExtension ext) {
        this.ext = ext;
        build();
        // Burp realizes the tab lazily; refresh the Burp-AI status + focus whenever the panel becomes visible.
        panel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && panel.isShowing()) {
                updateBurpAiStatus();
                focusFirstField();
                // Reflect CLI scan-mode override in the UI when the tab becomes visible.
                syncScanModeFromConfig();
            }
        });
    }

    /** Register the ScanLog phase-change listener so module checkboxes reflect whether their phase can still run.
     *  Called once from AiScannerExtension after both objects exist. */
    public void hookPhaseChanges(ScanLog scanLog) {
        scanLog.setPhaseChangeListener(this::refreshModuleStates);
    }

    /** Reflect the current scan mode + phase in the modules panel. Two jobs: (1) show/hide the whole attack
     *  block so SAST mode lists only the lifecycle phases it runs; (2) for a DAST mode, disable the probe boxes
     *  whose phase already ran this scan. Runs on the EDT (from ScanLog's listener, onSave, or syncScanMode). */
    private void refreshModuleStates() {
        boolean sast = ext.scanConfig().scanMode == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.SAST;
        // The attack block is HIDDEN in SAST mode → the panel shows only the ~10 lifecycle phases, matching the
        // status-bar /lifecycleCount denominator. Toggle + relayout so rows actually appear/disappear.
        for (java.awt.Component w : attackSectionWidgets) w.setVisible(!sast);
        if (modulesContainer != null) { modulesContainer.revalidate(); modulesContainer.repaint(); }
        if (sast) return;   // attack boxes hidden — nothing more to do
        boolean scanActive = ext.scanLog().isScanActive();
        for (java.util.Map.Entry<String, JCheckBox> e : moduleBoxes.entrySet()) {
            String key = e.getKey();
            JCheckBox cb = e.getValue();
            boolean passed = scanActive && ext.scanLog().attackPhasePassed(key);
            cb.setEnabled(!passed);
            cb.setToolTipText(passed
                    ? "This phase already ran in the current scan — it will apply next scan"
                    : (scanActive ? "Click to enqueue into the running scan" : null));
        }
    }

    private JComponent modulesContainer;   // right-half modules panel — toggled by scan mode

    public JComponent component() {
        // modulesPanel() builds every attack checkbox already reflecting the current scan mode (disabled in
        // SAST), so the returned panel is correct at construction — no post-hoc setEnabled that could race.
        modulesContainer = modulesPanel();
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(panel), modulesContainer);
        split.setResizeWeight(0.5);
        return split;
    }

    /** Sync UI from live runtime state — picks up CLI overrides for scan mode and log file. */
    public void syncScanModeFromConfig() {
        com.ioactive.aiscanner.scan.ScanConfig.ScanMode sm = ext.scanConfig().scanMode;
        String activeLog = ext.scanLog().logFilePath();
        javax.swing.SwingUtilities.invokeLater(() -> {
            // Scan mode radios
            dastRadio.setSelected(sm == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST);
            sastRadio.setSelected(sm == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.SAST);
            dastSastRadio.setSelected(sm == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST_SAST);
            refreshModuleStates();   // show/hide the attack block to match the (possibly CLI-overridden) mode
            // Log-to-file: reflect an active CLI sink (-Daiscanner.logFile) in the checkbox + path field
            if (activeLog != null && !activeLog.isBlank()) {
                logToFileBox.setSelected(true);
                logFileField.setText(activeLog);
            }
        });
    }

    // ---- Modules panel (right half): which scan modules run, reflecting -Daiscanner.only ----
    // The phase/module list lives in ONE place — com.ioactive.aiscanner.scan.ScanPhases — which this panel AND the
    // status-bar step counter (ScanLog) both read, so there is no second list to drift out of sync (that drift is
    // exactly what left "Source analysis (SAST)" showing as a step with no Modules entry). These counts derive from it.
    /** Attack modules a full scan runs (the filterable probe battery). */
    public static int attackModuleCount()  { return com.ioactive.aiscanner.scan.ScanPhases.attackCount(); }
    /** Always-run lifecycle phases (pre-attack + post-attack). */
    public static int lifecyclePhaseCount() { return com.ioactive.aiscanner.scan.ScanPhases.lifecycleCount(); }
    /** Total phases a full run performs = pre-attack + attack + post-attack. */
    public static int fullRunPhaseCount()  { return com.ioactive.aiscanner.scan.ScanPhases.totalPhases(); }

    private final java.util.Map<String, JCheckBox> moduleBoxes = new java.util.LinkedHashMap<>();
    // The whole "Attack modules" block (its section header + every probe checkbox + its spacer): HIDDEN in SAST
    // mode so the panel lists only the ~10 lifecycle phases the SAST pipeline actually runs — matching the
    // status-bar /lifecycleCount denominator. Shown again the instant the mode flips back to a DAST variant.
    private final java.util.List<java.awt.Component> attackSectionWidgets = new java.util.ArrayList<>();

    private JComponent modulesPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        // JLabel title = new JLabel("Modules");
        // title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize() + 2f));
        // p.add(title);
        // JLabel hint = new JLabel("Uncheck to skip on the scan");
        // hint.setForeground(Color.GRAY); p.add(hint); p.add(Box.createVerticalStrut(6));

        // Laid out top-to-bottom in the ORDER they execute — ALL derived from the ONE registry (ScanPhases), so
        // this panel, the progress total, and the status-bar step names can never drift apart.
        java.util.Set<String> only = parseOnlyFilter();   // null → all run
        attackSectionWidgets.clear();
        p.add(sectionLabel("Pre-attack modules"));
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (ph.section == com.ioactive.aiscanner.scan.ScanPhases.Section.BEFORE) p.add(prereqBox(ph.label));
        }
        // The attack block — header + spacer + every probe box — is tracked so SAST mode can hide it wholesale,
        // leaving just the lifecycle phases visible (the modules SAST actually runs).
        java.awt.Component atkStrut = Box.createVerticalStrut(8);
        JLabel atkLabel = sectionLabel("Attack modules");
        p.add(atkStrut);   attackSectionWidgets.add(atkStrut);
        p.add(atkLabel);   attackSectionWidgets.add(atkLabel);
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (!ph.isAttack()) continue;
            boolean checked = only == null || only.contains(ph.key);
            JCheckBox cb = new JCheckBox(ph.label, checked);
            moduleBoxes.put(ph.key, cb);
            attackSectionWidgets.add(cb);
            final String phKey = ph.key;
            cb.addActionListener(e -> {
                applyModuleSelection();
                // During an active scan: clicking a checkbox is an enqueue request — same as "test <module>"
                // in the chat. The checkbox is already disabled when its phase passed, so this only fires
                // for phases still in the future. Log the outcome so the analyst sees it.
                if (cb.isSelected() && ext.scanLog().isScanActive()) {
                    boolean passed = ext.scanLog().attackPhasePassed(phKey);
                    if (passed) {
                        ext.scanLog().log("[ai] '" + phKey + "' phase already ran this scan — will apply next scan");
                    } else {
                        appendOnlyFilter(phKey);
                        ext.scanLog().log("[ai] '" + phKey + "' queued into the running scan — runs when the battery reaches that phase");
                    }
                }
            });
            p.add(cb);
        }
        p.add(Box.createVerticalStrut(8));
        p.add(sectionLabel("Post-attack modules"));
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (ph.section == com.ioactive.aiscanner.scan.ScanPhases.Section.AFTER) p.add(prereqBox(ph.label));
        }
        // Born correct: hide the attack block immediately if we're loading straight into SAST mode (CLI override
        // or persisted setting), so the panel shows the 10 lifecycle phases from the very first paint.
        boolean sast = ext.scanConfig().scanMode == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.SAST;
        for (java.awt.Component w : attackSectionWidgets) w.setVisible(!sast);
        JScrollPane sp = new JScrollPane(p);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    private JLabel sectionLabel(String s) {
        JLabel l = new JLabel(s);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        return l;
    }

    /** A mandatory lifecycle phase: bold + disabled (checked + greyed already shows it can't be toggled off). */
    private JCheckBox prereqBox(String label) {
        JCheckBox cb = new JCheckBox(label, true);
        cb.setEnabled(false);
        cb.setFont(cb.getFont().deriveFont(Font.BOLD));
        return cb;
    }

    /** Current -Daiscanner.only / AISCANNER_ONLY as a set of terms, or null when unset (all modules run). */
    private static java.util.Set<String> parseOnlyFilter() {
        String v = System.getProperty("aiscanner.only");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_ONLY");
        if (v == null || v.isBlank()) return null;
        java.util.Set<String> s = new java.util.HashSet<>();
        for (String t : v.toLowerCase().split(",")) if (!t.trim().isEmpty()) s.add(t.trim());
        return s;
    }

    /** Recompute -Daiscanner.only from the checkboxes: all checked → no filter; otherwise only the checked keys. */
    private void applyModuleSelection() {
        java.util.List<String> checked = new java.util.ArrayList<>();
        for (java.util.Map.Entry<String, JCheckBox> e : moduleBoxes.entrySet())
            if (e.getValue().isSelected()) checked.add(e.getKey());
        if (checked.size() == moduleBoxes.size()) {
            System.clearProperty("aiscanner.only");   // everything on → no filter
        } else {
            System.setProperty("aiscanner.only", String.join(",", checked));
        }
    }

    /** Enqueue an attack module (Agent-tab "test &lt;module&gt;") into a scan already in progress. The only= write is
     *  SYNCHRONOUS (thread-safe System property, read live per phase by the running scan) so it takes effect at once
     *  and the caller can sample "did I catch it in time?" immediately after — NO deferred-EDT TOCTOU. Only the visual
     *  tick is deferred to the EDT. Returns true if the module (checkbox) exists. */
    public boolean selectModuleBox(String key) {
        if (key == null) return false;
        JCheckBox cb = moduleBoxes.get(key.toLowerCase());
        if (cb == null) return false;
        appendOnlyFilter(key.toLowerCase());   // authoritative synchronous write; the running scan reads only= live
        javax.swing.SwingUtilities.invokeLater(() -> { if (!cb.isSelected()) cb.setSelected(true); });  // visual only
        return true;
    }

    /** Append one attack-module key to {@code -Daiscanner.only} IN PLACE. No-op when no filter is active (a full run
     *  already runs everything — ticking one box must not RESTRICT it to just that one) or the key is already present.
     *  Keeps the ticked checkbox consistent with the property so a later {@link #applyModuleSelection()} agrees. */
    private static void appendOnlyFilter(String key) {
        String cur = System.getProperty("aiscanner.only");
        if (cur == null || cur.isBlank()) return;
        for (String k : cur.split(",")) if (k.trim().equalsIgnoreCase(key)) return;
        System.setProperty("aiscanner.only", cur + "," + key);
    }

    /** Focus the most relevant field for the current provider (called when the Settings view is opened). */
    public void focusBaseUrl() { focusFirstField(); }
    private void focusFirstField() {
        SwingUtilities.invokeLater(() -> {
            if (localRadio.isSelected()) { urlField.requestFocusInWindow(); urlField.selectAll(); }
            else burpAiRadio.requestFocusInWindow();
        });
    }

    private void build() {
        EngineConfig c = ext.engineConfig();
        ScanConfig s = ext.scanConfig();
        urlField.setText(c.baseUrl);
        modelField.setText(c.model);
        keyField.setText(c.apiKey);
        tempField.setText(String.valueOf(c.temperature));
        maxTokField.setText(String.valueOf(c.maxTokens));
        timeoutField.setText(String.valueOf(c.timeoutSeconds));
        thinkBox.setSelected(c.disableThinking);
        logLevelCombo.setSelectedItem(LogLevel.current().name());
        roundsField.setText(String.valueOf(s.rounds));
        payloadsField.setText(String.valueOf(s.payloadsPerRound));
        delayField.setText(String.valueOf(s.delayMs));
        reqTimeoutField.setText(String.valueOf(s.requestTimeoutMs));
        concurrencyField.setText(String.valueOf(Integer.getInteger("aiscanner.concurrency", 3)));
        crawlDepthField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.crawlDepth()));
        crawlPagesField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.crawlPages()));
        discRoundsField.setText(String.valueOf(com.ioactive.aiscanner.scan.EndpointDiscovery.discoveryRoundsPublic()));
        maxSourcesField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.maxSources()));
        maxCandidatesField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.maxCandidates()));
        crawlWaitField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.crawlWaitSec()));
        llmRespTimeoutField.setText(String.valueOf(Long.getLong("aiscanner.llmResponseTimeoutMs", 120000L)));
        llmHardDeadlineField.setText(String.valueOf(Long.getLong("aiscanner.llmHardDeadlineMs", 180000L)));
        // Log-to-file: reflect an already-active sink (e.g. -Daiscanner.logFile) if any, else the persisted setting.
        String activeLog = ext.scanLog().logFilePath();
        if (activeLog != null && !activeLog.isBlank()) {
            logToFileBox.setSelected(true); logFileField.setText(activeLog);
            s.logToFile = true; s.logFilePath = activeLog;   // reflect the active CLI sink so applyLogFile() keeps it
        } else {
            logToFileBox.setSelected(s.logToFile);
            logFileField.setText((s.logFilePath == null || s.logFilePath.isBlank()) ? "/tmp/aiscanner.log" : s.logFilePath);
        }

        // Scan mode radios
        ButtonGroup scanModeGroup = new ButtonGroup();
        scanModeGroup.add(dastRadio); scanModeGroup.add(sastRadio); scanModeGroup.add(dastSastRadio);
        com.ioactive.aiscanner.scan.ScanConfig.ScanMode sm = s.scanMode;
        dastRadio.setSelected(sm == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST);
        sastRadio.setSelected(sm == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.SAST);
        dastSastRadio.setSelected(sm == com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST_SAST || (sm != com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST && sm != com.ioactive.aiscanner.scan.ScanConfig.ScanMode.SAST));
        dastRadio.addActionListener(e -> onSave());
        sastRadio.addActionListener(e -> onSave());
        dastSastRadio.addActionListener(e -> onSave());

        ButtonGroup providerGroup = new ButtonGroup();
        providerGroup.add(burpAiRadio);
        providerGroup.add(localRadio);
        providerGroup.add(noAiRadio);
        boolean local = c.provider == EngineConfig.Provider.LOCAL_LLM;
        boolean noai  = c.provider == EngineConfig.Provider.NO_AI;
        burpAiRadio.setSelected(!local && !noai);
        localRadio.setSelected(local);
        noAiRadio.setSelected(noai);
        burpAiRadio.addActionListener(e -> onProviderChanged());
        localRadio.addActionListener(e -> onProviderChanged());
        noAiRadio.addActionListener(e -> onProviderChanged());
        burpAiStatus.setForeground(Color.GRAY);
        burpAiStatus.setFont(burpAiStatus.getFont().deriveFont(Font.ITALIC));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.anchor = GridBagConstraints.WEST;
        int y = 0;

        // Scan mode — top of the tab, most important choice.
        header(g, y++, "Scan mode");
        span(g, y++, dastSastRadio);
        span(g, y++, dastRadio);
        span(g, y++, sastRadio);

        // Logging FIRST (top of the tab). Apply the level LIVE on change (no Save needed) — LogLevel.current is a
        // volatile read by every log call, so a running scan switches verbosity immediately. Save still persists it.
        header(g, y++, "Logging");
        logLevelCombo.addActionListener(e ->
                LogLevel.set(LogLevel.parse(String.valueOf(logLevelCombo.getSelectedItem()))));
        row(g, y++, new JLabel("Log level:"), logLevelCombo);   // INFO / DEBUG / TRACE — applied instantly + on Save
        // Log to file: mirror the scan log + chat to a file, live (no restart) — same effect as -Daiscanner.logFile.
        logToFileBox.setToolTipText("Mirror the scan log + chat to the file on the right, live (no restart).");
        logFileField.setToolTipText("File to write the log + chat to (e.g. /tmp/aiscanner.log). Applied when 'Log to file' is on.");
        // Field FIRST and flush-left (hgap=0) so its left edge lines up exactly with urlField/modelField in the
        // column; the (label-less) enable checkbox sits to its right. Wider field → the full path stays readable.
        JPanel logFileRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        logFileRow.add(logFileField);
        logFileRow.add(Box.createHorizontalStrut(6));
        logFileRow.add(logToFileBox);
        row(g, y++, new JLabel("Log to file:"), logFileRow);

        header(g, y++, "AI provider");
        span(g, y++, noAiRadio);       // No AI first — deterministic-only baseline
        span(g, y++, burpAiRadio);
        span(g, y++, burpAiStatus);
        span(g, y++, localRadio);

        header(g, y++, "Local LLM (OpenAI-compatible: vLLM / llama.cpp / Ollama / LM Studio)");
        row(g, y++, urlLabel, urlField);
        row(g, y++, modelLabel, modelField);
        // API key field with eye-toggle button — panel keeps full column width via BorderLayout.
        eyeBtn.setMargin(new Insets(0, 4, 0, 4));
        eyeBtn.setToolTipText("Show / hide API key");
        char defaultEcho = keyField.getEchoChar();
        eyeBtn.addActionListener(e -> keyField.setEchoChar(eyeBtn.isSelected() ? (char) 0 : defaultEcho));
        JPanel keyRow = new JPanel(new BorderLayout(2, 0));
        keyRow.setOpaque(false);
        keyRow.add(keyField, BorderLayout.CENTER);
        keyRow.add(eyeBtn,   BorderLayout.EAST);
        row(g, y++, keyLabel, keyRow);
        row(g, y++, new JLabel("Temperature:"), tempField);   // temperature applies to both providers
        row(g, y++, maxTokLabel, maxTokField);
        row(g, y++, timeoutLabel, timeoutField);
        g.gridx = 1; g.gridy = y++; panel.add(thinkBox, g);

        header(g, y++, "Adaptive attack loop");
        row(g, y++, new JLabel("Refine rounds:"), roundsField);
        row(g, y++, new JLabel("Payloads per round:"), payloadsField);
        row(g, y++, new JLabel("Delay between requests (ms):"), delayField);
        row(g, y++, new JLabel("Probe request timeout (ms):"), reqTimeoutField);
        row(g, y++, new JLabel("Parallel workers (read-only probes, 1=sequential):"), concurrencyField);
        // WAF-evasion toggle: probes ALSO send obfuscated variants (JSON "$op"→"$op", SQL inline comments) so a
        // WAF that blocks the naive payload lets the equivalent one through. Sets a system property the probes
        // read (Evasion.enabled()), applied immediately on toggle.
        wafEvasionBox.setSelected(Boolean.getBoolean("aiscanner.wafEvasion"));
        wafEvasionBox.addActionListener(e ->
                System.setProperty("aiscanner.wafEvasion", String.valueOf(wafEvasionBox.isSelected())));
        g.gridx = 1; g.gridy = y++; panel.add(wafEvasionBox, g);

        // Source-assisted testing (SAST): only takes effect when a scan has a source repo associated (the
        // context-menu popup or -Daiscanner.sourceRepo). Selects the analyzer — coarse (single-shot: walk the
        // repo → one LLM call → directives) vs agentic (2-step: map entry→dispatch, follow the child-process
        // boundary to the real sink; slower, more precise, falls back to coarse). Applied on change + on Save.
        header(g, y++, "Source-assisted testing (SAST)");
        sastModeCombo.setSelectedItem(System.getProperty("aiscanner.sastMode", "coarse"));
        sastModeCombo.setToolTipText("Only used when a source repo is associated with the scan. "
                + "coarse: single-shot repo scan → directives. agentic: 2-step, follows child-process "
                + "boundary to pin the real sink (slower, more precise). iterative: 3-round exhaustive "
                + "route discovery (enumerate → enrich → critique) — maximises recall, not just sinks.");
        sastModeCombo.addActionListener(e ->
                System.setProperty("aiscanner.sastMode", String.valueOf(sastModeCombo.getSelectedItem())));
        row(g, y++, new JLabel("Source analysis mode:"), sastModeCombo);

        // Crawl & Discovery reach — how deep/wide the scanner explores (esp. the authenticated surface). Too-low
        // values under-cover multi-page apps (vuln pages behind category hubs). All read at scan time via Tuning.
        header(g, y++, "Crawl & Discovery reach");
        crawlDepthField.setToolTipText("Max link-clicks deep the self-crawl follows from the landing page (default 3).");
        crawlPagesField.setToolTipText("Max pages the self-crawl fetches — raise it if labs sit behind many category pages (default 60).");
        discRoundsField.setToolTipText("LLM discovery rounds unioned per host (default 3).");
        row(g, y++, new JLabel("Crawl depth (link-clicks):"), crawlDepthField);
        row(g, y++, new JLabel("Crawl breadth (max pages):"), crawlPagesField);
        row(g, y++, new JLabel("Discovery rounds (LLM):"), discRoundsField);
        row(g, y++, new JLabel("Max sources mined:"), maxSourcesField);
        row(g, y++, new JLabel("Max candidate endpoints:"), maxCandidatesField);

        // Timeouts — the deadlines that bound exploration latency. crawl-wait is the native-crawl settle cap; the
        // two LLM ones bound each model call (response-timeout is Montoya's; hard-deadline abandons a stalled call).
        header(g, y++, "Timeouts");
        crawlWaitField.setToolTipText("Max seconds to wait for Burp's native crawl to stabilise (default 240).");
        llmRespTimeoutField.setToolTipText("Per-LLM-call response timeout in ms (default 120000).");
        llmHardDeadlineField.setToolTipText("Hard client-side deadline per LLM call in ms — abandons a stalled call (default 180000).");
        row(g, y++, new JLabel("Crawl-wait (s):"), crawlWaitField);
        row(g, y++, new JLabel("LLM response timeout (ms):"), llmRespTimeoutField);
        row(g, y++, new JLabel("LLM hard-deadline (ms):"), llmHardDeadlineField);

        // Auto-save: settings persist as soon as you change them — no Save button. Text fields commit on Enter or
        // when focus leaves them (so a partial half-typed value isn't saved mid-keystroke); toggles/combos/radios
        // commit immediately. onSave() persists to Burp's extension prefs (survives restart) + re-applies the engine.
        wireAutoSave();
        applyLogFile();   // restore a persisted "Log to file" setting on startup (no-op if off / already open)
        // Initial modules-panel visibility is applied inside modulesPanel() (called later from component()),
        // which reads the same scanMode — so the attack block starts hidden when loading into SAST mode.

        JButton test = new JButton("Test connection");
        test.addActionListener(e -> onTest());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(test);
        g.gridx = 1; g.gridy = y++; panel.add(buttons, g);

        status.setEditable(false);
        status.setLineWrap(true);
        status.setWrapStyleWord(true);
        status.setOpaque(false);
        status.setBorder(null);
        g.gridx = 1; g.gridy = y++; panel.add(status, g);

        setLocalEnabled(local);
        updateBurpAiStatus();
    }

    /** Enable/disable the whole Local-LLM connection group based on the selected provider. */
    private void onProviderChanged() {
        setLocalEnabled(localRadio.isSelected());
        updateBurpAiStatus();
    }

    private void setLocalEnabled(boolean en) {
        for (JComponent cpt : new JComponent[]{urlField, modelField, keyField, eyeBtn, tempField, maxTokField, timeoutField,
                thinkBox, urlLabel, modelLabel, keyLabel, maxTokLabel, timeoutLabel}) {
            cpt.setEnabled(en);
        }
    }

    /** Show whether Burp's built-in AI is currently enabled (subscription + per-extension opt-in). */
    private void updateBurpAiStatus() {
        boolean enabled = false;
        try { enabled = ext.api().ai().isEnabled(); } catch (Throwable ignore) { }
        if (enabled) {
            burpAiStatus.setForeground(new Color(0, 128, 0));
            String bal = null;
            try { bal = com.ioactive.aiscanner.engine.MontoyaAiEngine.readCreditBalance(); } catch (Throwable ignore) { }
            burpAiStatus.setText("Burp AI: enabled ✓" + (bal == null || bal.isBlank() ? "" : "   (credits available: "
                    + com.ioactive.aiscanner.engine.MontoyaAiEngine.displayBalance(bal) + ")"));
        } else {
            burpAiStatus.setForeground(new Color(176, 96, 0));
            burpAiStatus.setText("Burp AI not enabled for this extension. Reload this extension (Extensions → right click on AI Scanner → Reload) and approve the usage of Burp AI");
        }
    }

    private EngineConfig configFromFields() {
        EngineConfig.Provider provider = noAiRadio.isSelected() ? EngineConfig.Provider.NO_AI
                : burpAiRadio.isSelected() ? EngineConfig.Provider.BURP_AI
                : EngineConfig.Provider.LOCAL_LLM;
        return new EngineConfig(
                provider,
                urlField.getText(),
                modelField.getText(),
                new String(keyField.getPassword()),
                parseD(tempField.getText(), 0.3),
                parseI(maxTokField.getText(), 512),
                thinkBox.isSelected(),
                parseI(timeoutField.getText(), 120));
    }

    /** Wire every setting to auto-persist on change so no Save button is needed. Text fields commit on Enter and on
     *  focus-loss (NOT per keystroke — a half-typed URL/model shouldn't be applied mid-edit); checkboxes, combos and
     *  the provider radios commit immediately. Each path calls {@link #onSave()} (persist to prefs + re-apply engine). */
    private void wireAutoSave() {
        java.awt.event.FocusAdapter onBlur = new java.awt.event.FocusAdapter() {
            @Override public void focusLost(java.awt.event.FocusEvent e) { onSave(); }
        };
        for (JTextField f : new JTextField[]{urlField, modelField, keyField, tempField, maxTokField, timeoutField,
                roundsField, payloadsField, delayField, reqTimeoutField, concurrencyField,
                crawlDepthField, crawlPagesField, discRoundsField, maxSourcesField, maxCandidatesField,
                crawlWaitField, llmRespTimeoutField, llmHardDeadlineField, logFileField}) {
            f.addActionListener(e -> onSave());   // Enter commits
            f.addFocusListener(onBlur);           // leaving the field commits
        }
        logToFileBox.addActionListener(e -> onSave());
        thinkBox.addActionListener(e -> onSave());
        wafEvasionBox.addActionListener(e -> onSave());
        logLevelCombo.addActionListener(e -> onSave());
        sastModeCombo.addActionListener(e -> onSave());
        burpAiRadio.addActionListener(e -> onSave());
        localRadio.addActionListener(e -> onSave());
        noAiRadio.addActionListener(e -> onSave());
    }

    private void onSave() {
        ScanConfig s = ext.scanConfig();
        s.rounds = parseI(roundsField.getText(), s.rounds);
        s.payloadsPerRound = parseI(payloadsField.getText(), s.payloadsPerRound);
        s.delayMs = parseI(delayField.getText(), s.delayMs);
        s.requestTimeoutMs = parseI(reqTimeoutField.getText(), s.requestTimeoutMs);
        s.scanMode = sastRadio.isSelected()     ? com.ioactive.aiscanner.scan.ScanConfig.ScanMode.SAST
                   : dastRadio.isSelected()     ? com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST
                                                : com.ioactive.aiscanner.scan.ScanConfig.ScanMode.DAST_SAST;
        // SAST mode: extension probes don't run → grey-out the modules panel so it's clear. Route through
        // refreshModuleStates so switching BACK to a DAST mode re-enables only the phases that haven't run yet.
        refreshModuleStates();
        s.logToFile = logToFileBox.isSelected();
        s.logFilePath = logFileField.getText() == null ? "" : logFileField.getText().trim();
        System.setProperty("aiscanner.concurrency", String.valueOf(Math.max(1, parseI(concurrencyField.getText(), 3))));
        // Crawl & Discovery reach + Timeouts → system props Tuning / MontoyaLlmHttp read at scan time.
        System.setProperty("aiscanner.crawlDepth",           String.valueOf(parseI(crawlDepthField.getText(), 3)));
        System.setProperty("aiscanner.crawlPages",           String.valueOf(parseI(crawlPagesField.getText(), 60)));
        System.setProperty("aiscanner.discoveryRounds",      String.valueOf(parseI(discRoundsField.getText(), 3)));
        System.setProperty("aiscanner.maxSources",           String.valueOf(parseI(maxSourcesField.getText(), 40)));
        System.setProperty("aiscanner.maxCandidates",        String.valueOf(parseI(maxCandidatesField.getText(), 200)));
        System.setProperty("aiscanner.crawlWaitSec",         String.valueOf(parseI(crawlWaitField.getText(), 240)));
        System.setProperty("aiscanner.llmResponseTimeoutMs", String.valueOf(parseI(llmRespTimeoutField.getText(), 120000)));
        System.setProperty("aiscanner.llmHardDeadlineMs",    String.valueOf(parseI(llmHardDeadlineField.getText(), 180000)));
        System.setProperty("aiscanner.sastMode", String.valueOf(sastModeCombo.getSelectedItem()));
        LogLevel.set(LogLevel.parse(String.valueOf(logLevelCombo.getSelectedItem())));   // apply verbosity immediately
        ext.applyEngineConfig(configFromFields());
        applyLogFile();   // open/close the live file sink to match the toggle (no-op if the path is unchanged)
        // Autosave is silent: no "Saved." flash on every field change — it's redundant with autosave and
        // setting text on the bottom status area scrolled the panel down. status is left for onTest() feedback.
    }

    /** Open/close the ScanLog file sink to match the "Log to file" toggle + path. Idempotent (ScanLog no-ops if
     *  the path is unchanged), so it's safe to call from every onSave(). */
    private void applyLogFile() {
        ScanConfig s = ext.scanConfig();
        boolean on = s.logToFile && s.logFilePath != null && !s.logFilePath.isBlank();
        ext.scanLog().setLogFile(on ? s.logFilePath : null);
    }

    private void onTest() {
        status.setForeground(Color.GRAY);
        status.setText("Testing…");
        AiEngine test = ext.buildEngine(configFromFields());
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                return test.chat("You are a connectivity check. Reply with exactly one word: OK", "ping");
            }
            @Override protected void done() {
                String r;
                try { r = get(); } catch (Exception ex) { r = ""; }
                if (r != null && !r.isBlank()) {
                    status.setForeground(new Color(0, 128, 0));
                    status.setText("OK — " + test.name() + " replied: "
                            + (r.length() > 60 ? r.substring(0, 60) + "…" : r) + burpAiCreditSuffix());
                } else {
                    status.setForeground(Color.RED);
                    status.setText("Failed: " + (test.lastError().isBlank() ? "no response" : test.lastError()));
                }
            }
        }.execute();
    }

    /** For a Burp AI test, append the available credit balance so "Test connection" shows how much is left. */
    private String burpAiCreditSuffix() {
        if (!burpAiRadio.isSelected()) return "";
        try {
            String bal = com.ioactive.aiscanner.engine.MontoyaAiEngine.readCreditBalance();
            return (bal == null || bal.isBlank()) ? "   |   Burp AI credits: unknown (Burp hasn't synced a balance yet)"
                    : "   |   Burp AI credits available: " + com.ioactive.aiscanner.engine.MontoyaAiEngine.displayBalance(bal);
        } catch (Throwable t) { return ""; }
    }

    private void header(GridBagConstraints g, int y, String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        g.gridx = 0; g.gridy = y; g.gridwidth = 2; panel.add(l, g); g.gridwidth = 1;
    }

    /** A full-width row (used for radios / status that span both columns). */
    private void span(GridBagConstraints g, int y, Component c) {
        g.gridx = 0; g.gridy = y; g.gridwidth = 2; panel.add(c, g); g.gridwidth = 1;
    }

    private void row(GridBagConstraints g, int y, Component label, Component field) {
        g.gridx = 0; g.gridy = y; panel.add(label, g);
        g.gridx = 1; g.gridy = y; panel.add(field, g);
    }

    private static double parseD(String s, double def) {
        try { return Double.parseDouble(s.trim()); } catch (Exception e) { return def; }
    }
    private static int parseI(String s, int def) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return def; }
    }
}
