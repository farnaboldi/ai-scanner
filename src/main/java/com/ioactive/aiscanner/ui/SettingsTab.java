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
    private final JComboBox<String> sastModeCombo = new JComboBox<>(new String[]{"coarse", "agentic"});
    private final JTextArea status = new JTextArea(3, 40);

    public SettingsTab(AiScannerExtension ext) {
        this.ext = ext;
        build();
        // Burp realizes the tab lazily; refresh the Burp-AI status + focus whenever the panel becomes visible.
        panel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && panel.isShowing()) {
                updateBurpAiStatus();
                focusFirstField();
            }
        });
    }

    public JComponent component() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(panel), modulesPanel());
        split.setResizeWeight(0.5);   // split the screen in half
        return split;
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
        p.add(sectionLabel("Pre-attack modules"));
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (ph.section == com.ioactive.aiscanner.scan.ScanPhases.Section.BEFORE) p.add(prereqBox(ph.label));
        }
        p.add(Box.createVerticalStrut(8));
        p.add(sectionLabel("Attack modules"));
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (!ph.isAttack()) continue;
            boolean checked = only == null || only.contains(ph.key);
            JCheckBox cb = new JCheckBox(ph.label, checked);
            moduleBoxes.put(ph.key, cb);
            cb.addActionListener(e -> applyModuleSelection());
            p.add(cb);
        }
        p.add(Box.createVerticalStrut(8));
        p.add(sectionLabel("Post-attack modules"));
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase ph : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (ph.section == com.ioactive.aiscanner.scan.ScanPhases.Section.AFTER) p.add(prereqBox(ph.label));
        }
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
        concurrencyField.setText(String.valueOf(Integer.getInteger("aiscanner.concurrency", 3)));
        crawlDepthField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.crawlDepth()));
        crawlPagesField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.crawlPages()));
        discRoundsField.setText(String.valueOf(com.ioactive.aiscanner.scan.EndpointDiscovery.discoveryRoundsPublic()));
        maxSourcesField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.maxSources()));
        maxCandidatesField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.maxCandidates()));
        crawlWaitField.setText(String.valueOf(com.ioactive.aiscanner.scan.Tuning.crawlWaitSec()));
        llmRespTimeoutField.setText(String.valueOf(Long.getLong("aiscanner.llmResponseTimeoutMs", 120000L)));
        llmHardDeadlineField.setText(String.valueOf(Long.getLong("aiscanner.llmHardDeadlineMs", 180000L)));

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

        // Logging FIRST (top of the tab). Apply the level LIVE on change (no Save needed) — LogLevel.current is a
        // volatile read by every log call, so a running scan switches verbosity immediately. Save still persists it.
        header(g, y++, "Logging");
        logLevelCombo.addActionListener(e ->
                LogLevel.set(LogLevel.parse(String.valueOf(logLevelCombo.getSelectedItem()))));
        row(g, y++, new JLabel("Log level:"), logLevelCombo);   // INFO / DEBUG / TRACE — applied instantly + on Save

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
                + "coarse: single-shot repo scan → directives. agentic: 2-step, follows the child-process "
                + "boundary to pin the real sink (slower, more precise; falls back to coarse).");
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
                roundsField, payloadsField, delayField, concurrencyField,
                crawlDepthField, crawlPagesField, discRoundsField, maxSourcesField, maxCandidatesField,
                crawlWaitField, llmRespTimeoutField, llmHardDeadlineField}) {
            f.addActionListener(e -> onSave());   // Enter commits
            f.addFocusListener(onBlur);           // leaving the field commits
        }
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
        status.setForeground(new Color(0, 128, 0));
        status.setText("Saved.");
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
