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
    // Filterable ATTACK probes, listed in their ACTUAL execution order in the probe battery (AiScanner.scanDiscovered).
    // Keys match ScanLog.MODULE_ALIASES; only phases whose title contains "probe" are skippable, so these are exactly
    // those. Unchecking one adds it to the skip set for the NEXT scan. (LLM) ones only run when an LLM engine is set.
    private static final String[][] PROBE_MODULES = {
        {"agentflow","Agent-flow (LLM)"}, {"llmfuzz","LLM-fuzz (LLM)"}, {"csrf","CSRF"}, {"redirect","Open-redirect"},
        {"oauth","OAuth-logic"}, {"sqli","Blind SQLi"}, {"rxss","Reflected-XSS (context-aware breakout)"},
        {"pathtrav","Path-reflection"}, {"nosql","NoSQL injection"}, {"cmdi","Command injection"},
        {"chain","Create->consume chain (leak replay)"}, {"bodymut","Body-mutation"}, {"fileserve","File-serve bypass"},
        {"idor","IDOR"}, {"bfla","BFLA"}, {"jwt","JWT analysis"}, {"unauth","Unauthenticated-access"},
        {"webhook","Webhook fail-open"}, {"privparity","Privilege-parity"}, {"secrets","Response secret-exposure"},
        {"graphql","GraphQL"}, {"deser","Insecure deserialization"}, {"xxe","Blind XXE (OOB)"},
        {"lfi","Path-traversal / LFI"}, {"ssrf","SSRF"}, {"tamper","Restriction-bypass / tampering"},
        {"flow","Flow-engine (LLM, multi-step)"},
    };
    // Prerequisite phases that ALWAYS run (before/after the attack probes) — shown checked + disabled.
    private static final String[] PREREQ_MODULES = {
        "Authentication (default-creds / register / SQLi-bypass)", "Native crawl", "Endpoint discovery (JS/OpenAPI mining)",
        "Authenticated explore + form-exercise", "Native Burp active audit", "Benchmark tally",
    };
    private final java.util.Map<String, JCheckBox> moduleBoxes = new java.util.LinkedHashMap<>();

    private JComponent modulesPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        JLabel title = new JLabel("Modules");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize() + 2f));
        p.add(title);
        // JLabel hint = new JLabel("Uncheck to skip on the scan");
        // hint.setForeground(Color.GRAY); p.add(hint); p.add(Box.createVerticalStrut(6));

        p.add(sectionLabel("Always run (before / after)"));
        for (String pr : PREREQ_MODULES) {
            JCheckBox cb = new JCheckBox(pr, true);
            cb.setEnabled(false);   // prerequisites are not skippable — the probes need them
            p.add(cb);
        }
        p.add(Box.createVerticalStrut(8));
        p.add(sectionLabel("Attack modules"));
        java.util.Set<String> only = parseOnlyFilter();   // null → all run
        for (String[] m : PROBE_MODULES) {
            boolean checked = only == null || only.contains(m[0]);
            JCheckBox cb = new JCheckBox(m[1], checked);
            moduleBoxes.put(m[0], cb);
            cb.addActionListener(e -> applyModuleSelection());
            p.add(cb);
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
        row(g, y++, keyLabel, keyField);
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

        JButton save = new JButton("Save");
        save.addActionListener(e -> onSave());
        JButton test = new JButton("Test connection");
        test.addActionListener(e -> onTest());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(save);
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
        for (JComponent cpt : new JComponent[]{urlField, modelField, keyField, tempField, maxTokField, timeoutField,
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
            burpAiStatus.setText("Burp AI: enabled ✓" + (bal == null || bal.isBlank() ? "" : "   (credits available: " + bal + ")"));
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

    private void onSave() {
        ScanConfig s = ext.scanConfig();
        s.rounds = parseI(roundsField.getText(), s.rounds);
        s.payloadsPerRound = parseI(payloadsField.getText(), s.payloadsPerRound);
        s.delayMs = parseI(delayField.getText(), s.delayMs);
        System.setProperty("aiscanner.concurrency", String.valueOf(Math.max(1, parseI(concurrencyField.getText(), 3))));
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
                    : "   |   Burp AI credits available: " + bal;
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
