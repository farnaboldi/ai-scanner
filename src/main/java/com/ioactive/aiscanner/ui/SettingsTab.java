package com.ioactive.aiscanner.ui;

import com.ioactive.aiscanner.AiScannerExtension;
import com.ioactive.aiscanner.engine.AiEngine;
import com.ioactive.aiscanner.engine.EngineConfig;
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

    private final JCheckBox verboseBox = new JCheckBox("Verbose logging (print request body + response to Output)");
    private final JCheckBox wafEvasionBox = new JCheckBox("WAF evasion mode (obfuscate probe payloads to bypass a WAF)");
    private final JTextField roundsField = new JTextField(6);
    private final JTextField payloadsField = new JTextField(6);
    private final JTextField delayField = new JTextField(6);
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

    public JComponent component() { return new JScrollPane(panel); }

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
        verboseBox.setSelected(c.verbose);
        roundsField.setText(String.valueOf(s.rounds));
        payloadsField.setText(String.valueOf(s.payloadsPerRound));
        delayField.setText(String.valueOf(s.delayMs));

        ButtonGroup providerGroup = new ButtonGroup();
        providerGroup.add(burpAiRadio);
        providerGroup.add(localRadio);
        boolean local = c.provider == EngineConfig.Provider.LOCAL_LLM;
        burpAiRadio.setSelected(!local);
        localRadio.setSelected(local);
        burpAiRadio.addActionListener(e -> onProviderChanged());
        localRadio.addActionListener(e -> onProviderChanged());
        burpAiStatus.setForeground(Color.GRAY);
        burpAiStatus.setFont(burpAiStatus.getFont().deriveFont(Font.ITALIC));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.anchor = GridBagConstraints.WEST;
        int y = 0;

        header(g, y++, "AI provider");
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
        g.gridx = 1; g.gridy = y++; panel.add(verboseBox, g);

        header(g, y++, "Adaptive attack loop");
        row(g, y++, new JLabel("Refine rounds:"), roundsField);
        row(g, y++, new JLabel("Payloads per round:"), payloadsField);
        row(g, y++, new JLabel("Delay between requests (ms):"), delayField);
        // WAF-evasion toggle: probes ALSO send obfuscated variants (JSON "$op"→"$op", SQL inline comments) so a
        // WAF that blocks the naive payload lets the equivalent one through. Sets a system property the probes
        // read (Evasion.enabled()), applied immediately on toggle.
        wafEvasionBox.setSelected(Boolean.getBoolean("aiscanner.wafEvasion"));
        wafEvasionBox.addActionListener(e ->
                System.setProperty("aiscanner.wafEvasion", String.valueOf(wafEvasionBox.isSelected())));
        g.gridx = 1; g.gridy = y++; panel.add(wafEvasionBox, g);

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
            burpAiStatus.setText("Burp AI: enabled ✓");
        } else {
            burpAiStatus.setForeground(new Color(176, 96, 0));
            burpAiStatus.setText("Burp AI: not enabled for this extension. If Settings → AI is already ON, "
                    + "reload this extension (Extensions → AI Scanner → Reload) and approve the AI-access prompt "
                    + "Burp shows. Or use a local LLM below — no Burp AI needed.");
        }
    }

    private EngineConfig configFromFields() {
        EngineConfig.Provider provider = burpAiRadio.isSelected()
                ? EngineConfig.Provider.BURP_AI : EngineConfig.Provider.LOCAL_LLM;
        return new EngineConfig(
                provider,
                urlField.getText(),
                modelField.getText(),
                new String(keyField.getPassword()),
                parseD(tempField.getText(), 0.3),
                parseI(maxTokField.getText(), 512),
                thinkBox.isSelected(),
                parseI(timeoutField.getText(), 120),
                verboseBox.isSelected());
    }

    private void onSave() {
        ScanConfig s = ext.scanConfig();
        s.rounds = parseI(roundsField.getText(), s.rounds);
        s.payloadsPerRound = parseI(payloadsField.getText(), s.payloadsPerRound);
        s.delayMs = parseI(delayField.getText(), s.delayMs);
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
                    status.setText("OK — " + test.name() + " replied: " + (r.length() > 60 ? r.substring(0, 60) + "…" : r));
                } else {
                    status.setForeground(Color.RED);
                    status.setText("Failed: " + (test.lastError().isBlank() ? "no response" : test.lastError()));
                }
            }
        }.execute();
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
