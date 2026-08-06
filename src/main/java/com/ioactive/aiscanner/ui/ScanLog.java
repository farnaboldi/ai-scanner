package com.ioactive.aiscanner.ui;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Live progress + log panel shown in the extension tab. The scan check and engine
 * write here (and it mirrors to Burp's Output), so the user can identify and follow
 * our activity even though it runs inside Burp's native audit task.
 */
public final class ScanLog {

    private final JPanel panel = new JPanel(new BorderLayout());
    private final JTextArea area = new JTextArea(14, 100);
    private final JLabel status = new JLabel(" ");
    private final JLabel phase = new JLabel(" ");
    private final Consumer<String> mirror;
    private final AtomicInteger scanned = new AtomicInteger();
    private final AtomicInteger findings = new AtomicInteger();
    private volatile String currentPhase = "Idle";
    private volatile boolean verbose = false;
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private final List<String> lines = Collections.synchronizedList(new ArrayList<>());   // display buffer (bounded)
    private final JTextField search = new JTextField();
    private volatile String filter = "";
    // BOUNDS — a big scan emits thousands of lines; an UNBOUNDED JTextArea + one forced caret-scroll per line
    // floods the Swing EDT and the whole AI Scanner tab goes unresponsive (clicks/tab-switches queue behind the
    // append backlog). Cap the in-memory buffer and, more importantly, the visible document. Findings are NOT in
    // this buffer (they go to findingsLog / the report), so trimming old log lines never drops a finding.
    private static final int MAX_BUFFER_LINES = 10000;   // filter/search source
    private static final int MAX_VIEW_LINES   = 4000;    // JTextArea document — keeps append + relayout cheap

    public ScanLog(Consumer<String> mirror) {
        this.mirror = mirror != null ? mirror : s -> { };

        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JPanel top = new JPanel(new BorderLayout());
        status.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        phase.setBorder(BorderFactory.createEmptyBorder(4, 6, 0, 6));
        phase.setFont(phase.getFont().deriveFont(Font.BOLD));
        updateStatus();
        updatePhase();
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> clear());
        JPanel labels = new JPanel(new GridLayout(2, 1));
        labels.add(phase);
        labels.add(status);
        top.add(labels, BorderLayout.CENTER);
        top.add(clear, BorderLayout.EAST);

        // filter/search row — live-filters the log to lines containing the text (Cmd-F / Ctrl-F focuses it)
        JPanel searchRow = new JPanel(new BorderLayout(4, 0));
        searchRow.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        searchRow.add(new JLabel("Filter:"), BorderLayout.WEST);
        search.putClientProperty("JTextField.placeholderText", "type to filter (Cmd-F)");
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        searchRow.add(search, BorderLayout.CENTER);
        top.add(searchRow, BorderLayout.SOUTH);

        panel.setBorder(BorderFactory.createTitledBorder("Scan progress / log"));
        panel.add(top, BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);

        // Cmd-F (mac) / Ctrl-F → focus the filter field
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        KeyStroke cmdF = KeyStroke.getKeyStroke(KeyEvent.VK_F, menuMask);
        KeyStroke ctrlF = KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK);
        panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(cmdF, "focusFilter");
        panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(ctrlF, "focusFilter");
        panel.getActionMap().put("focusFilter", new AbstractAction() {
            public void actionPerformed(ActionEvent e) { search.requestFocusInWindow(); search.selectAll(); }
        });
    }

    private void applyFilter() {
        filter = search.getText() == null ? "" : search.getText().trim().toLowerCase();
        render();
    }

    private boolean matches(String line) {
        return filter.isEmpty() || line.toLowerCase().contains(filter);
    }

    /** Rebuild the visible area from the buffer applying the current filter. */
    private void render() {
        StringBuilder sb = new StringBuilder();
        synchronized (lines) {
            for (String l : lines) if (matches(l)) sb.append(l).append('\n');
        }
        SwingUtilities.invokeLater(() -> {
            area.setText(sb.toString());
            area.setCaretPosition(area.getDocument().getLength());
        });
    }

    public JComponent component() { return panel; }

    public void setVerbose(boolean v) { this.verbose = v; }

    /** Always shown — reserve for phases, counts, and vulnerabilities. */
    public void log(String s) {
        String line = LocalDateTime.now().format(TS) + " " + s;
        mirror.accept(line);
        lines.add(line);
        if (lines.size() > MAX_BUFFER_LINES + 512) {           // bulk-trim the buffer (amortized, front removal is O(n))
            synchronized (lines) {
                int drop = lines.size() - MAX_BUFFER_LINES;
                if (drop > 0) lines.subList(0, Math.min(drop, lines.size())).clear();
            }
        }
        if (s.contains(">>>")) {
            findingsLog.add(s.replaceAll(".*>>>\\s*", "").trim());   // capture findings for the harness report
            flushReport();   // persist immediately so a crash/OOM mid-scan doesn't lose findings already found
        }
        if (matches(line)) {
            SwingUtilities.invokeLater(() -> {
                area.append(line + "\n");
                trimView();                                     // keep the visible document bounded → EDT stays responsive
                area.setCaretPosition(area.getDocument().getLength());
            });
        }
    }

    /** Drop the oldest lines from the VISIBLE document once it exceeds the cap (the full log stays in the buffer /
     *  report). Must run on the EDT. Bounds append cost + relayout so heavy logging can't freeze the tab. */
    private void trimView() {
        try {
            int lc = area.getLineCount();
            if (lc > MAX_VIEW_LINES) {
                int cut = area.getLineEndOffset(lc - MAX_VIEW_LINES - 1);
                area.replaceRange("", 0, cut);
            }
        } catch (Throwable ignore) { }
    }

    /** Diagnostic detail — shown only when verbose is on (still mirrored to Burp Output). */
    public void debug(String s) {
        if (verbose) log(s);
    }

    public void scanned(String url, String point) {
        debug("scanning " + url + "  @ insertion point: " + point);
    }

    /** Count insertion points actually submitted to Burp's audit (called per audited request). */
    public void addInsertionPoints(int n) {
        if (n > 0) { scanned.addAndGet(n); updateStatus(); }
    }

    /** Count a confirmed real vulnerability (non-informational). */
    public void incFinding() {
        findings.incrementAndGet();
        updateStatus();
    }

    /** Confirmed real vulnerabilities counted this session (used when audit.issues() is unavailable). */
    public int findingCount() { return findings.get(); }

    private final List<String> findingsLog = Collections.synchronizedList(new ArrayList<>());
    /** Every finding line ("＞＞＞ …") seen this run — a machine-readable report for the benchmark harness. */
    public List<String> findingsReport() { synchronized (findingsLog) { return new ArrayList<>(findingsLog); } }

    /** Drop the captured findings + reset the finding counter — call between targets in a batch run so each
     *  target's report contains only its own findings. */
    public void clearFindings() {
        synchronized (findingsLog) { findingsLog.clear(); }
        findings.set(0);
        updateStatus();
    }

    // Incremental report path (-Daiscanner.report / AISCANNER_REPORT): findings are flushed here as they
    // occur, so a crash/OOM mid-scan (Burp is memory-hungry) still leaves the harness a scored report.
    private final String reportPath = resolveReportPath();
    private static String resolveReportPath() {
        String p = System.getProperty("aiscanner.report");
        if (p == null || p.isBlank()) p = System.getenv("AISCANNER_REPORT");
        return (p == null || p.isBlank()) ? null : p;
    }
    private void flushReport() {
        if (reportPath == null) return;
        try { java.nio.file.Files.write(java.nio.file.Path.of(reportPath), findingsReport()); } catch (Throwable ignore) { }
    }

    /** The last N buffered log lines — scan context for the chat assistant. */
    public String recentLog(int maxLines) {
        synchronized (lines) {
            int from = Math.max(0, lines.size() - maxLines);
            return String.join("\n", lines.subList(from, lines.size()));
        }
    }

    /** Add a chat input row at the bottom; submitted text is handed to {@code onSubmit}. Chat lines are
     *  written back through {@link #log} by the caller, so they interleave with the scan log. */
    public void enableChat(java.util.function.Consumer<String> onSubmit) {
        JTextField chatInput = new JTextField();
        chatInput.putClientProperty("JTextField.placeholderText", "ask the model about anything in scope…");
        JButton sendBtn = new JButton("Send");
        JPanel row = new JPanel(new BorderLayout(4, 0));
        row.setBorder(BorderFactory.createEmptyBorder(2, 6, 6, 6));
        row.add(new JLabel("Chat:"), BorderLayout.WEST);
        row.add(chatInput, BorderLayout.CENTER);
        row.add(sendBtn, BorderLayout.EAST);
        Runnable go = () -> {
            String t = chatInput.getText().trim();
            if (!t.isEmpty()) { chatInput.setText(""); onSubmit.accept(t); }
        };
        sendBtn.addActionListener(e -> go.run());
        chatInput.addActionListener(e -> go.run());
        panel.add(row, BorderLayout.SOUTH);
        panel.revalidate();
    }

    /** Turns a confirmed finding into a Burp AuditIssue so it shows on the dashboard (site map issues),
     *  not just in this log. Set once at init by the extension (which holds the MontoyaApi + scope). */
    public interface IssueSink {
        void raise(String vulnClass, String url, String detail, burp.api.montoya.http.message.HttpRequestResponse... evidence);
    }
    private volatile IssueSink issueSink;
    public void setIssueSink(IssueSink s) { this.issueSink = s; }

    /**
     * A confirmed vulnerability — always shown, prominently. (Counting is done via incFinding.) Pass ALL the
     * request/response pairs that establish the finding as evidence (varargs) — e.g. BFLA attaches the
     * unauth-denied, our-session-reached, and junk-control probes so the raised Burp issue shows the full
     * proof across multiple request/response tabs, not just one.
     */
    public void found(String vulnClass, String url, String point,
                      burp.api.montoya.http.message.HttpRequestResponse... evidence) {
        // Global dedup: a probe (or a routine that runs over several candidates) can rediscover the same
        // issue; report each distinct (class @ url : detail) only ONCE so the findings report has no dupes.
        String key = (vulnClass + "|" + url + "|" + (point == null ? "" : point)).toLowerCase();
        if (!emittedFindings.add(key)) return;
        log("[AI Scanner] >>> VULNERABILITY: " + vulnClass + "  @ " + url
                + (point == null || point.isBlank() ? "" : "  (" + point + ")"));
        IssueSink s = issueSink;
        if (s != null) { try { s.raise(vulnClass, url, point, evidence); } catch (Throwable ignore) { } }
    }
    private final java.util.Set<String> emittedFindings = Collections.synchronizedSet(new java.util.HashSet<>());

    /** Set the current activity shown prominently in the panel (and echoed to the log). */
    public void phase(String s) {
        currentPhase = (s == null || s.isBlank()) ? "Idle" : s;
        log("[AI Scanner] ── " + currentPhase);
        updatePhase();
    }

    public void clear() {
        scanned.set(0);
        findings.set(0);
        lines.clear();
        SwingUtilities.invokeLater(() -> {
            area.setText("");
            updateStatus();
        });
    }

    private void updateStatus() {
        SwingUtilities.invokeLater(() ->
                status.setText("Insertion points: " + scanned.get()
                        + "     |     Findings (real vulns): " + findings.get()));
    }

    private void updatePhase() {
        SwingUtilities.invokeLater(() -> phase.setText("Current activity: " + currentPhase));
    }
}
