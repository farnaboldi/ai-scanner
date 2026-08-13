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
    private JScrollPane scroll;   // log viewport — used to follow the tail ONLY when the user is already at the bottom
    private final JTextArea area = new JTextArea(14, 100);
    private final JLabel status = new JLabel(" ");
    private final JLabel phase = new JLabel(" ");
    private final Consumer<String> mirror;
    private final AtomicInteger scanned = new AtomicInteger();
    private final AtomicInteger findings = new AtomicInteger();
    /** Invoked by the Agent-tab "Stop" button — the extension wires this to cancel the running scan. */
    private volatile Runnable stopHandler;
    public void setStopHandler(Runnable r) { this.stopHandler = r; }
    /** The Stop button — enabled only while a scan is active (disabled on click + when idle). */
    private JButton stopBtn;
    /** True while a scan runs; {@link #phase(String)} throws {@link ScanStopped} once this flips off via Stop. */
    private volatile java.util.function.BooleanSupplier stopCheck;
    public void setStopCheck(java.util.function.BooleanSupplier s) { this.stopCheck = s; }
    /** Wall-clock scan timer for the benchmark's "time" column: stamped when a scan goes active, read at the
     *  SCAN COMPLETE tally. 0 until the first scan of this session starts. */
    private volatile long scanStartMillis = 0L;
    /** True while a scan is running — read by the Suite tab to auto-focus the Agent view when you open it mid-scan. */
    private volatile boolean scanActive = false;
    public boolean isScanActive() { return scanActive; }
    /** Enable/disable the Stop button (scan start → true, scan end / clicked → false). EDT-safe. */
    public void setScanActive(boolean active) {
        this.scanActive = active;
        if (active) { scanStartMillis = System.currentTimeMillis(); hostClassClaimed.clear(); }   // start clock + reset host gate
        javax.swing.SwingUtilities.invokeLater(() -> { if (stopBtn != null) stopBtn.setEnabled(active); });
    }

    /** Host-wide one-shot gate for SYSTEMIC classes (e.g. stack-trace disclosure) that several probes may each
     *  observe on different endpoints of the same host: returns true only the FIRST time this (vulnClass, host) is
     *  seen this scan, so the systemic misconfig collapses to a single issue instead of one per endpoint. */
    private final java.util.Set<String> hostClassClaimed = java.util.concurrent.ConcurrentHashMap.newKeySet();
    public boolean firstForHost(String vulnClass, String url) {
        String host = url;
        try { java.net.URI u = new java.net.URI(url); if (u.getHost() != null) host = u.getHost(); } catch (Throwable ignore) { }
        return hostClassClaimed.add(vulnClass + "@@" + host);
    }
    /** Elapsed wall-clock since the current scan started, formatted "Nm Ss" (or "Ss" under a minute). */
    public String scanElapsed() {
        if (scanStartMillis <= 0) return "n/a";
        long s = Math.max(0, (System.currentTimeMillis() - scanStartMillis) / 1000L);
        return s >= 60 ? (s / 60) + "m " + (s % 60) + "s" : s + "s";
    }
    /** Raw elapsed seconds since scan start (for machine-readable rows); -1 if no scan started. */
    public long scanElapsedSeconds() {
        return scanStartMillis <= 0 ? -1 : Math.max(0, (System.currentTimeMillis() - scanStartMillis) / 1000L);
    }
    /** Thrown by {@link #phase(String)} when the user hit Stop — unwinds the current probe so the sequence drains
     *  without a per-probe checkpoint (every probe calls phase() first). RuntimeException → caught by the probes'
     *  {@code catch (Throwable)} so it just skips them; the scan then finalizes the partial report. */
    public static final class ScanStopped extends RuntimeException {
        public ScanStopped() { super("scan stopped by user"); }
    }
    /** Thrown by {@link #phase(String)} to SKIP a single probe phase not selected by -Daiscanner.only (fast
     *  debugging). Caught by each phase's own try/catch(Throwable) → body skipped, next phase runs normally. */
    public static final class PhaseSkipped extends RuntimeException {
        public PhaseSkipped() { super("phase not selected by -Daiscanner.only"); }
    }
    /** Comma-separated module filter (-Daiscanner.only / AISCANNER_ONLY): run ONLY the probe phases whose title
     *  contains one of these terms. Null/blank → run everything. Case-insensitive. e.g. only=reflected-xss,sqli. */
    private static String moduleFilter() {
        String v = System.getProperty("aiscanner.only");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_ONLY");
        return (v == null || v.isBlank()) ? null : v.toLowerCase();
    }
    /** Lifecycle/prerequisite phases that -Daiscanner.only NEVER skips (auth, crawl, discovery, explore, re-auth,
     *  audit submission, idle) — the attack surface + session they set up is required by whichever probe you select. */
    private static boolean isLifecyclePhase(String title) {
        String s = title.toLowerCase();
        return s.contains("authenticating") || s.contains("source analysis") || s.startsWith("crawling")
            || s.contains("exploring") || s.contains("submitting") || s.contains("idle")
            || s.contains("native baseline") || s.startsWith("auditing at") || s.contains("re-authenticat");
    }
    /** Short module names → a substring of the phase title, so `-Daiscanner.only=rxss,sqli,idor` is ergonomic.
     *  An unlisted term is matched as a raw substring of the title, so any word from a phase title also works. */
    private static final java.util.Map<String,String> MODULE_ALIASES = java.util.Map.ofEntries(
            java.util.Map.entry("rxss", "reflected-xss"), java.util.Map.entry("xss", "reflected-xss"),
            java.util.Map.entry("sqli", "blind sqli"), java.util.Map.entry("cmdi", "command inject"),
            java.util.Map.entry("idor", "idor"), java.util.Map.entry("ssrf", "ssrf"),
            java.util.Map.entry("xxe", "xxe"), java.util.Map.entry("nosql", "nosql"),
            java.util.Map.entry("bfla", "bfla"), java.util.Map.entry("jwt", "jwt"),
            java.util.Map.entry("csrf", "csrf"), java.util.Map.entry("lfi", "lfi"),
            java.util.Map.entry("graphql", "graphql"), java.util.Map.entry("deser", "deserial"),
            java.util.Map.entry("redirect", "open-redirect"), java.util.Map.entry("oauth", "oauth"),
            java.util.Map.entry("secrets", "secret-exposure"), java.util.Map.entry("webhook", "webhook"),
            java.util.Map.entry("flow", "flow-engine"), java.util.Map.entry("chain", "chain"),
            java.util.Map.entry("tamper", "tampering"), java.util.Map.entry("fileserve", "file-serve"),
            java.util.Map.entry("bodymut", "body-mutation"), java.util.Map.entry("unauth", "unauthenticated"),
            java.util.Map.entry("pathtrav", "path travers"), java.util.Map.entry("privparity", "privilege-parity"),
            java.util.Map.entry("agentflow", "agent-flow"), java.util.Map.entry("llmfuzz", "llm-fuzz"),
            java.util.Map.entry("saml", "saml"), java.util.Map.entry("verberr", "verbose-error"),
            java.util.Map.entry("stacktrace", "verbose-error"));
    private volatile String currentPhase = "Idle";
    private volatile boolean filterAnnounced = false;   // -Daiscanner.only banner printed once per session
    public String currentPhase() { return currentPhase; }
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
        stopBtn = new JButton("Stop");
        stopBtn.setToolTipText("Stop the current scan");
        stopBtn.setEnabled(false);   // only clickable while a scan is active
        stopBtn.addActionListener(e -> {
            stopBtn.setEnabled(false);                 // one-shot: disabled until the next scan starts
            Runnable h = stopHandler; if (h != null) h.run();
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> clear());
        JPanel labels = new JPanel(new GridLayout(2, 1));
        labels.add(phase);
        labels.add(status);
        top.add(labels, BorderLayout.CENTER);
        // Stop sits to the LEFT of Clear.
        JPanel btns = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 4, 0));
        btns.add(stopBtn);
        btns.add(clear);
        top.add(btns, BorderLayout.EAST);

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
        scroll = new JScrollPane(area);
        // A JTextArea's DefaultCaret defaults to UPDATE_WHEN_ON_EDT: on every document insert it moves the caret
        // to track the change, which drags the viewport to the bottom — so append() ALONE scrolls you down even
        // when you've deliberately scrolled up to read. NEVER_UPDATE stops that; log() then pins to the bottom
        // EXPLICITLY (via the scrollbar) only when the user was already there.
        if (area.getCaret() instanceof javax.swing.text.DefaultCaret dc)
            dc.setUpdatePolicy(javax.swing.text.DefaultCaret.NEVER_UPDATE);
        panel.add(scroll, BorderLayout.CENTER);

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

    /** Jump the log viewport to the tail (re-enter autoscroll). Called when the Agent tab is focused so opening it
     *  mid-scan lands you at the live tail; after that the caret policy leaves manual scroll-up alone as before. */
    public void scrollToBottom() {
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (scroll == null) return;
            javax.swing.JScrollBar v = scroll.getVerticalScrollBar();
            if (v != null) v.setValue(v.getMaximum());
        });
    }

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
                // Follow the tail ONLY when the user is already at (or near) the bottom. If they scrolled up to
                // read, appending must NOT yank the view back down — measured BEFORE the append. With the caret on
                // NEVER_UPDATE, append() no longer scrolls on its own, so when the user is scrolled up we do
                // nothing (and we also SKIP trimView, whose top-removal would shift their content and jump them).
                boolean atBottom = true;
                try {
                    JScrollBar vb = scroll != null ? scroll.getVerticalScrollBar() : null;
                    if (vb != null) atBottom = (vb.getValue() + vb.getVisibleAmount()) >= (vb.getMaximum() - 24);
                } catch (Throwable ignore) { }
                area.append(line + "\n");
                if (atBottom) {
                    trimView();                                 // keep the visible document bounded → EDT stays responsive
                    // Pin to the bottom explicitly. Nested invokeLater so the append + relayout is done and the
                    // scrollbar maximum reflects the new content before we jump to it.
                    SwingUtilities.invokeLater(() -> {
                        JScrollBar vb = scroll != null ? scroll.getVerticalScrollBar() : null;
                        if (vb != null) vb.setValue(vb.getMaximum());
                    });
                }
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

    /** Diagnostic detail — shown at DEBUG or TRACE (see {@link com.ioactive.aiscanner.engine.LogLevel}). */
    public void debug(String s) {
        if (com.ioactive.aiscanner.engine.LogLevel.debug()) log(s);
    }

    /** Deepest detail (full bodies etc.) — shown only at TRACE. */
    public void trace(String s) {
        if (com.ioactive.aiscanner.engine.LogLevel.trace()) log(s);
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

    /** Whether Burp's native active audit is available (Pro) — set by the scanner before probes run. */
    private volatile boolean burpNativeAudit = false;
    public void setBurpNativeAudit(boolean b) { this.burpNativeAudit = b; }
    /** Families Burp's native active audit covers well: for these we defer the DASHBOARD issue to Burp's own
     *  (we submit every target to Burp's audit, so Burp raises it) — avoiding a two-issue dashboard duplicate.
     *  Our detection + source provenance still go to the log + AI report. Disable with -Daiscanner.deferToBurp=false. */
    private static final java.util.Set<String> BURP_COVERED =
            java.util.Set.of("sqli", "xss", "cmdi", "path", "xxe", "ssti");
    private static final boolean DEFER_TO_BURP =
            !"false".equalsIgnoreCase(System.getProperty("aiscanner.deferToBurp", "true"));

    /**
     * A confirmed vulnerability — always shown, prominently. (Counting is done via incFinding.) Pass ALL the
     * request/response pairs that establish the finding as evidence (varargs) — e.g. BFLA attaches the
     * unauth-denied, our-session-reached, and junk-control probes so the raised Burp issue shows the full
     * proof across multiple request/response tabs, not just one.
     */
    /** Normalize a URL for finding-dedup: drop the fragment, resolve ./.. segments + collapse //, and unify a
     *  trailing slash on the path (query preserved). So …/fi/ ≡ …/fi/. ≡ …/fi collapse to one finding. */
    private static String normUrl(String u) {
        if (u == null) return "";
        int h = u.indexOf('#'); if (h >= 0) u = u.substring(0, h);
        try { u = java.net.URI.create(u).normalize().toString(); } catch (Exception ignore) { }
        int q = u.indexOf('?');
        String path = q >= 0 ? u.substring(0, q) : u, qs = q >= 0 ? u.substring(q) : "";
        if (path.length() > 1 && path.endsWith("/")) path = path.substring(0, path.length() - 1);
        return path + qs;
    }

    public void found(String vulnClass, String url, String point,
                      burp.api.montoya.http.message.HttpRequestResponse... evidence) {
        found(vulnClass, url, point, false, evidence);
    }

    /**
     * @param forceRaise raise OUR dashboard issue even for a Burp-covered class — for findings we've CONFIRMED
     *   that Burp only under-reports (e.g. a breakout-confirmed reflected XSS whose sink is an HTML comment /
     *   &lt;script&gt; block: Burp leaves those at INFO and never escalates, so deferring would drop the HIGH).
     */
    public void found(String vulnClass, String url, String point, boolean forceRaise,
                      burp.api.montoya.http.message.HttpRequestResponse... evidence) {
        // Cross-channel dedup: our error-based probe, our blind probe, the LLM tier, AND Burp's native audit
        // all report the SAME underlying flaw under different labels — collapse to ONE finding per (family @ url)
        // so the count isn't inflated (see claimFinding). URL is path-normalized so /fi ≡ /fi/ ≡ /fi/index.php.
        if (!claimFinding(vulnClass, url)) return;
        // For classes Burp's native audit covers, let Burp's own issue be the single dashboard record (we fed it
        // the endpoint) — otherwise both engines raise a duplicate. Our finding + provenance still reach the report.
        // forceRaise overrides this for a confirmed finding Burp only reports as INFO (see the ReflectedXssProbe).
        boolean deferToBurp = !forceRaise && DEFER_TO_BURP && burpNativeAudit && BURP_COVERED.contains(familyKey(vulnClass));
        log("[AI Scanner] >>> VULNERABILITY: " + vulnClass + "  @ " + url
                + (point == null || point.isBlank() ? "" : "  (" + point + ")")
                + (deferToBurp ? "  [dashboard issue deferred to Burp's native audit]" : ""));
        IssueSink s = issueSink;
        if (s != null && !deferToBurp) { try { s.raise(vulnClass, url, point, evidence); } catch (Throwable ignore) { } }
    }
    private final java.util.Set<String> emittedFindings = Collections.synchronizedSet(new java.util.HashSet<>());

    /** Canonical vuln FAMILY for cross-channel dedup. Our probes ("SQL injection", "SQL injection (blind)"),
     *  the LLM tier ("AI: SQL Injection"), and Burp's native audit ("SQL injection") name the SAME flaw
     *  differently; map them to one token so a single flaw at a single endpoint is counted once, not 3×. */
    private static String familyKey(String vulnClass) {
        if (vulnClass == null) return "";
        String c = vulnClass.toLowerCase().replaceFirst("^ai:\\s*", "").trim();
        if (c.contains("sql injection") || c.contains("sqli")) return "sqli";
        if (c.contains("cross-site scripting") || c.contains("xss")) return "xss";
        if (c.contains("command injection") || c.contains("os command")) return "cmdi";
        if (c.contains("path traversal") || c.contains("file inclusion") || c.contains("directory traversal")) return "path";
        if (c.contains("xxe") || c.contains("xml external") || c.contains("xml injection")) return "xxe";
        if (c.contains("cross-site request forgery") || c.contains("csrf")) return "csrf";
        if (c.contains("deserial")) return "deser";
        // open redirect: our "Open redirect" vs Burp-native "Open redirection" / "URL redirection to untrusted site"
        if (c.contains("redirect")) return "openredir";
        // SSRF: our name vs Burp-native "Server-side request forgery"
        if (c.contains("server-side request forgery") || c.contains("ssrf")) return "ssrf";
        if (c.contains("ldap injection")) return "ldapi";
        if (c.contains("template injection") || c.contains("ssti")) return "ssti";
        return c;   // otherwise dedupe by the exact class name
    }

    /** Path-only normalized URL (drop query + fragment, unify trailing slash, strip a trailing directory-index
     *  file) so the SAME endpoint reached as /x, /x/, /x/index.php collapses across channels. */
    private static String pathKey(String u) {
        String n = normUrl(u);
        int q = n.indexOf('?'); if (q >= 0) n = n.substring(0, q);
        n = n.replaceFirst("/(index|default|main)\\.[a-z]{2,4}$", "/");
        if (n.length() > 1 && n.endsWith("/")) n = n.substring(0, n.length() - 1);
        return n;
    }

    /** Claim (family @ path) once across ALL channels (our probes + AiTriage's native issues). Returns false
     *  if this flaw at this endpoint was already reported → the caller must skip (no duplicate line/count). */
    public boolean claimFinding(String vulnClass, String url) {
        return emittedFindings.add((familyKey(vulnClass) + "|" + pathKey(url)).toLowerCase());
    }

    /** Set the current activity shown prominently in the panel (and echoed to the log). */
    public void phase(String s) {
        // Single-point stop: every probe calls phase() first, so throwing here unwinds the current probe and the
        // whole remaining battery drains (each subsequent phase() throws again → body skipped) with no per-probe
        // checkpoint. Thrown only after the user hit Stop; a normal run never trips it.
        java.util.function.BooleanSupplier sc = stopCheck;
        if (sc != null && sc.getAsBoolean()) throw new ScanStopped();
        currentPhase = (s == null || s.isBlank()) ? "Idle" : s;
        // Module selector for fast debugging: -Daiscanner.only=rxss,sqli runs ONLY the matching PROBE phases.
        // Applies solely to probe phases (title contains "probe") so crawl/auth/discovery/audit prerequisites
        // always run — and skipping the earlier probes means the selected one runs with a FRESHER session.
        String only = moduleFilter();
        // Filter ONLY phases whose title contains "probe" — that is EXACTLY the set of probe phases each wrapped in
        // its own try/catch(Throwable), so throwing PhaseSkipped skips just that phase. Non-"probe" phases (crawl,
        // discovery, explore, re-auth, audit submit, and the few probes without "probe" in their title) are NOT
        // individually caught, so a thrown skip there would abort the whole scan — never filter them.
        if (only != null && currentPhase.toLowerCase().contains("probe") && !isLifecyclePhase(currentPhase)) {
            String tl = currentPhase.toLowerCase();
            boolean match = false;
            for (String k : only.split(",")) {
                String t = k.trim().toLowerCase();
                if (t.isEmpty()) continue;
                String needle = MODULE_ALIASES.getOrDefault(t, t);   // short alias → title substring
                if (tl.contains(needle)) { match = true; break; }
            }
            if (!match) {
                if (!filterAnnounced) {   // announce the active filter ONCE, then just mark each skip tersely
                    filterAnnounced = true;
                    log("[AI Scanner] module filter active: -Daiscanner.only=" + only + " — skipping all non-selected probe phases");
                }
                log("[AI Scanner] ── " + currentPhase + "  (skip)");
                throw new PhaseSkipped();
            }
        }
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
