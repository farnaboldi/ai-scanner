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
    /** Right-side chat panel (added by enableChat). Non-null once the chat is wired. */
    private javax.swing.JEditorPane chatPane;   // renders each turn's markdown as HTML — no scan-log noise
    private JScrollPane chatScroll;
    /** Raw chat turns ({speaker, markdown}); the whole HTML doc is re-rendered on each append. */
    private final java.util.List<String[]> chatTurns = new java.util.ArrayList<>();
    private final JLabel status = new JLabel(" ");
    private final JLabel phase = new JLabel(" ");
    /** Progress bar: fraction of probe phases completed this scan run. Hidden when idle. */
    private final JProgressBar probeProgress = new JProgressBar(0, 100);
    /** Running count of phase() calls this scan — numerator for the progress bar. */
    private final java.util.concurrent.atomic.AtomicInteger phaseSeen = new java.util.concurrent.atomic.AtomicInteger(0);
    // Canonical phases (per ScanPhases) already counted this run — so re-entering a phase (a mid-scan re-auth) or a
    // transient sub-status never advances the step number twice. One entry per distinct ScanPhases label.
    private final java.util.Set<String> countedPhases = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile int lastStep = 0;   // current step number = the active phase's position in ScanPhases
    /** Override the progress-bar denominator (0 = use ScanPhases.filteredTotal). Set to lifecycle-only count
     *  in SAST mode so the bar shows X/N where N reflects only the phases that actually run. */
    private volatile int phaseTotal = 0;
    public void setPhaseTotal(int n) { this.phaseTotal = n; }
    /** Panel holding the progress bar + (later) the chat row — occupies BorderLayout.SOUTH. */
    private final JPanel southPanel = new JPanel(new BorderLayout());
    private final Consumer<String> mirror;
    /** Optional live file sink — the Settings "Log to file" toggle and -Daiscanner.logFile both point here. When
     *  set, every emitted log line AND every chat turn is also written to it, so a session is followable outside
     *  the GUI. Volatile: toggled live from the EDT, read from scan threads. */
    private volatile java.io.PrintWriter fileSink;
    private volatile String fileSinkPath;
    /** Per-scan target tag (e.g. "[localhost:3005] ") prepended to EVERY emitted line so a parallel two-target run is
     *  atomic to review/grep — set once at the start of each per-target scan thread; InheritableThreadLocal so all the
     *  worker threads that scan spawns (crawl, discovery, probes, the shared LLM engine's calling thread) inherit it.
     *  Empty for a normal single-target run. */
    public static final InheritableThreadLocal<String> TARGET_TAG = new InheritableThreadLocal<>();
    /** In a PARALLEL run each per-target ScanLog is headless (its JLabels aren't in any panel). Point it at the MAIN
     *  (UI-attached) ScanLog so its phase/progress/findings still drive the visible status bar — tagged — instead of
     *  the bar sitting idle. null on the single-target UI ScanLog itself. */
    private volatile ScanLog uiMirror;
    public void setUiMirror(ScanLog m) { this.uiMirror = m; }
    // Per-target progress for a LABELED parallel status bar: tag → {done,total} + tag → phase. Scales with N scans
    // (1/2/3 → that many labeled segments), so the bar can never confuse whose progress is whose.
    private final java.util.Map<String, int[]> parProgress = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Map<String, String> parPhase = new java.util.concurrent.ConcurrentHashMap<>();
    private final AtomicInteger scanned = new AtomicInteger();
    private final AtomicInteger findings = new AtomicInteger();
    /** Invoked by the Agent-tab "Stop" button — the extension wires this to cancel the running scan. */
    private volatile Runnable stopHandler;
    public void setStopHandler(Runnable r) { this.stopHandler = r; }
    /** The Stop button — enabled only while a scan is active (disabled on click + when idle). */
    private JButton stopBtn;
    /** The Rescan button — enabled only when a target was previously scanned AND no scan is running. */
    private JButton rescanBtn;
    /** Invoked by the Rescan button with the last scanned URL — extension wires this to startScan(). */
    private volatile Consumer<String> rescanHandler;
    public void setRescanHandler(Consumer<String> h) { this.rescanHandler = h; }
    /** Last URL that was successfully started via startScan — used by the Rescan button. */
    private volatile String lastTarget;
    public void setLastTarget(String url) {
        this.lastTarget = url;
        // Enable Rescan whenever a target is registered and no scan is active.
        javax.swing.SwingUtilities.invokeLater(() -> { if (rescanBtn != null) rescanBtn.setEnabled(!scanActive); });
    }
    /** True while a scan runs; {@link #phase(String)} throws {@link ScanStopped} once this flips off via Stop. */
    private volatile java.util.function.BooleanSupplier stopCheck;
    public void setStopCheck(java.util.function.BooleanSupplier s) { this.stopCheck = s; }
    /** Wall-clock scan timer for the benchmark's "time" column: stamped when a scan goes active, read at the
     *  SCAN COMPLETE tally. 0 until the first scan of this session starts. */
    private volatile long scanStartMillis = 0L;
    /** True while a scan is running — read by the Suite tab to auto-focus the Agent view when you open it mid-scan. */
    private volatile boolean scanActive = false;
    public boolean isScanActive() { return scanActive; }

    // ---- stall watchdog: every log line stamps lastProgressMillis; a daemon thread dumps the scan threads' stacks
    //      when no line has appeared for Tuning.stallWarnSec (so a phase blocked on a hung Burp/Collaborator/LLM call
    //      surfaces the exact blocked method in minutes, not after a multi-hour silent hang), and force-ends the scan
    //      after Tuning.stallAbortSec. The watchdog's OWN output is excluded from progress so a continuing stall keeps
    //      being reported. See Tuning.stallWarnSec/stallAbortSec.
    private volatile long lastProgressMillis = System.currentTimeMillis();
    private volatile Thread watchdog;
    private volatile boolean abortRequested = false;
    private void touchProgress() { if (Thread.currentThread() != watchdog) lastProgressMillis = System.currentTimeMillis(); }
    /** Enable/disable the Stop and Rescan buttons (scan start → true, scan end / clicked → false). EDT-safe. */
    public void setScanActive(boolean active) {
        this.scanActive = active;
        if (active) {
            scanStartMillis = System.currentTimeMillis();
            lastProgressMillis = System.currentTimeMillis();
            abortRequested = false;
            startWatchdog();
            hostClassClaimed.clear();
            phaseSeen.set(0);
            countedPhases.clear();
            lastStep = 0;
            phaseTotal = 0;   // reset per-scan override so next scan uses the full ScanPhases count by default
        } else {
            stopWatchdog();
            currentPhase = "Idle";
        }
        Runnable pcl = phaseChangeListener; if (pcl != null) SwingUtilities.invokeLater(pcl);
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (stopBtn != null) stopBtn.setEnabled(active);
            if (rescanBtn != null) rescanBtn.setEnabled(!active && lastTarget != null);
            probeProgress.setVisible(active || probeProgress.getValue() > 0);
            if (active) { probeProgress.setValue(0); probeProgress.setString("Starting…"); }
            else if (phaseSeen.get() > 0) {
                probeProgress.setValue(100); probeProgress.setString("Complete ✓");
            }
        });
    }

    /** Start the stall watchdog daemon (idempotent — replaces any prior one). */
    private void startWatchdog() {
        stopWatchdog();
        Thread t = new Thread(this::watchdogLoop, "aiscanner-stall-watchdog");
        t.setDaemon(true);
        watchdog = t;
        t.start();
    }

    private void stopWatchdog() {
        Thread t = watchdog; watchdog = null;
        if (t != null) t.interrupt();
    }

    /** Poll for lack-of-progress; dump scan-thread stacks on a stall and force-end a truly wedged scan. */
    private void watchdogLoop() {
        long warnMs  = com.ioactive.aiscanner.scan.Tuning.stallWarnSec()  * 1000L;
        long abortMs = com.ioactive.aiscanner.scan.Tuning.stallAbortSec() * 1000L;   // 0 → disabled
        long checkMs = Math.max(5000L, warnMs / 4);
        long nextWarn = warnMs;
        while (scanActive && watchdog == Thread.currentThread()) {
            try { Thread.sleep(checkMs); } catch (InterruptedException e) { return; }
            if (!scanActive) return;
            long idle = System.currentTimeMillis() - lastProgressMillis;
            if (idle < warnMs) { nextWarn = warnMs; continue; }              // healthy → re-arm
            if (idle >= nextWarn) { dumpStall(idle); nextWarn = idle + warnMs; }   // stalled → dump, re-arm one interval out
            if (abortMs > 0 && idle >= abortMs && !abortRequested) {
                abortRequested = true;
                log("[AI Scanner] ⚠ WATCHDOG: no progress for " + (idle / 1000) + "s (> "
                        + (abortMs / 1000) + "s abort budget) — force-ending the wedged scan via the Stop handler. "
                        + "Raise -Daiscanner.stallAbortSec if a phase is legitimately this slow.");
                Runnable stop = stopHandler;
                if (stop != null) { try { stop.run(); } catch (Throwable ignore) { } }
            }
        }
    }

    /** Emit a stall warning plus a stack dump of every thread currently executing our scan code — turns a silent
     *  multi-hour hang into a log line that names the exact blocked method (Burp audit-status / Collaborator poll /
     *  LLM send / socket read). Its own log() calls don't reset the progress clock (watchdog thread is excluded). */
    private void dumpStall(long idleMs) {
        log("[AI Scanner] ⚠ WATCHDOG: no scan progress for " + (idleMs / 1000) + "s — phase '" + currentPhase
                + "' appears blocked. Stacks of scan threads (topmost frame = where it is stuck):");
        int dumped = 0;
        for (java.util.Map.Entry<Thread, StackTraceElement[]> e : Thread.getAllStackTraces().entrySet()) {
            Thread th = e.getKey();
            if (th == watchdog || th == Thread.currentThread()) continue;
            StackTraceElement[] st = e.getValue();
            if (st == null || st.length == 0) continue;
            boolean ours = false;
            for (StackTraceElement f : st) if (f.getClassName().startsWith("com.ioactive.aiscanner")) { ours = true; break; }
            if (!ours) continue;
            StringBuilder sb = new StringBuilder("[AI Scanner]   thread '" + th.getName() + "' [" + th.getState() + "]");
            int n = 0;
            for (StackTraceElement f : st) {
                sb.append("\n[AI Scanner]       at ").append(f);
                if (++n >= 20) { sb.append("\n[AI Scanner]       … (").append(st.length - n).append(" more)"); break; }
            }
            log(sb.toString());
            if (++dumped >= 6) break;   // bound the dump — the culprit is almost always the first blocked scan thread
        }
        if (dumped == 0)
            log("[AI Scanner]   (no thread currently in com.ioactive.aiscanner code — the block is inside a Burp/JDK "
                    + "call invoked from our thread; check WAITING/BLOCKED threads in Burp's own diagnostics.)");
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
        @Override public String toString() { return "(module skipped)"; }
    }
    /** Comma-separated module filter (-Daiscanner.only / AISCANNER_ONLY): run ONLY the probe phases whose title
     *  contains one of these terms. Null/blank → run everything. Case-insensitive. e.g. only=reflected-xss,sqli. */
    private static String moduleFilter() {
        String v = System.getProperty("aiscanner.only");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_ONLY");
        return (v == null || v.isBlank()) ? null : v.toLowerCase();
    }
    /** Lifecycle/prerequisite phases that -Daiscanner.only NEVER skips — they set up the attack surface and
     *  session that every selected probe depends on. Listing "auth" in only= is informational only (it always runs).
     *  These appear in the log so the analyst can see what the scanner is doing even when using a narrow only= filter. */
    // (Phase classification + the -Daiscanner.only= module filter now derive entirely from ScanPhases — the one
    //  registry the Settings panel also reads — so there is no per-phase list to keep in sync here.)
    private volatile String currentPhase = "Idle";
    private volatile Runnable phaseChangeListener;
    /** Called on every phase transition; {@link SettingsTab} uses this to keep module-checkbox enabled/disabled state
     *  in sync with the running scan (a module whose phase has already passed is greyed out — can't be enqueued). */
    public void setPhaseChangeListener(Runnable r) { this.phaseChangeListener = r; }
    private volatile boolean filterAnnounced = false;   // -Daiscanner.only banner printed once per session
    public String currentPhase() { return currentPhase; }
    /** Best-effort "is it too late?": has the running scan's attack battery already advanced PAST the phase for
     *  {@code key}? Used by the Agent-tab "test &lt;module&gt;" enqueue to warn when a module is added after its phase
     *  already ran. Returns false during any lifecycle/earlier phase (i.e. still in time). Registry-ordered, so it
     *  tracks the exact execution order the attack loop follows. */
    public boolean attackPhasePassed(String key) {
        if (key == null) return false;
        com.ioactive.aiscanner.scan.ScanPhases.Phase target = null, cur = null;
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase p : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            if (p.isAttack() && key.equalsIgnoreCase(p.key)) target = p;
            // The attack battery sets currentPhase to the phase LABEL (scanLog.phase(Phase) → currentPhase=p.label),
            // so resolve the current phase by LABEL — NOT ScanPhases.match(), whose titleMatch substring misses 6
            // attack labels (CSRF/IDOR/SSRF/GraphQL/Path-reflection/WebSocket fuzz) and would wrongly report "in time".
            if (p.label.equalsIgnoreCase(currentPhase)) cur = p;
        }
        if (target == null || cur == null || !cur.isAttack()) return false;   // in lifecycle/sub-status → still in time
        // >= : if the target's OWN phase is the current one, its skip decision has already been made this scan → too late.
        return com.ioactive.aiscanner.scan.ScanPhases.position(cur) >= com.ioactive.aiscanner.scan.ScanPhases.position(target);
    }
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
        rescanBtn = new JButton("Rescan");
        rescanBtn.setToolTipText("Re-run the last scan target with current settings");
        rescanBtn.setEnabled(false);   // enabled only after first scan completes
        rescanBtn.addActionListener(e -> {
            String url = lastTarget;
            Consumer<String> h = rescanHandler;
            if (url != null && h != null) {
                rescanBtn.setEnabled(false);
                new Thread(() -> h.accept(url), "aiscanner-rescan").start();
            }
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> clear());
        JPanel labels = new JPanel(new GridLayout(2, 1));
        labels.add(phase);
        labels.add(status);
        top.add(labels, BorderLayout.CENTER);
        // Stop | Rescan | Clear — left to right.
        JPanel btns = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 4, 0));
        btns.add(stopBtn);
        btns.add(rescanBtn);
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

        panel.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        panel.add(top, BorderLayout.NORTH);
        scroll = new JScrollPane(area);
        // A JTextArea's DefaultCaret defaults to UPDATE_WHEN_ON_EDT: on every document insert it moves the caret
        // to track the change, which drags the viewport to the bottom — so append() ALONE scrolls you down even
        // when you've deliberately scrolled up to read. NEVER_UPDATE stops that; log() then pins to the bottom
        // EXPLICITLY (via the scrollbar) only when the user was already there.
        if (area.getCaret() instanceof javax.swing.text.DefaultCaret dc)
            dc.setUpdatePolicy(javax.swing.text.DefaultCaret.NEVER_UPDATE);
        panel.add(scroll, BorderLayout.CENTER);

        // Progress bar — sits in the SOUTH panel above the chat row (added later by enableChat).
        probeProgress.setStringPainted(true);
        probeProgress.setString("Idle");
        probeProgress.setVisible(false);   // hidden when no scan is running
        JPanel progressWrap = new JPanel(new BorderLayout());
        progressWrap.setBorder(BorderFactory.createEmptyBorder(2, 6, 0, 6));
        progressWrap.add(probeProgress, BorderLayout.CENTER);
        southPanel.add(progressWrap, BorderLayout.NORTH);
        panel.add(southPanel, BorderLayout.SOUTH);

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

    /** Returns the split-pane when the chat is enabled, or just the log panel before that. */
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

    /** Enable/disable the live file sink (Settings "Log to file" toggle, and startup for -Daiscanner.logFile).
     *  path null/blank closes it. Opens in APPEND mode so toggling on/off across a session keeps the transcript.
     *  Thread-safe; applied live with no restart. */
    public synchronized void setLogFile(String path) {
        String p = (path == null) ? "" : path.trim();
        if (!p.isEmpty() && p.equals(fileSinkPath) && fileSink != null) return;   // already open on this file
        if (fileSink != null) {
            log("file logging stopped (" + fileSinkPath + ")");
            try { fileSink.close(); } catch (Throwable ignore) { }
            fileSink = null; fileSinkPath = null;
        }
        if (p.isEmpty()) return;
        try {
            java.io.PrintWriter pw = new java.io.PrintWriter(new java.io.FileWriter(p, true), true);
            pw.println(LocalDateTime.now().format(TS) + " [AI Scanner] ==== log file opened ====");
            fileSink = pw; fileSinkPath = p;
            log("logging scan log + chat to file: " + p);
        } catch (Throwable e) {
            log("cannot open log file " + p + ": " + e);
        }
    }
    /** The active log-file path, or null when file logging is off. */
    public String logFilePath() { return fileSinkPath; }

    /** Always shown — reserve for phases, counts, and vulnerabilities. */
    public void log(String s) {
        touchProgress();   // every emitted line = scan progress → resets the stall watchdog clock
        String tag = TARGET_TAG.get();
        // Normalize: EVERY line carries the "[AI Scanner]" tag exactly once. Most callers embed it, but helpers
        // (e.g. scanned(), a few debug lines) pass a bare string — without this those render as "TS scanning …"
        // with no tag, breaking the log's uniform structure.
        String core = (s != null && s.startsWith("[AI Scanner]")) ? s : "[AI Scanner] " + (s == null ? "" : s);
        String line = LocalDateTime.now().format(TS) + " " + (tag != null ? tag : "") + core;
        mirror.accept(line);
        if (s.contains(">>>")) {
            findingsLog.add(s.replaceAll(".*>>>\\s*", "").trim());   // capture findings for the harness report (per-target)
            flushReport();   // persist immediately so a crash/OOM mid-scan doesn't lose findings already found
        }
        // Centralize the VISIBLE log into the ONE Agent tab: a parallel per-target ScanLog renders into the MAIN
        // (UI-attached) ScanLog's buffer + area, so the tab shows both targets interleaved (tagged) instead of split.
        // (The mirror above already sent this line to Burp's Output + the cell-log file on THIS per-target log.)
        (uiMirror != null ? uiMirror : this).render(line);
    }

    /** Buffer a formatted line and append it to THIS log's visible tab area (search-filtered, tail-following). */
    private void render(String line) {
        java.io.PrintWriter fs = fileSink;   // mirror EVERY line to the file sink (pre-filter: the file is the full log)
        if (fs != null) { try { fs.println(line); } catch (Throwable ignore) { } }
        lines.add(line);
        if (lines.size() > MAX_BUFFER_LINES + 512) {           // bulk-trim the buffer (amortized, front removal is O(n))
            synchronized (lines) {
                int drop = lines.size() - MAX_BUFFER_LINES;
                if (drop > 0) lines.subList(0, Math.min(drop, lines.size())).clear();
            }
        }
        if (!matches(line)) return;
        SwingUtilities.invokeLater(() -> {
            // Follow the tail ONLY when the user is already at (or near) the bottom. If they scrolled up to read,
            // appending must NOT yank the view back down — measured BEFORE the append.
            boolean atBottom = true;
            try {
                JScrollBar vb = scroll != null ? scroll.getVerticalScrollBar() : null;
                if (vb != null) atBottom = (vb.getValue() + vb.getVisibleAmount()) >= (vb.getMaximum() - 24);
            } catch (Throwable ignore) { }
            area.append(line + "\n");
            if (atBottom) {
                trimView();                                 // keep the visible document bounded → EDT stays responsive
                SwingUtilities.invokeLater(() -> {
                    JScrollBar vb = scroll != null ? scroll.getVerticalScrollBar() : null;
                    if (vb != null) vb.setValue(vb.getMaximum());
                });
            }
        });
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
        ScanLog um = uiMirror;
        if (um != null) um.externalFinding();   // parallel: reflect in the shared UI aggregate
    }

    /** Confirmed real vulnerabilities counted this session (used when audit.issues() is unavailable). */
    public int findingCount() { return findings.get(); }

    /** Precise phase status for the Agent system prompt: each phase labelled DONE / → RUNNING / pending.
     *  Derived from the authoritative ScanPhases registry — the model sees the EXACT list, not a guess. */
    public String phaseContext() {
        String cur = currentPhase;
        boolean active = scanActive;
        StringBuilder sb = new StringBuilder();
        boolean seenCurrent = false;
        for (com.ioactive.aiscanner.scan.ScanPhases.Phase p : com.ioactive.aiscanner.scan.ScanPhases.ALL) {
            String state;
            if (!active && lastStep == 0) {
                state = "pending";
            } else if (p.label.equalsIgnoreCase(cur) && active) {
                state = "→ RUNNING";
                seenCurrent = true;
            } else if (!seenCurrent && !p.label.equalsIgnoreCase(cur)) {
                state = "done";
            } else {
                state = "pending";
            }
            sb.append("  ").append(p.isAttack() ? "[module] " : "[phase]  ")
              .append(p.label).append(": ").append(state).append('\n');
        }
        sb.append("Current: ").append(cur).append(" | Scan active: ").append(active);
        return sb.toString();
    }

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

    /** Build and return the Agent (chat) panel — a standalone JPanel to be placed in its own tab.
     *  Submitted text goes to {@code onSubmit}; turns appear only here, never in the Log panel. */
    public JPanel buildChatPanel(java.util.function.Consumer<String> onSubmit) {
        // --- chat pane: renders each turn's markdown as HTML ---
        chatPane = new javax.swing.JEditorPane();
        chatPane.setEditable(false);
        chatPane.setContentType("text/html");
        chatPane.putClientProperty(javax.swing.JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        chatPane.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        if (chatPane.getCaret() instanceof javax.swing.text.DefaultCaret dc)
            dc.setUpdatePolicy(javax.swing.text.DefaultCaret.NEVER_UPDATE);
        // Copy strips the zero-width break opportunities we injected for wrapping, so selecting a wrapped
        // URL copies it clean (no invisible characters that would corrupt a paste into a terminal/browser).
        // Covers every copy path (Cmd/Ctrl+C, right-click menu, drag) since they all route through here.
        chatPane.setTransferHandler(new javax.swing.TransferHandler() {
            @Override protected java.awt.datatransfer.Transferable createTransferable(javax.swing.JComponent c) {
                String sel = ((javax.swing.text.JTextComponent) c).getSelectedText();
                return new java.awt.datatransfer.StringSelection(sel == null ? "" : sel.replace(ZWSP, ""));
            }
            @Override public int getSourceActions(javax.swing.JComponent c) { return COPY; }
        });
        renderChat();   // seed with the (empty) document skeleton
        chatScroll = new JScrollPane(chatPane);
        chatScroll.setBorder(boldTitle("Chat"));

        // --- input row (right panel, bottom) ---
        JTextField chatInput = new JTextField();
        chatInput.putClientProperty("JTextField.placeholderText", "ask the model or type 'scan <url>'…");
        JButton sendBtn = new JButton("Send");
        JPanel inputRow = new JPanel(new BorderLayout(4, 0));
        inputRow.setBorder(BorderFactory.createEmptyBorder(2, 6, 6, 6));
        inputRow.add(chatInput, BorderLayout.CENTER);
        inputRow.add(sendBtn, BorderLayout.EAST);
        // Terminal-style input history: submitted messages are remembered; ↑ walks back, ↓ walks forward
        // (↓ past the newest returns to an empty line). idx[0] == history.size() means "on the fresh line".
        final java.util.List<String> inHist = new java.util.ArrayList<>();
        final int[] idx = { 0 };
        Runnable go = () -> {
            String t = chatInput.getText().trim();
            if (!t.isEmpty()) {
                if (inHist.isEmpty() || !inHist.get(inHist.size() - 1).equals(t)) inHist.add(t);  // skip consecutive dup
                idx[0] = inHist.size();
                chatInput.setText("");
                onSubmit.accept(t);
            }
        };
        sendBtn.addActionListener(e -> go.run());
        chatInput.addActionListener(e -> go.run());
        chatInput.getInputMap().put(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_UP, 0), "histPrev");
        chatInput.getInputMap().put(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_DOWN, 0), "histNext");
        chatInput.getActionMap().put("histPrev", new javax.swing.AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) {
                if (idx[0] > 0) {
                    idx[0]--;
                    chatInput.setText(inHist.get(idx[0]));
                    chatInput.setCaretPosition(chatInput.getText().length());
                }
            }
        });
        chatInput.getActionMap().put("histNext", new javax.swing.AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) {
                if (idx[0] < inHist.size()) {
                    idx[0]++;
                    chatInput.setText(idx[0] == inHist.size() ? "" : inHist.get(idx[0]));
                    chatInput.setCaretPosition(chatInput.getText().length());
                }
            }
        });

        JPanel chatPanel = new JPanel(new BorderLayout());
        chatPanel.add(chatScroll, BorderLayout.CENTER);
        chatPanel.add(inputRow, BorderLayout.SOUTH);
        return chatPanel;
    }

    /** Clear all chat turns and re-render an empty pane. Called by the /clear command. */
    public void clearChat() {
        synchronized (chatTurns) { chatTurns.clear(); }
        javax.swing.SwingUtilities.invokeLater(this::renderChat);
    }

    /** Append a User or AI turn to the chat panel (right side only — not the scan log). Thread-safe.
     *  The turn's text is treated as markdown and rendered as HTML. */
    public void appendChat(String speaker, String text) {
        // Mirror the turn to stdout (Burp Output / the launcher log) so the conversation is observable from
        // outside the GUI — the pane itself stays the primary view. Kept out of the scan-log PANE on purpose.
        System.out.println("[chat " + speaker + "] " + (text == null ? "" : text));
        if (chatPane == null) { log("[" + speaker + "] " + text); return; }  // fallback before split is built (log→file sink)
        java.io.PrintWriter fs = fileSink;   // mirror chat to the file sink too, when "Log to file" is on
        if (fs != null) { try { fs.println(LocalDateTime.now().format(TS) + " [AI Scanner] [chat " + speaker + "] " + (text == null ? "" : text)); } catch (Throwable ignore) { } }
        synchronized (chatTurns) { chatTurns.add(new String[]{ speaker, text == null ? "" : text }); }
        javax.swing.SwingUtilities.invokeLater(() -> {
            renderChat();
            // auto-scroll chat to bottom
            javax.swing.JScrollBar vb = chatScroll.getVerticalScrollBar();
            if (vb != null) vb.setValue(vb.getMaximum());
        });
    }

    /** Re-render the whole chat transcript into the HTML pane. Cheap: chat turns are few. EDT-only. */
    private void renderChat() {
        StringBuilder b = new StringBuilder();
        b.append("<html><head><style>")
         .append("body{font-family:sans-serif;font-size:10px;margin:2px 4px;}")
         .append(".you{color:#3b78c3;font-weight:bold;}")
         .append(".ai{color:#177245;font-weight:bold;}")
         .append(".turn{margin:0 0 10px 0;}")
         .append("code{font-family:monospace;background:#eef;padding:0 2px;}")
         .append("pre{font-family:monospace;font-size:8px;background:#f4f4f4;padding:4px;margin:4px 0;}")
         .append("ul,ol{margin:2px 0 2px 18px;}")
         .append("</style></head><body>");
        synchronized (chatTurns) {
            for (String[] t : chatTurns) {
                boolean ai = "ai".equals(t[0]);
                String cls = ai ? "ai" : "you";
                String marker = ai ? "&bull;" : "&gt;";   // Claude Code CLI style: '>' for you, bullet for the agent
                b.append("<div class=\"turn\"><span class=\"").append(cls).append("\">")
                 .append(marker).append("</span> ")
                 .append(mdToHtml(t[1])).append("</div>");
            }
        }
        b.append("</body></html>");
        chatPane.setText(b.toString());
        // Autoscroll: defer to a nested invokeLater so it runs AFTER setText's re-layout — only then does
        // the vertical scrollbar report the NEW maximum. Pinning to max follows both your messages and the
        // model's replies to the bottom. (Reading max right after setText would use the stale pre-layout
        // value and never actually scroll.)
        final javax.swing.JScrollPane sc = chatScroll;
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (sc == null) return;   // seed render runs before chatScroll is assigned
            javax.swing.JScrollBar vb = sc.getVerticalScrollBar();
            if (vb != null) vb.setValue(vb.getMaximum());
        });
    }

    /** Titled border with a bold title, derived from the current default title font. */
    private static javax.swing.border.TitledBorder boldTitle(String title) {
        javax.swing.border.TitledBorder tb = BorderFactory.createTitledBorder(title);
        java.awt.Font f = tb.getTitleFont();
        if (f == null) f = javax.swing.UIManager.getFont("TitledBorder.font");
        if (f == null) f = new Font(Font.SANS_SERIF, Font.PLAIN, 12);
        tb.setTitleFont(f.deriveFont(Font.BOLD));
        return tb;
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Minimal, self-contained markdown → HTML for chat turns (no external deps). Handles fenced/inline
     *  code, bold, italic, headings, ordered/unordered lists, links, and paragraph breaks. HTML-escapes
     *  everything first so raw markup can't inject into the pane. */
    static String mdToHtml(String md) {
        if (md == null || md.isEmpty()) return "";
        try {
            return mdToHtml0(md);
        } catch (Throwable t) {
            // Fail safe: a malformed turn must never break the pane or leak raw markup — fall back to
            // HTML-escaped plain text with line breaks preserved.
            return escapeHtml(md).replace("\n", "<br>");
        }
    }

    // Sentinel delimiters wrapping an extracted code block's index. Control chars that never occur in LLM
    // text; scrubbed at the end so one can never reach the pane even if a fence is unbalanced.
    private static final char BLK_A = '\u0001', BLK_B = '\u0002';

    private static String mdToHtml0(String md) {
        // Pull fenced code blocks out first so their contents are not further formatted. Substitute a
        // sentinel, then swap the real <pre> blocks back in as the FINAL step via a global replace — so it
        // works whether the fence landed on its own line or mid-paragraph. (The previous " BLOCKn "/NUL
        // sentinel was removed by String.trim() before the restore check, leaking "BLOCK0" into output.)
        java.util.List<String> blocks = new java.util.ArrayList<>();
        java.util.regex.Matcher fm = java.util.regex.Pattern
                .compile("```[a-zA-Z0-9]*\\n?([\\s\\S]*?)```").matcher(md);
        StringBuffer pre = new StringBuffer();
        while (fm.find()) {
            blocks.add("<pre>" + escapeHtml(fm.group(1).strip()) + "</pre>");   // trim surrounding blank lines
            fm.appendReplacement(pre, java.util.regex.Matcher.quoteReplacement(BLK_A + "" + (blocks.size() - 1) + BLK_B));
        }
        fm.appendTail(pre);

        String[] lines = pre.toString().split("\n", -1);
        StringBuilder out = new StringBuilder();
        String listType = null;   // "ul" or "ol" while inside a list
        int li = 0;
        while (li < lines.length) {
            String line = lines[li];
            // --- GitHub-style table: a pipe row immediately followed by a |---|---| separator row ---
            if (isTableRow(line) && li + 1 < lines.length && isTableSep(lines[li + 1])) {
                if (listType != null) { out.append("</").append(listType).append('>'); listType = null; }
                out.append("<table border=\"1\" cellspacing=\"0\" cellpadding=\"3\">");
                out.append(tableRow(line, true));          // header
                li += 2;                                    // skip header + separator
                while (li < lines.length && isTableRow(lines[li])) {
                    out.append(tableRow(lines[li], false));
                    li++;
                }
                out.append("</table>");
                continue;
            }
            java.util.regex.Matcher h = java.util.regex.Pattern.compile("^(#{1,6})\\s+(.*)$").matcher(line);
            java.util.regex.Matcher ul = java.util.regex.Pattern.compile("^\\s*[-*]\\s+(.*)$").matcher(line);
            java.util.regex.Matcher ol = java.util.regex.Pattern.compile("^\\s*\\d+[.)]\\s+(.*)$").matcher(line);
            if (h.matches()) {
                if (listType != null) { out.append("</").append(listType).append('>'); listType = null; }
                int level = Math.min(6, h.group(1).length());
                out.append("<h").append(level).append('>').append(inline(h.group(2)))
                   .append("</h").append(level).append('>');
            } else if (ul.matches()) {
                if (!"ul".equals(listType)) {
                    if (listType != null) out.append("</").append(listType).append('>');
                    out.append("<ul>"); listType = "ul";
                }
                out.append("<li>").append(inline(ul.group(1))).append("</li>");
            } else if (ol.matches()) {
                if (!"ol".equals(listType)) {
                    if (listType != null) out.append("</").append(listType).append('>');
                    out.append("<ol>"); listType = "ol";
                }
                out.append("<li>").append(inline(ol.group(1))).append("</li>");
            } else if (line.trim().isEmpty()) {
                if (listType != null) { out.append("</").append(listType).append('>'); listType = null; }
                out.append("<br>");
            } else {
                if (listType != null) { out.append("</").append(listType).append('>'); listType = null; }
                out.append(inline(line)).append("<br>");
            }
            li++;
        }
        if (listType != null) out.append("</").append(listType).append('>');
        // Restore fenced blocks; a global replace handles standalone and inline placeholders alike.
        String html = out.toString();
        for (int i = 0; i < blocks.size(); i++)
            html = html.replace(BLK_A + "" + i + BLK_B, blocks.get(i));
        // Scrub any orphan sentinel (e.g. an unbalanced fence) so a control char never reaches the pane.
        html = html.replace(String.valueOf(BLK_A), "").replace(String.valueOf(BLK_B), "");
        return html;
    }

    /** A markdown table separator row, e.g. {@code |---|:--:|---|} — only pipes/dashes/colons/space, ≥1 dash. */
    private static boolean isTableSep(String l) {
        String t = l.trim();
        return t.indexOf('-') >= 0 && t.matches("\\|?[\\s:|-]+\\|?");
    }

    /** A table row: contains a pipe, has some non-pipe content, and is not itself a separator row. */
    private static boolean isTableRow(String l) {
        String t = l.trim();
        return t.indexOf('|') >= 0 && !t.replace("|", "").trim().isEmpty() && !isTableSep(l);
    }

    /** Render one markdown table row as {@code <tr>} of {@code <th>}/{@code <td>} cells (inline-formatted). */
    private static String tableRow(String l, boolean header) {
        String t = l.trim();
        if (t.startsWith("|")) t = t.substring(1);
        if (t.endsWith("|"))   t = t.substring(0, t.length() - 1);
        String tag = header ? "th" : "td";
        StringBuilder r = new StringBuilder("<tr>");
        for (String c : t.split("\\|", -1))
            r.append('<').append(tag).append('>').append(inline(c.trim())).append("</").append(tag).append('>');
        return r.append("</tr>").toString();
    }

    /** Inline markdown spans: escape HTML, then code / bold / italic / links, then soft-break long tokens. */
    private static String inline(String s) {
        s = escapeHtml(s);
        s = s.replaceAll("`([^`]+)`", "<code>$1</code>");
        s = s.replaceAll("\\*\\*([^*]+)\\*\\*", "<b>$1</b>");
        s = s.replaceAll("__([^_]+)__", "<b>$1</b>");
        s = s.replaceAll("(?<![\\w*])\\*([^*\\s][^*]*?)\\*(?![\\w*])", "<i>$1</i>");
        s = s.replaceAll("(?<![\\w_])_([^_\\s][^_]*?)_(?![\\w_])", "<i>$1</i>");   // _italic_ (guarded vs some_var)
        s = s.replaceAll("\\[([^\\]]+)\\]\\((https?://[^)\\s]+)\\)", "<a href=\"$2\">$1</a>");
        s = softBreakTextNodes(s);
        return s;
    }

    /** Zero-width space: inserted as a break OPPORTUNITY inside long unbroken tokens (URLs/hashes) so the
     *  HTML pane can wrap them — Swing's HTMLEditorKit ignores CSS word-break/overflow-wrap. It is stripped
     *  back out on copy (see the TransferHandler in enableChat), so selecting a wrapped URL yields it clean. */
    static final String ZWSP = "​";

    /** Insert ZWSP after break-friendly characters inside long tokens, operating ONLY on text between tags
     *  (never inside a tag or an href attribute) so generated markup and link targets stay intact. */
    private static String softBreakTextNodes(String html) {
        StringBuilder out = new StringBuilder(html.length() + 32);
        StringBuilder token = new StringBuilder();
        boolean inTag = false;
        for (int i = 0; i < html.length(); i++) {
            char c = html.charAt(i);
            if (inTag) { out.append(c); if (c == '>') inTag = false; continue; }
            if (c == '<') { flushToken(token, out); inTag = true; out.append(c); continue; }
            // Whitespace and '&' (entity start) end the current token without breaking inside it.
            if (Character.isWhitespace(c) || c == '&') { flushToken(token, out); out.append(c); continue; }
            token.append(c);
        }
        flushToken(token, out);
        return out.toString();
    }

    private static void flushToken(StringBuilder token, StringBuilder out) {
        if (token.length() == 0) return;
        String t = token.toString();
        token.setLength(0);
        if (t.length() < 24) { out.append(t); return; }   // short tokens (normal prose) untouched
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            out.append(c);
            if (i < t.length() - 1 && "-./_?=@:;,".indexOf(c) >= 0) out.append(ZWSP);
        }
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
        log(">>> VULNERABILITY: " + vulnClass + "  @ " + url
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

    /** Set the current activity from a raw title (lifecycle phases emit these); classified against ScanPhases. */
    public void phase(String s) { phaseInternal(s, com.ioactive.aiscanner.scan.ScanPhases.match(s == null ? "" : s)); }

    /** Set the current activity from a ScanPhases entry — the data-driven attack battery calls THIS, so the phase
     *  identity comes straight from the registry (no title string to drift, no match() to guess). */
    public void phase(com.ioactive.aiscanner.scan.ScanPhases.Phase p) { phaseInternal(p == null ? "Idle" : p.label, p); }

    private void phaseInternal(String s, com.ioactive.aiscanner.scan.ScanPhases.Phase cp) {
        // Single-point stop: every probe calls phase() first, so throwing here unwinds the current probe and the
        // whole remaining battery drains (each subsequent phase() throws again → body skipped) with no per-probe
        // checkpoint. Thrown only after the user hit Stop; a normal run never trips it.
        java.util.function.BooleanSupplier sc = stopCheck;
        if (sc != null && sc.getAsBoolean()) throw new ScanStopped();
        currentPhase = (s == null || s.isBlank()) ? "Idle" : s;
        Runnable pcl = phaseChangeListener; if (pcl != null) SwingUtilities.invokeLater(pcl);
        // Module selector for fast debugging: -Daiscanner.only=rxss,sqli runs ONLY the selected ATTACK phases;
        // lifecycle phases (crawl/auth/discovery/audit) always run. Each attack probe is wrapped in its own
        // try/catch(Throwable), so throwing PhaseSkipped skips just that phase and the battery drains on.
        String only = moduleFilter();
        if (only != null && cp != null && cp.isAttack() && cp.key != null) {
            boolean match = false;
            for (String k : only.split(",")) { if (cp.key.equalsIgnoreCase(k.trim())) { match = true; break; } }
            if (!match) {
                if (!filterAnnounced) {   // announce the active filter ONCE, then just mark each skip tersely
                    filterAnnounced = true;
                    log("module filter active: -Daiscanner.only=" + only + " — skipping all non-selected probe phases");
                }
                log("── " + currentPhase + "  (skip)");
                throw new PhaseSkipped();
            }
        }
        log("── " + currentPhase);
        updatePhase();
        // The step NUMBER is the phase's position among the phases that ACTUALLY RUN under the active -Daiscanner.only
        // filter, over the count of those phases — both derived from the ONE ScanPhases registry. With NO filter this
        // equals the phase's absolute registry position, so the status-bar step still matches the Settings "Modules"
        // panel row for row (no emission-order to sync). Under only= it is the ordinal within just the executed subset
        // (e.g. cswsh → 8/11, not its absolute 40/44). A transient sub-status (cp == null) keeps the step, refreshes text.
        if (cp != null) {
            // MONOTONIC: never let the step number REGRESS. A LIFECYCLE phase legitimately re-runs mid-scan — the
            // authenticated re-crawl, a mid-scan re-auth, a second "AI endpoint discovery" pass — and its early
            // registry position would otherwise snap the bar backwards (observed: ~25/46 → 2/46 when discovery
            // re-ran). Clamp to the furthest phase reached so the bar only ever advances. The LABEL below still
            // shows the current (re-entered) activity; only the numeric progress is pinned forward.
            // When a lifecycle-only denominator is in force (SAST mode sets phaseTotal=lifecycleCount), count the
            // numerator among lifecycle phases too, so a post-attack phase can't read past the total (the "44/10").
            int posInScheme = phaseTotal > 0
                    ? com.ioactive.aiscanner.scan.ScanPhases.lifecyclePosition(cp)
                    : com.ioactive.aiscanner.scan.ScanPhases.filteredPosition(cp, only);
            lastStep = Math.max(lastStep, posInScheme);
            // Track distinct phases entered so the scan-end block can flip the bar to "Complete ✓" (it gates on
            // phaseSeen>0) and learn the real phase count. The DISPLAYED step is lastStep above, not this.
            if (countedPhases.add(String.valueOf(com.ioactive.aiscanner.scan.ScanPhases.position(cp)))) phaseSeen.incrementAndGet();
        }
        int done = lastStep;
        int total = phaseTotal > 0 ? phaseTotal : com.ioactive.aiscanner.scan.ScanPhases.filteredTotal(only);
        int pct = total > 0 ? Math.min(100, done * 100 / total) : 0;
        String label = done + "/" + total + " — " + (cp != null ? cp.label : currentPhase);
        if (label.length() > 60) label = label.substring(0, 57) + "…";
        final String barLabel = label;
        javax.swing.SwingUtilities.invokeLater(() -> {
            probeProgress.setValue(pct);
            probeProgress.setString(barLabel);
            probeProgress.setVisible(true);
        });
        ScanLog um = uiMirror;   // parallel: drive the ONE status bar with a LABELED per-target segment
        if (um != null) um.externalProgress(TARGET_TAG.get(), done, total, cp != null ? cp.label : currentPhase);
    }

    /** Driven by a parallel per-target ScanLog to keep the shared UI status bar live (tagged activity + progress). */
    public void externalProgress(String tag, int done, int total, String phaseLabel) {
        String t = (tag == null || tag.trim().isEmpty()) ? "scan" : tag.trim();
        parProgress.put(t, new int[]{done, total});
        parPhase.put(t, phaseLabel == null ? "" : phaseLabel);
        StringBuilder sb = new StringBuilder();
        int sumPct = 0, n = 0;
        for (java.util.Map.Entry<String, int[]> e : parProgress.entrySet()) {
            int d = e.getValue()[0], tot = e.getValue()[1];
            int p = tot > 0 ? Math.min(100, d * 100 / tot) : 0;
            sumPct += p; n++;
            if (sb.length() > 0) sb.append("   ·   ");
            sb.append(e.getKey()).append(' ').append(d).append('/').append(tot)
              .append(' ').append(parPhase.getOrDefault(e.getKey(), ""));
        }
        final int avg = n > 0 ? sumPct / n : 0;
        final String status = sb.toString();
        SwingUtilities.invokeLater(() -> {
            probeProgress.setValue(avg);
            probeProgress.setString(status);   // e.g. "[localhost:3005] 12/44 SQLi   ·   [localhost:4000] 9/44 XSS"
            probeProgress.setVisible(true);
            phase.setText("Current activity: " + status);
        });
    }
    /** Bump the shared UI findings counter for a parallel per-target finding (aggregate across targets). */
    public void externalFinding() { findings.incrementAndGet(); updateStatus(); }

    public void clear() {
        scanned.set(0);
        findings.set(0);
        lines.clear();
        boolean idle = !scanActive;   // don't wipe a LIVE scan's progress — only reset the advancement UI when idle
        if (idle) { phaseSeen.set(0); countedPhases.clear(); lastStep = 0; }
        SwingUtilities.invokeLater(() -> {
            area.setText("");
            if (idle) {   // a stale progress bar after Clear is meaningless → reset + hide it and the phase label
                probeProgress.setValue(0);
                probeProgress.setString("Idle");
                probeProgress.setVisible(false);
                phase.setText(" ");
            }
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
