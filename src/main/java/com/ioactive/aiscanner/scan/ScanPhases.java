package com.ioactive.aiscanner.scan;

import java.util.List;

/**
 * SINGLE SOURCE OF TRUTH for the scan's phases / attack modules. Both the Settings "Modules" panel (labels +
 * which entries are filterable attack modules) AND the status-bar step counter (which emitted titles are
 * canonical steps vs transient sub-status) derive from this ONE ordered list — so adding or removing a probe
 * updates the UI, the progress total, and the phase classification together, with nothing to keep in sync by hand.
 *
 * <p>Each {@link Phase} carries a lowercase {@code titleMatch} substring so the DESCRIPTIVE {@code scanLog.phase("…")}
 * strings the scanner emits (e.g. {@code "SSRF probe (OAST / Collaborator)"}) map back to their canonical phase
 * ({@code ssrf}) without forcing the call sites to pass short keys. A title that matches NOTHING here is a transient
 * sub-status (a mid-scan re-auth, per-security-level audit tick, terminal idle) and is deliberately not a step.</p>
 */
public final class ScanPhases {

    public enum Section { BEFORE, ATTACK, AFTER }

    public static final class Phase {
        /** Filter key for {@code -Daiscanner.only=…}; null for a lifecycle phase (never skippable). */
        public final String key;
        /** Settings-panel label. */
        public final String label;
        public final Section section;
        /** Lowercase substring of the emitted phase() title this phase represents (must be unique across phases). */
        public final String titleMatch;
        Phase(String key, String label, Section section, String titleMatch) {
            this.key = key; this.label = label; this.section = section; this.titleMatch = titleMatch;
        }
        public boolean isAttack() { return section == Section.ATTACK; }
    }

    private static Phase pre(String label, String m)  { return new Phase(null, label, Section.BEFORE, m); }
    private static Phase post(String label, String m) { return new Phase(null, label, Section.AFTER, m); }
    private static Phase atk(String key, String label, String m) { return new Phase(key, label, Section.ATTACK, m); }

    /** Canonical, execution-ordered phase list. {@code titleMatch} must be a UNIQUE substring of the phase title. */
    public static final List<Phase> ALL = List.of(
        // ---- pre-attack lifecycle (always run; listed for visibility, never skipped by the module filter) ----
        //      LISTED IN ACTUAL EXECUTION ORDER (verified against a live run's ── phase markers) so the Settings
        //      panel's step order == the status-bar step order: crawl → discovery → register → auth → re-crawl →
        //      submit → SAST (SAST runs in scanDiscovered, just before the attack battery).
        pre("Native crawl", "crawling"),
        pre("Endpoint discovery (JS/HTML/OpenAPI mining)", "endpoint discovery"),
        pre("Automatic user registration (disposable mailbox)", "automatic user registration"),
        pre("Authentication (default credentials / SQLi-bypass)", "authenticating"),
        pre("Authenticated re-crawl + form exercise", "re-crawling"),
        pre("Submit discovered requests to active audit", "submitting discovered"),
        pre("Source analysis (SAST — route/sink harvest, when a source repo is set)", "source analysis"),
        // ---- attack modules (the filterable probe battery) ----
        atk("agentflow",  "Agent-flow (LLM)",                 "agent-flow"),
        atk("llmfuzz",    "LLM-fuzz (LLM)",                    "llm-fuzz"),
        atk("csrf",       "CSRF",                              "csrf probe"),
        atk("redirect",   "Open-redirect",                     "open-redirect"),
        atk("oauth",      "OAuth-logic",                       "oauth-logic"),
        atk("sqli",       "Blind SQLi",                        "blind sqli"),
        atk("rxss",       "Reflected-XSS (breakout + WAF-evasion)", "reflected-xss"),
        atk("sxss",       "Stored-XSS (create→view)",          "stored-xss"),
        atk("pathtrav",   "Path-reflection",                   "path reflection"),
        atk("nosql",      "NoSQL injection",                   "nosql"),
        atk("cmdi",       "Command injection",                 "command injection"),
        atk("ssti",       "Server-Side Template Injection",    "server-side template"),
        atk("chain",      "Create->consume chain (leak replay)", "consume chain"),
        atk("bodymut",    "Body-mutation",                     "body-mutation"),
        atk("fileserve",  "File-serve bypass",                 "file-serve"),
        atk("idor",       "IDOR",                              "idor probe"),
        atk("bolawrite",  "BOLA write (cross-user PUT)",       "bola write"),
        atk("massassign", "Mass-assignment (priv-diff)",       "mass-assignment"),
        atk("bfla",       "BFLA",                              "bfla"),
        atk("jwt",        "JWT analysis",                      "jwt analysis"),
        atk("unauth",     "Unauthenticated-access",            "unauthenticated-access"),
        atk("webhook",    "Webhook fail-open",                 "webhook"),
        atk("privparity", "Privilege-parity",                  "privilege-parity"),
        atk("secrets",    "Response secret-exposure",          "secret-exposure"),
        atk("graphql",    "GraphQL",                           "graphql probe"),
        atk("deser",      "Insecure deserialization",          "deserial"),
        atk("xxe",        "Blind XXE (OOB)",                   "xxe"),
        atk("saml",       "SAML SSO",                          "saml"),
        atk("verberr",    "Verbose-error / stack-trace",       "verbose-error"),
        atk("lfi",        "Path-traversal / LFI",              "traversal / lfi"),
        atk("ssrf",       "SSRF",                              "ssrf probe"),
        atk("log4shell",  "Log4Shell / JNDI (OOB)",            "log4shell"),
        atk("tamper",     "Restriction-bypass / tampering",    "tampering"),
        atk("cswsh",      "WebSocket CSWSH (cross-site hijack)", "websocket cswsh"),
        atk("wsfuzz",     "WebSocket message fuzzing (SQLi/XSS/SSTI/…)", "websocket fuzz"),
        atk("flow",       "Flow-engine (LLM, multi-step)",     "flow-engine"),
        // ---- post-attack lifecycle ----
        post("Audit login/signin pages (separate pass)", "auditing login"),
        post("Native Burp active audit",                 "auditing at"),
        post("Benchmark tally",                          "benchmark tally")
    );

    /** Map an emitted phase() title to its canonical phase — or null when the title is a transient sub-status. */
    public static Phase match(String emittedTitle) {
        if (emittedTitle == null) return null;
        String s = emittedTitle.toLowerCase();
        for (Phase p : ALL) if (s.contains(p.titleMatch)) return p;
        return null;
    }

    /** The attack modules in execution order — the data-driven battery iterates exactly this (see AiScanner). */
    public static List<Phase> attackModules() {
        java.util.List<Phase> out = new java.util.ArrayList<>();
        for (Phase p : ALL) if (p.isAttack()) out.add(p);
        return out;
    }

    /** 1-based position of a phase in the registry — the SAME ordinal the Settings panel shows for it, so the
     *  status-bar step number is derived from this one list (not an emission counter that could disagree). */
    public static int position(Phase p) { int i = ALL.indexOf(p); return i < 0 ? 0 : i + 1; }

    /** 1-based position of {@code p} among ONLY the lifecycle (non-attack) phases; 0 if p is an attack phase.
     *  SAST-only mode runs no attack battery and caps the status-bar denominator to {@link #lifecycleCount()},
     *  so the numerator must count lifecycle phases too — otherwise a post-attack phase's absolute index (e.g.
     *  "Auditing login/signin" = 44) shows against the 10-phase total → the nonsensical "44/10". */
    public static int lifecyclePosition(Phase p) {
        if (p == null || p.isAttack()) return 0;
        int n = 0;
        for (Phase q : ALL) { if (!q.isAttack()) { n++; if (q == p) return n; } }
        return 0;
    }

    /** Does this phase run given a {@code -Daiscanner.only=} filter? Lifecycle phases (null key) always run; an
     *  attack phase runs only if its key is listed. Null/blank filter → everything runs. */
    public static boolean runsUnderFilter(Phase p, String only) {
        if (only == null || only.isBlank()) return true;
        if (p == null) return false;
        if (!p.isAttack() || p.key == null) return true;
        for (String k : only.toLowerCase().split(",")) if (p.key.equalsIgnoreCase(k.trim())) return true;
        return false;
    }

    /** 1-based position of {@code p} among the phases that RUN under the filter (registry order); 0 if p won't run.
     *  With no filter this equals {@link #position} (so the status bar still matches the Modules panel row for row);
     *  under {@code only=} it is the ordinal within just the executed subset (e.g. cswsh → 8, not its absolute 40). */
    public static int filteredPosition(Phase p, String only) {
        if (!runsUnderFilter(p, only)) return 0;
        int n = 0;
        for (Phase q : ALL) { if (runsUnderFilter(q, only)) { n++; if (q == p) return n; } }
        return n;
    }

    /** Count of phases that run under the filter — the status-bar denominator (full total with no filter). */
    public static int filteredTotal(String only) {
        int n = 0; for (Phase q : ALL) if (runsUnderFilter(q, only)) n++; return n;
    }

    public static int totalPhases()   { return ALL.size(); }
    public static int attackCount()   { int n = 0; for (Phase p : ALL) if (p.isAttack()) n++; return n; }
    public static int lifecycleCount(){ return ALL.size() - attackCount(); }
}
