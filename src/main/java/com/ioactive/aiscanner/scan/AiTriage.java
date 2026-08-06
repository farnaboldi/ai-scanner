package com.ioactive.aiscanner.scan;

import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.ioactive.aiscanner.ui.ScanLog;

/**
 * Real-time findings in the AI Scanner log, straight from Burp as it confirms them. Registered
 * globally (so late OOB/Collaborator findings still surface after our monitor loop ends),
 * but filtered by {@link ScanScope} to the hosts WE are scanning — so unrelated background
 * traffic Burp audits never contaminates the log. INFO → shown with a lesser marker (not
 * counted as a finding); real vulns → prominent and counted.
 */
public final class AiTriage implements AuditIssueHandler {

    private final ScanLog scanLog;
    private final ScanScope scope;
    // Dedup: Burp re-reports the same issue across passes (main audit + the separate login audit, confidence
    // upgrades, …). Log + count each unique issue ONCE. AiTriage is the single real-time logger for
    // Burp-native issues (reportNewIssues / the end-of-scan recap were removed to stop double-logging).
    private final java.util.Set<String> seen = java.util.concurrent.ConcurrentHashMap.newKeySet();

    public AiTriage(ScanLog scanLog, ScanScope scope) {
        this.scanLog = scanLog;
        this.scope = scope;
    }

    @Override
    public void handleNewAuditIssue(AuditIssue issue) {
        try {
            if (!scope.contains(issue.baseUrl())) return;   // only hosts we're scanning
            // Our OWN findings are added to the site map named "AI: …" (see AiScannerExtension.raiseAiIssue);
            // they are already logged + counted at their source, so don't double-handle them here. This
            // handler exists for Burp-NATIVE issues.
            if (issue.name() != null && issue.name().startsWith("AI:")) return;
            String line = format(issue);
            // Zero-FP discipline: only FIRM/CERTAIN native issues become COUNTED findings in the report.
            // INFORMATION and TENTATIVE (Burp's own low-confidence guesses) are shown for the analyst with a
            // lesser marker but NOT counted and NOT written to the findings report — and NOT marked seen, so a
            // later confidence upgrade (TENTATIVE→FIRM) can still be reported as a real finding.
            if (issue.severity() == AuditIssueSeverity.INFORMATION
                    || issue.confidence() == AuditIssueConfidence.TENTATIVE) {
                scanLog.log("[AI Scanner]  ·  " + line);
                return;
            }
            if (!seen.add(issue.severity() + "|" + issue.name() + "|" + issue.baseUrl())) return;   // once per unique issue
            scanLog.log("[AI Scanner] >>> " + line);            // real vuln → prominent + counted + in report
            scanLog.incFinding();
        } catch (Throwable t) {
            // best-effort; never disrupt Burp's issue flow
        }
    }

    /** Uniform, column-aligned finding line: "SEV   (CONF)  name @ url". */
    static String format(AuditIssue issue) {
        return String.format("%-5s (%s)  %s @ %s",
                shortSeverity(issue.severity()), issue.confidence(), issue.name(), issue.baseUrl());
    }

    static String shortSeverity(AuditIssueSeverity s) {
        switch (s) {
            case HIGH: return "HIGH";
            case MEDIUM: return "MED";
            case LOW: return "LOW";
            case FALSE_POSITIVE: return "FP";
            default: return "INFO";
        }
    }
}
