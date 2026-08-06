package com.ioactive.aiscanner.scan;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Human-readable advisory text for the AI Scanner's own findings, keyed by vuln class. Gives each raised
 * Burp AuditIssue a real severity + background + remediation (instead of a bare one-liner). Matched by
 * keyword against the class name the probes/flow-engine emit — generic, no per-app content.
 */
public final class IssueLibrary {

    public static final class Info {
        public final AuditIssueSeverity severity;
        public final String background;    // HTML — what the issue is / why it matters
        public final String remediation;   // HTML — how to fix it
        Info(AuditIssueSeverity severity, String background, String remediation) {
            this.severity = severity; this.background = background; this.remediation = remediation;
        }
    }

    private static final AuditIssueSeverity HIGH = AuditIssueSeverity.HIGH;
    private static final AuditIssueSeverity MEDIUM = AuditIssueSeverity.MEDIUM;
    private static final AuditIssueSeverity LOW = AuditIssueSeverity.LOW;

    public static Info describe(String vulnClass) {
        String v = vulnClass == null ? "" : vulnClass.toLowerCase();

        if (v.contains("nosql"))
            return new Info(HIGH,
                "<p>The application builds a NoSQL (e.g. MongoDB) query from request data without separating "
                + "data from query structure. Substituting a query operator such as <code>{\"$ne\":null}</code> "
                + "or <code>{\"$regex\":\".*\"}</code> for a literal value changes the query's meaning &mdash; "
                + "letting an attacker bypass filters, read other users' records, or authenticate without valid "
                + "credentials.</p>",
                "<p>Never interpolate request data into a query as structure. Reject non-string values where a "
                + "string is expected (e.g. a JSON object in place of a coupon code), validate/cast types "
                + "server-side, and use the database driver's typed query APIs. Enforce a strict schema on "
                + "request bodies so operator objects are rejected before they reach the database.</p>");

        if (v.contains("sql"))
            return new Info(HIGH,
                "<p>User input is concatenated into a SQL statement, so crafted input alters the query logic. "
                + "This can expose or modify arbitrary data, bypass authentication, or (with stacked queries) "
                + "change the database. Detected via boolean/differential responses to true-vs-false payloads "
                + "(or a time delay), not mere reflection.</p>",
                "<p>Use parameterised queries / prepared statements for every database call; never build SQL by "
                + "string concatenation. Apply least-privilege database accounts and validate input types and "
                + "ranges server-side.</p>");

        if (v.contains("idor") || v.contains("direct object") || v.contains("object-level") || v.contains("bfla") || v.contains("function level"))
            return new Info(HIGH,
                "<p>The endpoint returns or acts on an object identified by a client-supplied id without checking "
                + "that the caller owns or may access that object. Enumerating the id therefore exposes other "
                + "users' data or lets the caller act on resources that are not theirs (Broken Object-Level / "
                + "Function-Level Authorization).</p>",
                "<p>Enforce an authorization check on every object access: verify the authenticated principal is "
                + "permitted to act on the specific object, server-side, for reads and writes alike. Prefer "
                + "unguessable identifiers as defence-in-depth, but never rely on them in place of an "
                + "authorization check.</p>");

        if (v.contains("mass assignment") || v.contains("input validation"))
            return new Info(HIGH,
                "<p>The endpoint binds request fields straight onto server-side state without a whitelist or "
                + "range validation, so a client can set fields it should not control or push values out of "
                + "range (e.g. a negative quantity that increases an account balance instead of decreasing it).</p>",
                "<p>Bind only an explicit allow-list of client-settable fields; never mass-bind the whole request "
                + "onto a domain/entity object. Validate numeric ranges and business invariants server-side "
                + "(reject negative quantities, recompute totals/credit on the server).</p>");

        if (v.contains("path traversal") || v.contains("file inclusion") || v.contains("lfi") || v.contains("sensitive file"))
            return new Info(HIGH,
                "<p>A file path or resource name is taken from request input, so sequences like "
                + "<code>../</code> (or extension/null-byte tricks) let the caller read files outside the "
                + "intended directory &mdash; confirmed by a recognizable OS-file signature in the response.</p>",
                "<p>Do not build filesystem paths from user input. Resolve the canonical path and confirm it "
                + "stays within an allowed base directory, map requests to an allow-list of known resources, and "
                + "run with least-privilege filesystem permissions.</p>");

        if (v.contains("open redirect"))
            return new Info(LOW,
                "<p>A redirect target is taken from request input without validation, so the application will "
                + "redirect users to an attacker-controlled host &mdash; useful for phishing and for stealing "
                + "OAuth tokens/credentials that ride on the redirect.</p>",
                "<p>Redirect only to an allow-list of internal paths/hosts, or map an opaque token to the target "
                + "server-side. Reject absolute URLs and protocol-relative (<code>//host</code>) values.</p>");

        if (v.contains("restriction bypass") || v.contains("parameter tampering"))
            return new Info(MEDIUM,
                "<p>Controls enforced only in the client (option lists, maxlength, format/regex validation, "
                + "read-only or computed fields) are not re-checked server-side, so a request that violates them "
                + "is accepted &mdash; the client-side control provides no real protection.</p>",
                "<p>Re-validate every constraint on the server: allowed option values, lengths, formats, "
                + "read-only fields, and any computed totals. Treat client-side validation purely as a UX aid.</p>");

        // Server hands the client the answer to its own verification challenge (captcha/puzzle).
        if (v.contains("challenge") || v.contains("discloses the answer"))
            return new Info(MEDIUM,
                "<p>A verification challenge (e.g. a captcha or puzzle the client is meant to SOLVE) is returned by "
                + "the server together with its own answer, so the check can be passed without solving it — the "
                + "verification provides no protection (CWE-345, insufficient verification of data authenticity).</p>",
                "<p>Never send the expected answer to the client. Keep the solution server-side, accept the client's "
                + "submitted answer, and compare on the server; for bot protection use a vetted captcha the client "
                + "cannot read the answer to.</p>");

        // Token EXPIRATION / lifetime — distinct from signature verification (do NOT describe as alg:none).
        if (v.contains("expiry") || v.contains("lifetime") || v.contains("no exp"))
            return new Info(MEDIUM,
                "<p>A session/bearer JSON Web Token is issued without an expiry (<code>exp</code>) claim, or with an "
                + "excessively long lifetime. A token that never (or slowly) expires stays valid indefinitely, so a "
                + "token captured from logs, a proxy, browser storage, or a referrer header can be replayed long "
                + "after the session should have ended (CWE-613).</p>",
                "<p>Issue short-lived access tokens with an <code>exp</code> claim (minutes), pair them with a "
                + "separately-revocable refresh token, and reject tokens without a valid <code>exp</code>. Support "
                + "server-side revocation/rotation so a leaked token can be invalidated.</p>");

        // Sensitive data readable in a (signed, NOT encrypted) token payload.
        if (v.contains("sensitive data") && v.contains("jwt"))
            return new Info(MEDIUM,
                "<p>A JSON Web Token is signed but NOT encrypted — its payload is only base64url-encoded, so anyone "
                + "who obtains the token can read every claim. Placing secrets or PII (passwords, keys, card/account "
                + "numbers) in the payload discloses them to any holder of the token (CWE-312).</p>",
                "<p>Keep secrets and PII out of the token payload; carry only opaque identifiers and look up "
                + "sensitive data server-side. If confidential data must travel in the token, use an encrypted JWE.</p>");

        if (v.contains("jwt"))
            return new Info(HIGH,
                "<p>The service accepts JSON Web Tokens whose signature it does not properly verify (e.g. the "
                + "<code>none</code> algorithm, a fetched <code>jku</code>/<code>kid</code>, or a weak key), so "
                + "an attacker can forge a token and impersonate any user.</p>",
                "<p>Pin the accepted algorithm(s) to what you issue, reject <code>alg:none</code>, do not fetch "
                + "keys from token-controlled URLs (<code>jku</code>/<code>x5u</code>), verify the signature with "
                + "a strong secret/key, and validate standard claims (iss/aud/exp).</p>");

        if (v.contains("credential"))
            return new Info(HIGH,
                "<p>An account is usable with default or weak credentials, giving an attacker authenticated "
                + "access with no real barrier.</p>",
                "<p>Remove or rotate default accounts, enforce strong unique passwords, add rate limiting and "
                + "lockout on authentication, and offer MFA.</p>");

        return new Info(MEDIUM,
            "<p>Reported by the AI Scanner extension after observing a deterministic server-side effect from a "
            + "benign proof payload.</p>", "");
    }

    private IssueLibrary() { }
}
