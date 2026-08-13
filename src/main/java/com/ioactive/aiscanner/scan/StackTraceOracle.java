package com.ioactive.aiscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.regex.Pattern;

/**
 * Shared, STRONG, zero-FP stack-trace / verbose-error oracle. Used by {@link SamlProbe} (SAML routes) and
 * {@link VerboseErrorProbe} (host-wide) so the disclosure detection is defined once. Fires only on a real stack
 * frame paired with an exception token, OR an unmistakable framework error-page signature — a bare generic 500
 * (custom error page, no frames) does NOT match.
 */
final class StackTraceOracle {
    private StackTraceOracle() {}

    /** A real stack frame: `at Namespace.Class.Method(` (.NET/Java) — deliberately narrow to avoid prose matches. */
    static final Pattern STACK_FRAME = Pattern.compile("at [A-Za-z_][A-Za-z0-9_.]+\\.[A-Za-z0-9_]+\\(");
    /** An exception type token, or a Python traceback header. */
    static final Pattern EXCEPTION_TOKEN = Pattern.compile("(?i)\\b([A-Za-z0-9_.]*Exception|Traceback \\(most recent call last\\))\\b");
    /** Framework error-page signatures that are themselves conclusive (ASP.NET yellow-screen, etc.). */
    static final Pattern FRAMEWORK_ERR = Pattern.compile("(?i)Server Error in |ASP\\.NET Version:|Stack Trace:");

    /** True on (a real stack frame AND an exception token) OR a framework error-page signature. */
    static boolean hasStackTrace(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String body;
        try { body = rr.response().bodyToString(); } catch (Throwable t) { return false; }
        if (body == null || body.isEmpty()) return false;
        boolean frame = STACK_FRAME.matcher(body).find() && EXCEPTION_TOKEN.matcher(body).find();
        return frame || FRAMEWORK_ERR.matcher(body).find();
    }
}
