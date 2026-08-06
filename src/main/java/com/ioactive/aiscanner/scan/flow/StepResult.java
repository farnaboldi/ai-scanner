package com.ioactive.aiscanner.scan.flow;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Outcome of sending one planned request: status, response body, elapsed ms, the exchange, and the
 * anti-hallucination {@code live} gate ({@code false} for 404/501/5xx/0/dead — those never reach VERIFY).
 * A 401/403 is treated as live: a real-but-authz-blocked endpoint is exactly the IDOR/mass-assign surface.
 */
public record StepResult(int status, String body, long elapsedMs, HttpRequestResponse rr, boolean live) {
    public static StepResult dead(long ms) { return new StepResult(0, "", ms, null, false); }
    public boolean ok2xx() { return status >= 200 && status < 300; }
}
