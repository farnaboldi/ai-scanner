package com.ioactive.aiscanner.engine;

import java.util.List;

/**
 * Minimal transport abstraction for LLM calls, so {@link LocalAiEngine} does not depend directly on a
 * concrete HTTP client. The sole implementation is {@link MontoyaLlmHttp}, which routes calls through
 * Burp's own HTTP engine (api.http().sendRequest with upstream TLS verification) — BApp-compliant, no
 * raw sockets. The interface remains so the engine stays unit-testable with a stub.
 */
public interface LlmHttp {
    /**
     * POST a JSON body and return the raw response body as a string.
     * @param headers extra headers as "Name: value" lines (Content-Type is added by the impl)
     */
    String postJson(String url, String jsonBody, List<String> headers) throws Exception;
}
