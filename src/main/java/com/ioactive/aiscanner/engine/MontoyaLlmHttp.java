package com.ioactive.aiscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * {@link LlmHttp} backed by Burp's own networking (api.http()). Third-party LLM
 * calls go through Burp's HTTP engine with upstream TLS verification, so they
 * respect the user's upstream proxy config and appear in the Logger for
 * transparency. Avoids the java.net.http HTTP/2 h2c body-drop issue entirely.
 */
public final class MontoyaLlmHttp implements LlmHttp {

    private final MontoyaApi api;

    // HARD client-side deadline for one LLM call. Montoya's withResponseTimeout does NOT bound a STALLED response body
    // (headers arrive, then the stream stalls): observed a single call hang ~21 minutes under sustained load, freezing
    // the whole scan and burning the audit/watchdog budget. We run the request on a daemon thread and abandon it past
    // this deadline so the caller ALWAYS unblocks. Override with -Daiscanner.llmHardDeadlineMs.
    private static final long HARD_DEADLINE_MS = Long.getLong("aiscanner.llmHardDeadlineMs", 180_000L);
    private static final ExecutorService LLM_POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "aiscanner-llm-http"); t.setDaemon(true); return t;   // daemon → a hung request never blocks JVM exit
    });

    public MontoyaLlmHttp(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public String postJson(String url, String jsonBody, List<String> headers) {
        // Encode the body as EXPLICIT UTF-8 bytes. withBody(String) encodes as ISO-8859-1, which mangles the
        // multi-byte UTF-8 characters in JS-source chunks into invalid JSON — vLLM then rejects the request
        // with HTTP 400 "error parsing the body". Sending the raw UTF-8 ByteArray preserves the exact bytes.
        ByteArray bodyBytes = ByteArray.byteArray(jsonBody.getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/json")
                .withBody(bodyBytes);
        if (headers != null) {
            for (String h : headers) {
                if (h != null && !h.isBlank()) {
                    req = req.withAddedHeader(HttpHeader.httpHeader(h.trim()));
                }
            }
        }
        RequestOptions opts = RequestOptions.requestOptions().withResponseTimeout(120000L);
        // Enforce the HARD deadline: run on a daemon thread, abandon it (best-effort cancel) if it exceeds the bound.
        // Montoya's own timeout can't be trusted for a stalled body, so this is the real guarantee the scan proceeds.
        final HttpRequest fReq = req;
        Future<HttpRequestResponse> fut = LLM_POOL.submit(() -> api.http().sendRequest(fReq, opts));
        HttpRequestResponse rr;
        try {
            rr = fut.get(HARD_DEADLINE_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            fut.cancel(true);
            throw new RuntimeException("LLM request exceeded hard deadline (" + (HARD_DEADLINE_MS / 1000) + "s) — abandoned (" + url + ")");
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new RuntimeException("LLM request failed: " + cause.getClass().getSimpleName()
                    + (cause.getMessage() == null ? "" : ": " + cause.getMessage()) + " (" + url + ")");
        }
        if (rr.response() == null) {
            throw new RuntimeException("No response from LLM endpoint (" + url + ")");
        }
        int code = rr.response().statusCode();
        // Decode the response as UTF-8 too (bodyToString() would use ISO-8859-1 and corrupt any non-ASCII).
        String body = new String(rr.response().body().getBytes(), StandardCharsets.UTF_8);
        if (code / 100 != 2) {
            String snippet = body == null ? "" : body.substring(0, Math.min(400, body.length()));
            throw new RuntimeException("HTTP " + code + ": " + snippet);
        }
        return body;
    }
}
