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
    // Explicit ops overrides (null when the -D property is unset) — these ALWAYS win, so a headless/CLI run can
    // still pin the deadline regardless of the Settings-tab value. When unset, the per-call budget passed by the
    // engine (EngineConfig.timeoutSeconds, wired via postJson's callTimeoutMs) is used; failing that, the default.
    private static final Long HARD_DEADLINE_PROP = Long.getLong("aiscanner.llmHardDeadlineMs");
    private static final Long RESP_TIMEOUT_PROP  = Long.getLong("aiscanner.llmResponseTimeoutMs");
    private static final long HARD_DEADLINE_DEFAULT_MS = 180_000L;
    private static final long RESP_TIMEOUT_DEFAULT_MS  = 120_000L;
    // ABSOLUTE ceiling on the per-call deadline AFTER the ×parallelism scaling. Without it, N concurrent scans push the
    // hard deadline to 180s×N (observed 15 min at N≈5), so a single stalled response can pin the whole scan for a
    // quarter hour before the watchdog even notices. A genuine discovery call is 2–25s even at 5×, so capping at 5 min
    // only ever kills a truly stuck call. Override with -Daiscanner.llmHardDeadlineCapMs.
    private static final long HARD_DEADLINE_CAP_MS = Long.getLong("aiscanner.llmHardDeadlineCapMs", 300_000L);
    // LIVE count of scans hitting the LLM concurrently — each scan increments on start / decrements on end
    // (AiContextMenuProvider.crawlAndScan), so it stays correct even when scans are ADDED at will (an Agent-tab
    // command launching more targets into a running Burp). N concurrent scans share ONE local model → each call waits
    // ~N× longer, so we scale BOTH timeouts by max(1,N). 0 when idle → max(1,0)=1× (no effect).
    public static final java.util.concurrent.atomic.AtomicInteger PARALLELISM = new java.util.concurrent.atomic.AtomicInteger(0);
    private static final ExecutorService LLM_POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "aiscanner-llm-http"); t.setDaemon(true); return t;   // daemon → a hung request never blocks JVM exit
    });

    public MontoyaLlmHttp(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public String postJson(String url, String jsonBody, List<String> headers) {
        return postJson(url, jsonBody, headers, 0L);
    }

    @Override
    public String postJson(String url, String jsonBody, List<String> headers, long callTimeoutMs) {
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
        int par = Math.max(1, PARALLELISM.get());   // scale timeouts by the number of concurrent scans sharing the model
        // Base per-call budgets: an explicit -Daiscanner.llm*Ms wins; else the caller's configured timeout
        // (EngineConfig.timeoutSeconds → callTimeoutMs); else the built-in default. The hard deadline tracks the
        // response timeout at 1.5× so the graceful response timeout fires first and the daemon-abandon is the backstop.
        long baseResp = RESP_TIMEOUT_PROP  != null ? RESP_TIMEOUT_PROP
                      : (callTimeoutMs > 0 ? callTimeoutMs : RESP_TIMEOUT_DEFAULT_MS);
        long baseHard = HARD_DEADLINE_PROP != null ? HARD_DEADLINE_PROP
                      : (callTimeoutMs > 0 ? callTimeoutMs * 3 / 2 : HARD_DEADLINE_DEFAULT_MS);
        // Scale by concurrency BUT clamp to an absolute ceiling — a leaked/high `par` must not let one stalled call
        // block the scan for a quarter hour (see HARD_DEADLINE_CAP_MS). Response timeout tracks the same cap.
        long hardDeadline = Math.min(baseHard * par, HARD_DEADLINE_CAP_MS);
        RequestOptions opts = RequestOptions.requestOptions()
                .withResponseTimeout(Math.min(baseResp * par, HARD_DEADLINE_CAP_MS));
        // Enforce the HARD deadline: run on a daemon thread, abandon it (best-effort cancel) if it exceeds the bound.
        // Montoya's own timeout can't be trusted for a stalled body, so this is the real guarantee the scan proceeds.
        final HttpRequest fReq = req;
        Future<HttpRequestResponse> fut = LLM_POOL.submit(() -> api.http().sendRequest(fReq, opts));
        HttpRequestResponse rr;
        try {
            rr = fut.get(hardDeadline, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            fut.cancel(true);
            throw new RuntimeException("LLM request exceeded hard deadline (" + (hardDeadline / 1000) + "s) — abandoned (" + url + ")");
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
