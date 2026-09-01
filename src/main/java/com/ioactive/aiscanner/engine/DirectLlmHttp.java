package com.ioactive.aiscanner.engine;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * GUI-free {@link LlmHttp} for the SAST integration test ({@code SastItest}). Talks straight to an
 * OpenAI-compatible endpoint over {@code java.net.http}, bypassing Burp's HTTP engine — so the SAST
 * analyzers can be exercised end-to-end without a running Burp. NOT wired into the extension (the
 * shipped transport is {@link MontoyaLlmHttp}); this class exists only for the headless test harness.
 */
public final class DirectLlmHttp implements LlmHttp {

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)   // vLLM/uvicorn drops large POST bodies over java.net.http's h2
            .connectTimeout(Duration.ofSeconds(15))
            .build();

    @Override
    public String postJson(String url, String jsonBody, List<String> headers) throws Exception {
        return postJson(url, jsonBody, headers, 0);
    }

    @Override
    public String postJson(String url, String jsonBody, List<String> headers, long callTimeoutMs) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(callTimeoutMs > 0 ? callTimeoutMs : 600_000))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        if (headers != null) {
            for (String h : headers) {
                int i = h.indexOf(':');
                if (i > 0) b.header(h.substring(0, i).trim(), h.substring(i + 1).trim());
            }
        }
        HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) {
            String body = r.body() == null ? "null" : r.body();
            System.err.println("[http] status=" + r.statusCode() + " reqBytes=" + jsonBody.length()
                    + " resp=" + body.substring(0, Math.min(400, body.length())));
        }
        return r.body();
    }
}
