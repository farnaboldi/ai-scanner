package com.ioactive.aiscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * {@link LlmHttp} backed by Burp's own networking (api.http()). Third-party LLM
 * calls go through Burp's HTTP engine with upstream TLS verification, so they
 * respect the user's upstream proxy config and appear in the Logger for
 * transparency. Avoids the java.net.http HTTP/2 h2c body-drop issue entirely.
 */
public final class MontoyaLlmHttp implements LlmHttp {

    private final MontoyaApi api;

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
        HttpRequestResponse rr = api.http().sendRequest(req, opts);
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
