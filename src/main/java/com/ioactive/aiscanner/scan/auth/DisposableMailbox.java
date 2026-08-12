package com.ioactive.aiscanner.scan.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * A throwaway PUBLIC mailbox for autonomous sign-up flows that email a verification code / magic-link.
 * Fully generic — no per-app knowledge: it mints a random address on a public disposable provider and reads
 * that inbox over the provider's API. It only FETCHES the raw email text — the verification value is pulled
 * out of it by the model ({@link com.ioactive.aiscanner.engine.AiEngine#extractVerificationCode}), so no
 * brittle per-provider regex lives here.
 *
 * <p><b>Multi-provider with fallback.</b> A single disposable service is unreliable — Mailinator's public API
 * hard-throttles (HTTP 500) under rapid polling, and any one provider's domain may be blocked by the target
 * or simply not deliver. So we support several providers and try them in order ({@link #mintAll}); the caller
 * re-runs the whole sign-up against the next provider's mailbox if the first never receives the email.
 * Order is configurable via {@code -Daiscanner.mailProvider} (csv of {@code mailinator,mailtm}); default tries
 * Mailinator first (widely delivered-to), then mail.tm (a reliable authenticated JSON API) as the fallback.
 */
public final class DisposableMailbox {

    /** One provider-backed mailbox: knows its address and how to read its own inbox. */
    public interface Provider {
        String name();
        String address();
        /** Poll until a message arrives (or timeout); return newest subject+body text, or "" on timeout. */
        String awaitMessage(int seconds);
    }

    private final Provider provider;
    private DisposableMailbox(Provider p) { this.provider = p; }

    public String address() { return provider.address(); }
    public String providerName() { return provider.name(); }
    public String awaitMessage(int seconds) { return provider.awaitMessage(seconds); }

    /** First healthy mailbox across the configured providers (null if none could be established). */
    public static DisposableMailbox mint(MontoyaApi api) {
        List<DisposableMailbox> all = mintAll(api);
        return all.isEmpty() ? null : all.get(0);
    }

    /** One mailbox per configured provider, in order — the caller tries each until sign-up verification
     *  completes, so a throttled/blocked provider is transparently skipped. */
    public static List<DisposableMailbox> mintAll(MontoyaApi api) {
        List<DisposableMailbox> out = new ArrayList<>();
        String order = prop("aiscanner.mailProvider", "AISCANNER_MAIL_PROVIDER", "mailinator,mailtm");
        for (String name : order.split(",")) {
            name = name.trim().toLowerCase();
            try {
                Provider p = null;
                if (name.equals("mailinator")) p = Mailinator.create(api);
                else if (name.equals("mailtm") || name.equals("mail.tm")) p = MailTm.create(api);
                if (p != null) out.add(new DisposableMailbox(p));
            } catch (Throwable ignore) { }
        }
        return out;
    }

    // ---- provider: Mailinator (stateless public API) ----
    static final class Mailinator implements Provider {
        private final MontoyaApi api; private final String inbox, address;
        private Mailinator(MontoyaApi api, String inbox, String domain) { this.api = api; this.inbox = inbox; this.address = inbox + "@" + domain; }
        static Mailinator create(MontoyaApi api) {
            String domain = prop("aiscanner.mailDomain", "AISCANNER_MAIL_DOMAIN", "mailinator.com");
            String inbox = "ais" + Long.toString(Math.abs(System.nanoTime()), 36);
            return new Mailinator(api, inbox, domain);
        }
        public String name() { return "mailinator"; }
        public String address() { return address; }
        public String awaitMessage(int seconds) {
            long deadline = System.currentTimeMillis() + seconds * 1000L;
            String listUrl = "https://api.mailinator.com/api/v2/domains/public/inboxes/" + inbox;
            while (System.currentTimeMillis() < deadline) {
                try {
                    JSONArray msgs = new JSONObject(orEmpty(get(api, listUrl, null))).optJSONArray("msgs");
                    if (msgs != null && msgs.length() > 0) {
                        JSONObject newest = null; long best = Long.MAX_VALUE;
                        for (int i = 0; i < msgs.length(); i++) {
                            JSONObject m = msgs.optJSONObject(i);
                            if (m == null) continue;
                            long age = m.optLong("seconds_ago", i);
                            if (age <= best) { best = age; newest = m; }
                        }
                        if (newest != null) {
                            String id = newest.optString("id", "");
                            return mailinatorText(newest.optString("subject", ""), get(api, listUrl + "/messages/" + id, null));
                        }
                    }
                } catch (Throwable ignore) { }
                if (!sleep(4000)) return "";
            }
            return "";
        }
        private static String mailinatorText(String subject, String messageJson) {
            StringBuilder sb = new StringBuilder(subject == null ? "" : subject).append('\n');
            try {
                JSONArray parts = new JSONObject(orEmpty(messageJson)).optJSONArray("parts");
                if (parts != null)
                    for (int i = 0; i < parts.length(); i++)
                        sb.append(parts.getJSONObject(i).optString("body", "")).append('\n');
            } catch (Throwable ignore) { }
            return sb.toString();
        }
    }

    // ---- provider: mail.tm (authenticated JSON API — reliable fallback) ----
    static final class MailTm implements Provider {
        private static final String BASE = "https://api.mail.tm";
        private final MontoyaApi api; private final String address, token;
        private MailTm(MontoyaApi api, String address, String token) { this.api = api; this.address = address; this.token = token; }
        static MailTm create(MontoyaApi api) {
            try {
                String domsRaw = get(api, BASE + "/domains", null);
                if (domsRaw == null) return null;
                Object dj = new org.json.JSONTokener(domsRaw).nextValue();
                JSONArray doms = dj instanceof JSONObject ? ((JSONObject) dj).optJSONArray("hydra:member") : (JSONArray) dj;
                if (doms == null || doms.length() == 0) return null;
                String domain = doms.getJSONObject(0).getString("domain");
                String local = "ais" + Long.toString(Math.abs(System.nanoTime()), 36);
                String addr = local + "@" + domain, pw = "AiScan!" + local;
                post(api, BASE + "/accounts", "{\"address\":\"" + addr + "\",\"password\":\"" + pw + "\"}", null);
                String tokRaw = post(api, BASE + "/token", "{\"address\":\"" + addr + "\",\"password\":\"" + pw + "\"}", null);
                if (tokRaw == null) return null;
                String token = new JSONObject(orEmpty(tokRaw)).optString("token", "");
                return token.isBlank() ? null : new MailTm(api, addr, token);
            } catch (Throwable t) { return null; }
        }
        public String name() { return "mailtm"; }
        public String address() { return address; }
        public String awaitMessage(int seconds) {
            long deadline = System.currentTimeMillis() + seconds * 1000L;
            while (System.currentTimeMillis() < deadline) {
                try {
                    String raw = get(api, BASE + "/messages?order[createdAt]=desc", token);   // newest first
                    if (raw != null) {
                        Object mj = new org.json.JSONTokener(raw).nextValue();
                        JSONArray msgs = mj instanceof JSONObject ? ((JSONObject) mj).optJSONArray("hydra:member") : (JSONArray) mj;
                        if (msgs != null && msgs.length() > 0) {
                            String id = msgs.getJSONObject(0).optString("id", "");
                            String full = get(api, BASE + "/messages/" + id, token);
                            JSONObject m = new JSONObject(orEmpty(full));
                            StringBuilder sb = new StringBuilder(m.optString("subject", "")).append('\n').append(m.optString("text", "")).append('\n');
                            JSONArray htmlArr = m.optJSONArray("html");
                            if (htmlArr != null) for (int i = 0; i < htmlArr.length(); i++) sb.append(htmlArr.optString(i, "")).append('\n');
                            return sb.toString();
                        }
                    }
                } catch (Throwable ignore) { }
                if (!sleep(5000)) return "";
            }
            return "";
        }
    }

    // ---- shared HTTP + helpers ----
    private static String get(MontoyaApi api, String url, String bearer) {
        try {
            HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod("GET").withHeader("Accept", "application/json");
            if (bearer != null && !bearer.isBlank()) r = r.withHeader("Authorization", "Bearer " + bearer);
            HttpRequestResponse rr = api.http().sendRequest(r, RequestOptions.requestOptions().withResponseTimeout(12000L));
            return rr == null || rr.response() == null ? null : rr.response().bodyToString();
        } catch (Throwable t) { return null; }
    }
    private static String post(MontoyaApi api, String url, String json, String bearer) {
        try {
            HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                    .withHeader("Accept", "application/json").withHeader("Content-Type", "application/json").withBody(json);
            if (bearer != null && !bearer.isBlank()) r = r.withHeader("Authorization", "Bearer " + bearer);
            HttpRequestResponse rr = api.http().sendRequest(r, RequestOptions.requestOptions().withResponseTimeout(12000L));
            return rr == null || rr.response() == null ? null : rr.response().bodyToString();
        } catch (Throwable t) { return null; }
    }
    private static boolean sleep(long ms) {
        try { Thread.sleep(ms); return true; } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return false; }
    }
    private static String orEmpty(String s) { return s == null || s.isBlank() ? "{}" : s; }

    static String prop(String p, String e, String def) {
        String v = System.getProperty(p);
        if (v == null || v.isBlank()) v = System.getenv(e);
        return v == null || v.isBlank() ? def : v.trim();
    }
}
