package com.ioactive.aiscanner.engine;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared base for every {@link AiEngine}: all the higher-level tasks (payload generation, finding
 * explanation, insertion-point suggestion, endpoint extraction, next-request planning) are expressed
 * purely in terms of a single abstract {@link #chat(String, String)} call, plus tolerant JSON parsing.
 * A concrete engine only supplies {@code chat()}, {@code name()}, {@code isConfigured()} and the transport
 * behind them — so a new backend (Burp AI, a local OpenAI-compatible server, …) is a ~30-line subclass.
 */
public abstract class PromptAiEngine implements AiEngine {

    private volatile String lastError = "";

    protected void setLastError(String e) { this.lastError = e == null ? "" : e; }

    @Override public String lastError() { return lastError; }

    @Override
    public List<String> generatePayloads(String vulnClass, String guidance, String requestContext,
                                         String feedback, int count) {
        String system =
                "You are an offensive web-security payload generator embedded in a Burp Suite extension.\n"
                + "Given a target HTTP request and a single insertion point, produce attack payloads for the\n"
                + "specified vulnerability class, tailored to that insertion point (respect its format:\n"
                + "numeric vs string, JSON, path segment, header, etc.).\n"
                + "Provide RAW payloads only — do NOT URL-encode or HTML-entity-encode them; the tool applies\n"
                + "any encoding needed for the insertion point.\n"
                + "Output ONLY a JSON array of strings (the raw payload values to substitute at the insertion\n"
                + "point). No markdown, no commentary, no keys — just the array. Max " + count + " items.";
        StringBuilder user = new StringBuilder();
        user.append("Vulnerability class: ").append(vulnClass).append("\n");
        if (guidance != null && !guidance.isBlank()) user.append("Technique hint: ").append(guidance).append("\n");
        user.append("\n").append(requestContext).append("\n");
        if (feedback != null && !feedback.isBlank()) {
            user.append("\nPrevious attempt (adapt / try something different):\n").append(feedback).append("\n");
        }
        user.append("\nReturn the JSON array now.");

        return parseStringArray(chat(system, user.toString()), count);
    }

    @Override
    public String explainFinding(String vulnClass, String requestContext, String payload, String evidence) {
        String system =
                "You are a web-security analyst. In 1-3 sentences, plain English, explain why the following\n"
                + "payload confirms a " + vulnClass + " issue at the insertion point, referencing the concrete\n"
                + "evidence. Name the technique. No markdown, no preamble.";
        String user = requestContext + "\n\nPayload sent:\n" + payload + "\n\nObserved evidence:\n" + evidence;
        String out = chat(system, user);
        return out == null ? "" : out.trim();
    }

    @Override
    public List<String> suggestInsertionValues(String requestText, int max) {
        String system =
                "You are a web-security testing assistant embedded in Burp Suite. Given a raw HTTP request,\n"
                + "identify NON-OBVIOUS injection points that Burp's default parameter parser will MISS:\n"
                + "values inside a JSON/XML body, an ID or slug embedded in the URL PATH, and app-specific\n"
                + "header values (e.g. X-User-Id, Authorization subfields). Do NOT list ordinary URL query\n"
                + "params or standard form body params — Burp already covers those.\n"
                + "Output ONLY a JSON array of strings, each the EXACT substring (verbatim, copied from the\n"
                + "request) of the VALUE to fuzz — not the key, not a description. Max " + max + " items.\n"
                + "If there are no non-obvious points, output [].";
        return parseStringArray(chat(system, "Raw HTTP request:\n" + requestText + "\n\nReturn the JSON array now."), max);
    }

    @Override
    public String extractEndpointsJson(String clientCode) {
        String system =
                "You are a web-security assistant. Given client-side code (JavaScript and/or HTML) from a\n"
                + "single web app, extract every SERVER-SIDE endpoint it calls or references that a crawler\n"
                + "which cannot execute JS would MISS: AJAX / $http / fetch / XMLHttpRequest URLs, Angular/JS\n"
                + "route targets that hit the server, and <form> actions. For each, infer the HTTP method and\n"
                + "the request PARAMETER NAMES it sends (query params AND request-body / JSON field names).\n"
                + "Pay SPECIAL attention to AUTHENTICATION endpoints — login, sign-in, register, token, session —\n"
                + "and ALWAYS include their credential field names (e.g. username, email, password).\n"
                + "Output ONLY a JSON array of objects, no markdown/comments:\n"
                + "[{\"method\":\"POST\",\"path\":\"/rest/user/login\",\"params\":[\"email\",\"password\"]}]\n"
                + "Use server PATHS only (no scheme/host). Skip static assets (.css/.js/.png/…). [] if none.";
        String raw = chat(system, "Client-side code:\n" + clientCode + "\n\nReturn the JSON array now.");
        if (raw == null) return "";
        return sliceEndpointArray(raw);
    }

    /**
     * Pull the JSON array-of-objects out of a raw LLM reply, tolerant of prose/markdown/reasoning around it.
     * The naive {@code indexOf('[')..lastIndexOf(']')} mis-slices when the model's text has a stray '[' before
     * the array (e.g. "based on the code [analysis], here: [{…}]") → the whole chunk drops to 0 candidates. So we
     * find the first '[' that opens an array of OBJECTS ('[' then optional whitespace then '{') and return its
     * bracket-balanced, string-aware slice. Falls back to the legacy first-'['..last-']' (covers "[]"), then "".
     */
    static String sliceEndpointArray(String raw) {
        for (int i = 0; i < raw.length(); i++) {
            if (raw.charAt(i) != '[') continue;
            int j = i + 1;
            while (j < raw.length() && Character.isWhitespace(raw.charAt(j))) j++;
            if (j >= raw.length() || raw.charAt(j) != '{') continue;   // not an array of objects — skip prose "[…]"
            String slice = balancedArray(raw, i);
            if (slice != null) return slice;                            // balanced → done (ignores trailing prose)
            String salvaged = salvageObjects(raw, i);                   // TRUNCATED (finish_reason=length) → keep the
            if (salvaged != null) return salvaged;                      // complete objects before the cut, not zero
        }
        int s = raw.indexOf('['), e = raw.lastIndexOf(']');             // fallback (handles "[]" / no objects)
        return (s >= 0 && e > s) ? raw.substring(s, e + 1) : "";
    }

    /**
     * Salvage a TRUNCATED array-of-objects (the model hit max_tokens mid-array, finish_reason=length): collect the
     * complete top-level {…} objects that DID close and re-wrap them as a valid array. Turns "big roll got cut → 0
     * candidates" into "keep the N complete endpoints before the cut" — critical because the model's endpoint count
     * is wildly variable (1..100+), so the big rolls are exactly the ones that truncate and must not be lost whole.
     */
    private static String salvageObjects(String raw, int start) {
        int lastObjEnd = -1;                 // index just past the last COMPLETE top-level object's '}'
        int brace = 0;
        boolean inStr = false, esc = false;
        for (int i = start + 1; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '{') brace++;
            else if (c == '}' && --brace == 0) lastObjEnd = i + 1;
        }
        return lastObjEnd < 0 ? null : raw.substring(start, lastObjEnd) + "]";
    }

    /** {@code raw[start..matching ']']} with bracket-depth + JSON-string awareness, or null if never closed (a
     *  truncated reply — let the caller fall back rather than return a half-array). */
    private static String balancedArray(String raw, int start) {
        int depth = 0;
        boolean inStr = false, esc = false;
        for (int i = start; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '[') depth++;
            else if (c == ']' && --depth == 0) return raw.substring(start, i + 1);
        }
        return null;
    }

    @Override
    public String planNextRequest(String goal, String observation, String feedback) {
        String system =
                "You are an autonomous web-pentest planner embedded in a Burp Suite extension driving an\n"
                + "authenticated session. You OBSERVE the last HTTP request and its response, then PLAN the SINGLE\n"
                + "next request that advances the goal — a chain a single-shot fuzzer can't reach:\n"
                + "  create->consume: a POST created a resource; the response returned an id/token; GET/track/consume it.\n"
                + "  IDOR: the response listed or embedded a neighbor id; request that id.\n"
                + "  mass-assignment: the response revealed a role/privilege field; resend the body with it elevated.\n"
                + "  token flow: a login response yielded a JWT; reuse or tamper (alg:none) it.\n"
                + "  lesson: read what a page/assignment asks and submit the exact answer.\n"
                + "You do NOT decide whether anything is vulnerable — a deterministic oracle does; your job is targeting.\n"
                + "RULES: use ONLY paths, params, ids and tokens that appear VERBATIM in the observation — never invent\n"
                + "an endpoint (an invented one is live-probed and discarded). Keep the SAME host. When probing SQLi/XSS/\n"
                + "SSTI/traversal, embed the exact canary tokens named in the goal so the oracle can confirm.\n"
                + "Output ONLY one JSON object with keys method,url,headers,body,intent,vulnClassHint,extractHint.\n"
                + "No markdown, no prose, no array — just the object.";
        StringBuilder user = new StringBuilder();
        if (goal != null && !goal.isBlank()) user.append("Goal: ").append(goal).append('\n');
        user.append("\n--- observation (last request + response) ---\n").append(observation).append('\n');
        if (feedback != null && !feedback.isBlank())
            user.append("\nPrior steps (adapt; do not repeat a request that failed):\n").append(feedback).append('\n');
        user.append("\nReturn the JSON object now.");
        return firstJsonObject(chat(system, user.toString()));
    }

    @Override
    public List<String> proposeSensitivePaths(String fingerprint, int max) {
        String system =
                "You are a web content-discovery assistant embedded in a Burp Suite extension.\n"
                + "Burp's crawler only FOLLOWS links; it cannot reach server-side paths that are not linked\n"
                + "anywhere (no href, absent from robots.txt / sitemap). Given a target's fingerprint and the\n"
                + "paths already observed, propose likely UNLINKED, security-sensitive paths worth probing:\n"
                + "admin / management consoles, user or account dumps, config / backup / status endpoints —\n"
                + "tailored to the detected server and stack. Use server-relative PATHS only (no scheme/host).\n"
                + "Skip static assets (.css .js .png etc.) and any path already observed. Every path is LIVE-\n"
                + "PROBED and any non-existent one is silently discarded, so favour plausible, framework-\n"
                + "idiomatic guesses.\n"
                + "Output ONLY a JSON array of path strings. No markdown, no commentary. Max " + max + " items.";
        String user = fingerprint + "\n\nReturn the JSON array of candidate paths now.";
        return parseStringArray(chat(system, user), max);
    }

    // ---- shared tolerant parsing ----

    /** Tolerant JSON-OBJECT slice — sibling of parseStringArray. "" if not real JSON. */
    public static String firstJsonObject(String raw) {
        if (raw == null) return "";
        int s = raw.indexOf('{'), e = raw.lastIndexOf('}');
        if (s < 0 || e <= s) return "";
        String slice = raw.substring(s, e + 1);
        try { new JSONObject(slice); return slice; }
        catch (Exception ignore) { return ""; }
    }

    /** Tolerantly pull a JSON array of strings out of an LLM reply (handles fences / stray prose). */
    public static List<String> parseStringArray(String raw, int max) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.isBlank()) return out;
        int start = raw.indexOf('[');
        int end = raw.lastIndexOf(']');
        if (start >= 0 && end > start) {
            try {
                JSONArray arr = new JSONArray(raw.substring(start, end + 1));
                for (int i = 0; i < arr.length() && out.size() < max; i++) {
                    Object v = arr.get(i);
                    String s = v == null ? "" : String.valueOf(v);
                    if (!s.isEmpty()) out.add(s);
                }
                if (!out.isEmpty()) return out;
            } catch (Exception ignore) {
                // fall through to line-based parsing
            }
        }
        // Fallback: one payload per non-empty line.
        for (String line : raw.split("\\r?\\n")) {
            String t = line.trim().replaceAll("^[-*\\d.\\s]+", "");
            if (!t.isEmpty() && out.size() < max) out.add(t);
        }
        return out;
    }
}
