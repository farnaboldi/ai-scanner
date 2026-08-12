package com.ioactive.aiscanner.scan.sast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * A single source-derived TESTING DIRECTIVE produced by {@link SourceAnalyzer}.
 *
 * <p>A hint is NOT a finding. It only <i>steers</i> the dynamic scan — which endpoint/param to test, which
 * payload class to prefer, how to interpret a response — and the deterministic oracles still decide every
 * verdict. So a wrong/low-quality hint costs coverage, never soundness.</p>
 */
public final class StaticHint {

    /** HTTP method for a (possibly hidden) endpoint the crawler may not have reached. May be blank. */
    public final String method;
    /** Route/path, e.g. {@code /api/users/{id}} or {@code /admin/export}. May be blank (param-only hint). */
    public final String path;
    /** Parameter names the code exposes on this endpoint (used to expand surface). Never null. */
    public final List<String> params;
    /** The single tainted parameter to attack (targeting). May be blank. */
    public final String paramName;
    /** Canonical vuln id — normalized to the ids the probes/VulnClasses use (e.g. {@code "SQL Injection"}). */
    public final String vulnClass;
    /** Coarse sink kind: sql|nosql|path|command|deser|idor|massassign|redirect|ssrf|xxe|other. */
    public final String sinkType;
    /** Provenance, e.g. {@code "UserDao.java:88"}. May be blank. */
    public final String sinkLocation;
    /** 0..1 model-estimated likelihood this param+class is genuinely exploitable. */
    public final double confidence;

    public StaticHint(String method, String path, List<String> params, String paramName,
                      String vulnClass, String sinkType, String sinkLocation, double confidence) {
        this.method = method == null ? "" : method.trim();
        this.path = path == null ? "" : path.trim();
        this.params = params == null ? new ArrayList<>() : params;
        this.paramName = paramName == null ? "" : paramName.trim();
        this.vulnClass = canonicalVulnClass(vulnClass);
        this.sinkType = sinkType == null ? "" : sinkType.trim().toLowerCase();
        this.sinkLocation = sinkLocation == null ? "" : sinkLocation.trim();
        this.confidence = confidence < 0 ? 0 : (confidence > 1 ? 1 : confidence);
    }

    public boolean hasEndpoint() { return !path.isBlank(); }
    public boolean hasParam() { return !paramName.isBlank(); }

    /** EndpointDiscovery spec {@code METHOD<sep>path<sep>csv-params}; the caller passes its own delimiter. */
    public String toEndpointSpec(String sep) {
        String m = method.isBlank() ? "GET" : method.toUpperCase();
        String csv = String.join(",", params);
        return m + sep + path + sep + csv;
    }

    /** Short provenance tag appended to a finding's evidence so the analyst sees WHY this was tested. */
    public String provenance() {
        String kind = sinkType.isBlank() ? vulnClass : sinkType;
        return "[source: " + kind + (sinkLocation.isBlank() ? "" : " @ " + sinkLocation) + "]";
    }

    /** True if this hint's path plausibly matches a live URL (suffix match on the path portion). */
    public boolean matchesUrl(String url) {
        if (path.isBlank() || url == null) return false;
        String p = path.replaceAll("\\{[^}]*}", "").replaceAll("/+$", "");
        String u = url.replaceFirst("(?i)^https?://[^/]+", "").replaceFirst("[?#].*$", "").replaceAll("/+$", "");
        return !p.isBlank() && (u.equalsIgnoreCase(p) || u.toLowerCase().contains(p.toLowerCase()));
    }

    // ---- parsing (tolerant; the analyzer feeds LLM JSON) ----

    public static List<StaticHint> parseArray(String rawJson) {
        List<StaticHint> out = new ArrayList<>();
        if (rawJson == null || rawJson.isBlank()) return out;
        // Strict parse first (clean, complete array).
        String slice = sliceArray(rawJson);
        if (slice != null) {
            try {
                JSONArray arr = new JSONArray(slice);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.optJSONObject(i);
                    if (o != null) out.add(fromJson(o));
                }
                if (!out.isEmpty()) return out;
            } catch (Exception ignore) { /* fall through to lenient salvage */ }
        }
        // Lenient salvage: a big directive set can be TRUNCATED by max_tokens → the array is unterminated and a
        // strict JSONArray parse throws, dropping ALL hints. Extract every COMPLETE top-level {...} object so a
        // partial reply still yields directives (common when a large flat app produces many directives).
        for (String obj : balancedObjects(rawJson)) {
            try { out.add(fromJson(new JSONObject(obj))); } catch (Exception ignore) { }
        }
        return out;
    }

    /** Every balanced top-level {@code {...}} object in a (possibly truncated) string, ignoring braces in strings. */
    private static List<String> balancedObjects(String s) {
        List<String> objs = new ArrayList<>();
        int depth = 0, start = -1;
        boolean inStr = false, esc = false;
        char q = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == q) inStr = false;
                continue;
            }
            if (c == '"' || c == '\'') { inStr = true; q = c; }
            else if (c == '{') { if (depth == 0) start = i; depth++; }
            else if (c == '}' && depth > 0) { if (--depth == 0 && start >= 0) { objs.add(s.substring(start, i + 1)); start = -1; } }
        }
        return objs;
    }

    private static StaticHint fromJson(JSONObject o) {
        List<String> params = new ArrayList<>();
        JSONArray pa = o.optJSONArray("params");
        if (pa != null) for (int i = 0; i < pa.length(); i++) {
            String s = pa.optString(i, "").trim();
            if (!s.isBlank()) params.add(s);
        }
        return new StaticHint(
                o.optString("method", ""),
                o.optString("path", ""),
                params,
                o.optString("paramName", o.optString("param", "")),
                o.optString("vulnClass", o.optString("class", "")),
                o.optString("sinkType", o.optString("sink", "")),
                o.optString("sinkLocation", o.optString("location", "")),
                o.optDouble("confidence", 0.5));
    }

    /** Extract the first {@code [ ... ]} array from a possibly-chatty model reply. */
    private static String sliceArray(String s) {
        int a = s.indexOf('['), b = s.lastIndexOf(']');
        return (a >= 0 && b > a) ? s.substring(a, b + 1) : null;
    }

    /** Map loose model output ("sqli", "sql", "SQL_INJECTION") to the canonical ids the probes/oracles use. */
    private static String canonicalVulnClass(String c) {
        if (c == null) return "";
        String x = c.toLowerCase().replaceAll("[^a-z]", "");
        if (x.contains("sqli") || x.contains("sqlinjection") || x.equals("sql")) return "SQL Injection";
        if (x.contains("nosql")) return "NoSQL";
        if (x.contains("idor") || x.contains("bola") || x.contains("objectreference")) return "IDOR";
        if (x.contains("bfla") || x.contains("functionlevel") || x.contains("privilege")) return "BFLA";
        if (x.contains("massassign")) return "mass-assignment";
        if (x.contains("pathtravers") || x.contains("lfi") || x.contains("fileinclusion") || x.contains("filepath"))
            return "Path traversal / File inclusion (LFI)";
        if (x.contains("cmd") || x.contains("command") || x.contains("rce")) return "Command injection";
        if (x.contains("ssrf")) return "SSRF";
        if (x.contains("xxe")) return "XXE";
        if (x.contains("deser")) return "Insecure deserialization";
        if (x.contains("openredirect") || x.contains("redirect")) return "Open redirect";
        if (x.contains("xss")) return "Cross-Site Scripting (Reflected)";
        return c.trim();
    }
}
