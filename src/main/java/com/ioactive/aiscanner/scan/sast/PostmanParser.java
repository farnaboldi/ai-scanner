package com.ioactive.aiscanner.scan.sast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * DETERMINISTIC route harvest from Postman collections shipped in a source repo. Many APIs publish NO live spec
 * (no Swagger/OpenAPI endpoint) and answer a catch-all 200 for every path — so a black-box crawl finds nothing and
 * status-based existence probing is defeated — yet the repo ships a Postman collection that documents the whole
 * surface: exact routes, methods, query/body parameter names, even example payloads (an SSRF {@code ?url=}, a
 * mass-assignment {@code role} field). {@link RouteHarvester} only reads code files (its EXT filter excludes
 * {@code .json}), so that collection was invisible. This parses every Postman v2 collection into route hints
 * (method + path + param names), which ride the SAME live-probe + oracle path as any other {@link StaticHint} — a
 * dead/renamed route is filtered out exactly like a mined one, so a stale collection never yields phantom coverage.
 */
public final class PostmanParser {

    private PostmanParser() {}

    private static final int  MAX_COLLECTIONS = 50;      // Postman files parsed per repo
    private static final int  MAX_REQUESTS    = 600;     // route hints emitted (bound memory)
    private static final long MAX_FILE_BYTES  = 8_000_000L;

    /** Every Postman v2 collection under {@code repoPath} → route hints (method + path + query/body param names). */
    public static SourceFindings parse(String repoPath) {
        LinkedHashMap<String, StaticHint> dedup = new LinkedHashMap<>();
        for (JSONObject req : collectRequests(repoPath)) {
            StaticHint h = fromRequest(req);
            if (h != null && h.hasEndpoint()) dedup.putIfAbsent(h.method + " " + h.path + " " + h.params, h);
        }
        return new SourceFindings(new ArrayList<>(dedup.values()));
    }

    /**
     * Every Postman collection → a minimal OpenAPI 3.0 spec (paths → post/put ops with a JSON requestBody whose
     * schema lists the body field names). This lets the mature SPEC-DRIVEN auth bootstrap
     * ({@code EndpointDiscovery.acquireSpecToken}) treat the collection as if the app served a live spec — so a
     * register/login request in the collection drives the exact same register→login→extract-token flow, with ZERO
     * new auth logic. Returns null when the repo ships no Postman collection with a JSON body.
     */
    public static org.json.JSONObject toOpenApiSpec(String repoPath) {
        JSONObject paths = new JSONObject();
        for (JSONObject req : collectRequests(repoPath)) {
            String method = req.optString("method", "GET").trim().toLowerCase();
            if (!method.equals("post") && !method.equals("put")) continue;   // auth is a write; keep the spec small
            Object urlNode = req.opt("url");
            JSONObject urlObj = urlNode instanceof JSONObject ? (JSONObject) urlNode : null;
            String raw = urlObj != null ? urlObj.optString("raw", "") : (urlNode instanceof String ? (String) urlNode : "");
            String path = pathOf(urlObj, raw);
            if (path.isBlank() || path.contains("{{")) continue;
            Set<String> keys = bodyKeys(req.optJSONObject("body"));
            if (keys.isEmpty()) continue;
            JSONObject props = new JSONObject();
            for (String k : keys) props.put(k, new JSONObject().put("type", "string"));
            JSONObject op = new JSONObject().put("requestBody", new JSONObject().put("content",
                    new JSONObject().put("application/json", new JSONObject().put("schema",
                            new JSONObject().put("type", "object").put("properties", props)))));
            // Carry the collection's EXAMPLE body verbatim (x-example): it holds the real demo credentials the
            // author shipped (e.g. {"email":"test@test.com","password":"test123"}). The auth bootstrap replays it
            // directly (register-then-login with the SAME creds) instead of only synthesizing guesses.
            JSONObject bodyObj = req.optJSONObject("body");
            if (bodyObj != null && "raw".equals(bodyObj.optString("mode"))) {
                String rawB = bodyObj.optString("raw", "").trim();
                if (rawB.startsWith("{") && !rawB.contains("{{")) op.put("x-example", rawB);
            }
            JSONObject item = paths.optJSONObject(path);
            if (item == null) { item = new JSONObject(); paths.put(path, item); }
            item.put(method, op);
        }
        return paths.length() > 0 ? new JSONObject().put("paths", paths) : null;
    }

    /** All leaf {@code request} objects across every Postman collection under {@code repoPath} (bounded). */
    private static List<JSONObject> collectRequests(String repoPath) {
        List<JSONObject> out = new ArrayList<>();
        if (repoPath == null || repoPath.isBlank()) return out;
        Path root;
        try { root = Paths.get(repoPath).toRealPath(); } catch (Exception e) { return out; }
        if (!Files.isDirectory(root)) return out;
        int[] cols = {0};
        try (Stream<Path> walk = Files.walk(root, 12)) {
            List<Path> jsons = new ArrayList<>();
            walk.filter(Files::isRegularFile)
                .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".json"))
                .limit(20_000)
                .forEach(jsons::add);
            for (Path p : jsons) {
                if (cols[0] >= MAX_COLLECTIONS || out.size() >= MAX_REQUESTS) break;
                String text;
                try {
                    if (Files.size(p) > MAX_FILE_BYTES) continue;
                    text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                } catch (Exception e) { continue; }
                if (!looksLikePostman(text)) continue;
                try {
                    JSONObject col = new JSONObject(text);
                    JSONArray items = col.optJSONArray("item");
                    if (items == null) continue;
                    cols[0]++;
                    collectItems(items, out);
                } catch (Exception ignore) { }
            }
        } catch (Exception ignore) { }
        return out;
    }

    /** Cheap sniff: a Postman v2 collection has an {@code item} array and a Postman signature. */
    private static boolean looksLikePostman(String t) {
        if (t == null || !t.contains("\"item\"")) return false;
        return t.contains("schema.getpostman.com") || t.contains("_postman_id")
                || (t.contains("\"request\"") && t.contains("\"method\""));
    }

    /** Postman folders nest an {@code item} array; leaf items carry a {@code request}. Recurse tolerantly. */
    private static void collectItems(JSONArray items, List<JSONObject> out) {
        for (int i = 0; i < items.length() && out.size() < MAX_REQUESTS; i++) {
            JSONObject it = items.optJSONObject(i);
            if (it == null) continue;
            JSONArray sub = it.optJSONArray("item");
            if (sub != null) { collectItems(sub, out); continue; }   // folder → recurse
            JSONObject req = it.optJSONObject("request");
            if (req != null) out.add(req);
        }
    }

    private static StaticHint fromRequest(JSONObject req) {
        String method = req.optString("method", "GET").trim().toUpperCase();
        Object urlNode = req.opt("url");
        JSONObject urlObj = urlNode instanceof JSONObject ? (JSONObject) urlNode : null;
        String raw = urlObj != null ? urlObj.optString("raw", "") : (urlNode instanceof String ? (String) urlNode : "");
        String path = pathOf(urlObj, raw);
        if (path.isBlank() || path.contains("{{")) return null;   // unresolved Postman var → skip (no concrete route)

        LinkedHashSet<String> params = new LinkedHashSet<>();
        if (urlObj != null) {
            JSONArray q = urlObj.optJSONArray("query");
            if (q != null) for (int i = 0; i < q.length(); i++) {
                JSONObject e = q.optJSONObject(i);
                if (e != null) addKey(params, e.optString("key", ""));
            }
            JSONArray vars = urlObj.optJSONArray("variable");   // :id style path variables
            if (vars != null) for (int i = 0; i < vars.length(); i++) {
                JSONObject e = vars.optJSONObject(i);
                if (e != null) addKey(params, e.optString("key", ""));
            }
        } else {
            // rawUrl query string: /x?a=1&b=2
            int qm = raw.indexOf('?');
            if (qm >= 0) for (String kv : raw.substring(qm + 1).split("&")) {
                int eq = kv.indexOf('='); addKey(params, eq > 0 ? kv.substring(0, eq) : kv);
            }
        }
        params.addAll(bodyKeys(req.optJSONObject("body")));

        return new StaticHint(method, path, new ArrayList<>(params), "", "", "", "postman-collection", 0.5, "");
    }

    /** Resolve the URL path: prefer the structured {@code url.path} segments, else strip scheme/host/query from raw.
     *  {@code :id} path variables are normalized to {@code {id}} to match {@link RouteHarvester}'s templating. */
    private static String pathOf(JSONObject urlObj, String raw) {
        String p = "";
        JSONArray segs = urlObj != null ? urlObj.optJSONArray("path") : null;
        if (segs != null && segs.length() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < segs.length(); i++) {
                String s = segs.optString(i, "").trim();
                if (s.isBlank()) continue;
                // Postman single-slash raw ("http:/host/…") mis-parses the HOST into path[0] (e.g. "localhost:5000").
                // Drop a leading host-looking segment so the real path (and its query params) isn't buried under a
                // phantom "/localhost:5000/…" that only hits the catch-all.
                if (i == 0 && looksLikeHost(s)) continue;
                sb.append('/').append(s);
            }
            p = sb.toString();
        } else if (raw != null && !raw.isBlank()) {
            // Strip scheme://authority — tolerate a malformed single-slash scheme (Postman collections sometimes
            // ship "http:/host/…"): use https?:/+ so "http:/localhost:5000/api/x" doesn't leave "localhost:5000"
            // stuck in the path (which would create a phantom endpoint AND lose the real path's params).
            p = raw.replaceFirst("(?i)^https?:/+[^/]+", "").replaceFirst("[?#].*$", "");
            if (!p.startsWith("/")) p = "/" + p;
        }
        p = p.replaceAll(":([A-Za-z_][A-Za-z0-9_]*)(?=/|$)", "{$1}");   // :id path var → {id} (NOT a host :port)
        p = p.replaceAll("/+", "/");
        return p.equals("/") ? "" : p;
    }

    /** A path segment that is really a HOST (host:port / IPv4 / localhost / domain.tld) — a Postman single-slash
     *  mis-parse artifact, never a legitimate first path component. */
    private static boolean looksLikeHost(String s) {
        String x = s.toLowerCase();
        return x.contains(":")                                 // host:port — a colon is never valid in a path segment
            || x.equals("localhost")
            || x.matches("\\d{1,3}(\\.\\d{1,3}){3}")           // IPv4
            || x.matches("([a-z0-9\\-]+\\.)+[a-z]{2,}");       // domain.tld
    }

    /** Body parameter names: raw-JSON top-level keys, urlencoded/formdata keys. Raw XML/text yields none (the XXE/
     *  deserialization probe targets the whole body, and the route hint alone is enough to steer it there). */
    private static Set<String> bodyKeys(JSONObject body) {
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        if (body == null) return keys;
        String mode = body.optString("mode", "");
        if ("raw".equals(mode)) {
            String raw = body.optString("raw", "").trim();
            if (raw.startsWith("{")) {
                try { for (String k : new JSONObject(raw).keySet()) addKey(keys, k); } catch (Exception ignore) { }
            }
        } else if ("urlencoded".equals(mode) || "formdata".equals(mode)) {
            JSONArray arr = body.optJSONArray(mode);
            if (arr != null) for (int i = 0; i < arr.length(); i++) {
                JSONObject e = arr.optJSONObject(i);
                if (e != null) addKey(keys, e.optString("key", ""));
            }
        }
        return keys;
    }

    private static void addKey(Set<String> set, String k) {
        if (k == null) return;
        String t = k.trim();
        if (!t.isBlank() && !t.contains("{{")) set.add(t);
    }
}
