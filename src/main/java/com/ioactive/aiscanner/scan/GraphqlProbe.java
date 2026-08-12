package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * GraphQL probe — GENERIC and deterministic. Burp natively DETECTS a GraphQL endpoint, but it won't exercise the
 * resolver ARGUMENTS unless it is handed a valid query with those args as insertion points — so a GraphQL-backed
 * RCE/injection sails through undetected. This probe closes that gap using the app's OWN introspected schema (no
 * hardcoded field names):
 *
 * <ol>
 *   <li>locate the endpoint — a POST that answers {@code {query}} with a {@code {"data":…}} envelope;</li>
 *   <li>run INTROSPECTION. If the schema comes back, that is itself an information-exposure finding (it hands an
 *       attacker every type/resolver/argument) AND it gives us the resolver list + argument names/types;</li>
 *   <li>for each resolver taking a String argument, inject into that arg via query VARIABLES with a deterministic
 *       oracle: send {@code echo <nonce>} — if the resolver's reply is EXACTLY {@code <nonce>} (the command RAN)
 *       rather than the literal {@code echo <nonce>} (mere reflection), the argument reaches a shell → unauth RCE
 *       (CWE-78/CWE-94). Zero-FP by construction: a unique nonce that only appears if the echo executed.</li>
 * </ol>
 *
 * The introspected resolver queries are also the exact requests to hand Burp's active audit (variables = natural
 * JSON insertion points) so its SQLi/injection checks fire on GraphQL too — see AiScanner wiring.
 */
public final class GraphqlProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private static final int MAX_RESOLVERS = 40;

    // Minimal introspection: query/mutation type names + each field's name and its arguments' (unwrapped) types.
    private static final String INTROSPECTION =
            "query{__schema{queryType{name} mutationType{name} types{name kind "
          + "fields{name args{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}}";

    public GraphqlProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    private static final class Resolver {
        final String name;
        final List<String> stringArgs = new ArrayList<>();
        Resolver(String name) { this.name = name; }
    }

    /** Find a GraphQL endpoint on {@code host}, introspect it, and injection-test its resolvers. Returns findings. */
    public int probe(String host) {
        try {
            String url = findEndpoint(host);
            if (url == null) { scanLog.debug("[AI Scanner]   graphql: no GraphQL endpoint on " + host); return 0; }
            scanLog.log("[AI Scanner] ── GraphQL probe @ " + url);

            HttpRequestResponse intro = send(url, new JSONObject().put("query", INTROSPECTION).toString());
            JSONObject schema = schemaOf(intro);
            if (schema == null) {
                scanLog.log("[AI Scanner] graphql probe: endpoint present but introspection disabled — no schema to drive resolver tests.");
                return 0;
            }
            int hits = 0;

            // (1) introspection enabled → information exposure (deterministic: a populated __schema came back).
            scanLog.found("GraphQL introspection enabled", url,
                    "The GraphQL endpoint answers a full __schema introspection query (unauthenticated) — it discloses "
                  + "every type, resolver and argument, i.e. the complete attack surface (CWE-200). Deterministic: the "
                  + "reply contains a populated __schema.", intro);
            hits++;

            // (2) resolver-argument injection, driven by the introspected schema.
            List<Resolver> resolvers = resolvers(schema);
            int tested = 0;
            for (Resolver r : resolvers) {
                if (tested >= MAX_RESOLVERS) break;
                if (r.stringArgs.isEmpty()) continue;
                tested++;
                String arg = r.stringArgs.get(0);
                String nonce = "AISC" + Long.toHexString(System.nanoTime()).toUpperCase();
                HttpRequestResponse rr = sendResolver(url, r.name, arg, "echo " + nonce);
                String reply = resolverValue(rr, r.name);
                if (reply == null) continue;
                String t = reply.trim();
                // Command RAN if the reply carries the nonce but NOT the literal "echo <nonce>" (that would be
                // plain reflection of the argument). Unique nonce ⇒ no coincidence, no need for a baseline.
                if (t.contains(nonce) && !t.contains("echo " + nonce)) {
                    scanLog.found("GraphQL OS command injection (RCE)", url,
                            "Resolver '" + r.name + "(" + arg + ")' executes its argument as a shell command: setting "
                          + arg + " = `echo " + nonce + "` returned `" + clip(t) + "` — the command EXECUTED server-side "
                          + "(not reflected). Unauthenticated remote command execution (CWE-78/CWE-94). Deterministic: a "
                          + "unique-nonce echo ran on the server.", rr);
                    hits++;
                }
            }
            scanLog.log("[AI Scanner] graphql probe: " + hits + " finding(s) over " + tested + " resolver(s) with a string arg.");
            return hits;
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner]   graphql probe error: " + t);
            return 0;
        }
    }

    // ---- endpoint discovery ----
    private String findEndpoint(String host) {
        // 1) a /graphql URL Burp already captured in the site map.
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = rr.request() == null ? null : rr.request().url();
                if (u == null || !host.equalsIgnoreCase(hostOf(u))) continue;
                if (u.toLowerCase().contains("graphql") || u.toLowerCase().endsWith("/gql")) {
                    String base = u.split("\\?")[0];
                    if (isGraphql(base)) return base;
                }
            }
        } catch (Throwable ignore) { }
        // 2) construct from any base URL on this host and try the conventional paths.
        String base = baseUrlFor(host);
        if (base != null) for (String p : new String[]{ "graphql", "api/graphql", "graphql/console", "gql", "query" }) {
            String u = base + p;
            if (isGraphql(u)) return u;
        }
        return null;
    }

    /** True if the URL answers a trivial GraphQL query with a data envelope (so it's really a GraphQL endpoint). */
    private boolean isGraphql(String url) {
        HttpRequestResponse rr = send(url, "{\"query\":\"{__typename}\"}");
        if (rr == null || rr.response() == null) return false;
        String b = rr.response().bodyToString();
        return b != null && b.contains("\"data\"") && b.contains("__typename");
    }

    // ---- schema parsing ----
    private JSONObject schemaOf(HttpRequestResponse rr) {
        try {
            if (rr == null || rr.response() == null) return null;
            JSONObject o = new JSONObject(rr.response().bodyToString());
            JSONObject data = o.optJSONObject("data");
            JSONObject s = data == null ? null : data.optJSONObject("__schema");
            return (s != null && s.optJSONArray("types") != null) ? s : null;
        } catch (Throwable t) { return null; }
    }

    /** Resolvers of the Query + Mutation root types, each with the names of its String-typed arguments. */
    private List<Resolver> resolvers(JSONObject schema) {
        List<Resolver> out = new ArrayList<>();
        try {
            java.util.Set<String> roots = new java.util.LinkedHashSet<>();
            JSONObject qt = schema.optJSONObject("queryType");
            JSONObject mt = schema.optJSONObject("mutationType");
            if (qt != null) roots.add(qt.optString("name"));
            if (mt != null) roots.add(mt.optString("name"));
            JSONArray types = schema.optJSONArray("types");
            for (int i = 0; types != null && i < types.length(); i++) {
                JSONObject ty = types.optJSONObject(i);
                if (ty == null || !roots.contains(ty.optString("name"))) continue;
                JSONArray fields = ty.optJSONArray("fields");
                for (int f = 0; fields != null && f < fields.length(); f++) {
                    JSONObject fld = fields.optJSONObject(f);
                    if (fld == null) continue;
                    Resolver r = new Resolver(fld.optString("name"));
                    JSONArray args = fld.optJSONArray("args");
                    for (int a = 0; args != null && a < args.length(); a++) {
                        JSONObject arg = args.optJSONObject(a);
                        if (arg != null && "String".equals(unwrapType(arg.optJSONObject("type"))))
                            r.stringArgs.add(arg.optString("name"));
                    }
                    if (!r.name.isEmpty()) out.add(r);
                }
            }
        } catch (Throwable ignore) { }
        return out;
    }

    /** Unwrap a GraphQL type ref (NON_NULL/LIST wrappers via ofType) down to its named scalar/type. */
    private static String unwrapType(JSONObject type) {
        for (int hop = 0; hop < 6 && type != null; hop++) {
            String name = type.optString("name", null);
            if (name != null && !name.equals("null") && !name.isEmpty()) return name;
            type = type.optJSONObject("ofType");
        }
        return null;
    }

    // ---- resolver invocation ----
    private HttpRequestResponse sendResolver(String url, String resolver, String arg, String value) {
        JSONObject q = new JSONObject();
        q.put("query", "query($v:String!){" + resolver + "(" + arg + ":$v)}");
        q.put("variables", new JSONObject().put("v", value));
        return send(url, q.toString());
    }

    /** The scalar value the resolver returned (data.<resolver>), stringified; null if absent/error. */
    private String resolverValue(HttpRequestResponse rr, String resolver) {
        try {
            if (rr == null || rr.response() == null) return null;
            JSONObject data = new JSONObject(rr.response().bodyToString()).optJSONObject("data");
            if (data == null || data.isNull(resolver)) return null;
            Object v = data.get(resolver);
            return v instanceof String ? (String) v : String.valueOf(v);
        } catch (Throwable t) { return null; }
    }

    // ---- helpers ----
    private HttpRequestResponse send(String url, String jsonBody) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                    .withHeader("Content-Type", "application/json").withBody(jsonBody);
            return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Throwable t) { return null; }
    }

    private String baseUrlFor(String host) {
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String u = rr.request() == null ? null : rr.request().url();
                if (u != null && host.equalsIgnoreCase(hostOf(u))) {
                    URI x = URI.create(u);
                    int port = x.getPort();
                    return x.getScheme() + "://" + x.getHost() + (port < 0 ? "" : ":" + port) + "/";
                }
            }
        } catch (Throwable ignore) { }
        return null;
    }

    private static String hostOf(String u) {
        try { return URI.create(u).getHost(); } catch (Throwable t) { return ""; }
    }
    private static String clip(String s) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() <= 60 ? s : s.substring(0, 60) + "…";
    }
}
