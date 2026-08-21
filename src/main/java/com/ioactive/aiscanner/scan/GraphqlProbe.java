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
import java.util.regex.Pattern;

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

    /** Engine-agnostic SQL-error signatures (SQLite/Python, MySQL, PostgreSQL, Oracle, MSSQL, generic ORM). Used by
     *  the error-based resolver-arg SQLi differential — the `'`-vs-`''` guard makes even a broad pattern zero-FP. */
    private static final Pattern SQL_ERROR = Pattern.compile("(?i)("
            + "sqlite3?\\.(Operational|Programming|Integrity|Interface)Error|SQLITE_ERROR|unrecognized token|no such column|"   // SQLite / Python
            + "You have an error in your SQL syntax|MySQLSyntaxError|Warning:\\s*mysqli|"                                       // MySQL
            + "PG::\\w+|psycopg2|invalid input syntax for|syntax error at or near|"                                             // PostgreSQL
            + "ORA-\\d{5}|"                                                                                                     // Oracle
            + "Incorrect syntax near|Unclosed quotation mark|System\\.Data\\.SqlClient|"                                        // MSSQL
            + "SQLSTATE\\[|\\bOperationalError\\b|ProgrammingError|\\[SQL:)");                                                  // generic ORM/SQLAlchemy

    // Minimal introspection: query/mutation type names + each field's name and its arguments' (unwrapped) types.
    private static final String INTROSPECTION =
            "query{__schema{queryType{name} mutationType{name} types{name kind "
          + "fields{name type{kind name ofType{kind name ofType{kind name}}} "
          + "args{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}}";

    public GraphqlProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    private static final class Resolver {
        final String name;
        final List<String> stringArgs = new ArrayList<>();
        boolean returnsObject;   // return type unwraps to OBJECT/INTERFACE/UNION → the query MUST select a subfield
        Resolver(String name) { this.name = name; }
    }

    /** Find a GraphQL endpoint on {@code host}, introspect it, and injection-test its resolvers. Returns findings. */
    public int probe(String host) {
        try {
            String url = findEndpoint(host);
            if (url == null) { scanLog.debug("  graphql: no GraphQL endpoint on " + host); return 0; }
            scanLog.log("── GraphQL probe @ " + url);

            HttpRequestResponse intro = send(url, new JSONObject().put("query", INTROSPECTION).toString());
            JSONObject schema = schemaOf(intro);
            if (schema == null) {
                scanLog.log("graphql probe: endpoint present but introspection disabled — no schema to drive resolver tests.");
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
                // (2a) error-based SQLi on the resolver arg: a single quote that breaks the SQL string surfaces a DB
                //      error the balanced quote ('') does not → the value reaches a SQL sink unescaped (CWE-89).
                //      Zero-FP differential (a non-SQL error, e.g. a missing required arg, errors on BOTH → no finding).
                HttpRequestResponse sqlBad = sendResolver(url, r.name, arg, "aisc'", r.returnsObject);
                if (sqlError(sqlBad) && !sqlError(sendResolver(url, r.name, arg, "aisc''", r.returnsObject))) {
                    scanLog.found("GraphQL SQL injection", url,
                            "Resolver '" + r.name + "(" + arg + ")' reaches a SQL sink: a single quote in the argument "
                          + "surfaced a database error that the balanced quote ('') did not, so the value is concatenated "
                          + "into a SQL statement unescaped (CWE-89). Deterministic error-based differential — DB error: "
                          + clip(sqlErrText(sqlBad)) + ".", sqlBad);
                    hits++;
                }
                String nonce = "AISC" + Long.toHexString(System.nanoTime()).toUpperCase();
                HttpRequestResponse rr = sendResolver(url, r.name, arg, "echo " + nonce, r.returnsObject);
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

            // (3) request AMPLIFICATION via aliasing / array-batching — one request triggers N operations with no
            // query-cost/complexity or per-operation rate limit → auth-throttle bypass (batched credential brute-
            // force) + DoS (CWE-770). Non-destructive (benign __typename); zero-FP (N results for ONE request).
            hits += amplificationTest(url);

            scanLog.log("graphql probe: " + hits + " finding(s) over " + tested + " resolver(s) with a string arg.");
            return hits;
        } catch (Throwable t) {
            scanLog.debug("  graphql probe error: " + t);
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
                    r.returnsObject = isObjectKind(fld.optJSONObject("type"));
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

    /** True if a field's return type unwraps (past NON_NULL/LIST) to an OBJECT/INTERFACE/UNION — such a field
     *  REQUIRES a subfield selection, so the probe query must add one; scalars/enums must NOT have one. */
    private static boolean isObjectKind(JSONObject type) {
        for (int hop = 0; hop < 8 && type != null; hop++) {
            String kind = type.optString("kind", "");
            if ("OBJECT".equals(kind) || "INTERFACE".equals(kind) || "UNION".equals(kind)) return true;
            if ("SCALAR".equals(kind) || "ENUM".equals(kind)) return false;
            type = type.optJSONObject("ofType");   // unwrap NON_NULL / LIST
        }
        return false;
    }

    // ---- resolver invocation ----
    private HttpRequestResponse sendResolver(String url, String resolver, String arg, String value, boolean selectSubfield) {
        JSONObject q = new JSONObject();
        // Object/list resolvers REQUIRE a subfield selection — without it the query is INVALID (a validation error,
        // HTTP 400) and never reaches the resolver, so no injection sink is exercised. Scalars must NOT have one.
        String sel = selectSubfield ? "{__typename}" : "";
        q.put("query", "query($v:String!){" + resolver + "(" + arg + ":$v)" + sel + "}");
        q.put("variables", new JSONObject().put("v", value));
        return send(url, q.toString());
    }

    /** True if the response body carries a SQL/DB error signature (see {@link #SQL_ERROR}). */
    private static boolean sqlError(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String b = rr.response().bodyToString();
        return b != null && SQL_ERROR.matcher(b).find();
    }

    /** The matched SQL-error snippet (+ a little trailing context) for the finding's evidence; "" if none. */
    private static String sqlErrText(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "";
        String b = rr.response().bodyToString();
        if (b == null) return "";
        java.util.regex.Matcher m = SQL_ERROR.matcher(b);
        if (!m.find()) return "";
        return b.substring(m.start(), Math.min(b.length(), m.end() + 60)).replaceAll("\\s+", " ");
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
    // ---- request amplification (aliasing / array batching) ----
    /** One HTTP request → N GraphQL operations. A server returning ~N results for one request enforces no
     *  query-complexity/cost or per-operation rate limit (CWE-770): an attacker aliases a login/OTP resolver to
     *  bypass auth throttling (batched brute-force) or an expensive resolver for DoS. Non-destructive (benign
     *  __typename), zero-FP (only a server that actually executed N ops can return N results). */
    private int amplificationTest(String url) {
        final int N = 100;
        StringBuilder q = new StringBuilder("{");
        for (int i = 0; i < N; i++) q.append("a").append(i).append(":__typename ");
        q.append("}");
        HttpRequestResponse ar = send(url, new JSONObject().put("query", q.toString()).toString());
        int aliased = aliasCount(ar);
        if (aliased >= N / 2) {
            scanLog.found("GraphQL request amplification — no query-cost/rate limit (aliasing)", url,
                    "One request carrying " + N + " aliased operations returned " + aliased + " results — the endpoint "
                  + "enforces no query-complexity/cost or per-operation rate limit, so a single request multiplies work "
                  + "N-fold. An attacker aliases a login/OTP resolver to bypass auth throttling (batched credential brute-"
                  + "force) or an expensive resolver for denial of service (CWE-770). Deterministic: " + aliased
                  + " results returned for ONE request.", ar);
            return 1;
        }
        final int B = 25;
        StringBuilder batch = new StringBuilder("[");
        for (int i = 0; i < B; i++) { if (i > 0) batch.append(","); batch.append("{\"query\":\"{__typename}\"}"); }
        batch.append("]");
        HttpRequestResponse br = send(url, batch.toString());
        int batched = batchCount(br);
        if (batched >= B / 2) {
            scanLog.found("GraphQL request amplification — no rate limit (array batching)", url,
                    "A single HTTP request carrying a JSON array of " + B + " GraphQL operations executed " + batched
                  + " of them (array response of " + batched + ") — no per-operation rate limit, enabling batched "
                  + "credential brute-force (auth-throttle bypass) and DoS (CWE-770). Deterministic: " + batched
                  + " results for one request.", br);
            return 1;
        }
        return 0;
    }

    /** Count populated aXX alias keys in the data envelope (how many aliased ops the server executed). */
    private int aliasCount(HttpRequestResponse rr) {
        try {
            if (rr == null || rr.response() == null) return 0;
            JSONObject data = new JSONObject(rr.response().bodyToString()).optJSONObject("data");
            if (data == null) return 0;
            int n = 0;
            for (String k : data.keySet()) if (k.length() > 1 && k.charAt(0) == 'a' && !data.isNull(k)) n++;
            return n;
        } catch (Throwable t) { return 0; }
    }

    /** If the response is a JSON ARRAY of operation results (batching enabled), count the data-bearing ones. */
    private int batchCount(HttpRequestResponse rr) {
        try {
            if (rr == null || rr.response() == null) return 0;
            Object parsed = new org.json.JSONTokener(rr.response().bodyToString()).nextValue();
            if (parsed instanceof JSONArray) {
                JSONArray a = (JSONArray) parsed;
                int n = 0;
                for (int i = 0; i < a.length(); i++) { JSONObject o = a.optJSONObject(i); if (o != null && o.has("data")) n++; }
                return n;
            }
        } catch (Throwable ignore) { }
        return 0;
    }

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
        return Net.authority(u);
    }
    private static String clip(String s) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() <= 60 ? s : s.substring(0, 60) + "…";
    }
}
