package com.ioactive.aiscanner.scan;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure GraphQL transport helpers (no Burp, no external deps — just bundled org.json): build the introspection
 * query, parse an introspection response into Query/Mutation operations + their arguments, and synthesize an
 * operation document that places a payload into a chosen argument.
 *
 * <p>This is the reusable CORE of the GraphQL transport (benchmark build-step 1): it turns every resolver
 * argument into a first-class insertion point so the deterministic oracle battery (SQLi/NoSQL/cmd/IDOR/…) can be
 * driven through GraphQL. It decides nothing — it only shapes requests; the oracle still decides the verdict.
 * The Burp {@code HttpRequest} wiring in {@code GraphqlProbe} is a thin runtime layer over these functions.</p>
 */
public final class GraphqlOperations {
    private GraphqlOperations() {}

    /** A resolver argument: its name, its ultimate named type, and whether it is non-null (required). */
    public static final class Arg {
        public final String name;
        public final String typeName;
        public final boolean required;
        public Arg(String name, String typeName, boolean required) {
            this.name = name; this.typeName = typeName == null ? "" : typeName; this.required = required;
        }
    }

    /** A top-level operation: query or mutation field, its return type, whether that return is a leaf
     *  (scalar/enum → no selection set), and its arguments. */
    public static final class Op {
        public final String kind;        // "query" | "mutation"
        public final String field;
        public final String returnType;
        public final boolean returnIsLeaf;
        public final List<Arg> args;
        public Op(String kind, String field, String returnType, boolean returnIsLeaf, List<Arg> args) {
            this.kind = kind; this.field = field; this.returnType = returnType == null ? "" : returnType;
            this.returnIsLeaf = returnIsLeaf; this.args = args == null ? new ArrayList<>() : args;
        }
        public Arg arg(String name) { for (Arg a : args) if (a.name.equals(name)) return a; return null; }
    }

    /** The standard introspection query (enough to recover Query/Mutation fields, their args, and return kinds). */
    public static String introspectionQuery() {
        return """
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                types {
                  name
                  kind
                  fields(includeDeprecated: true) {
                    name
                    type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
                    args {
                      name
                      type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
                    }
                  }
                }
              }
            }""";
    }

    /** JSON POST body for a GraphQL document: {@code {"query":"…"}} (properly escaped via org.json). */
    public static String postBody(String document) {
        return new JSONObject().put("query", document == null ? "" : document).toString();
    }

    /** Convenience: the introspection request body. */
    public static String introspectionBody() { return postBody(introspectionQuery()); }

    /** Parse an introspection response into the list of Query + Mutation operations. Empty on any problem. */
    public static List<Op> parseIntrospection(String json) {
        List<Op> ops = new ArrayList<>();
        if (json == null || json.isBlank()) return ops;
        try {
            JSONObject root = new JSONObject(json);
            JSONObject data = root.optJSONObject("data");
            JSONObject schema = (data != null ? data : root).optJSONObject("__schema");
            if (schema == null) return ops;
            String qName = nameOf(schema.optJSONObject("queryType"), "Query");
            String mName = nameOf(schema.optJSONObject("mutationType"), "");
            JSONArray types = schema.optJSONArray("types");
            if (types == null) return ops;
            for (int i = 0; i < types.length(); i++) {
                JSONObject t = types.optJSONObject(i);
                if (t == null) continue;
                String tn = t.optString("name", "");
                String kind = tn.equals(qName) ? "query"
                        : (!mName.isBlank() && tn.equals(mName) ? "mutation" : null);
                if (kind == null) continue;
                JSONArray fields = t.optJSONArray("fields");
                if (fields == null) continue;
                for (int j = 0; j < fields.length(); j++) {
                    JSONObject f = fields.optJSONObject(j);
                    if (f == null) continue;
                    String fname = f.optString("name", "");
                    if (fname.isBlank()) continue;
                    String[] rt = unwrap(f.optJSONObject("type"));
                    boolean leaf = rt[1].equals("SCALAR") || rt[1].equals("ENUM");
                    List<Arg> args = new ArrayList<>();
                    JSONArray aa = f.optJSONArray("args");
                    if (aa != null) for (int k = 0; k < aa.length(); k++) {
                        JSONObject a = aa.optJSONObject(k);
                        if (a == null) continue;
                        String an = a.optString("name", "");
                        if (an.isBlank()) continue;
                        JSONObject at = a.optJSONObject("type");
                        boolean req = at != null && "NON_NULL".equals(at.optString("kind", ""));
                        args.add(new Arg(an, unwrap(at)[0], req));
                    }
                    ops.add(new Op(kind, fname, rt[0], leaf, args));
                }
            }
        } catch (Exception ignore) { /* malformed introspection → no ops (probe falls back) */ }
        return ops;
    }

    /**
     * Synthesize a GraphQL document that calls {@code op.field}, placing {@code payload} into {@code targetArg}
     * (as an escaped string literal) and benign type-matched fillers into the other REQUIRED args. Requests a
     * minimal selection ({@code __typename}) for object returns; none for leaf returns.
     */
    public static String buildOperation(Op op, String targetArg, String payload) {
        if (op == null) return "";
        StringBuilder args = new StringBuilder();
        for (Arg a : op.args) {
            boolean isTarget = a.name.equals(targetArg);
            if (!isTarget && !a.required) continue;   // keep the doc minimal + valid: only target + required args
            if (args.length() > 0) args.append(", ");
            args.append(a.name).append(": ").append(isTarget ? gqlString(payload) : filler(a.typeName));
        }
        String argPart = args.length() > 0 ? "(" + args + ")" : "";
        String selection = op.returnIsLeaf ? "" : " { __typename }";
        return op.kind + " { " + op.field + argPart + selection + " }";
    }

    // ---- helpers ----

    private static String nameOf(JSONObject o, String dflt) {
        return o == null ? dflt : o.optString("name", dflt);
    }

    /** Unwrap NON_NULL/LIST wrappers to the ultimate {name, kind}. */
    private static String[] unwrap(JSONObject type) {
        String name = "", kind = "";
        JSONObject t = type;
        for (int guard = 0; t != null && guard < 12; guard++) {
            String k = t.optString("kind", "");
            String n = t.optString("name", "");
            if (!n.isBlank() && !k.equals("NON_NULL") && !k.equals("LIST")) { name = n; kind = k; break; }
            t = t.optJSONObject("ofType");
        }
        return new String[]{name, kind};
    }

    /** A benign, type-matched filler for a required non-target argument. */
    private static String filler(String typeName) {
        String x = typeName == null ? "" : typeName.toLowerCase();
        if (x.equals("int") || x.equals("float") || x.contains("number")) return "1";
        if (x.equals("boolean") || x.equals("bool")) return "true";
        return gqlString("1");   // String/ID (enums are rare as required args) → quoted
    }

    /** Escape a value as a GraphQL string literal. */
    static String gqlString(String s) {
        if (s == null) s = "";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"':  b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:   b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
