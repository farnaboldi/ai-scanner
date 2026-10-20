package com.ioactive.aiscanner.scan;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Per-action risk tiering + a gate for state-changing sends — a lesson borrowed from Burp AT, whose tools
 * carry {@code DESTRUCTIVE / IDEMPOTENT / INERT / READ} annotations and whose "Judge" rates a resolved
 * request's risk BEFORE it is sent.
 *
 * <p>We already keep detection deterministic and zero-FP; this adds the missing safety/precision layer on the
 * WRITE side: don't blind-POST an exercise to an arbitrary endpoint just because a field name matched. A
 * concrete case it fixes — an empty-credentials "registration" was fired at {@code /rest/order-history} and
 * {@code /rest/saveLoginIp} (email-bearing but NOT registration sinks), producing spurious 500s. The gate is
 * generic: it reasons from the request method, the path, and the learned schema — never from app identity.
 */
public final class WriteGuard {

    /** READ = safe/idempotent GET-like; WRITE = state-changing (POST); DESTRUCTIVE = PUT/DELETE/PATCH/MERGE. */
    public enum Tier { READ, WRITE, DESTRUCTIVE }

    private WriteGuard() { }

    public static Tier tier(String method) {
        if (method == null) return Tier.WRITE;
        switch (method.toUpperCase()) {
            case "GET": case "HEAD": case "OPTIONS": case "TRACE": return Tier.READ;
            case "PUT": case "DELETE": case "PATCH": case "MERGE": return Tier.DESTRUCTIVE;
            default: return Tier.WRITE;   // POST / other
        }
    }

    // A registration sink is a NOUN collection you create an account in (users, accounts, members, register,
    // signup, …) — identified by PATH. Deliberately path-only: a password-like field in the RESPONSE is NOT a
    // registration signal (endpoints like /rest/saveLoginIp echo a password hash yet accept no registration),
    // so keying on schema fields false-fired. Universal web idioms, not app-specific names. Handles plurals.
    private static final Pattern REGISTRATION_PATH = Pattern.compile(
            "(?i).*/(?:users?|regist(?:er|ration)s?|sign-?ups?|accounts?|auth|customers?|members?)(?:/|$|\\?).*");

    /**
     * Gate for an empty-/weak-credentials registration exercise: allow ONLY when the target PATH is a plausible
     * registration/users collection. Rejects arbitrary email/password-bearing endpoints (order history,
     * login-IP logs, …) that are not account-creation sinks. Under-fires by design — a blind write is worse
     * than a missed one.
     */
    public static boolean allowsRegistration(String url, List<String> schemaKeys) {
        return url != null && REGISTRATION_PATH.matcher(Net.stripQuery(url)).matches();
    }

    /** True when a state-changing exercise of this method is allowed to be sent unattended (never DESTRUCTIVE). */
    public static boolean allowsUnattended(String method) {
        return tier(method) != Tier.DESTRUCTIVE;
    }

    // ---- DELETE / PATCH hard block ---------------------------------------------------------------------------
    // Rule: the extension never sends DELETE or PATCH. Against a real target, a probe or a native-audit replay of a
    // captured DELETE/PATCH can destroy or rewrite live data (e.g. user records), and no finding is worth
    // that. MERGE is blocked too: it is the OData v1-v3 / SharePoint spelling of PATCH (a partial update).
    // The block covers every way a request can CLAIM one of those methods, because frameworks disagree on precedence
    // (Rack reads _method before the header; Symfony/Laravel read the header, then body _method incl. the JSON bag,
    // then the query; OData reads X-HTTP-Method): the request line, every override header (comma-split), every
    // _method/_HttpMethod parameter of any non-cookie type (URL, form, multipart, JSON), and sub-requests tunnelled in
    // a batch envelope (multipart $batch request lines, JSON {"method":"DELETE"}). Values are URL-decoded first.
    // A JSON body that merely mentions "method":"DELETE" as data is over-blocked on purpose: a missed probe is
    // acceptable, a deleted record is not. AISCANNER_ALLOW_DELETE_PATCH=1 re-enables them ONLY for local/private
    // lab hosts (bench containers on localhost / RFC1918); it is ignored, with a log line, for any other host.
    private static final java.util.Set<String> BLOCKED = java.util.Set.of("DELETE", "PATCH", "MERGE");
    private static final java.util.Set<String> SAFE_READ = java.util.Set.of("GET", "HEAD", "OPTIONS");
    private static final java.util.regex.Pattern EMBEDDED_LINE =
            java.util.regex.Pattern.compile("(?im)^[ \\t]*(DELETE|PATCH|MERGE)[ \\t]+\\S+[ \\t]+HTTP/\\d");
    private static final java.util.regex.Pattern EMBEDDED_JSON =
            java.util.regex.Pattern.compile("(?i)\"method\"\\s*:\\s*\"\\s*(DELETE|PATCH|MERGE)\\s*\"");

    /** The lab opt-in flag (process-wide). Honoured only for local/private hosts — see {@link #blocksDestructiveVerb}. */
    public static boolean allowDeletePatch() {
        return Tuning.b("aiscanner.allowDeletePatch", "AISCANNER_ALLOW_DELETE_PATCH", false);
    }

    /** True when the opt-in may apply to this host: loopback, localhost, RFC1918 or docker-internal. Lexical only (no
     *  DNS), so a public hostname never qualifies even if it happens to resolve to a private address. */
    public static boolean isLabHost(String host) {
        if (host == null) return false;
        String h = host.trim().toLowerCase(java.util.Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        if (h.equals("localhost") || h.endsWith(".localhost") || h.equals("host.docker.internal") || h.equals("::1")) return true;
        if (h.matches("127(\\.\\d{1,3}){3}") || h.matches("10(\\.\\d{1,3}){3}") || h.matches("192\\.168(\\.\\d{1,3}){2}")) return true;
        return h.matches("172\\.(1[6-9]|2\\d|3[01])(\\.\\d{1,3}){2}");
    }

    private static String hostOf(burp.api.montoya.http.message.requests.HttpRequest req) {
        try { if (req.httpService() != null && req.httpService().host() != null) return req.httpService().host(); } catch (Throwable ignore) { }
        try { return java.net.URI.create(req.url()).getHost(); } catch (Throwable ignore) { return null; }
    }

    // Override names in CANONICAL form (see canonicalName): the header spellings and the common parameter spellings.
    private static final java.util.Set<String> OVERRIDE_NAMES = java.util.Set.of(
            "x_http_method_override", "x_http_method", "x_method_override",
            "_method", "__method", "_httpmethod", "_http_method", "__http_method");
    // Whole tokens only: "payment_method" is not an override name and "merge_request" is not a verb.
    private static final java.util.regex.Pattern VERB_WORD =
            java.util.regex.Pattern.compile("(?i)(?<![a-z0-9_])(delete|patch|merge)(?![a-z0-9_])");
    private static final java.util.regex.Pattern OVERRIDE_TOKEN = java.util.regex.Pattern.compile(
            "(?<![a-z0-9])(x_http_method_override|x_http_method|x_method_override|__http_method|_http_method|_httpmethod|__method|_method)(?![a-z0-9])");
    private static final java.util.regex.Pattern BATCH_LINE =
            java.util.regex.Pattern.compile("(?im)^[ \\t]*(DELETE|PATCH|MERGE)[ \\t]+\\S");
    private static final java.util.regex.Pattern JSON_ESCAPE = java.util.regex.Pattern.compile("\\\\u([0-9a-fA-F]{4})");
    private static final int MAX_INSPECTED_BODY = 32 * 1024 * 1024;

    /** Canonical text for matching: percent-decoding (twice, for double encoding) and JSON \\uXXXX unescaping, cut at
     *  the first NUL (servers commonly truncate there). Matching always runs on this, never on the raw bytes. */
    static String canonical(String v) {
        if (v == null) return "";
        for (int i = 0; i < 2; i++) {
            try { v = java.net.URLDecoder.decode(v, java.nio.charset.StandardCharsets.UTF_8); } catch (Exception ignore) { break; }
        }
        java.util.regex.Matcher m = JSON_ESCAPE.matcher(v);
        StringBuilder sb = new StringBuilder();
        while (m.find()) m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(
                String.valueOf((char) Integer.parseInt(m.group(1), 16))));
        m.appendTail(sb);
        v = sb.toString();
        int nul = v.indexOf('\0');
        return nul >= 0 ? v.substring(0, nul) : v;
    }

    private static String norm(String v) { return canonical(v).trim().toUpperCase(java.util.Locale.ROOT); }

    /** Canonical parameter/header NAME: lower-case, with '-', '.' and whitespace folded to '_' (frameworks and PHP
     *  normalise names this way before a handler sees them). */
    static String canonicalName(String n) {
        return canonical(n).trim().toLowerCase(java.util.Locale.ROOT).replaceAll("[-.\\s]", "_");
    }

    /** True when the body looks like a batch/multipart envelope that can tunnel sub-requests. */
    private static boolean batchLike(burp.api.montoya.http.message.requests.HttpRequest req, String body) {
        String ct = "";
        try { if (req.hasHeader("Content-Type")) ct = String.valueOf(req.headerValue("Content-Type")).toLowerCase(java.util.Locale.ROOT); } catch (Throwable ignore) { }
        String b = body.toLowerCase(java.util.Locale.ROOT);
        return ct.contains("multipart/mixed") || ct.contains("application/http") || b.contains("application/http")
                || b.contains("--batch") || b.contains("--changeset");
    }

    /** Every method a server might act on for this request (see the section comment). Throws if the request can't be
     *  inspected; the caller treats that as "block". */
    public static java.util.Set<String> claimedMethods(burp.api.montoya.http.message.requests.HttpRequest req) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        out.add(norm(req.method()));
        for (burp.api.montoya.http.message.HttpHeader h : req.headers()) {
            if (!OVERRIDE_NAMES.contains(canonicalName(h.name()))) continue;
            for (String part : String.valueOf(h.value()).split(",")) out.add(norm(part));
        }
        for (burp.api.montoya.http.message.params.ParsedHttpParameter p : req.parameters()) {
            if (p.type() == burp.api.montoya.http.message.params.HttpParameterType.COOKIE) continue;
            if (OVERRIDE_NAMES.contains(canonicalName(p.name()))) out.add(norm(p.value()));
        }
        String body = req.bodyToString();
        String query = "";
        try { String u = req.url(); int q = u == null ? -1 : u.indexOf('?'); if (q >= 0) query = u.substring(q + 1); } catch (Throwable ignore) { }
        if (body == null) body = "";
        if (body.length() > MAX_INSPECTED_BODY) throw new IllegalStateException("body too large to inspect");
        if (!body.isEmpty()) {
            // A compressed request body can't be inspected: refuse it rather than guess.
            try {
                if (req.hasHeader("Content-Encoding")) {
                    String ce = String.valueOf(req.headerValue("Content-Encoding")).trim().toLowerCase(java.util.Locale.ROOT);
                    if (!ce.isEmpty() && !ce.equals("identity")) throw new IllegalStateException("encoded body");
                }
            } catch (IllegalStateException e) { throw e; } catch (Throwable ignore) { }
            String cb = canonical(body);
            java.util.regex.Matcher m = EMBEDDED_LINE.matcher(cb);
            while (m.find()) out.add(m.group(1).toUpperCase(java.util.Locale.ROOT));
            m = EMBEDDED_JSON.matcher(cb);
            while (m.find()) out.add(m.group(1).toUpperCase(java.util.Locale.ROOT));
            if (batchLike(req, cb)) {
                m = BATCH_LINE.matcher(cb);
                while (m.find()) out.add(m.group(1).toUpperCase(java.util.Locale.ROOT));
            }
        }
        // Conservative backstop, independent of how Burp parsed the parameters: an override NAME anywhere in the
        // canonical query/body together with a destructive verb word anywhere in it counts as that verb.
        String raw = canonicalName(query) + " " + canonicalName(body);
        if (OVERRIDE_TOKEN.matcher(raw).find()) {
            java.util.regex.Matcher v = VERB_WORD.matcher(canonical(query) + " " + canonical(body));
            while (v.find()) out.add(v.group(1).toUpperCase(java.util.Locale.ROOT));
        }
        return out;
    }

    /** For logging: the first blocked method this request claims, else its request-line method. */
    public static String effectiveMethod(burp.api.montoya.http.message.requests.HttpRequest req) {
        try { for (String m : claimedMethods(req)) if (BLOCKED.contains(m)) return m; } catch (Throwable ignore) { }
        return req.method() == null ? "" : req.method().toUpperCase(java.util.Locale.ROOT);
    }

    /** True when this request must NOT be sent. Fails closed when the request cannot be parsed, except for a
     *  body-less plain read (GET/HEAD/OPTIONS), which cannot carry a tunnelled method. */
    public static boolean blocksDestructiveVerb(burp.api.montoya.http.message.requests.HttpRequest req) {
        if (req == null) return false;
        boolean destructive;
        try {
            destructive = false;
            for (String m : claimedMethods(req)) if (BLOCKED.contains(m)) { destructive = true; break; }
        } catch (Throwable t) {
            // Could not inspect it: block, unless it is provably a body-less plain read without override headers.
            String rl = null;
            try { rl = req.method() == null ? "" : req.method().trim().toUpperCase(java.util.Locale.ROOT); } catch (Throwable ignore) { }
            String b = null;
            try { b = req.bodyToString(); } catch (Throwable ignore) { }
            boolean overrideHeader;
            try {
                overrideHeader = false;
                for (burp.api.montoya.http.message.HttpHeader h : req.headers())
                    if (OVERRIDE_NAMES.contains(canonicalName(h.name()))) { overrideHeader = true; break; }
            } catch (Throwable ignore) { overrideHeader = true; }
            destructive = !(rl != null && SAFE_READ.contains(rl) && (b == null || b.isEmpty()) && !overrideHeader);
        }
        if (!destructive) return false;
        if (allowDeletePatch()) {
            String host = hostOf(req);
            if (isLabHost(host)) return false;
            SafeHttp.noteOptInIgnored(host);
        }
        return true;
    }

}
