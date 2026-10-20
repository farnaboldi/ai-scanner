package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Account / privileged-account enumeration through an account-recovery flow (CWE-204 / CWE-200).
 *
 * <p>A "forgot password" / reset / recovery endpoint that answers an EXISTING account differently from an invented
 * one — another status, another body shape, or a disclosed attribute such as an admin/role flag — lets anyone test
 * candidate usernames/emails. When the differing attribute is a privilege flag it points attackers straight at the
 * administrators. The login form is often hardened (generic error) while recovery is forgotten.
 *
 * <p><b>Oracle.</b> Take a captured recovery request (site map or proxy history — preferring the genuine browser
 * request that carries Origin/Referer) and an identifier KNOWN to exist: the username of a captured SUCCESSFUL login,
 * else the operator's configured login email. Replay the recovery request with an invented identifier (N1), with the
 * known identifier ONCE (V), and with a second invented identifier (N2), using the weakest credential that the endpoint
 * accepts (none → anonymous/pre-login client token → session). N1 and N2 must agree (status, shape, normalized body),
 * so a volatile field cannot fake a difference; fire when V differs from them on status, body shape, a stable scalar
 * field, or normalized content (identifiers masked so an echoed address never counts).
 *
 * <p>Side effects are bounded: exactly ONE recovery request per endpoint for the known (operator's own) account, which
 * may trigger a reset message to that mailbox; invented identifiers trigger nothing.
 */
public final class RecoveryEnumProbe extends Probe {

    private static final Pattern RECOVERY_URL = Pattern.compile(
            "(?i)(forgot|reset|recover|lost)[-_/]?(your[-_/]?)?(password|passwd|pass|pwd|credentials?|login|account|username)"
          + "|password[-_/]?(reset|forgot|recovery|recover|request)|account[-_/]?recovery");
    private static final Pattern LOGINISH = Pattern.compile("(?i)(login|signin|sign-in|logon|authenticate|/auth(/|$)|session)");
    private static final Pattern PW_FIELD = Pattern.compile("(?i)(^|[_-])?(pass|passwd|password|pwd|passphrase)([_-]|$)?");
    private static final Pattern ID_FIELD = Pattern.compile("(?i)(user|e-?mail|login|account|identifier|mail|principal)");
    private static final Pattern EMAILY = Pattern.compile("(?i)^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern PRIV_FIELD = Pattern.compile("(?i)(admin|role|privilege|superuser|staff|owner|permission|elevated|is_?root)");
    private static final Pattern VOLATILE_KEY = Pattern.compile("(?i)(timestamp|^time$|date|expir|nonce|token|request_?id|trace|csrf|stamp|uuid|guid)");
    private static final Pattern UUID_ANY = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern SKIP = Pattern.compile("(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\\?.*)?$");

    public RecoveryEnumProbe(MontoyaApi api, ScanLog scanLog) { super(api, scanLog); }

    private static final class Tier {
        final String label, cookie, bearer;
        Tier(String label, String cookie, String bearer) { this.label = label; this.cookie = cookie; this.bearer = bearer; }
    }

    /** The recovery request layout: body kind and the identity field. */
    private static final class Shape {
        boolean json; String idField;
    }

    public int probe(String host, String cookie, String bearer, String anonBearer) {
        int hits = 0;
        try {
            LinkedHashSet<String> known = knownIdentities(host);
            Map<String, HttpRequest> cands = recoveryCandidates(host);
            scanLog.log("recovery-enum: " + cands.size() + " account-recovery endpoint(s)"
                    + (cands.isEmpty() ? "" : " " + cands.keySet()) + "; known account(s): "
                    + (known.isEmpty() ? "none" : known.size() + " (" + mask(known.iterator().next()) + (known.size() > 1 ? ", …" : "") + ")"));
            if (cands.isEmpty()) return 0;
            if (known.isEmpty()) {
                scanLog.log("recovery-enum: no account known to exist (capture a successful login or set AISCANNER_LOGIN_EMAIL) — skipped.");
                return 0;
            }
            for (Map.Entry<String, HttpRequest> e : cands.entrySet()) {
                try { if (oracle(e.getKey(), e.getValue(), known.iterator().next(), cookie, bearer, anonBearer)) hits++; }
                catch (Throwable t) { scanLog.log("recovery-enum: " + e.getKey() + " — error: " + t); }
            }
        } catch (Throwable t) {
            scanLog.debug("recovery-enum probe error: " + t);
        }
        return hits;
    }

    // ---------------------------------------------------------------- known accounts

    /** Identifiers known to exist: usernames of captured SUCCESSFUL logins (proxy history keeps the original
     *  response), then the operator's configured login email, then usernames of other captured logins. */
    private LinkedHashSet<String> knownIdentities(String host) {
        LinkedHashSet<String> ok = new LinkedHashSet<>(), weak = new LinkedHashSet<>();
        try {
            for (burp.api.montoya.proxy.ProxyHttpRequestResponse ph : api.proxy().history()) {
                try {
                    int st = ph.hasResponse() && ph.response() != null ? ph.response().statusCode() : -1;
                    collectLogin(ph.finalRequest(), st, host, ok, weak);
                } catch (Throwable ignore) {}
            }
        } catch (Throwable ignore) {}
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                try { collectLogin(rr.request(), rr.response() == null ? -1 : rr.response().statusCode(), host, ok, weak); }
                catch (Throwable ignore) {}
            }
        } catch (Throwable ignore) {}
        String cfg = Tuning.str("aiscanner.loginEmail", "AISCANNER_LOGIN_EMAIL");
        LinkedHashSet<String> out = new LinkedHashSet<>(ok);
        if (cfg != null) out.add(cfg);
        out.addAll(weak);
        return out;
    }

    private void collectLogin(HttpRequest req, int st, String host, Set<String> ok, Set<String> weak) {
        if (req == null || !"POST".equalsIgnoreCase(req.method())) return;
        String url = req.url();
        if (!host.equalsIgnoreCase(hostOf(url))) return;
        String path = Net.stripQuery(url);
        if (!LOGINISH.matcher(path).find() || RECOVERY_URL.matcher(path).find()) return;
        Map<String, String> f = fields(req);
        boolean hasPw = false; String user = null;
        for (Map.Entry<String, String> e : f.entrySet()) {
            if (PW_FIELD.matcher(e.getKey()).matches() || e.getKey().toLowerCase().contains("password")) hasPw = true;
            else if (user == null && ID_FIELD.matcher(e.getKey()).find() && !e.getValue().isBlank()) user = e.getValue();
        }
        if (!hasPw || user == null || user.toLowerCase().startsWith("aisc")) return;   // never our own invented ids
        (st / 100 == 2 ? ok : weak).add(user);
    }

    // ---------------------------------------------------------------- candidates

    private Map<String, HttpRequest> recoveryCandidates(String host) {
        Map<String, HttpRequest> cands = new LinkedHashMap<>();
        Map<String, Integer> score = new HashMap<>();
        List<HttpRequest> all = new ArrayList<>();
        try { for (HttpRequestResponse rr : api.siteMap().requestResponses()) all.add(rr.request()); } catch (Throwable ignore) {}
        try { for (burp.api.montoya.proxy.ProxyHttpRequestResponse ph : api.proxy().history()) all.add(ph.finalRequest()); } catch (Throwable ignore) {}
        for (HttpRequest req : all) {
            try {
                if (req == null) continue;
                String m = req.method();
                if (!"POST".equalsIgnoreCase(m) && !"PUT".equalsIgnoreCase(m)) continue;
                String url = req.url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                String path = Net.stripQuery(url);
                if (!RECOVERY_URL.matcher(path).find()) continue;
                if (shapeOf(req) == null) continue;                 // needs an identity field (not a token/new-password reset)
                String key = m.toUpperCase() + " " + path;
                int sc = (hasHdr(req, "Origin") ? 1000 : 0) + (hasHdr(req, "Referer") ? 300 : 0) + headerCount(req);
                if (sc > score.getOrDefault(key, -1)) { cands.put(key, req); score.put(key, sc); }
            } catch (Throwable ignore) {}
        }
        return cands;
    }

    /** Identity field of a recovery request (JSON or form); null when there is none or it is a reset-with-token
     *  form carrying a new password. */
    private static Shape shapeOf(HttpRequest req) {
        Map<String, String> f = fields(req);
        Shape s = new Shape();
        s.json = isJson(req);
        for (Map.Entry<String, String> e : f.entrySet()) {
            String k = e.getKey();
            if (k.toLowerCase().contains("password") || PW_FIELD.matcher(k).matches()) return null;   // new-password reset step
        }
        for (Map.Entry<String, String> e : f.entrySet())               // prefer an email-valued identity field
            if (ID_FIELD.matcher(e.getKey()).find() && EMAILY.matcher(e.getValue()).matches()) { s.idField = e.getKey(); return s; }
        for (Map.Entry<String, String> e : f.entrySet())
            if (ID_FIELD.matcher(e.getKey()).find()) { s.idField = e.getKey(); return s; }
        return null;
    }

    /** String-valued body fields (JSON object or form). */
    private static Map<String, String> fields(HttpRequest req) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            String b = req.bodyToString();
            if (b != null && b.trim().startsWith("{")) {
                JSONObject o = new JSONObject(b.trim());
                for (String k : o.keySet()) { Object v = o.opt(k); if (v instanceof String) out.put(k, (String) v); }
                return out;
            }
        } catch (Throwable ignore) {}
        try {
            for (ParsedHttpParameter p : req.parameters())
                if (p.type() == HttpParameterType.BODY) out.put(p.name(), p.value() == null ? "" : p.value());
        } catch (Throwable ignore) {}
        return out;
    }

    // ---------------------------------------------------------------- oracle

    private boolean oracle(String key, HttpRequest captured, String knownId, String cookie, String bearer, String anonBearer) {
        Shape sh = shapeOf(captured);
        if (sh == null) return false;
        HttpRequest base = strip(captured);
        String domain = knownId.contains("@") ? knownId.substring(knownId.indexOf('@') + 1) : null;
        String inv1 = invented(domain), inv2 = invented(domain);

        // weakest credential tier the endpoint accepts (probed with an INVENTED identifier — no side effect)
        List<Tier> ladder = new ArrayList<>();
        ladder.add(new Tier("unauthenticated (no credentials)", "", ""));
        if (!blank(anonBearer)) ladder.add(new Tier("anonymous client token (no account / pre-login)", "", anonBearer));
        if (!blank(cookie) || !blank(bearer)) ladder.add(new Tier("authenticated session", nz(cookie), nz(bearer)));
        Tier tier = null; HttpRequestResponse n1 = null; StringBuilder st = new StringBuilder();
        for (Tier t : ladder) {
            HttpRequestResponse r = send(withId(base, sh, inv1), t);
            int s = status(r);
            st.append(st.length() == 0 ? "" : ", ").append(t.label.split(" \\(")[0]).append("=").append(s);
            if (s != 0 && s != 401 && s != 403 && s != 407 && s != 429 && s < 500) { tier = t; n1 = r; break; }
        }
        if (tier == null) { why(key, "no credential tier reached the recovery logic (" + st + ")"); return false; }

        HttpRequestResponse v  = send(withId(base, sh, knownId), tier);    // the ONE request for the real account
        HttpRequestResponse n2 = send(withId(base, sh, inv2), tier);
        int sv = status(v), s1 = status(n1), s2 = status(n2);
        if (sv == 0 || sv == 401 || sv == 403 || sv == 407 || sv == 429 || sv >= 500) { why(key, "known account → HTTP " + sv + " (inconclusive)"); return false; }

        String[] ids = { knownId, inv1, inv2 };
        String b1 = norm(body(n1), ids), b2 = norm(body(n2), ids), bv = norm(body(v), ids);
        boolean stable = s1 == s2 && Net.shape(n1).equals(Net.shape(n2)) && b1.equals(b2);
        if (!stable) { why(key, "two invented identifiers answer differently (volatile response) — cannot attribute a difference"); return false; }

        List<String> diffs = new ArrayList<>();
        if (sv != s1) diffs.add("status " + sv + " vs " + s1);
        if (!Net.shape(v).equals(Net.shape(n1))) diffs.add("body shape");
        Map<String, String[]> fieldDiff = scalarDiff(body(v), body(n1), body(n2));
        for (Map.Entry<String, String[]> e : fieldDiff.entrySet()) diffs.add(e.getKey() + "=" + e.getValue()[0] + " vs " + e.getValue()[1]);
        if (diffs.isEmpty() && !bv.equals(b1)) diffs.add("response content");
        if (diffs.isEmpty()) { why(key, "known and invented accounts get the same answer (" + sv + ") — recovery does not enumerate"); return false; }

        String privKey = null;
        for (String k : fieldDiff.keySet()) if (PRIV_FIELD.matcher(k).find()) { privKey = k; break; }
        String access = tier.label.startsWith("unauthenticated") ? "unauthenticated"
                : tier.label.startsWith("anonymous") ? "anonymous client token" : "authenticated session";
        String cls = (privKey != null ? "Privileged-account enumeration via account-recovery response"
                                      : "Account enumeration via account-recovery response") + " (" + access + ")";

        StringBuilder d = new StringBuilder();
        d.append(key).append(" answers an account known to exist differently from invented ones — ")
         .append(String.join("; ", diffs)).append(". Reachable with: ").append(tier.label).append(". ")
         .append("Request 1: a known account → HTTP ").append(sv).append(". Requests 2 and 3: two different invented identifiers → HTTP ")
         .append(s1).append(" with identical answers (the difference is stable, not noise). ");
        if (privKey != null) {
            String[] pv = fieldDiff.get(privKey);
            d.append("The differing field '").append(privKey).append("' is a privilege attribute (").append(pv[0]).append(" for the known account, ")
             .append(pv[1]).append(" for invented ones): the response tells an unauthenticated caller which identifiers belong to privileged ")
             .append("accounts, pointing credential attacks at administrators. ");
        } else {
            d.append("Any caller can therefore test candidate usernames/emails and learn which are registered accounts. ");
        }
        d.append("One recovery request was sent for the known account (it may trigger a reset message to that mailbox); invented identifiers trigger nothing.");
        scanLog.found(cls, Net.stripQuery(base.url()), d.toString(), v, n1, n2);
        scanLog.incFinding();
        return true;
    }

    /** Scalar top-level JSON fields whose value differs for the known account while the two invented ones agree. */
    static Map<String, String[]> scalarDiff(String bv, String b1, String b2) {
        Map<String, String[]> out = new LinkedHashMap<>();
        try {
            JSONObject v = new JSONObject(bv.trim()), n1 = new JSONObject(b1.trim()), n2 = new JSONObject(b2.trim());
            for (String k : v.keySet()) {
                if (!n1.has(k) || !n2.has(k) || isVolatile(k)) continue;
                Object a = v.opt(k), x = n1.opt(k), y = n2.opt(k);
                if (!(a instanceof Boolean || a instanceof Number || a instanceof String)) continue;
                if (a instanceof String && ((String) a).length() > 64) continue;
                if (String.valueOf(x).equals(String.valueOf(y)) && !String.valueOf(a).equals(String.valueOf(x)))
                    out.put(k, new String[]{ String.valueOf(a), String.valueOf(x) });
            }
        } catch (Throwable ignore) {}
        return out;
    }

    private static boolean isVolatile(String k) {
        return VOLATILE_KEY.matcher(k).find() || k.equals("id") || k.endsWith("Id") || k.endsWith("_id");
    }

    /** Body with the sent identifiers masked (an echoed address must never count as a difference) and volatile
     *  tokens (UUIDs, long numbers) normalized. */
    static String norm(String body, String[] ids) {
        String b = body == null ? "" : body;
        for (String id : ids) if (id != null && !id.isEmpty()) b = b.replaceAll("(?i)" + Pattern.quote(id), "<ident>");
        b = UUID_ANY.matcher(b).replaceAll("<uuid>");
        return b.replaceAll("\\d{4,}", "#").trim();
    }

    private static String invented(String domain) {
        String local = "aisc-nouser-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        return domain != null ? local + "@" + domain : local.replace("-", "");
    }

    private static HttpRequest withId(HttpRequest req, Shape sh, String value) {
        try {
            if (sh.json) {
                JSONObject o = new JSONObject(req.bodyToString().trim());
                o.put(sh.idField, value);
                return req.withBody(o.toString());
            }
            return req.withUpdatedParameters(HttpParameter.parameter(sh.idField, value, HttpParameterType.BODY));
        } catch (Throwable t) { return req; }
    }

    // ---------------------------------------------------------------- plumbing

    private int transientRetries = 4;

    private HttpRequestResponse send(HttpRequest req, Tier t) {
        try {
            HttpRequest r = req;
            if (!blank(t.cookie)) r = r.withHeader("Cookie", t.cookie);
            if (!blank(t.bearer)) r = r.withHeader("Authorization", t.bearer.startsWith("Bearer ") ? t.bearer : "Bearer " + t.bearer);
            HttpRequestResponse rr = send(r);
            for (int attempt = 1; attempt <= 2 && isTransientBlock(rr) && transientRetries > 0; attempt++) {
                transientRetries--;
                try { Thread.sleep(5000L * attempt); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
                rr = send(r);
            }
            return rr;
        } catch (Throwable e) { return null; }
    }

    private static boolean isTransientBlock(HttpRequestResponse rr) {
        int st = status(rr);
        if (st == 429) return true;
        if (st != 403) return false;
        String b = body(rr).trim();
        return !(b.startsWith("{") || b.startsWith("["));
    }

    private static HttpRequest strip(HttpRequest req) {
        HttpRequest r = req;
        try { if (r.hasHeader("Authorization")) r = r.withRemovedHeader("Authorization"); } catch (Throwable ignore) {}
        try { if (r.hasHeader("Cookie")) r = r.withRemovedHeader("Cookie"); } catch (Throwable ignore) {}
        return r;
    }

    private void why(String key, String reason) { scanLog.log("recovery-enum: " + key + " — not reported: " + reason); }

    private static String mask(String id) {
        int at = id.indexOf('@');
        return at > 1 ? id.charAt(0) + "***" + id.substring(at) : "***";
    }

    private static String body(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : ""; } catch (Throwable t) { return ""; }
    }
    private static int status(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : 0; } catch (Throwable t) { return 0; }
    }
    private static boolean hasHdr(HttpRequest r, String n) { try { return r.hasHeader(n); } catch (Throwable t) { return false; } }
    private static int headerCount(HttpRequest r) { try { return r.headers() == null ? 0 : r.headers().size(); } catch (Throwable t) { return 0; } }
    private static boolean blank(String s) { return s == null || s.isBlank(); }
    private static String nz(String s) { return s == null ? "" : s; }
}
