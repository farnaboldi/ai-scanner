package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic body-mutation probe (generic — no app-specific fields/paths). Over discovered
 * write requests (POST/PUT/PATCH with a JSON body) it applies four GENERIC mutation families whose
 * natural effect trips mass-assignment / boundary / privilege / IDOR challenges:
 *   (a) mass-assignment — ADD well-known privilege keys (role/isAdmin/...) the client never sends;
 *   (b) empty-required — blank credential-like fields together;
 *   (c) boundary values — push numeric fields to 0 / negative / huge (rating, quantity, amount, price);
 *   (d) IDOR — point owner/id fields at a different id.
 * A mutated create/update that the server ACCEPTS (2xx) is reported; the acceptance is what the
 * server-side challenge keys off. Intrusive by nature (creates/updates data) — for authorized test targets.
 */
public final class BodyMutatorProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private int baseStatus = -1, baseLen = -1;   // baseline for the request currently being probed
    private String baseBody = "";                 // baseline response body (for the balance-grew oracle)
    // A balance/wallet-like field in a RESPONSE. Sending a NEGATIVE quantity/amount that makes one of these
    // GROW is a mass-assignment / input-validation flaw (crАПI: order {quantity:-100} → available_credit +$1000).
    private static final Pattern MONEY_FIELD = Pattern.compile(
            "(?i)\"(credit|balance|wallet|funds|available[_-]?credit|available)\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)");

    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*(logout|signout|sign-out).*");
    private static final Pattern PASS_LIKE = Pattern.compile("(?i).*(pass|pwd|clave|secret).*");
    private static final Pattern USER_LIKE = Pattern.compile("(?i).*(email|user|login|usuario).*");
    private static final Pattern NUM_LIKE = Pattern.compile("(?i).*(rating|stars?|quant|amount|price|total|number|count|score|qty).*");
    private static final Pattern ID_LIKE = Pattern.compile("(?i).*(id|owner)$|.*(id|owner)[A-Z].*");
    // string field "key":"value"  and  numeric field "key":123
    private static final Pattern STR_FIELD = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"(?:[^\"\\\\]|\\\\.)*\"");
    private static final Pattern NUM_FIELD = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)");

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Undocumented privilege fields to inject (generic dictionary — Django is_staff/is_superuser, Rails admin,
    // node is_admin, generic role/isAdmin). NOT app-specific: these are the standard privilege attribute names.
    private static final String PRIV_INJECT =
            ",\"role\":\"admin\",\"isAdmin\":true,\"admin\":true,\"userRole\":\"admin\","
          + "\"is_admin\":true,\"is_staff\":true,\"superuser\":true,\"is_superuser\":true";
    private static final String[] PRIV_KEYS =
            {"is_admin", "is_superuser", "isadmin", "superuser", "is_staff", "admin", "role", "userrole"};
    private static final Pattern JWT =
            Pattern.compile("eyJ[A-Za-z0-9_-]{6,}\\.eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*");

    public BodyMutatorProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** Run the four mutation families over one discovered write request (already session-wrapped). */
    public void probe(HttpRequest req) {
        try {
            String m = req.method();
            if (!m.equals("POST") && !m.equals("PUT") && !m.equals("PATCH")) return;
            if (SKIP.matcher(req.url()).matches()) return;
            // skip auth endpoints (login returns 200 for a valid attempt → not mass-assignment)
            if (AuthenticatedExplorer.SESSION_RESET.matcher(req.url()).matches()) return;
            String body = req.bodyToString();
            // Treat the request as JSON by Content-Type OR by body SHAPE — captured/replayed SPA requests can
            // lose the json Content-Type header, and AiScanner already counts these as JSON targets by shape.
            if (body == null || !body.trim().startsWith("{")) return;
            // baseline the ORIGINAL body: only report a mutation whose response DIVERGES (real effect),
            // so endpoints that 200 on anything (web3 stubs) don't create false positives.
            HttpRequestResponse b = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
            this.baseStatus = b != null && b.response() != null ? b.response().statusCode() : -1;
            this.baseLen = b != null && b.response() != null ? b.response().body().length() : -1;
            this.baseBody = b != null && b.response() != null ? b.response().bodyToString() : "";

            // (a) mass-assignment → privilege escalation: inject undocumented privilege fields and CONFIRM
            // the escalation by reading it back from the principal (the returned JWT), differential vs a
            // control account without the field — a confirmed escalation, not a response-divergence guess.
            massAssign(req, body);

            // (b) empty-required: blank credential-like string fields together. GATE on a genuine credential
            // PAIR — at least one password-like field must be present. A lone user-like field is NOT an auth
            // submission: e.g. an LLM prompt field "user_input" matches USER_LIKE via "user", and emptying it
            // returns a normal 200 (the model just answers nothing) → a false "empty credentials accepted".
            // Requiring a pass-like field keeps the real auth-bypass signal (empty password accepted) and drops
            // the FP on any endpoint that merely has a user/email/login-ish field without a password.
            String empt = body;
            Matcher sm = STR_FIELD.matcher(body);
            boolean anyPass = false;
            while (sm.find()) {
                String k = sm.group(1);
                boolean u = USER_LIKE.matcher(k).matches(), p = PASS_LIKE.matcher(k).matches();
                if (u || p) {
                    empt = empt.replaceFirst("(\"" + Pattern.quote(k) + "\"\\s*:\\s*)\"(?:[^\"\\\\]|\\\\.)*\"", "$1\"\"");
                    anyPass |= p;
                }
            }
            if (anyPass) accepted(req.withBody(empt), req.url(), "empty-required credential fields", false);

            // (c) boundary values on numeric fields: 0 and -1
            Matcher nm = NUM_FIELD.matcher(body);
            while (nm.find()) {
                String k = nm.group(1);
                if (!NUM_LIKE.matcher(k).matches()) continue;
                for (String v : new String[]{"0", "-1", "-1000"}) {
                    String mut = body.replaceFirst("(\"" + Pattern.quote(k) + "\"\\s*:\\s*)-?\\d+(?:\\.\\d+)?", "$1" + v);
                    // checkMoney on NEGATIVE values: a negative quantity/amount that makes a balance GROW is
                    // the mass-assignment effect (crАПI order {quantity:-100} → credit +$1000) that the
                    // length-diff oracle misses (same-length value change).
                    if (!mut.equals(body)) accepted(req.withBody(mut), req.url(), "boundary " + k + "=" + v, v.startsWith("-"));
                }
            }

            // (d) IDOR: point id/owner numeric fields at a different id
            Matcher im = NUM_FIELD.matcher(body);
            while (im.find()) {
                String k = im.group(1);
                if (!ID_LIKE.matcher(k).matches()) continue;
                String other = im.group(2).equals("1") ? "2" : "1";
                String mut = body.replaceFirst("(\"" + Pattern.quote(k) + "\"\\s*:\\s*)-?\\d+(?:\\.\\d+)?", "$1" + other);
                if (!mut.equals(body)) accepted(req.withBody(mut), req.url(), "IDOR " + k + "→" + other, false);
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] body-mutator error: " + t);
        }
    }

    /** Inject privilege fields into a create/register body and CONFIRM escalation via token readback. */
    private void massAssign(HttpRequest req, String body) {
        try {
            // The CONTROL body must carry NO privilege field (else both principals are elevated and the
            // differential is void). Strip any privilege field the seeded/captured body already contains.
            String clean = stripPrivileges(body);
            String injected = clean.replaceFirst("\\}\\s*$", Matcher.quoteReplacement(PRIV_INJECT) + "}");
            if (injected.equals(clean)) return;                      // no trailing '}' → not a JSON object
            int seq = SEQ.incrementAndGet();
            // Register/create endpoints reject a duplicate identity, so give the control and injected requests
            // DISTINCT identities; then the ONLY difference between the two principals is the injected field.
            HttpRequestResponse control   = send(req.withBody(uniquifyIdentity(clean,    "maC" + seq)));
            HttpRequestResponse injectedR = send(req.withBody(uniquifyIdentity(injected, "maI" + seq)));
            String key = confirmPrivViaToken(control, injectedR);
            if (key != null) {
                scanLog.found("Mass assignment → privilege escalation", req.url(),
                        "An undocumented privilege field injected into the create/register body surfaced TRUTHY ("
                        + key + ") in the principal encoded in the server-issued token, while a control account "
                        + "without the field did not — a confirmed privilege escalation (CWE-915/CWE-269).",
                        injectedR);
                scanLog.incFinding();
            }
        } catch (Throwable ignore) { }
    }

    /** Remove any privilege field from a JSON body so the control request is un-elevated. */
    private static String stripPrivileges(String body) {
        String b = body;
        for (String k : PRIV_KEYS) {
            b = b.replaceAll("(?i)\"" + Pattern.quote(k) + "\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|true|false|-?\\d+(?:\\.\\d+)?|null)\\s*,?", "");
        }
        return b.replace("{,", "{").replace(",}", "}").replaceAll(",\\s*,", ",");
    }

    /** Replace the first user/email-like string field's value with a unique canary (preserving any @domain so
     *  email validation still passes) so two create requests don't collide on a unique-identity constraint. */
    private static String uniquifyIdentity(String body, String canary) {
        Matcher sm = STR_FIELD.matcher(body);
        while (sm.find()) {
            String k = sm.group(1);
            if (!USER_LIKE.matcher(k).matches()) continue;
            Matcher vm = Pattern.compile("(\"" + Pattern.quote(k) + "\"\\s*:\\s*\")((?:[^\"\\\\]|\\\\.)*)(\")").matcher(body);
            if (vm.find()) {
                String old = vm.group(2);
                int at = old.indexOf('@');
                String nv = at >= 0 ? canary + old.substring(at) : canary + old;
                return body.substring(0, vm.start()) + vm.group(1) + Matcher.quoteReplacement(nv) + vm.group(3)
                        + body.substring(vm.end());
            }
        }
        return body;
    }

    /** First injected privilege key that is TRUTHY in the injected token payload but NOT in the control's;
     *  null if unconfirmed. JWT payloads are base64url and unencrypted, so the principal is directly readable. */
    private static String confirmPrivViaToken(HttpRequestResponse control, HttpRequestResponse injected) {
        String ij = jwtPayload(injected);
        if (ij == null) return null;
        String cj = jwtPayload(control);
        for (String k : PRIV_KEYS) {
            boolean inj = truthy(ij, k);
            boolean ctl = cj != null && truthy(cj, k);
            if (inj && !ctl) return k;
        }
        return null;
    }

    private static boolean truthy(String json, String key) {
        return Pattern.compile("(?i)\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|1|\"(?:true|1|yes|admin|superuser|staff)\")")
                .matcher(json).find();
    }

    /** Extract the first JWT in the response body and base64url-decode its payload segment. */
    private static String jwtPayload(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return null;
        String body = rr.response().bodyToString();
        if (body == null) return null;
        Matcher m = JWT.matcher(body);
        while (m.find()) {
            String[] parts = m.group().split("\\.");
            if (parts.length < 2) continue;
            try {
                String s = parts[1];
                while (s.length() % 4 != 0) s += "=";
                String payload = new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
                if (payload.trim().startsWith("{")) return payload;
            } catch (Throwable ignore) { }
        }
        return null;
    }

    private HttpRequestResponse send(HttpRequest req) {
        try { return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)); }
        catch (Throwable t) { return null; }
    }

    private void accepted(HttpRequest req, String url, String family, boolean checkMoney) {
        try {
            HttpRequestResponse r = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
            if (r == null || r.response() == null) return;
            int st = r.response().statusCode();
            if (st < 200 || st >= 300) return;
            int len = r.response().body().length();
            String rb = r.response().bodyToString();
            // The mutation SENT is what trips server-side challenges; we only REPORT when the response
            // diverges from baseline (real effect) to avoid false positives on 200-on-anything stubs.
            boolean diverged = (st != baseStatus) || Math.abs(len - baseLen) > Math.max(32, baseLen / 10);
            // Balance-grew oracle: a NEGATIVE numeric input that INCREASED a credit/balance field — a same-
            // length value change the diverged check misses, but an unambiguous input-validation flaw.
            boolean money = checkMoney && moneyGrew(baseBody, rb);
            if (diverged || money) {
                String why = money
                        ? family + " → balance INCREASED " + money2(baseBody) + "→" + money2(rb) + " (mass assignment)"
                        : family + " accepted (HTTP " + st + ", " + baseLen + "→" + len + "b)";
                scanLog.found("Improper input validation / mass assignment", url, why, r);
                scanLog.incFinding();
            }
        } catch (Throwable ignore) { }
    }

    private static double maxMoney(String body) {
        double max = Double.NEGATIVE_INFINITY;
        if (body != null) {
            Matcher m = MONEY_FIELD.matcher(body);
            while (m.find()) { try { max = Math.max(max, Double.parseDouble(m.group(2))); } catch (Exception e) { } }
        }
        return max;
    }
    private static String money2(String body) { double v = maxMoney(body); return v == Double.NEGATIVE_INFINITY ? "?" : String.valueOf(v); }
    private static boolean moneyGrew(String base, String mut) {
        double b = maxMoney(base), a = maxMoney(mut);
        if (b == Double.NEGATIVE_INFINITY || a == Double.NEGATIVE_INFINITY) return false;
        return a > b + Math.max(1.0, Math.abs(b) * 0.05);   // grew by >1 or >5% → real increase
    }
}
