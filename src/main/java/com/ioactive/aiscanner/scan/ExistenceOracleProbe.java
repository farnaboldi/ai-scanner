package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Existence / identity oracle on a NAME-keyed lookup — tenant/account/resource enumeration (CWE-204 / CWE-200).
 *
 * <p>A lookup {@code GET …/<collection>/<name>[/<sub-resource>]} that answers a name that EXISTS with 2xx plus an
 * internal identifier (UUID / id) or security-relevant configuration (login methods, SSO providers, MFA policy), and a
 * name that does NOT exist with a distinct application-level "not found", lets a caller confirm which tenants /
 * organizations / accounts exist by guessing human-meaningful names and harvest what each one discloses.
 * Pre-login "find my organization" and "which login methods does it use" lookups are the classic cases.
 *
 * <p><b>Oracle</b> (per captured GET; the name may be the last segment or sit before up to two fixed sub-resource
 * segments; the segment must be a guessable slug, never a random id):
 * <ol>
 *   <li><b>credential ladder</b> — replay the real name with the WEAKEST credential that works: none → an
 *       operator-supplied anonymous/pre-login client token (optional) → the scan's session, the latter only when a
 *       second identity B ALSO resolves the same name (so "it exists" is not confused with "it is mine").</li>
 *   <li>the 2xx answer must be JSON and disclose an identifier or authentication configuration.</li>
 *   <li>a same-shape NONEXISTENT name (same credential) must return a not-found-class answer (404/410, or a 400/422
 *       saying not-found) — never an authz denial (401/403) — whose shape differs from the real answer.</li>
 *   <li>that miss must ALSO differ from two routing-miss baselines — (a) bogus collection + bogus name, (b) the REAL
 *       path plus one extra bogus segment (every real name stays valid, only routing fails) — so the miss is the
 *       application looking the name up, not the router failing to match a fixed path segment.</li>
 * </ol>
 * Read-only GETs; one invented name per endpoint — it proves the oracle exists, it never enumerates real names.
 */
public final class ExistenceOracleProbe extends Probe {

    private static final Pattern UUID_SEG  = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern OBJID_SEG = Pattern.compile("^[0-9a-fA-F]{24}$");
    private static final Pattern NUM_SEG   = Pattern.compile("^[0-9]{1,18}$");
    // a random token (letters AND digits, no word separators, long) is not guessable → not an enumeration surface
    private static final Pattern TOKEN_SEG = Pattern.compile("^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9]{12,}$");
    private static final Pattern SLUG_SEG  = Pattern.compile("^(?=.*[A-Za-z])[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$");
    // API prefix / version segments are never the collection a name belongs to
    private static final Pattern PREFIX_SEG = Pattern.compile("(?i)^(api|apis|v\\d+(\\.\\d+)*|rest|public|internal|graphql|web|services?)$");
    private static final Pattern UUID_ANY  = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern ID_KEY    = Pattern.compile("(?i)\"([a-z_]*(?:id|uuid|guid))\"\\s*:\\s*\"?([A-Za-z0-9-]{4,})");
    // authentication / SSO / MFA configuration keys — disclosing these for a named tenant is security-relevant
    private static final Pattern AUTH_CFG_KEY = Pattern.compile(
            "(?i)\"[a-z0-9_]*(password|saml|sso|oidc|oauth|openid|mfa|2fa|totp|login|idp|identityprovider|ldap|kerberos)[a-z0-9_]*\"\\s*:");
    // generic tenant / principal namespaces — wording only (the oracle never depends on it)
    private static final Pattern TENANT_NS = Pattern.compile(
            "(?i)^(institution|tenant|org|organi[sz]ation|account|compan(y|ie)|customer|workspace|team|realm|domain|site|clinic|hospital|practice|school|group|user|member|profile)s?$");
    private static final Pattern NOT_FOUND_WORDS = Pattern.compile("(?i)(not[ _-]?found|does ?n[o']t exist|no such|unknown|not[ _-]?exist)");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf|html?|php|aspx?|jsp)(\\?.*)?$");

    private static final String BOGUS_NAME  = "aisc0nonexistent0name0zq";
    private static final String BOGUS_COLL  = "aisc0nonexistent0coll0zq";
    private static final String BOGUS_ROUTE = "aisc0nonexistent0route0zq";
    private static final int MAX_CANDIDATES = 40;
    private static final int MAX_TRAILING = 2;     // name may precede up to two fixed sub-resource segments

    public ExistenceOracleProbe(MontoyaApi api, ScanLog scanLog) { super(api, scanLog); }

    /** A credential tier: what to attach, and how to describe it in the finding. */
    private static final class Tier {
        final String label, cookie, bearer; final boolean session;
        Tier(String label, String cookie, String bearer, boolean session) {
            this.label = label; this.cookie = cookie; this.bearer = bearer; this.session = session;
        }
    }

    /** A candidate: the request plus WHICH path segment holds the name. */
    private static final class Cand {
        final HttpRequest req; final int pos;
        Cand(HttpRequest req, int pos) { this.req = req; this.pos = pos; }
    }

    public int probe(String host, String cookieA, String bearerA, String cookieB, String bearerB, String anonBearer) {
        int hits = 0;
        try {
            Map<String, Cand> cands = new LinkedHashMap<>();
            Map<String, Integer> candScore = new HashMap<>();
            List<String> seen = new ArrayList<>();
            int scanned = 0;
            // Source 1: the site map (every discovered GET). Source 2: the PROXY HISTORY — it preserves the genuine
            // browser/SPA request with its real headers (Origin/Referer/etc.), which the site map may have overwritten
            // with the native crawler's bare replay. An API that validates Origin would 403 the bare request before it
            // ever looks the name up, masking the oracle — so the history copy is often the only usable candidate.
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                try {
                    int st = rr.response() == null ? -1 : rr.response().statusCode();
                    scanned += consider(rr.request(), st, host, seen, cands, candScore);
                    if (cands.size() >= MAX_CANDIDATES) break;
                } catch (Throwable perEntry) { /* skip this entry */ }
            }
            try {
                for (burp.api.montoya.proxy.ProxyHttpRequestResponse ph : api.proxy().history()) {
                    try {
                        int st = ph.hasResponse() && ph.response() != null ? ph.response().statusCode() : -1;
                        consider(ph.finalRequest(), st, host, seen, cands, candScore);
                        if (cands.size() >= MAX_CANDIDATES) break;
                    } catch (Throwable perEntry) { /* skip */ }
                }
            } catch (Throwable noHistory) { /* proxy history unavailable */ }

            scanLog.log("existence-oracle: " + cands.size() + " name-keyed GET template(s) to test (of " + scanned + " GETs on " + host + ")"
                    + (cands.isEmpty() ? "" : ": " + String.join(", ", cands.keySet())));
            for (String x : seen) scanLog.log("existence-oracle:   GET " + x);
            for (Map.Entry<String, Cand> e : cands.entrySet()) {
                try {
                    if (oracle(e.getKey(), e.getValue(), cookieA, bearerA, cookieB, bearerB, anonBearer)) hits++;
                } catch (Throwable perCand) {
                    scanLog.log("existence-oracle: " + e.getKey() + " — error: " + perCand);
                }
            }
        } catch (Throwable t) {
            scanLog.debug("existence-oracle probe error: " + t);
        }
        return hits;
    }

    /** Score one request into the per-template candidates (one template per plausible name position). Returns 1 when
     *  it was a GET on {@code host} (for the scanned counter). Ranks requests sharing a template: Origin &gt; Referer &gt;
     *  originally-2xx &gt; more headers — so the genuine SPA request wins over a bare crawler replay. */
    private int consider(HttpRequest req, int st, String host, List<String> seen,
                         Map<String, Cand> cands, Map<String, Integer> candScore) {
        if (req == null || !"GET".equalsIgnoreCase(req.method())) return 0;
        String url = req.url();
        if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) return 0;
        String key = Net.stripQuery(url) + (hasHdr(req, "Origin") ? " [+Origin]" : "");
        // The STORED status is only a hint: lifecycle phases replay and overwrite it (e.g. a transient edge 403 over the
        // original 200). Keep anything that may resolve with credentials; drop only definitive answers.
        boolean usable = st / 100 == 2 || st / 100 == 3 || st == 401 || st == 403 || st == 429;
        if (!usable) { note(seen, key, "stored status " + st); return 1; }
        String[] segs = pathOf(url).split("/");
        int n = segs.length, added = 0;
        for (int p = n - 1; p >= Math.max(2, n - 1 - MAX_TRAILING); p--) {
            if (!namePositionOk(segs, p)) continue;
            String tpl = template(segs, p);
            int score = (hasHdr(req, "Origin") ? 1000 : 0) + (hasHdr(req, "Referer") ? 300 : 0)
                      + (st / 100 == 2 ? 100 : 0) + headerCount(req);
            if (score > candScore.getOrDefault(tpl, -1)) { cands.put(tpl, new Cand(req, p)); candScore.put(tpl, score); }
            added++;
        }
        note(seen, key, added == 0 ? "no guessable name segment" : "candidate (stored " + st + ", " + added + " name position(s))");
        return 1;
    }

    /** Segment {@code p} can hold a looked-up name: a guessable slug, below a real collection word (not an API prefix
     *  or an id), followed only by fixed sub-resource words (no ids). */
    static boolean namePositionOk(String[] segs, int p) {
        if (p < 2 || p >= segs.length) return false;
        if (!isGuessableName(segs[p]) || PREFIX_SEG.matcher(segs[p]).matches()) return false;
        String coll = segs[p - 1];
        if (coll.isEmpty() || PREFIX_SEG.matcher(coll).matches() || isIdLike(coll)) return false;
        for (int i = p + 1; i < segs.length; i++) if (segs[i].isEmpty() || isIdLike(segs[i])) return false;
        return true;
    }

    static String template(String[] segs, int p) {
        String[] t = segs.clone(); t[p] = "{name}"; return String.join("/", t);
    }

    static boolean isGuessableName(String s) {
        if (s == null || s.isEmpty()) return false;
        if (isIdLike(s)) return false;
        return SLUG_SEG.matcher(s).matches();
    }

    private static boolean isIdLike(String s) {
        return UUID_SEG.matcher(s).matches() || OBJID_SEG.matcher(s).matches()
                || NUM_SEG.matcher(s).matches() || TOKEN_SEG.matcher(s).matches();
    }

    private boolean oracle(String tpl, Cand cand, String cookieA, String bearerA,
                           String cookieB, String bearerB, String anonBearer) {
        HttpRequest base = strip(cand.req);
        int p = cand.pos;

        // 1) credential ladder — weakest credential that still resolves the real name
        List<Tier> ladder = new ArrayList<>();
        ladder.add(new Tier("unauthenticated (no credentials)", "", "", false));
        if (!blank(anonBearer)) ladder.add(new Tier("anonymous client token (no account / pre-login)", "", anonBearer, false));
        boolean haveA = !blank(cookieA) || !blank(bearerA), haveB = !blank(cookieB) || !blank(bearerB);
        if (haveA && haveB) ladder.add(new Tier("any authenticated user (confirmed with a second, unrelated identity)", nz(cookieA), nz(bearerA), true));

        Tier tier = null; HttpRequestResponse r1 = null;
        StringBuilder ladderStatuses = new StringBuilder();
        for (Tier t : ladder) {
            HttpRequestResponse r = send(base, t);
            ladderStatuses.append(ladderStatuses.length() == 0 ? "" : ", ").append(t.label.split(" \\(")[0]).append("=").append(status(r));
            if (status(r) / 100 == 2) { tier = t; r1 = r; break; }
        }
        if (tier == null) { why(tpl, "no credential tier resolved the real name (statuses: " + ladderStatuses + ")"); return false; }
        boolean idDisclosed = disclosesId(r1), authCfg = disclosesAuthCfg(r1);
        if (!isJsonResp(r1) || !(idDisclosed || authCfg)) {
            why(tpl, "2xx at tier [" + tier.label + "] but not JSON / discloses neither an identifier nor auth configuration"); return false;
        }

        // session tier: B must resolve the SAME name to the same object, else 2xx may just mean "it's mine"
        HttpRequestResponse rB = null;
        if (tier.session) {
            rB = send(base, new Tier("B", nz(cookieB), nz(bearerB), true));
            if (status(rB) / 100 != 2 || !Net.shape(rB).equals(Net.shape(r1))) {
                why(tpl, "identity B did not resolve the same name (HTTP " + status(rB) + ") — ownership-scoped, not an oracle"); return false;
            }
        }

        // 2) nonexistent name, same credential → must be a not-found-class miss that differs from the hit
        HttpRequestResponse r2 = send(withSegments(base, p, BOGUS_NAME, null, null), tier);
        int s2 = status(r2);
        boolean notFoundClass = s2 == 404 || s2 == 410
                || ((s2 == 400 || s2 == 422) && NOT_FOUND_WORDS.matcher(body(r2)).find());
        if (!notFoundClass) { why(tpl, "invented name → HTTP " + s2 + " (not a not-found-class answer)"); return false; }
        String sh1 = Net.shape(r1), sh2 = Net.shape(r2);
        if (sh1.equals(sh2)) { why(tpl, "real and invented names answer with the same shape"); return false; }

        // 3) the miss must differ from BOTH routing-miss baselines — proves the application looked the name up
        HttpRequestResponse r0  = send(withSegments(base, p, BOGUS_NAME, BOGUS_COLL, null), tier);   // bogus collection + name
        HttpRequestResponse r0b = send(withSegments(base, p, null, null, BOGUS_ROUTE), tier);        // real path + extra segment
        if (Net.shape(r0).equals(sh2) || Net.shape(r0b).equals(sh2)) {
            why(tpl, "invented-name miss looks like an unknown ROUTE (" + sh2 + ") — fixed path segment, not a looked-up name"); return false;
        }

        String[] segs = pathOf(base.url()).split("/");
        String coll = segs[p - 1], realName = segs[p];
        boolean tenantNs = TENANT_NS.matcher(coll).matches();
        String kind = tenantNs ? "tenant/account enumeration" : "resource enumeration";
        String what = idDisclosed ? "" : " + login-method disclosure";
        String access = tier.session ? "any authenticated user"
                : blank(tier.bearer) && blank(tier.cookie) ? "unauthenticated" : "anonymous client token";
        String cls = "Existence/identity oracle — " + kind + what + " (" + access + ")";

        TreeSet<String> keys = jsonKeys(body(r1));
        StringBuilder d = new StringBuilder();
        d.append("GET ").append(tpl).append(" answers whether a name exists and, if it does, discloses ")
         .append(idDisclosed ? "its internal identifier" : "its authentication configuration")
         .append(" — reachable with: ").append(tier.label).append(". ")
         .append("Request 1: the real name '").append(realName).append("' → HTTP ").append(status(r1))
         .append(" disclosing ").append(keys.isEmpty() ? (idDisclosed ? "an identifier" : "authentication settings") : "fields " + keys).append(". ");
        int nreq = 2;
        if (rB != null) { d.append("A second, unrelated identity resolves the same name identically (not an ownership effect). "); }
        d.append("Request ").append(nreq++).append(": a nonexistent name → HTTP ").append(s2).append(" (application-level not-found, different shape). ")
         .append("Request ").append(nreq++).append(": an unknown collection → HTTP ").append(status(r0)).append(", and Request ").append(nreq)
         .append(": the real path plus one unknown segment → HTTP ").append(status(r0b))
         .append(" — both routing misses look different from Request 2, so that miss is the application looking the name up. ")
         .append("A caller can therefore test candidate names (")
         .append(tenantNs ? "organization / tenant / account names" : "resource names")
         .append(") and learn which exist").append(idDisclosed ? ", harvesting their identifiers" : " and how each one authenticates (password / SSO providers)")
         .append(". Only one invented name was sent; no real names were enumerated.");
        List<HttpRequestResponse> ev = new ArrayList<>();
        ev.add(r1); ev.add(r2); ev.add(r0); ev.add(r0b);
        if (rB != null) ev.add(rB);
        scanLog.found(cls, Net.stripQuery(base.url()), d.toString(), ev.toArray(new HttpRequestResponse[0]));
        scanLog.incFinding();
        return true;
    }

    // ---- helpers ----

    private void why(String tpl, String reason) { scanLog.log("existence-oracle: " + tpl + " — not reported: " + reason); }

    private static void note(List<String> seen, String key, String what) {
        if (seen.size() >= 20) return;
        for (String x : seen) if (x.startsWith(key + " ")) return;
        seen.add(key + " → " + what);
    }

    /** Probe-wide budget for transient edge blocks (429, or a non-JSON 403 from a WAF/edge throttle). */
    private int transientRetries = 6;

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

    /** 429, or a 403 whose body is not JSON (an edge/WAF page rather than the application's own denial). */
    private static boolean isTransientBlock(HttpRequestResponse rr) {
        int st = status(rr);
        if (st == 429) return true;
        if (st != 403) return false;
        String b = body(rr).trim();
        return !(b.startsWith("{") || b.startsWith("["));
    }

    /** Rewrite the path: name at {@code p} (if non-null), the collection at {@code p-1} (if non-null), and/or append one
     *  extra segment (if non-null). Query string preserved. */
    private static HttpRequest withSegments(HttpRequest req, int p, String name, String coll, String extra) {
        try {
            String url = req.url();
            String[] segs = pathOf(url).split("/");
            if (name != null) segs[p] = name;
            if (coll != null && p >= 1) segs[p - 1] = coll;
            String path = String.join("/", segs) + (extra != null ? "/" + extra : "");
            String q = ""; int qi = url.indexOf('?'); if (qi >= 0) q = url.substring(qi);
            return req.withPath(path + q);
        } catch (Throwable t) { return req; }
    }

    private static HttpRequest strip(HttpRequest req) {
        HttpRequest r = req;
        try { if (r.hasHeader("Authorization")) r = r.withRemovedHeader("Authorization"); } catch (Throwable ignore) {}
        try { if (r.hasHeader("Cookie")) r = r.withRemovedHeader("Cookie"); } catch (Throwable ignore) {}
        return r;
    }

    private static boolean isJsonResp(HttpRequestResponse rr) {
        String b = body(rr).trim();
        if (b.startsWith("{") || b.startsWith("[")) return true;
        try { String ct = rr.response().headerValue("Content-Type"); return ct != null && ct.toLowerCase().contains("json"); }
        catch (Throwable t) { return false; }
    }

    private static boolean disclosesId(HttpRequestResponse rr) {
        String b = body(rr);
        return UUID_ANY.matcher(b).find() || ID_KEY.matcher(b).find();
    }

    private static boolean disclosesAuthCfg(HttpRequestResponse rr) { return AUTH_CFG_KEY.matcher(body(rr)).find(); }

    private static TreeSet<String> jsonKeys(String body) {
        TreeSet<String> out = new TreeSet<>();
        try {
            String t = body.trim();
            if (t.startsWith("{")) out.addAll(new org.json.JSONObject(t).keySet());
        } catch (Throwable ignore) {}
        return out;
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
