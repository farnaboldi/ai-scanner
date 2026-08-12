package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;
import org.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Generic Broken-Function-Level-Authorization (BFLA) probe — no app-specific paths. Classic BFLA lives at
 * a PRIVILEGED path that mirrors a user path (…/user/videos/{id} vs …/admin/videos/{id}) with the
 * function-level authorization check missing, so a normal authenticated user can invoke the admin-tier
 * function. We discover candidates by ROLE-SEGMENT SUBSTITUTION: take each observed authenticated path and
 * swap a user-tier segment (user/me/account/…) for an admin-tier one (admin/superuser/root/…).
 *
 * <p>The oracle is DETERMINISTIC and NON-DESTRUCTIVE (only ever sends a bogus id — it never mutates a real
 * object). For a candidate privileged path, using a bogus id and a state-changing verb:
 * <ol>
 *   <li><b>R2</b> (no session) must be DENIED (401/403) — proves the endpoint requires authentication, so
 *       it is not a legitimately public endpoint.</li>
 *   <li><b>R3</b> (our normal-user session) must NOT be 401/403 — a properly-secured admin function returns
 *       403 to a non-admin; anything else means our non-privileged caller reached the handler.</li>
 *   <li><b>Control</b> (our session, same path but the resource-noun segment replaced with a junk token)
 *       gives the app's route-NOT-FOUND response shape. R3 must DIFFER from it — proving the candidate is a
 *       REAL handler that ran (not a non-existent route that merely 404s). Compared by JSON key-SHAPE (or a
 *       path-stripped token signature), so response value/ordering noise cannot move it.</li>
 * </ol>
 * FIRE iff R2 denied AND R3 not-denied AND R3-shape != control-shape. That triple means an authenticated,
 * per-route, admin-tier function executed for a non-privileged user — real missing function-level authz.
 */
public final class BflaProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    private static final int MAX_CANDIDATES = 24;
    private static final String BOGUS_ID = "999999999";
    private static final String JUNK_NOUN = "aisc_nonexistent_zzq";   // guaranteed non-existent control segment
    // User-tier segments (substitute FROM) and strong privilege-tier segments (substitute TO). Kept strong
    // on the admin side (a bare "manage" is too benign) so reaching one as a non-admin is a defensible finding.
    private static final Pattern USER_TIER = Pattern.compile(
            "(?i)^(users?|me|self|account|profile|my|customer|member|consumer)$");
    private static final String[] ADMIN_TIER = { "admin", "administrator", "superuser", "root", "sysadmin", "backoffice" };
    private static final String[] METHODS = { "DELETE", "PUT", "PATCH" };
    private static final Pattern AUTHY = Pattern.compile("(?i)/(login|logout|signin|signout|signup|register|token|auth)(/|$)");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public BflaProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    public int probe(String host, String cookieHeader, String bearer) {
        int hits = 0;
        try {
            List<Cand> candidates = discover(host);
            for (Cand c : candidates) {
                for (String method : METHODS) {
                    if (oracle(c, method, cookieHeader, bearer)) { hits++; break; }   // one finding per candidate path
                }
            }
            hits += probeRoleFunctions(host, cookieHeader, bearer);   // directly-observed privileged-role functions
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] BFLA probe error: " + t);
        }
        return hits;
    }

    // A path segment naming a PRIVILEGED ROLE whose functions a normal user must not invoke. Staff/operator
    // roles — NOT user-facing nouns (customer/member/merchant/user), so a role-function gate won't fire on
    // e.g. /merchant/contact_mechanic (a user feature). Generic role vocabulary, not app-specific paths.
    private static final Pattern PRIV_ROLE = Pattern.compile(
            "(?i)^(admin|administrator|superuser|root|sysadmin|backoffice|mechanic|manager|staff|moderator|operator|employee|agent)$");

    /**
     * Second BFLA source: a function DIRECTLY OBSERVED under a privileged-role segment (…/mechanic/… ,
     * …/admin/…) that our NORMAL user reaches. Unlike the substitution source, the privileged path is already
     * in the site map (crAPI's mechanic endpoints), so no user→admin mirror is needed. Same triple gate:
     * unauth is DENIED (401/403 — the function requires auth), our non-privileged session is NOT denied
     * (reaches the handler), and the response DIFFERS from a junk-noun control (a real function, not a 404).
     * FP-safe: the role segment must be a NON-LEAF namespace (so /mechanic alone or /merchant/… never match),
     * and the junk-control gate rejects routes that don't really exist.
     */
    private int probeRoleFunctions(String host, String cookie, String bearer) {
        int hits = 0;
        Set<String> seen = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                String url = req.url();
                if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches() || AUTHY.matcher(url).find()) continue;
                if (!"GET".equals(req.method())) continue;                       // read functions (non-destructive)
                String[] segs = pathSegs(req.pathWithoutQuery());
                int roleIdx = -1;
                for (int i = 0; i < segs.length - 1; i++) if (PRIV_ROLE.matcher(segs[i]).matches()) { roleIdx = i; break; }
                if (roleIdx < 0) continue;                                       // role segment must exist and be NON-LEAF
                int nounIdx = segs.length - 1;                                   // the function/noun after the role
                if (nounIdx <= roleIdx) continue;
                Cand c = new Cand(baseOf(url), segs, nounIdx);
                if (!seen.add(c.base + c.path())) continue;
                String u = c.base + c.path();
                HttpRequestResponse r2 = send("GET", u, null, null);             // no session
                int s2 = status(r2);
                // Unauth-exposure branch: a privileged-role function that answers an ANONYMOUS caller with a
                // real 2xx body is broken access control by itself (no boundary to cross — it's simply open).
                // FP-safe: real PRIV_ROLE non-leaf segment + a non-trivial, non-error 2xx body.
                if (s2 >= 200 && s2 < 300 && nonTrivialBody(r2)) {
                    scanLog.found("Privileged endpoint exposed without authentication", u,
                            "GET '" + segs[roleIdx] + "/" + segs[nounIdx] + "' returned " + s2 + " with a real body to "
                            + "an UNAUTHENTICATED caller — a privileged-role function is served to the anonymous public "
                            + "(broken access control / information exposure).", r2);
                    scanLog.incFinding();
                    hits++;
                    continue;
                }
                if (s2 != 401 && s2 != 403) continue;                            // public / not auth-gated → not BFLA
                HttpRequestResponse r3 = send("GET", u, cookie, bearer);         // our NON-privileged session
                int s3 = status(r3);
                if (s3 < 200 || s3 >= 300) continue;                             // must actually REACH the function (2xx)
                HttpRequestResponse ctrl = send("GET", c.base + c.controlPath(), cookie, bearer);
                if (status(ctrl) == 0 || shape(r3).equals(shape(ctrl))) continue;// junk noun → route doesn't exist
                scanLog.found("Broken Function Level Authorization (BFLA)", u,
                        "GET reached the privileged-role function '" + segs[roleIdx] + "/" + segs[nounIdx]
                        + "' as a non-privileged user. Evidence req/resp: [1] our-session=" + s3
                        + " (reached), [2] no-session=" + s2 + " (denied — proves auth-gated), [3] control=junk-noun"
                        + " (differs from [1], so [1] is a real handler not a 404)", r3, r2, ctrl);
                scanLog.incFinding();
                hits++;
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] BFLA role-function probe error: " + t);
        }
        return hits;
    }

    /** A privileged candidate: absolute URL up to the id slot, with a bogus id, plus the noun-segment index. */
    private static final class Cand {
        final String base;      // scheme://authority
        final String[] segs;    // path segments, with admin substitution + trailing bogus id
        final int nounIdx;      // index of the resource-noun segment (immediately before the id)
        Cand(String base, String[] segs, int nounIdx) { this.base = base; this.segs = segs; this.nounIdx = nounIdx; }
        String path() { return "/" + String.join("/", segs); }
        String controlPath() {
            String[] c = segs.clone();
            c[nounIdx] = JUNK_NOUN;
            return "/" + String.join("/", c);
        }
    }

    /** Role-segment substitution over observed authenticated paths → admin-tier candidates with a bogus id.
     *  Iterated ADMIN-TOKEN-OUTER so the primary "admin" variant of EVERY observed user path is enumerated
     *  before the rarer tokens — the candidate cap can't then crowd out the likeliest real target. */
    private List<Cand> discover(String host) {
        // collect each observed (base, path-segments, user-tier-segment-index) once
        List<Occ> occ = new ArrayList<>();
        Set<String> seenOcc = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpRequest req = rr.request();
            String url = req.url();
            if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches() || AUTHY.matcher(url).find()) continue;
            String[] segs = pathSegs(req.pathWithoutQuery());
            if (segs.length < 2) continue;
            for (int i = 0; i < segs.length; i++) {
                if (!USER_TIER.matcher(segs[i]).matches()) continue;
                if (seenOcc.add(baseOf(url) + "|" + String.join("/", segs) + "|" + i)) occ.add(new Occ(baseOf(url), segs, i));
            }
        }
        List<Cand> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String adm : ADMIN_TIER) {
            for (Occ o : occ) {
                String[] v = o.segs.clone();
                v[o.userIdx] = adm;
                String[] withId; int nounIdx;   // ensure a trailing id slot (reuse numeric tail, else append)
                if (v[v.length - 1].matches("\\d{1,10}")) {
                    withId = v.clone(); withId[withId.length - 1] = BOGUS_ID; nounIdx = withId.length - 2;
                } else {
                    withId = Arrays.copyOf(v, v.length + 1); withId[withId.length - 1] = BOGUS_ID; nounIdx = withId.length - 2;
                }
                if (nounIdx < 0 || nounIdx == o.userIdx) continue;          // need a distinct resource noun
                if (!seen.add(o.base + "|" + String.join("/", withId))) continue;
                out.add(new Cand(o.base, withId, nounIdx));
                if (out.size() >= MAX_CANDIDATES) return out;
            }
        }
        return out;
    }

    private static final class Occ {
        final String base; final String[] segs; final int userIdx;
        Occ(String base, String[] segs, int userIdx) { this.base = base; this.segs = segs; this.userIdx = userIdx; }
    }

    private boolean oracle(Cand c, String method, String cookie, String bearer) {
        String url = c.base + c.path();
        HttpRequestResponse r2 = send(method, url, null, null);                     // no session
        int s2 = status(r2);
        if (s2 != 401 && s2 != 403) return false;                                  // public / not auth-gated → not BFLA
        HttpRequestResponse r3 = send(method, url, cookie, bearer);                // our normal-user session
        int s3 = status(r3);
        if (s3 == 0 || s3 == 401 || s3 == 403) return false;                       // secured (403) / denied → correct
        HttpRequestResponse ctrl = send(method, c.base + c.controlPath(), cookie, bearer);
        if (status(ctrl) == 0) return false;
        if (shape(r3).equals(shape(ctrl))) return false;                           // route-not-found → doesn't exist
        scanLog.found("Broken Function Level Authorization (BFLA)", url,
                method + " reached an admin-tier function as a non-privileged user. Evidence req/resp: "
                        + "[1] our-session=" + s3 + " (reached the function), [2] no-session=" + s2
                        + " (denied — proves it is auth-gated), [3] control=junk-noun (differs from [1], so [1] is a real handler)",
                r3, r2, ctrl);
        scanLog.incFinding();
        return true;
    }

    /** Response SHAPE = status + sorted top-level JSON keys (value/order-insensitive), or a path-stripped
     *  token signature for non-JSON — so a real handler's response is distinguishable from route-not-found
     *  without any framework-specific strings, and reorder noise can't move it. */
    private static String shape(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "none";
        int st = rr.response().statusCode();
        String body = rr.response().bodyToString();
        if (body != null) {
            String t = body.trim();
            if (t.startsWith("{")) {
                try {
                    JSONObject o = new JSONObject(t);
                    String[] keys = o.keySet().toArray(new String[0]);
                    Arrays.sort(keys);
                    return st + ":keys:" + String.join(",", keys);
                } catch (Throwable ignore) { /* fall through */ }
            }
        }
        String norm = (body == null ? "" : body)
                .replaceAll("\\d+", "#")
                .replaceAll("(?i)[a-z0-9/_.-]{16,}", " ")   // drop long path/id-ish tokens (incl. the echoed URL)
                .replaceAll("\\s+", " ").trim();
        String[] toks = norm.split(" ");
        Arrays.sort(toks);
        return st + ":body:" + String.join(" ", toks);
    }

    private HttpRequestResponse send(String method, String url, String cookie, String bearer) {
        try {
            HttpRequest r = HttpRequest.httpRequestFromUrl(url).withMethod(method);
            if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
            if (bearer != null && !bearer.isBlank()) r = r.withHeader("Authorization", "Bearer " + bearer);
            return api.http().sendRequest(r, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Throwable t) { return null; }
    }

    private static int status(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().statusCode() : 0;
    }

    /** A real payload, not an empty/redirect/error stub — guards the unauth-exposure branch against FPs. */
    private static boolean nonTrivialBody(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String b = rr.response().bodyToString();
        if (b == null) return false;
        String t = b.trim();
        if (t.length() < 40) return false;
        String lower = t.toLowerCase();
        if (lower.contains("\"error\"") || lower.contains("not found") || lower.contains("unauthor")) return false;
        return t.startsWith("{") || t.startsWith("[");   // JSON data payload (privileged API surface)
    }

    private static String[] pathSegs(String path) {
        List<String> out = new ArrayList<>();
        for (String s : (path == null ? "" : path).split("/")) if (!s.isEmpty()) out.add(s);
        return out.toArray(new String[0]);
    }

    private static String baseOf(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getAuthority(); }
        catch (Exception e) { return ""; }
    }

    private static String hostOf(String url) {
        try { return URI.create(url).getHost(); } catch (Exception e) { return ""; }
    }
}
