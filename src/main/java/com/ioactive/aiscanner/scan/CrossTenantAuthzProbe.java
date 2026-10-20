package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Cross-principal OBJECT authorization differential (BOLA / CWE-639 / CWE-285) — the sibling of
 * {@link BflaProbe} for the case the 2xx-only oracles miss.
 *
 * <p><b>The blind spot it closes.</b> {@link IdorGetProbe}/{@link BolaWriteProbe} only count a cross-principal
 * request as a finding when it returns <em>2xx with the victim's data</em>. But a broken object-authorization
 * check often does not surface as a clean 2xx: the request sails past the (missing) ownership gate and is then
 * stopped by some <em>unrelated downstream control</em> — a billing/quota check (402), a conflict (409), a
 * validation step (422), a state error (500). To a 2xx-only oracle that looks identical to a proper denial, so
 * the gap is reported as "secure". It is not: the server resolved another tenant's object for the attacker and
 * ran business logic on it; only an incidental, non-authorization control prevented the final effect.
 * (Typical shape: {@code PUT /api/v1/<collection>/<other-tenant-id>/<create-action>} → 402 Payment Required
 * for a cross-tenant caller, vs 400/404 for a non-existent id — the real foreign object was resolved and
 * reached a downstream billing check, while every sibling operation correctly returned 401.)
 *
 * <p><b>The oracle (same three-way differential as {@link BflaProbe}, applied cross-PRINCIPAL on the SAME
 * object path instead of via role-segment swaps):</b> for an id-bearing endpoint the primary session A reached,
 * replay the SAME request (method + body) with
 * <ol>
 *   <li><b>R2</b> = no credentials → must be DENIED (401/403): proves the endpoint is authorization-gated
 *       (so reaching it with a different principal is meaningful, not a public route);</li>
 *   <li><b>R3</b> = a SECOND, distinct identity B (a different tenant/user that does not own A's object) →
 *       must NOT be denied (anything other than 401/403/transport-error): B reached the handler for A's object;</li>
 *   <li><b>control</b> = identity B against the SAME endpoint with the object-id segment replaced by a fresh
 *       non-existent id → gives the app's "object not found / not mine" response shape.</li>
 * </ol>
 * FIRE iff <b>R2 denied AND R3 not-denied AND shape(R3) != shape(control)</b>. The shape compare
 * ({@link Net#shape}, which folds status + JSON-key/body signature) is what makes it precise: if the app applies
 * the downstream control <em>uniformly</em> (same 402 for a real foreign id and a bogus id — i.e. the control
 * runs before id resolution), the shapes match and nothing fires (correct: no evidence the foreign object was
 * resolved). It only fires when the REAL foreign object produced a DIFFERENT, further-along response than a
 * non-existent one — the fingerprint of "ownership check missing, object resolved, business logic ran".
 *
 * <p><b>Non-destructive.</b> R3 replays exactly the request A already issued (same verb + body). The probe does
 * not invent new mutations. For a write that is genuinely broken, the downstream control (billing/validation)
 * is what we observe; a true cross-tenant 2xx write is the strongest possible evidence and is reported, but the
 * probe never escalates beyond a single faithful replay per endpoint and never re-sends on success. The control
 * uses a non-existent id so it can touch no real object. Requires a real second identity B (no unauth fallback —
 * unauth cannot be both the gate-proof R2 and the cross principal R3), so it is a no-op without one.
 */
public final class CrossTenantAuthzProbe extends Probe {

    private static final int MAX_CANDIDATES = 48;
    // An id-shaped path segment, ANYWHERE in the path (not just the tail): UUID, Mongo ObjectId, long opaque
    // token, or a pure-numeric id. These are the object references whose ownership the server must check.
    private static final Pattern UUID_SEG   = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern OBJID_SEG  = Pattern.compile("^[0-9a-fA-F]{24}$");
    // An opaque token must mix letters AND digits: a long all-letter segment is a ROUTE word (createRecord,
    // sharedResources), not an object id. Treating it as an id made the control swap the action name
    // instead of the object id — hitting a non-existent ROUTE (always 404) and trivially "differing" from R3.
    private static final Pattern OPAQUE_SEG = Pattern.compile("^(?=[^/]*[0-9])(?=[^/]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9._~=-]{11,}$");
    private static final Pattern NUM_SEG    = Pattern.compile("^[0-9]{1,18}$");
    private static final Pattern AUTH_FLOW  = Pattern.compile("(?i)/(login|logout|signin|signout|signup|register|token|auth|keep-?alive)(/|$)");
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");

    public CrossTenantAuthzProbe(MontoyaApi api, ScanLog scanLog) { super(api, scanLog); }

    /**
     * @param cookieB,bearerB the REQUIRED second identity B (a different tenant/user). Probe is a no-op if absent.
     * @param targets the synthesized audit surface (write creates etc.) — merged with the live site map so
     *                create/update endpoints the crawl never issued are still differential-tested.
     */
    public int probe(String host, String cookieA, String bearerA, String cookieB, String bearerB, List<HttpRequest> targets) {
        boolean haveB = (cookieB != null && !cookieB.isBlank()) || (bearerB != null && !bearerB.isBlank());
        if (!haveB) { scanLog.log("cross-tenant authz probe: no second identity B provided — skipped (needs A and B, e.g. two tenants)."); return 0; }
        int hits = 0;
        Set<String> tried = new LinkedHashSet<>();
        try {
            // Candidate endpoints: every id-bearing request A reached (site map) + every synthesized target.
            LinkedHashMap<String, CandReq> cands = new LinkedHashMap<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.request() == null || rr.response() == null) continue;
                collect(cands, rr.request(), rr, host);
            }
            if (targets != null) for (HttpRequest t : targets) collect(cands, t, null, host);

            for (CandReq c : cands.values()) {
                if (hits >= MAX_CANDIDATES) break;
                if (!tried.add(c.template)) continue;
                if (oracle(c, cookieA, bearerA, cookieB, bearerB)) hits++;
            }
        } catch (Throwable t) {
            scanLog.debug("cross-tenant authz probe error: " + t);
        }
        return hits;
    }

    private void collect(Map<String, CandReq> cands, HttpRequest req, HttpRequestResponse orig, String host) {
        try {
            if (req == null) return;
            String url = req.url();
            if (!host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) return;
            if (AUTH_FLOW.matcher(url).find()) return;
            String path = pathOf(url);
            int idSeg = lastIdSegmentIndex(path);
            if (idSeg < 0) return;                       // no object reference → not an object-authz candidate
            String template = req.method() + " " + idTemplate(path) + (req.hasParameters() ? "?" : "");
            CandReq prev = cands.get(template);
            // Prefer the instance where A's OWN request succeeded (2xx): it is the strongest "this object is real
            // and A's" evidence, and it anchors the raised issue on a 2xx site-map node — every other piece of
            // access-control evidence is 4xx by nature, which Burp's default site-map filter hides.
            if (prev == null || (!is2xx(prev.orig) && is2xx(orig))) cands.put(template, new CandReq(req, orig, idSeg, template));
        } catch (Throwable ignore) { }
    }

    private static boolean is2xx(HttpRequestResponse rr) {
        int s = status(rr);
        return s >= 200 && s < 300;
    }

    /** The three-way cross-principal differential. */
    private boolean oracle(CandReq c, String cookieA, String bearerA, String cookieB, String bearerB) {
        HttpRequest base = c.req;
        String method = base.method();
        // R2: no credentials — the endpoint must be authorization-gated.
        HttpRequestResponse r2 = send(strip(base), null, null);
        int s2 = status(r2);
        if (s2 != 401 && s2 != 403) return false;                       // public / not auth-gated → not an object-authz gap
        // R3: identity B (a different principal) replays A's exact request against A's object.
        HttpRequestResponse r3 = send(strip(base), cookieB, bearerB);
        int s3 = status(r3);
        if (s3 == 0 || s3 == 401 || s3 == 403) return false;           // B correctly denied → ownership check works
        // control: identity B against the SAME endpoint with a non-existent object id.
        HttpRequest bogus = withBogusId(base, c.idSeg);
        HttpRequestResponse ctrl = send(strip(bogus), cookieB, bearerB);
        if (status(ctrl) == 0) return false;
        if (Net.shape(r3).equals(Net.shape(ctrl))) return false;       // uniform downstream control / not-found → foreign object NOT resolved
        boolean reached2xx = s3 >= 200 && s3 < 300;
        // Evidence is attached in the SAME order the detail numbers it, so "Request N" in the text is Burp's
        // "Request N" tab. A's own successful exchange (from the site map) goes first when available: it proves
        // the object is real and A's, and gives Burp a 2xx node to anchor the issue on (the access-control
        // evidence itself is 4xx by nature, which Burp's default site-map filter hides).
        boolean ownerOk = is2xx(c.orig);
        java.util.List<HttpRequestResponse> ev = new java.util.ArrayList<>();
        StringBuilder d = new StringBuilder(method + " on another principal's object (request numbers match the attached request/response tabs). ");
        int n = 1;
        if (ownerOk) {
            ev.add(c.orig);
            d.append("Request ").append(n++).append(" — owner identity A, its own request on its own object: HTTP ")
             .append(status(c.orig)).append(". ");
        }
        ev.add(r2);
        d.append("Request ").append(n++).append(" — no credentials: HTTP ").append(s2)
         .append(" (denied, so the endpoint is authorization-gated). ");
        int bN = n++;
        ev.add(r3);
        d.append("Request ").append(bN).append(" — a second, distinct identity B replaying A's request on A's object: HTTP ").append(s3)
         .append(reached2xx
                 ? " (SUCCEEDED — the " + (isMutation(method) ? "write" : "read") + " was performed across the principal/tenant boundary). "
                 : " (NOT denied — B reached business logic such as a billing, validation or conflict check, so the server "
                   + "resolved A's object for B before any ownership check). ");
        int cN = n;
        ev.add(ctrl);
        d.append("Request ").append(cN).append(" — control, identity B with a non-existent id: HTTP ").append(status(ctrl))
         .append(" (a different, earlier failure, proving Request ").append(bN).append(" resolved the REAL foreign object). ");
        d.append("A per-object ownership check would reject B with 401/403 exactly as it rejects the anonymous caller. "
                + "The probe replays A's own request verb and body; the control touches no real object.");
        String cls = reached2xx ? "Broken Object Level Authorization — cross-tenant access confirmed (BOLA)"
                                : "Broken Object Level Authorization — cross-principal (BOLA)";
        scanLog.found(cls, Net.stripQuery(base.url()), d.toString(), ev.toArray(new HttpRequestResponse[0]));
        scanLog.incFinding();
        return true;
    }

    // ---- helpers ------------------------------------------------------------------------------------------

    private static boolean isMutation(String m) {
        return m != null && (m.equals("POST") || m.equals("PUT") || m.equals("PATCH") || m.equals("DELETE"));
    }

    /** Index of the LAST id-shaped segment in the path, or -1. Prefers the most specific (last) object ref. */
    static int lastIdSegmentIndex(String path) {
        String[] segs = path.split("/");
        for (int i = segs.length - 1; i >= 0; i--) {
            String s = segs[i];
            if (s.isEmpty()) continue;
            if (UUID_SEG.matcher(s).matches() || OBJID_SEG.matcher(s).matches()
                    || NUM_SEG.matcher(s).matches() || OPAQUE_SEG.matcher(s).matches()) return i;
        }
        return -1;
    }

    /** Collapse every id-shaped segment to {id} for dedup across different object instances of one endpoint. */
    static String idTemplate(String path) {
        String[] segs = path.split("/");
        StringBuilder b = new StringBuilder();
        for (String s : segs) {
            if (s.isEmpty()) continue;
            b.append('/');
            if (UUID_SEG.matcher(s).matches() || OBJID_SEG.matcher(s).matches()
                    || NUM_SEG.matcher(s).matches() || OPAQUE_SEG.matcher(s).matches()) b.append("{id}");
            else b.append(s);
        }
        return b.length() == 0 ? "/" : b.toString();
    }

    /** Replace the id segment at {@code idSeg} with a fresh non-existent id of the SAME shape. */
    private static HttpRequest withBogusId(HttpRequest req, int idSeg) {
        try {
            String url = req.url();
            String path = pathOf(url);
            String[] segs = path.split("/");
            if (idSeg < 0 || idSeg >= segs.length) return req;
            String orig = segs[idSeg];
            String bogus;
            if (UUID_SEG.matcher(orig).matches())      bogus = "00000000-0000-4000-8000-0000000000aa";
            else if (OBJID_SEG.matcher(orig).matches())bogus = "aaaaaaaaaaaaaaaaaaaaaaaa";
            else if (NUM_SEG.matcher(orig).matches())  bogus = "999999999";
            else                                       bogus = "aisc0nonexistent0zzq0id";
            segs[idSeg] = bogus;
            String newPath = String.join("/", segs);
            String q = ""; int qi = url.indexOf('?'); if (qi >= 0) q = url.substring(qi);
            return req.withPath(newPath + q);
        } catch (Throwable t) { return req; }
    }

    private HttpRequestResponse send(HttpRequest req, String cookie, String bearer) {
        try {
            HttpRequest r = req;
            if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
            if (bearer != null && !bearer.isBlank()) r = r.withHeader("Authorization", "Bearer " + bearer);
            return send(r);
        } catch (Throwable t) { return null; }
    }

    /** Remove any inherited auth headers so each principal is applied cleanly (A's captured req may carry them). */
    private static HttpRequest strip(HttpRequest req) {
        HttpRequest r = req;
        try { if (r.hasHeader("Authorization")) r = r.withRemovedHeader("Authorization"); } catch (Throwable ignore) {}
        try { if (r.hasHeader("Cookie")) r = r.withRemovedHeader("Cookie"); } catch (Throwable ignore) {}
        return r;
    }

    private static int status(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : 0; }
        catch (Throwable t) { return 0; }
    }

    private static final class CandReq {
        final HttpRequest req; final HttpRequestResponse orig; final int idSeg; final String template;
        CandReq(HttpRequest req, HttpRequestResponse orig, int idSeg, String template) {
            this.req = req; this.orig = orig; this.idSeg = idSeg; this.template = template;
        }
    }
}
