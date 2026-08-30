package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.scan.sast.SourceFindings;
import com.ioactive.aiscanner.scan.sast.StaticHint;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WRITE-side BOLA (CWE-639) — the account-takeover-grade flaw {@link IdorGetProbe} can't reach (it is GET-only).
 * For a sub-resource write {@code PUT /collection/{id}/{field}} (VAmPI {@code /users/v1/{username}/email}; a common
 * REST shape), it mutates ANOTHER identity's field with OUR session, then READS THE OBJECT BACK to prove our marker
 * landed — a real cross-user write.
 *
 * <p>Zero-FP by construction:
 * <ul>
 *   <li>victim identities are sourced from the collection's OWN listing (never guessed);</li>
 *   <li>a unique marker we wrote must reappear in the victim's GET (only a real write makes that happen);</li>
 *   <li>we require the marker to land on {@code >= 2} DISTINCT identities — at most one of them can be our own
 *       account, so two confirmed writes prove at least one crossed a tenant boundary (no need to know "self");</li>
 *   <li>only readable-back fields (email/name/…) are tested — passwords aren't echoed, so they're unconfirmable here;</li>
 *   <li>each victim's original value is RESTORED afterward (non-destructive).</li>
 * </ul></p>
 */
public final class BolaWriteProbe extends Probe {

    // .../{id}/{field}: an id-keyed collection with a mutable SUB-RESOURCE (the field we can write + read back).
    private static final Pattern SUBRES = Pattern.compile("^(https?://[^/]+/.+/)([A-Za-z0-9][A-Za-z0-9._@%-]{0,63})/([A-Za-z][A-Za-z0-9_-]{0,40})$");
    private static final Pattern LIST_ID = Pattern.compile("(?i)\"(?:user(?:name)?|login|handle|slug|\\bid\\b|name|email|account)\"\\s*:\\s*\"([^\"\\n]{1,64})\"");
    // fields readable back in an object's representation (so a marker is confirmable). NOT passwords/tokens.
    private static final Pattern WRITABLE_FIELD = Pattern.compile("(?i)^(e-?mail|name|first_?name|last_?name|nickname|bio|about|address|phone|title|description|status)$");
    private static final int MAX_ENDPOINTS = 20;

    public BolaWriteProbe(MontoyaApi api, ScanLog scanLog) {
        super(api, scanLog);
    }

    public int probe(String host, SourceFindings hints, String baseUrl, List<HttpRequest> targets, String cookie, String bearer) {
        return probe(host, hints, baseUrl, targets, cookie, bearer, null, null);
    }

    /** @param cookieB,bearerB a SECOND distinct identity B. When present, the victim object is read back AS B after
     *  A's write: if B — a genuinely different user — witnesses A's marker, a SINGLE victim is a definitive cross-user
     *  write (no need for the statistical "&ge;2 distinct victims" gate). */
    public int probe(String host, SourceFindings hints, String baseUrl, List<HttpRequest> targets,
                     String cookie, String bearer, String cookieB, String bearerB) {
        int hits = 0;
        boolean haveB = (cookieB != null && !cookieB.isBlank()) || (bearerB != null && !bearerB.isBlank());
        // collect candidate write endpoints (PUT/PATCH id-keyed sub-resources) from SAST hints, the DISCOVERED
        // audit targets (synthesized writes — where an OpenAPI-mined PUT lives before the native audit runs it),
        // and observed traffic.
        List<String[]> writeEps = new ArrayList<>();   // {url-or-template, method}
        if (hints != null && baseUrl != null) {
            for (StaticHint h : hints.all()) {
                String m = h.method == null ? "" : h.method.toUpperCase();
                if ((!m.equals("PUT") && !m.equals("PATCH")) || !h.hasEndpoint()) continue;
                String p = h.path.startsWith("/") ? h.path : "/" + h.path;
                writeEps.add(new String[]{ baseUrl.replaceAll("/+$", "") + p, m });
            }
        }
        if (targets != null) {
            for (HttpRequest req : targets) {
                try {
                    String m = req.method();
                    if (("PUT".equals(m) || "PATCH".equals(m)) && host.equalsIgnoreCase(hostOf(req.url())))
                        writeEps.add(new String[]{ req.url().split("\\?")[0], m });
                } catch (Throwable ignore) { }
            }
        }
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String m = rr.request().method();
                if ((!"PUT".equals(m) && !"PATCH".equals(m)) || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                writeEps.add(new String[]{ rr.request().url().split("\\?")[0], m });
            }
        } catch (Throwable ignore) { }

        Set<String> tried = new LinkedHashSet<>();
        int seen = 0;
        for (String[] ep : writeEps) {
            if (seen++ >= MAX_ENDPOINTS) break;
            String method = ep[1];
            String norm = ep[0].replaceAll("\\{[^/}]+\\}", "__ID__");   // {username}/{id} placeholder → id slot
            Matcher sm = SUBRES.matcher(norm);
            if (!sm.matches()) continue;
            String root = sm.group(1), field = sm.group(3);
            if (!WRITABLE_FIELD.matcher(field).find()) continue;
            if (!tried.add(method + " " + root + "*/" + field)) continue;

            Set<String> landedVictims = new LinkedHashSet<>();
            HttpRequestResponse[] firstEvidence = null;
            boolean bWitnessed = false;   // a SECOND identity B independently read A's marker on a victim's object
            for (String victim : harvestIds(root, cookie, bearer)) {
                try {
                    String objUrl = root + victim, writeUrl = objUrl + "/" + field;
                    HttpRequestResponse before = send(HttpRequest.httpRequestFromUrl(objUrl).withMethod("GET"), cookie, bearer);
                    if (before == null || before.response() == null || before.response().statusCode() != 200) continue;
                    String original = fieldValue(before.response().bodyToString(), field);
                    String marker = field.toLowerCase().contains("mail")
                            ? "aiscbola" + Math.abs(victim.hashCode() % 100000) + "@example.com"
                            : "aiscBolaMk" + Math.abs(victim.hashCode() % 100000);
                    if (marker.equals(original)) continue;
                    // WRITE our marker into the victim's sub-resource with OUR session
                    HttpRequestResponse wr = send(HttpRequest.httpRequestFromUrl(writeUrl).withMethod(method)
                            .withBody("{\"" + field + "\":\"" + marker + "\"}").withHeader("Content-Type", "application/json"), cookie, bearer);
                    if (wr != null && wr.response() != null && wr.response().statusCode() < 400) {
                        // READ BACK: did our marker land on the victim's object?
                        HttpRequestResponse after = send(HttpRequest.httpRequestFromUrl(objUrl).withMethod("GET"), cookie, bearer);
                        if (after != null && after.response() != null && after.response().statusCode() == 200
                                && after.response().bodyToString() != null && after.response().bodyToString().contains(marker)) {
                            landedVictims.add(victim);
                            if (firstEvidence == null) firstEvidence = new HttpRequestResponse[]{ wr, after };
                            // SECOND-IDENTITY witness: read the victim's object back AS B. If a genuinely different
                            // registered user also sees A's marker, this ONE victim is a definitive cross-user write.
                            if (haveB) {
                                HttpRequestResponse asB = send(HttpRequest.httpRequestFromUrl(objUrl).withMethod("GET"), cookieB, bearerB);
                                if (asB != null && asB.response() != null && asB.response().statusCode() == 200
                                        && asB.response().bodyToString() != null && asB.response().bodyToString().contains(marker)) {
                                    bWitnessed = true;
                                    firstEvidence = new HttpRequestResponse[]{ wr, asB };   // prefer B's cross-user witness as evidence
                                }
                            }
                        }
                    }
                    // RESTORE the original value (non-destructive) whether or not it landed
                    if (original != null && !original.equals(marker))
                        send(HttpRequest.httpRequestFromUrl(writeUrl).withMethod(method)
                                .withBody("{\"" + field + "\":\"" + original + "\"}").withHeader("Content-Type", "application/json"), cookie, bearer);
                } catch (Throwable ignore) { }
            }
            // Cross-user write confirmed by EITHER: a second identity B witnessing A's marker on a single victim
            // (definitive), OR >= 2 DISTINCT identities mutated with one session (at most one is our own account).
            boolean fire = (landedVictims.size() >= 1 && bWitnessed) || landedVictims.size() >= 2;
            if (fire && firstEvidence != null) {
                String how = bWitnessed
                        ? "a SECOND registered user (identity B) then read the victim's object and saw A's marker — a "
                        + "definitive cross-user write"
                        : "at most one of the " + landedVictims.size() + " can be our own account, so at least one is a cross-user write";
                scanLog.found("Broken Object Level Authorization — cross-user WRITE (BOLA)", root.replaceAll("/+$", "") + "/{id}/" + field,
                        method + " changed the '" + field + "' of identity(ies) (" + String.join(", ", landedVictims)
                        + ") using OUR single session, confirmed by reading the marker back — " + how + " with no ownership "
                        + "check (CWE-639, account-takeover-grade). Victim ids sourced from the collection's listing.",
                        firstEvidence[0], firstEvidence[1]);
                scanLog.incFinding();
                hits++;
            }
        }
        return hits;
    }

    private HttpRequestResponse send(HttpRequest req, String cookie, String bearer) {
        try {
            HttpRequest r = req;
            if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
            if (bearer != null && !bearer.isBlank()) r = r.withHeader("Authorization", "Bearer " + bearer);
            return send(r);
        } catch (Throwable t) { return null; }
    }

    /** Source candidate victim identities from the collection root's listing (the app's OWN published ids). */
    private List<String> harvestIds(String root, String cookie, String bearer) {
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        try {
            HttpRequestResponse r = send(HttpRequest.httpRequestFromUrl(root.replaceAll("/+$", "")).withMethod("GET"), cookie, bearer);
            if (r != null && r.response() != null && r.response().statusCode() == 200 && r.response().bodyToString() != null) {
                Matcher m = LIST_ID.matcher(r.response().bodyToString());
                while (m.find() && ids.size() < 5) {
                    String v = m.group(1);
                    if (v != null && v.matches("[A-Za-z0-9][A-Za-z0-9._@%-]{0,63}")) ids.add(v);
                }
            }
        } catch (Throwable ignore) { }
        return new ArrayList<>(ids);
    }

    private static String fieldValue(String json, String field) {
        if (json == null) return null;
        Matcher m = Pattern.compile("(?i)\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"\\n]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    // hostOf(String) inherited from Probe.
}
