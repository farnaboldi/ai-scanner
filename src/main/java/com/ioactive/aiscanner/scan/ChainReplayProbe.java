package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generic create→consume chain: replay a record ONE endpoint leaked into a SIBLING write endpoint that
 * consumes the same fields, then probe that sink. This is the intended path for chained vulns where one
 * flaw feeds another (e.g. a NoSQL {@code $ne} bypass leaks a valid code, which a second, SQL-backed
 * endpoint then accepts) — the second endpoint is never reached by a crawler because the UI only calls it
 * after the first step succeeds with a value the crawler doesn't possess.
 *
 * <p>Entirely app-agnostic. The leaked record comes from {@link NoSqlProbe}'s bypass response (real
 * field:value pairs). The sink URLs are recovered by resolving API-path fragments mined from the site's
 * own JavaScript against the base prefixes of REAL captured requests (so a relative fragment like
 * {@code api/shop/apply_coupon} resolves to the observed {@code /workshop/api/shop/…} base — which naive
 * host-root resolution gets wrong). Reached sinks are handed to the deterministic oracles (blind-SQLi,
 * body-mutation, NoSQL); no verdict here.
 */
public final class ChainReplayProbe extends Probe {

    private static final int MAX_CANDIDATE_SINKS = 32;   // resolved sink URLs to consumption-test
    private static final int MAX_SINKS = 8;              // consumers we hand to the (heavier) oracles
    private static final int MAX_LEAKS = 4;
    private static final int MAX_FRAGMENTS = 400;

    // api + scanLog inherited from Probe
    private final Function<HttpRequest, HttpRequest> sessionizer;   // AiScanner::withSession (Cookie + Bearer)
    private final List<String> leaks;

    // A quoted API-path-ish string literal in client code.
    private static final Pattern QUOTED = Pattern.compile("[\"'`]([A-Za-z0-9_][A-Za-z0-9_./-]{3,160})[\"'`]");
    private static final Pattern API_ISH = Pattern.compile("(?i)(^|/)(api|rest|graphql|gql|v\\d+|services?)(/|$)");
    private static final Pattern STATIC = Pattern.compile(
            "(?i).*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf|json)(\\?.*)?$");
    private static final Pattern AUTHY = Pattern.compile("(?i)/(login|logout|signin|signout|signup|register|token|auth)(/|$)");

    public ChainReplayProbe(MontoyaApi api, ScanLog scanLog,
                            Function<HttpRequest, HttpRequest> sessionizer, List<String> leaks) {
        super(api, scanLog);
        this.sessionizer = sessionizer;
        this.leaks = leaks;
    }

    /** Returns the number of sink endpoints reached and probed. */
    public int run(String host) {
        if (leaks == null || leaks.isEmpty()) return 0;
        try {
            List<HttpRequest> observed = observedApiRequests(host);
            if (observed.isEmpty()) return 0;
            Set<String> fragments = mineFragments(host);
            if (fragments.isEmpty()) return 0;

            // Resolve fragments against observed request bases → concrete sink requests (POST, template
            // preserves scheme/host/port/version). Dedup by resolved path; skip already-observed paths.
            Set<String> observedPaths = new LinkedHashSet<>();
            for (HttpRequest r : observed) observedPaths.add(r.pathWithoutQuery());
            Set<String> sinkPaths = new LinkedHashSet<>();
            List<HttpRequest> sinks = new ArrayList<>();
            for (HttpRequest tmpl : observed) {
                String[] obs = segs(tmpl.pathWithoutQuery());
                for (String frag : fragments) {
                    String resolved = join(obs, segs(frag));
                    if (resolved == null || observedPaths.contains(resolved)) continue;
                    if (AUTHY.matcher(resolved).find()) continue;
                    if (!sinkPaths.add(resolved)) continue;
                    sinks.add(tmpl.withMethod("POST").withPath(resolved));
                    if (sinks.size() >= MAX_CANDIDATE_SINKS) break;
                }
                if (sinks.size() >= MAX_CANDIDATE_SINKS) break;
            }
            if (sinks.isEmpty()) return 0;

            // Only fuzz sinks that actually CONSUME the leaked fields. Replaying a coupon record into an
            // endpoint that ignores coupon_code (e.g. change-email) can only ever "fire" on response noise,
            // never on real SQL — so gate on consumption: the response to the real record must differ from
            // the response to a value-scrambled control of the same shape (canonical, order-insensitive).
            // This kills false positives at the source AND frees oracle slots for the real consumer.
            int probed = 0;
            for (HttpRequest sink : sinks) {
                if (probed >= MAX_SINKS) break;
                String hitRecord = null;
                int tried = 0;
                for (String record : leaks) {
                    if (tried++ >= MAX_LEAKS) break;
                    if (consumes(sink, record)) { hitRecord = record; break; }
                }
                if (hitRecord == null) continue;
                probed++;
                scanLog.log("  chain: sink CONSUMES leaked record -> POST "
                        + sink.pathWithoutQuery() + " (probing)");
                probeSink(sessionizer.apply(sink.withHeader("Content-Type", "application/json").withBody(hitRecord)));
            }
            if (probed > 0)
                scanLog.log("create->consume chain: " + probed + " sibling write sink(s) consumed a leaked record and were probed.");
            return probed;
        } catch (Throwable t) {
            scanLog.debug("chain-replay probe error: " + t);
            return 0;
        }
    }

    /** True iff the sink's behaviour depends on the leaked record's field VALUES (it consumes them):
     *  the canonical response to the real record differs from the response to a value-scrambled control
     *  of the same shape. The canonical signature is status + token-sorted body, so non-deterministic
     *  response ordering can't masquerade as a difference. Requires the real record to be reached. */
    private boolean consumes(HttpRequest sink, String record) {
        String control = controlRecord(record);
        if (control.equals(record)) return false;                          // nothing to scramble → can't test
        HttpRequestResponse rr = send(sessionizer.apply(
                sink.withHeader("Content-Type", "application/json").withBody(record)));
        int sr = st(rr);
        if (sr == 0 || sr == 404 || sr == 405 || sr == 501) return false;  // route miss / not reached
        HttpRequestResponse rc = send(sessionizer.apply(
                sink.withHeader("Content-Type", "application/json").withBody(control)));
        if (st(rc) == 0) return false;
        return !csig(sr, rr).equals(csig(st(rc), rc));
    }

    /** Same JSON shape, all field VALUES replaced with fixed dummies — isolates value-dependence. */
    private static String controlRecord(String json) {
        if (json == null || json.isEmpty()) return "";
        String c = Pattern.compile("(\"[^\"]+\"\\s*:\\s*\")[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"")
                .matcher(json).replaceAll(m -> m.group(1) + "AiscCtrlZ9\"");   // string values
        c = Pattern.compile("(\"[^\"]+\"\\s*:\\s*)-?\\d+(?:\\.\\d+)?")
                .matcher(c).replaceAll(m -> m.group(1) + "424242");            // numeric values
        return c;
    }

    /** Canonical, order-insensitive response signature: status + 32-hex-stripped, whitespace-collapsed,
     *  token-SORTED body — so a framework's non-deterministic word ordering is not seen as a difference. */
    private static String csig(int status, HttpRequestResponse rr) {
        String b = rr != null && rr.response() != null ? rr.response().bodyToString() : "";
        b = b.replaceAll("(?i)[a-f0-9]{32}", "").replaceAll("\\s+", " ").trim();
        String[] t = b.split(" ");
        java.util.Arrays.sort(t);
        return status + ":" + String.join(" ", t);
    }

    private int st(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().statusCode() : 0;
    }

    /** Hand a reached sink to the deterministic oracles. Returns true if any of them confirmed a finding. */
    private boolean probeSink(HttpRequest req) {
        boolean found = false;
        try { found |= new BlindSqliProbe(api, scanLog).probe(req); } catch (Throwable ignore) { }
        try { found |= new NoSqlProbe(api, scanLog).probe(req); } catch (Throwable ignore) { }
        try { new BodyMutatorProbe(api, scanLog).probe(req); } catch (Throwable ignore) { }
        return found;
    }

    // ---- sink discovery ----

    /** Real captured API requests on the host — their paths carry the correct service base prefixes. */
    private List<HttpRequest> observedApiRequests(String host) {
        List<HttpRequest> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpRequest req = rr.request();
            if (!host.equalsIgnoreCase(hostOf(req.url()))) continue;
            String path = req.pathWithoutQuery();
            if (!API_ISH.matcher(path).find() || STATIC.matcher(path).matches()) continue;
            if (seen.add(path)) out.add(req);
        }
        return out;
    }

    /** Mine API-path fragments from the host's JavaScript/HTML (quoted literals that look like endpoints). */
    private Set<String> mineFragments(String host) {
        Set<String> frags = new LinkedHashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
            String ct = rr.response().hasHeader("Content-Type") ? rr.response().headerValue("Content-Type") : "";
            String url = rr.request().url();
            boolean js = (ct != null && (ct.contains("javascript") || ct.contains("html")))
                    || url.toLowerCase().contains(".js");
            if (!js) continue;
            Matcher m = QUOTED.matcher(rr.response().bodyToString());
            while (m.find() && frags.size() < MAX_FRAGMENTS) {
                String f = m.group(1);
                if (f.startsWith("http") || STATIC.matcher(f).matches()) continue;
                if (!f.contains("/") || !API_ISH.matcher(f).find()) continue;
                frags.add(f.replaceAll("^/+", ""));
            }
        }
        return frags;
    }

    /** Splice a relative fragment onto an observed path: find the longest (>=2) contiguous run of the
     *  fragment's leading segments inside the observed segments, then keep the observed prefix before that
     *  run and append the whole fragment. e.g. obs=/workshop/api/shop/orders + frag=api/shop/apply_coupon
     *  -> /workshop/api/shop/apply_coupon. Returns null when no >=2-segment overlap exists. */
    static String join(String[] obs, String[] frag) {
        if (obs.length == 0 || frag.length < 2) return null;
        int best = 1, bestJ = -1;
        for (int j = 0; j < obs.length; j++) {
            int k = 0;
            while (k < frag.length && j + k < obs.length && obs[j + k].equalsIgnoreCase(frag[k])) k++;
            if (k >= 2 && k > best) { best = k; bestJ = j; }
        }
        if (bestJ < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bestJ; i++) sb.append('/').append(obs[i]);
        for (String f : frag) sb.append('/').append(f);
        return sb.toString();
    }

    private static String[] segs(String path) {
        String p = path == null ? "" : path.trim();
        int q = p.indexOf('?');
        if (q >= 0) p = p.substring(0, q);
        List<String> out = new ArrayList<>();
        for (String s : p.split("/")) if (!s.isEmpty()) out.add(s);
        return out.toArray(new String[0]);
    }

    // send(HttpRequest) inherited from Probe (politeness + configured request timeout).

    // hostOf(String) inherited from Probe.
}
