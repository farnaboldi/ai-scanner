package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic STORED (second-order) XSS probe: <b>create → view</b>. Burp's native reflected-XSS check and our
 * {@link ReflectedXssProbe} only confirm input that echoes back in the SAME response; a payload persisted by one
 * request (a blog comment, a profile field, a product review) and rendered UNENCODED on a DIFFERENT, later page is
 * invisible to a stateless active audit — yet it is the higher-impact class (runs in every viewer's browser).
 *
 * <p>Self-contained by design: stored XSS lives in FORMS, so the probe FINDS its own write surface rather than
 * relying on the generic form-synthesis (which is subject to a site-map/budget race). It (1) fetches the candidate
 * pages — the site root, every discovered target URL, and the crawled GET inventory — and parses each server-rendered
 * {@code <form>} into a POST write, carrying a FRESH anti-forgery token from that very page (so the write is not
 * rejected as a stale/invalid token); (2) submits a UNIQUE, executable marker {@code <svg onload=sxN>} into each
 * free-text field (textarea/text input), preserving the token and the rest of the body; (3) fetches the view pages
 * ONCE — the post/redirect (PRG) target, the write URL, the root, and the crawled inventory — and confirms the
 * marker present VERBATIM (unencoded) in an EXECUTABLE HTML context (not trapped in a comment/script). A marker
 * submitted to one request and executing on a separately-fetched page proves persisted, browser-executable XSS
 * (CWE-79). Each injection carries a distinct marker, so a hit attributes back to the exact form+field.</p>
 *
 * <p>Zero-FP by construction: an unguessable marker matched as a RAW substring — an encoded reflection ({@code
 * &lt;svg …}) never counts. Generic: no per-app field/route knowledge.</p>
 */
public final class StoredXssProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private static final AtomicInteger SEQ = new AtomicInteger();
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io)(\\b.*)?$|.*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)(\\?.*)?$");
    private static final int MAX_PAGES = 60;    // candidate pages we fetch + parse for forms
    private static final int MAX_WRITES = 40;   // form fields we inject a marker into
    private static final int MAX_VIEWS  = 60;   // pages we re-fetch looking for stored markers

    // Form parsing (mirror EndpointDiscovery's synthesis grammar).
    private static final Pattern FORM_BLOCK = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>");
    private static final Pattern F_ACTION   = Pattern.compile("(?is)\\baction\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_METHOD   = Pattern.compile("(?is)\\bmethod\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_FIELD    = Pattern.compile("(?is)<(input|textarea|select)\\b([^>]*)>");
    private static final Pattern F_NAME     = Pattern.compile("(?is)\\bname\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_VALUE    = Pattern.compile("(?is)\\bvalue\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    private static final Pattern F_TYPE     = Pattern.compile("(?is)\\btype\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");

    public StoredXssProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** A server-rendered POST form: where it submits, its fields (name→current value), and the free-text fields
     *  worth injecting. Parsed fresh so the anti-forgery token is valid for the current session. */
    private static final class Form {
        String action;                                                 // absolute submit URL
        final Map<String, String> fields = new LinkedHashMap<>();      // all named fields, filled
        final Set<String> injectable = new LinkedHashSet<>();          // free-text fields (the XSS candidates)
    }

    /**
     * @param base scheme://authority of the target (seeds the root as a page + a view), or null
     * @param targets discovered requests — their URLs are fetched and parsed for forms
     * @return number of confirmed stored-XSS sinks
     */
    public int probe(String base, List<HttpRequest> targets, UnaryOperator<HttpRequest> withSession) {
        UnaryOperator<HttpRequest> sess = withSession != null ? withSession : (r -> r);

        // Candidate pages to parse for forms + later re-scan for stored markers: root + target URLs + crawled GETs.
        LinkedHashSet<String> pages = new LinkedHashSet<>();
        if (base != null && !base.isBlank()) pages.add(base.replaceAll("/+$", "") + "/");
        if (targets != null) for (HttpRequest t : targets) { try { pages.add(t.url()); } catch (Throwable ignore) { } }
        addSiteMapGets(pages, base);

        Map<String, String[]> markerToPoint = new LinkedHashMap<>();          // marker -> {writeUrl, label}
        Map<String, HttpRequestResponse> markerToRr = new LinkedHashMap<>();  // marker -> the write req/resp (evidence)
        // HOT views (scanned FIRST): the PRG/redirect target + the write URL itself — the pages that render the
        // just-stored value. The bulk page/site-map set is scanned after, so the render page is never crowded past
        // the view cap by unrelated crawled pages.
        LinkedHashSet<String> hotViews = new LinkedHashSet<>();
        LinkedHashSet<String> viewUrls = new LinkedHashSet<>(pages);          // bulk: every page is also a potential view

        // Phase A — fetch each candidate page, parse its POST forms, and inject a unique marker into each free-text
        // field (preserving the page's own fresh token + the rest of the body).
        int planted = 0, fetched = 0;
        Set<String> writtenForms = new LinkedHashSet<>();                     // dedup identical (action + fields)
        for (String pageUrl : pages) {
            if (planted >= MAX_WRITES || fetched >= MAX_PAGES) break;
            try {
                if (SKIP.matcher(pageUrl).matches()) continue;
                if (AuthenticatedExplorer.SESSION_RESET.matcher(stripQ(pageUrl)).matches()) continue;
                fetched++;
                HttpRequestResponse pr = send(sess.apply(HttpRequest.httpRequestFromUrl(pageUrl).withMethod("GET")));
                if (!isHtml(pr)) continue;
                Map<String, String> pageCookies = setCookiesOf(pr);   // e.g. the anti-forgery cookie this form's token pairs with
                for (Form f : parseForms(pr.response().bodyToString(), pageUrl)) {
                    if (f.injectable.isEmpty()) continue;
                    if (AuthenticatedExplorer.SESSION_RESET.matcher(stripQ(f.action)).matches()) continue;
                    if (!writtenForms.add(f.action + " " + f.fields.keySet())) continue;   // one write per form shape
                    hotViews.add(f.action);                                             // inline-render pages (guestbook style)
                    scanLog.debug("  stored-xss: form POST " + stripQ(f.action) + " fields=" + f.fields.keySet()
                            + " inject=" + f.injectable + " pageCookies=" + pageCookies.keySet());
                    for (String field : f.injectable) {
                        if (planted >= MAX_WRITES) break;
                        String marker = "<svg onload=sx" + SEQ.incrementAndGet() + ">";
                        HttpRequestResponse rr = send(mergeCookies(sess.apply(buildPost(f, field, marker)), pageCookies));
                        markerToPoint.put(marker, new String[]{ f.action, "form field '" + field + "'" });
                        if (rr != null) markerToRr.put(marker, rr);
                        int st = rr != null && rr.response() != null ? rr.response().statusCode() : -1;
                        scanLog.debug("  stored-xss: submit " + field + "=" + marker + " → HTTP " + st
                                + (redirectLocation(rr) != null ? " →" + redirectLocation(rr) : ""));
                        String loc = redirectLocation(rr);
                        if (loc != null) try {
                            hotViews.add(URI.create(f.action).resolve(loc).toString().replaceFirst("^https://", "http://"));
                        } catch (Exception ignore) { }
                        planted++;
                    }
                }
            } catch (Throwable ignore) { }
        }
        if (markerToPoint.isEmpty()) return 0;
        scanLog.debug("  stored-xss: " + markerToPoint.size() + " marker(s) planted across form fields; scanning "
                + Math.min(viewUrls.size(), MAX_VIEWS) + " view page(s)…");

        // Phase B — fetch each view once; a marker present verbatim + in an executable context = stored XSS.
        int hits = 0;
        Set<String> fired = new LinkedHashSet<>();
        Set<String> seenSomewhere = new LinkedHashSet<>();   // marker core found in SOME view (persisted, maybe encoded)
        int scanned = 0;
        LinkedHashSet<String> orderedViews = new LinkedHashSet<>(hotViews);   // render pages first, then the bulk crawl
        orderedViews.addAll(viewUrls);
        for (String url : orderedViews) {
            if (scanned >= MAX_VIEWS || fired.size() >= markerToPoint.size()) break;
            try {
                if (SKIP.matcher(url).matches() || AuthenticatedExplorer.SESSION_RESET.matcher(stripQ(url)).matches()) continue;
                scanned++;
                HttpRequestResponse rr = send(sess.apply(HttpRequest.httpRequestFromUrl(url).withMethod("GET")));
                if (!isHtml(rr)) continue;
                String body = rr.response().bodyToString();
                for (Map.Entry<String, String[]> e : markerToPoint.entrySet()) {
                    String marker = e.getKey();
                    String core = marker.substring(marker.indexOf("sx"), marker.length() - 1);   // e.g. "sx42"
                    if (body.contains(core)) seenSomewhere.add(marker);
                    if (fired.contains(marker)) continue;
                    int i = body.indexOf(marker);
                    if (i < 0 || inComment(body, i) || inScript(body, i)) continue;   // encoded or non-live → skip
                    fired.add(marker);
                    String[] pt = e.getValue();
                    // forceRaise=true: the "xss" family defers to Burp's native audit for REFLECTED XSS, but Burp does
                    // not reliably find SECOND-ORDER stored XSS (write and sink are different requests) — so raise our
                    // own dashboard issue instead of deferring to an audit that will not surface it.
                    scanLog.found("Cross-site scripting (stored)", pt[0],
                            pt[1] + " is persisted and rendered UNENCODED into an executable HTML context on "
                          + stripQ(url) + " — the injected " + marker + " runs in every viewer's browser. Submitted to "
                          + "one request and confirmed executing on a different, later-fetched page: stored/second-order "
                          + "XSS (CWE-79).", true, markerToRr.get(marker));
                    scanLog.incFinding();
                    hits++;
                }
            } catch (Throwable ignore) { }
        }
        scanLog.debug("  stored-xss: " + hits + " confirmed; " + seenSomewhere.size() + "/" + markerToPoint.size()
                + " marker(s) persisted+visible on some view (the rest never stored — write rejected/not persisted).");
        return hits;
    }

    /** Parse every POST {@code <form>} on the page into a filled write (absolute action, fields, free-text sinks). */
    private java.util.List<Form> parseForms(String body, String pageUrl) {
        java.util.List<Form> out = new java.util.ArrayList<>();
        if (body == null) return out;
        Matcher fm = FORM_BLOCK.matcher(body);
        while (fm.find()) {
            String attrs = fm.group(1), inner = fm.group(2);
            String method = attrOf(F_METHOD, attrs);
            if (method == null || !method.equalsIgnoreCase("post")) continue;   // stored XSS is a write → POST only
            String action = attrOf(F_ACTION, attrs);
            String abs;
            try { abs = (action == null || action.isBlank()) ? stripQ(pageUrl) : URI.create(pageUrl).resolve(action).toString(); }
            catch (Exception e) { continue; }
            abs = abs.replaceFirst("^https://", "http://");
            Form f = new Form(); f.action = abs;
            Matcher im = F_FIELD.matcher(inner);
            while (im.find()) {
                String tagName = im.group(1).toLowerCase(), tag = im.group(2);
                String name = attrOf(F_NAME, tag); if (name == null || name.isBlank()) continue;
                String type = attrOf(F_TYPE, tag); type = type == null ? (tagName.equals("textarea") ? "textarea" : "text") : type.toLowerCase();
                if (type.equals("submit") || type.equals("button") || type.equals("reset") || type.equals("image")) continue;
                String val = attrOf(F_VALUE, tag);
                f.fields.put(name, val == null ? "" : val);   // keep hidden/token values verbatim
                // Free-text fields are the XSS sinks; leave password/checkbox/radio/file/hidden out of the marker set.
                if (tagName.equals("textarea") || type.equals("text") || type.equals("search")
                        || type.equals("url") || type.equals("email") || type.equals("tel") || type.isEmpty())
                    f.injectable.add(name);
            }
            if (!f.fields.isEmpty()) out.add(f);
        }
        return out;
    }

    /** Build the form POST with {@code field}=marker and every other field at its current value. */
    private HttpRequest buildPost(Form f, String field, String marker) {
        StringBuilder enc = new StringBuilder();
        for (Map.Entry<String, String> e : f.fields.entrySet()) {
            if (enc.length() > 0) enc.append('&');
            String v = e.getKey().equals(field) ? marker : (e.getValue() == null || e.getValue().isEmpty() ? "1" : e.getValue());
            enc.append(urlenc(e.getKey())).append('=').append(urlenc(v));
        }
        return HttpRequest.httpRequestFromUrl(stripQ(f.action)).withMethod("POST")
                .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(enc.toString());
    }

    /** Bounded crawled GET pages on the target host — form sources AND places stored content can surface. */
    private void addSiteMapGets(Set<String> pages, String base) {
        try {
            String host = base == null ? null : URI.create(base).getHost();
            int n = 0;
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (n >= 80) break;
                try {
                    HttpRequest rq = rr.request();
                    if (rq == null || !"GET".equalsIgnoreCase(rq.method())) continue;
                    String u = rq.url();
                    if (SKIP.matcher(u).matches()) continue;
                    if (host != null && !host.equalsIgnoreCase(URI.create(u).getHost())) continue;
                    if (pages.add(u)) n++;
                } catch (Exception ignore) { }
            }
        } catch (Throwable ignore) { }
    }

    private static String attrOf(Pattern p, String s) {
        Matcher m = p.matcher(s); if (!m.find()) return null; String v = m.group(1).trim();
        if (v.length() >= 2 && (v.charAt(0) == '"' || v.charAt(0) == '\'')) v = v.substring(1, v.length() - 1);
        return v;
    }
    private static String urlenc(String s) { try { return java.net.URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; } }

    /** The {@code name=value} of every Set-Cookie on a response (e.g. the anti-forgery cookie a form's token pairs
     *  with). Generic — no framework-specific cookie names. */
    private static Map<String, String> setCookiesOf(HttpRequestResponse rr) {
        Map<String, String> out = new LinkedHashMap<>();
        if (rr == null || rr.response() == null) return out;
        try {
            for (burp.api.montoya.http.message.HttpHeader h : rr.response().headers()) {
                if (!"Set-Cookie".equalsIgnoreCase(h.name())) continue;
                String first = h.value().split(";", 2)[0].trim();
                int eq = first.indexOf('=');
                if (eq > 0) out.put(first.substring(0, eq).trim(), first.substring(eq + 1).trim());
            }
        } catch (Throwable ignore) { }
        return out;
    }

    /** Merge the form page's Set-Cookie into the request's Cookie header, with the PAGE cookie WINNING on a name
     *  clash. This is essential for CSRF-protected forms: the anti-forgery token embedded in the form is minted
     *  against the anti-forgery cookie the SAME page GET issued, so the write must send THAT fresh cookie — not the
     *  older one captured at login (which {@code withSession} carries). A browser/curl jar naturally does this
     *  "latest wins"; we replicate it. The auth/session cookie is a different name, so it is preserved. */
    private static HttpRequest mergeCookies(HttpRequest req, Map<String, String> extra) {
        if (extra == null || extra.isEmpty()) return req;
        LinkedHashMap<String, String> jar = new LinkedHashMap<>();
        String cur = req.headerValue("Cookie");
        if (cur != null && !cur.isBlank())
            for (String pair : cur.split(";")) { int eq = pair.indexOf('='); if (eq > 0) jar.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim()); }
        jar.putAll(extra);   // page cookies win (fresh anti-forgery cookie the form's token pairs with)
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : jar.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return req.withHeader("Cookie", sb.toString());
    }
    private static String redirectLocation(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return null;
        int st = rr.response().statusCode();
        if (st < 300 || st >= 400) return null;
        String loc = rr.response().headerValue("Location");
        return loc == null || loc.isBlank() ? null : loc;
    }
    private static String stripQ(String u) { int q = u == null ? -1 : u.indexOf('?'); return q < 0 ? u : u.substring(0, q); }

    // --- send + jar alignment + HTML-context helpers (mirror ReflectedXssProbe; kept local to avoid coupling) ---

    /** Align Burp's cookie jar to the request's own Cookie header so a stale (unauthenticated) jar cookie can't
     *  override our authenticated Cookie header and bounce the request to login. No-op without a Cookie header. */
    private void syncJar(HttpRequest req) {
        try {
            String cookie = req.headerValue("Cookie");
            if (cookie == null || cookie.isBlank()) return;
            String host = URI.create(req.url()).getHost();
            for (String pair : cookie.split(";")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                api.http().cookieJar().setCookie(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim(),
                        "/", host, java.time.ZonedDateTime.now().plusDays(1));
            }
        } catch (Throwable ignore) { }
    }

    private HttpRequestResponse send(HttpRequest req) {
        try {
            syncJar(req);
            return AiScanner.decompress(
                    api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)));
        } catch (Throwable t) { return null; }
    }

    private static boolean isHtml(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return false;
        String ct = rr.response().headerValue("Content-Type");
        String body = rr.response().bodyToString();
        return (ct != null && ct.toLowerCase().contains("html"))
                || (body != null && (body.trim().regionMatches(true, 0, "<!doctype", 0, 9) || body.trim().startsWith("<")));
    }

    /** Inside an HTML comment: the last "<!--" before the position is not yet closed by a "-->". */
    private static boolean inComment(String body, int idx) {
        String b = body.substring(0, idx);
        return b.lastIndexOf("<!--") > b.lastIndexOf("-->");
    }

    /** Inside a &lt;script&gt; body: the last "<script" opens after the last "</script" closes. */
    private static boolean inScript(String body, int idx) {
        String b = body.substring(0, idx).toLowerCase();
        return b.lastIndexOf("<script") > b.lastIndexOf("</script");
    }
}
