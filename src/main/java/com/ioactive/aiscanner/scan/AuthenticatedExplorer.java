package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A small <em>authenticated</em> explorer that reaches the surface Burp's crawler can't.
 *
 * <p>Burp's crawler doesn't execute JS and doesn't carry our captured session the way we
 * need for a redirect-gated app, so the pages/scripts that only exist once logged in never
 * enter the site map. This explorer, seeded at the post-login landing URL:
 * <ol>
 *   <li>follows the login redirect chain to the real authenticated page,</li>
 *   <li>does a bounded, same-host BFS over the resources those pages reference
 *       (&lt;a href&gt;, &lt;script src&gt;, &lt;link href&gt;, &lt;form action&gt;),</li>
 *   <li>fetches each with the session cookie and adds it to the site map.</li>
 * </ol>
 * The point of step 2 is to pull the app's JS bundles into the site map so
 * {@link EndpointDiscovery} can mine them for the authenticated AJAX endpoints.
 *
 * <p>Site-agnostic: no hardcoded paths — every URL comes from the app's own markup.
 */
public final class AuthenticatedExplorer {

    private final MontoyaApi api;
    private final SessionStore session;
    private final ScanLog scanLog;

    private static final String   Q = "(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))";
    private static final Pattern A_HREF     = Pattern.compile("(?is)<a\\b[^>]*\\bhref\\s*=\\s*" + Q);
    private static final Pattern SCRIPT_SRC = Pattern.compile("(?is)<script\\b[^>]*\\bsrc\\s*=\\s*" + Q);
    private static final Pattern LINK_HREF  = Pattern.compile("(?is)<link\\b[^>]*\\bhref\\s*=\\s*" + Q);
    private static final Pattern FORM_ACT   = Pattern.compile("(?is)<form\\b[^>]*\\baction\\s*=\\s*" + Q);
    // RequireJS/AMD entry point: <script data-main="js/app" src=".../require.min.js"> — follow the entry
    // module so its dependency graph (and the endpoint/route literals inside) enters the site map. Generic.
    private static final Pattern DATA_MAIN  = Pattern.compile("(?is)\\bdata-main\\s*=\\s*" + Q);
    private static final Pattern SKIP = Pattern.compile(
            "(?i).*\\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webp|pdf|css)($|\\?).*");
    // NEVER follow logout/sign-out — it destroys the session we just captured and makes every
    // subsequent authenticated request bounce back to login (scanner self-sabotage).
    public static final Pattern LOGOUT = Pattern.compile("(?i).*(logout|log-out|log_off|logoff|signout|sign-out|sign_out).*");
    // Auth-flow pages that RESET the session when hit while logged in (GET signin/login → the app
    // bounces to login_error and invalidates the session). The explorer must never touch these —
    // they add nothing to discovery and kill the authenticated session mid-scan.
    static final Pattern SESSION_RESET = Pattern.compile(
            "(?i).*(logout|log-out|log_off|logoff|signout|sign-out|sign_out|signin|sign-in|/login|login\\.).*");
    // A CSRF / anti-forgery TOKEN parameter (Django csrfmiddlewaretoken, Rails authenticity_token, .NET
    // __RequestVerificationToken, Laravel _token, …). Fuzzing it is pointless AND harmful: any mutation invalidates
    // the token so the server returns 403 before the request reaches any sink — so probes must KEEP it (with its
    // captured value, to pass the CSRF check) but never treat it as an insertion point. Shared so every probe agrees.
    public static final Pattern CSRF_PARAM = Pattern.compile(
            "(?i)(csrf|xsrf|authenticity_?token|__requestverificationtoken|csrfmiddlewaretoken|anti.?forgery|^_token$)");
    /** True when a parameter name is a CSRF/anti-forgery token that must never be fuzzed (see {@link #CSRF_PARAM}). */
    public static boolean isCsrfParam(String name) { return name != null && CSRF_PARAM.matcher(name).find(); }
    // Path-like string literals in HTML/JS: SPA route targets, template URLs, endpoints the app
    // references (e.g. 'account-activity.html', 'bank/transfer-funds.html', '/bank/...'). This is how
    // we reach authenticated pages the crawler misses and fragment-routed views don't expose as <a href>.
    private static final Pattern PATH_TOKEN = Pattern.compile(
            "[\"']((?:/)?(?:[A-Za-z0-9_\\-]+/)*[A-Za-z0-9_\\-]+\\.html?|/[A-Za-z0-9_][A-Za-z0-9_\\-/.]{2,})[\"']");
    // SPA hash-route to a server fragment: "#lesson/SqlInjection.lesson", "#/route/view" — capture the path
    // AFTER the leading "#seg/" so it can be fetched as a content fragment. Generic SPA routing convention.
    private static final Pattern HASH_ROUTE = Pattern.compile(
            "[\"']#[A-Za-z0-9_\\-]+/([A-Za-z0-9_][A-Za-z0-9_./\\-]{2,})[\"']");
    // Relative dotted template/fragment token: "SqlInjection.lesson", "views/account.view" — a referenced
    // server-rendered fragment/endpoint (ext = 2-8 word chars; static assets are dropped by SKIP on resolve).
    private static final Pattern REL_TEMPLATE = Pattern.compile(
            "[\"']([A-Za-z0-9_\\-]+(?:/[A-Za-z0-9_\\-]+)*\\.[A-Za-z]{2,8})[\"']");

    // ---- POST-form exercise (so search/filter forms' BODY params enter the audit) ----
    private static final Pattern FORM_BLOCK  = Pattern.compile("(?is)<form\\b.*?</form>");
    private static final Pattern FIELD_TAG   = Pattern.compile("(?is)<(input|textarea|select)\\b([^>]*)>");
    private static final Pattern ATTR_NAME   = Pattern.compile("(?is)\\bname\\s*=\\s*" + Q);
    private static final Pattern ATTR_VALUE  = Pattern.compile("(?is)\\bvalue\\s*=\\s*" + Q);
    private static final Pattern ATTR_TYPE   = Pattern.compile("(?is)\\btype\\s*=\\s*" + Q);
    // SAFETY: NEVER auto-submit a state-changing / dangerous form. This explorer also runs against live prod
    // engagements — blindly POSTing forms could move money, delete data, change a password, or register users.
    // Only read/search/filter forms are exercised. Matched against BOTH the action URL and the whole form markup.
    private static final Pattern FORM_UNSAFE = Pattern.compile(
            "(?i).*(transfer|pay[-_]?bill|payment|payee|purchase|checkout|withdraw|delete|remove|destroy|"
          + "update|edit|change|reset|password|passwd|register|sign[-_]?up|create|new-account|admin|"
          + "settings|profile|deactivate|disable|logout|sign[-_]?out|upload).*");
    private static final int MAX_FORMS = 12;
    private int formsExercised = 0;

    private static final int MAX_FETCHES = 120;
    private static final int MAX_DEPTH = 3;
    private static final int MAX_REDIRECTS = 6;

    public AuthenticatedExplorer(MontoyaApi api, SessionStore session, ScanLog scanLog) {
        this.api = api;
        this.session = session;
        this.scanLog = scanLog;
    }

    /**
     * Explore the authenticated surface; returns how many resources were added. Seeds from the
     * post-login landing URL <em>and</em> the host's existing HTML pages (re-fetched authenticated),
     * so a redirect-only landing (e.g. an infra "accept certs" bounce) doesn't leave us empty-handed.
     */
    public int explore(String host, String landingUrl) {
        Set<String> visited = new LinkedHashSet<>();
        int fetches = 0, scripts = 0;
        formsExercised = 0;

        Deque<String[]> queue = new ArrayDeque<>();   // {url, depth}
        for (String seed : seeds(host, landingUrl)) queue.add(new String[]{seed, "0"});

        while (!queue.isEmpty() && fetches < MAX_FETCHES) {
            String[] item = queue.poll();
            String url = item[0];
            int depth = Integer.parseInt(item[1]);
            String norm = stripFragment(url);
            if (!sameHost(norm, host) || SESSION_RESET.matcher(norm).matches() || !visited.add(norm)) continue;

            HttpRequestResponse rr = fetchFollowingRedirects(norm);
            int st = statusOf(rr);
            if (rr == null || rr.response() == null) {
                scanLog.log("  explore: FAILED " + norm);
                continue;
            }
            api.siteMap().add(rr);
            fetches++;
            String finalUrl = rr.request().url();
            boolean js = isScript(finalUrl);
            if (js) scripts++;
            // show original → final so redirects (e.g. a protected page bouncing to login) are visible
            boolean bounced = !Net.stripQuery(finalUrl).equalsIgnoreCase(norm);
            String shown = bounced ? norm + " → " + finalUrl : finalUrl;
            // On a bounce, print the Cookie actually SENT (from the request itself) + any Set-Cookie the
            // server returned — this shows exactly when/why the session is lost (stale cookie? rotated?).
            String extra = "";
            if (bounced) {
                extra = "   [sent Cookie: " + trunc(reqCookie(rr), 80) + "]";
                String setc = respSetCookie(rr);
                if (!setc.isBlank()) extra += "  [Set-Cookie: " + trunc(setc, 80) + "]";
            }
            scanLog.log("  explore: HTTP " + st + "  " + shown + (js ? "  [script]" : "") + extra);

            // Expand from BOTH HTML and JS: HTML gives href/src/action; every body (HTML or JS) is
            // also scanned for path-like string literals — that's how we reach fragment-routed views
            // (e.g. an app referencing 'bank/account-activity.html' in its router/JS).
            if (depth >= MAX_DEPTH) continue;
            String base = rr.request().url();
            String body = rr.response().bodyToString();
            List<String> refs = new ArrayList<>();
            if (isHtml(rr)) {
                refs.addAll(extractRefs(body));
                // Exercise SAFE (search/filter) POST forms so their BODY fields (e.g. a "description" filter that
                // reflects into the page) enter the site map → the audit fuzzes them. Without this, a POST-only
                // insertion point is never tested (Burp only audits requests it captured). State-changing forms
                // are skipped by FORM_UNSAFE. Generic — no app-specific field/endpoint names.
                exerciseForms(host, base, body, visited);
                // RequireJS/AMD app: follow the data-main module graph (a runtime graph the BFS can't reach
                // via depth alone) so app-code endpoint/route literals enter the site map. Runs once/host.
                if (!amdWalked) {
                    List<String> dm = new ArrayList<>();
                    collect(DATA_MAIN, body, dm);
                    if (!dm.isEmpty()) {
                        String m = dm.get(0);
                        List<String> c = candidateUrls(base, m.endsWith(".js") ? m : m + ".js", host);
                        if (!c.isEmpty()) resolveAmdGraph(host, c.get(0));
                    }
                }
            }
            refs.addAll(extractPathTokens(body));
            refs.addAll(assembleRoutes(body));   // runtime-assembled routes: base + token + ".ext" (else missed)
            for (String ref : refs) {
                for (String abs : candidateUrls(base, ref, host)) {
                    if (sameHost(abs, host) && !visited.contains(abs)
                            && !SKIP.matcher(abs).matches() && !SESSION_RESET.matcher(abs).matches()) {
                        queue.add(new String[]{abs, String.valueOf(depth + 1)});
                    }
                }
            }
        }

        scanLog.log("authenticated explore: fetched " + fetches + " resource(s) ("
                + scripts + " script(s)) → site map.");
        return fetches;
    }

    /** Seed set: the login landing (if any) plus every HTML page already known for the host. */
    private List<String> seeds(String host, String landingUrl) {
        Set<String> out = new LinkedHashSet<>();
        if (landingUrl != null && !landingUrl.isBlank()) out.add(stripFragment(landingUrl));
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String url = rr.request().url();
            if (sameHost(url, host) && isHtmlUrl(url) && !SESSION_RESET.matcher(url).matches()) out.add(Net.stripQuery(url));
        }
        return new ArrayList<>(out);
    }

    // ---- fetching ----

    /** GET the URL authenticated, following up to MAX_REDIRECTS 3xx hops (adding each hop to the site map). */
    private HttpRequestResponse fetchFollowingRedirects(String url) {
        String current = url;
        HttpRequestResponse rr = null;
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            rr = getAuthed(current);
            if (rr == null || rr.response() == null) return rr;
            int st = rr.response().statusCode();
            if (st < 300 || st >= 400) return rr;                 // not a redirect → done
            String loc = safeHeader(rr, "Location");
            if (loc == null || loc.isBlank()) return rr;
            api.siteMap().add(rr);                                 // keep the redirect hop too
            try { current = stripFragment(URI.create(current).resolve(loc).toString()); }
            catch (Exception e) { return rr; }
        }
        return rr;
    }

    private HttpRequestResponse getAuthed(String url) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (session != null && session.has()) req = req.withHeader("Cookie", session.cookieHeader());
            // JWT/SPA apps gate the authenticated surface behind Authorization, not a cookie — carry the bearer.
            if (session != null && session.hasBearer()) req = req.withHeader("Authorization", "Bearer " + session.bearer());
            // Sign the request if the app is signature-gated (key captured at auth) — else /me/ and the merchant
            // data endpoints return "Missing request signature" and the authenticated explore stays shallow.
            if (session != null && session.hasSigningKey())
                req = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKey()).sign(req);
            // Decompress so crawl/mining parses real HTML (not gzip bytes) behind a compressing proxy/CDN.
            return AiScanner.decompress(
                    api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)));
        } catch (Throwable t) {
            return null;
        }
    }

    /** POST the URL authenticated with a form-urlencoded body (cookie/bearer/signing applied like getAuthed). */
    private HttpRequestResponse postAuthed(String url, String body) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                    .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                    .withBody(body == null ? "" : body);
            if (session != null && session.has()) req = req.withHeader("Cookie", session.cookieHeader());
            if (session != null && session.hasBearer()) req = req.withHeader("Authorization", "Bearer " + session.bearer());
            if (session != null && session.hasSigningKey())
                req = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKey()).sign(req);
            return AiScanner.decompress(
                    api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L)));
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Submit SAFE (read/search/filter) POST forms found in a page so their BODY fields become audited insertion
     * points. Fills empty text-like fields with a benign marker (a non-empty value the app will reflect/process),
     * preserves existing hidden values (CSRF tokens etc.), and NEVER submits a state-changing form (FORM_UNSAFE).
     * The POST response is added to the site map → the audit later fuzzes its body params. Generic + bounded.
     */
    private void exerciseForms(String host, String base, String html, Set<String> visited) {
        Matcher fm = FORM_BLOCK.matcher(html);
        while (fm.find() && formsExercised < MAX_FORMS) {
            String form = fm.group();
            // Exercise via POST regardless of the form's DECLARED method. A GET form's params are already audited
            // as URL params, but many apps process the same endpoint on POST too and a reflection/injection sink
            // can be POST-ONLY (Zero Bank's find-transactions "description" reflects on POST, not GET) — so the
            // URL-param pass misses it. Submitting a POST twin (only for SAFE forms, guarded below) closes that gap.
            String action = attr(FORM_ACT, form);
            String actUrl = null;
            for (String abs : candidateUrls(base, (action == null || action.isBlank()) ? base : action, host)) { actUrl = abs; break; }
            if (actUrl == null) actUrl = stripFragment(base);
            if (!sameHost(actUrl, host)) continue;
            // SAFETY GUARD: skip auth-reset and any state-changing/dangerous form (matched on URL AND markup).
            if (SESSION_RESET.matcher(actUrl).matches() || FORM_UNSAFE.matcher(actUrl).matches()
                    || FORM_UNSAFE.matcher(form).matches()) continue;
            String key = "POSTFORM " + stripFragment(actUrl);
            if (!visited.add(key)) continue;
            StringBuilder body = new StringBuilder();
            int fields = 0;
            Matcher tm = FIELD_TAG.matcher(form);
            while (tm.find()) {
                String tag = lc(tm.group(1)), attrs = tm.group(2);
                String name = attr(ATTR_NAME, attrs);
                if (name == null || name.isBlank()) continue;
                String type = lc(attr(ATTR_TYPE, attrs));
                if (type.equals("file") || type.equals("submit") || type.equals("button")
                        || type.equals("image") || type.equals("reset")) continue;
                // Fill by field SHAPE so the POST is a VALID request (else the app 400s and never reflects, so the
                // audited param never reaches its sink). Preserve existing values (hidden CSRF tokens / preselected).
                String val = attr(ATTR_VALUE, attrs);
                if (val == null || val.isBlank()) {
                    String ln = lc(name);
                    if (tag.equals("select")) val = "";                                    // wrong option value → 400; let it default
                    else if (type.equals("number") || type.equals("range")
                            || ln.contains("id") || ln.contains("account") || ln.contains("acct")) val = "1";
                    else if (type.matches("date|datetime|datetime-local|month|week|time")
                            || ln.contains("date") || ln.contains("amount") || ln.contains("amt")
                            || ln.contains("price") || ln.contains("min") || ln.contains("max")) val = "";  // valid "no filter"
                    else if (type.equals("email") || ln.contains("email")) val = "aiscan@example.com";
                    else val = "aiscan";                                                   // text/search/textarea → reflectable marker
                }
                if (body.length() > 0) body.append('&');
                body.append(enc(name)).append('=').append(enc(val));
                fields++;
            }
            if (fields == 0) continue;
            HttpRequestResponse rr = postAuthed(actUrl, body.toString());
            if (rr != null && rr.response() != null) {
                api.siteMap().add(rr);
                formsExercised++;
                scanLog.log("  exercised POST form → " + stripFragment(actUrl)
                        + " (" + fields + " field(s), HTTP " + rr.response().statusCode() + ") → site map/audit");
                // GENERIC debug: the cookie this POST used to reach its status — lets a later probe on the same
                // endpoint be compared (same cookie but different status ⇒ session/jar drift). No app-specific paths.
                String usedCookie = rr.request() != null ? rr.request().headerValue("Cookie") : null;
                if (usedCookie != null) scanLog.debug("    exercise cookie @ " + stripFragment(actUrl)
                        + " = " + trunc(usedCookie, 60));
            }
        }
    }

    private static String enc(String v) { try { return java.net.URLEncoder.encode(v == null ? "" : v, "UTF-8"); } catch (Exception e) { return ""; } }
    private static String lc(String s) { return s == null ? "" : s.toLowerCase(); }
    private static String attr(Pattern p, String s) {
        Matcher m = p.matcher(s);
        if (!m.find()) return null;
        return m.group(2) != null ? m.group(2) : m.group(3) != null ? m.group(3) : m.group(4);
    }

    // ---- markup parsing ----

    private static List<String> extractRefs(String html) {
        List<String> out = new ArrayList<>();
        collect(A_HREF, html, out);
        collect(SCRIPT_SRC, html, out);
        collect(LINK_HREF, html, out);
        collect(FORM_ACT, html, out);
        // RequireJS data-main: the value is a module path (usually extensionless) — fetch it as .js.
        List<String> dm = new ArrayList<>();
        collect(DATA_MAIN, html, dm);
        for (String m : dm) { out.add(m); if (!m.endsWith(".js")) out.add(m + ".js"); }
        return out;
    }

    private static void collect(Pattern p, String html, List<String> out) {
        Matcher m = p.matcher(html);
        while (m.find()) {
            String v = m.group(2) != null ? m.group(2) : m.group(3) != null ? m.group(3) : m.group(4);
            if (v == null) continue;
            v = v.trim();
            if (v.isEmpty() || v.startsWith("#") || v.startsWith("mailto:") || v.startsWith("javascript:")
                    || v.startsWith("tel:") || v.startsWith("data:")) continue;
            out.add(v);
        }
    }

    /** Path-like string literals in any body (HTML or JS): route targets, template/endpoint paths. */
    private boolean amdWalked = false;
    private static final Pattern AMD_PATHS = Pattern.compile("(?is)\\bpaths\\s*:\\s*\\{([^}]*)\\}");
    private static final Pattern AMD_PAIR  = Pattern.compile("([A-Za-z0-9_$-]+)\\s*:\\s*[\"']([^\"']+)[\"']");
    private static final Pattern AMD_DEPS  = Pattern.compile("(?is)(?:\\bdefine|\\brequire|\\bdeps)\\s*[:(]\\s*\\[([^\\]]*)\\]");
    private static final Pattern QUOTED    = Pattern.compile("[\"']([^\"']+)[\"']");
    // Any quoted AMD module-path reference: "goatApp/controller/MenuController" — has a '/', word segments,
    // NO dot (a dotted token like "service/x.mvc" is an endpoint, handled by fetchServerPaths, not a module).
    // Catches module refs that AMD_DEPS misses (single-string require('x'), inline requires, config maps).
    private static final Pattern MODULE_TOKEN = Pattern.compile("[\"']([A-Za-z][A-Za-z0-9_$]*(?:/[A-Za-z0-9_$-]+)+)[\"']");

    // Client-side route assembly (generic, no per-app paths). Some apps build nav URLs at RUNTIME as
    // `base + name + ".ext"` — e.g. Zero Bank: var path="/bank/"; location.href = path + feature + ".html".
    // A static crawler sees the base literal ("/bank/") and the route tokens ("transfer-funds") SEPARATELY and
    // never combines them, so the whole authenticated transactional area is unreachable. When a body shows that
    // concat shape, assemble base × route-token + ext; the real ones 2xx, enter the site map, and cascade via
    // their own nav (which DOES link the siblings). Bounded; junk combos just 404 and expand nothing.
    private static final Pattern EXT_CONCAT  = Pattern.compile("(?i)\\+\\s*[\"']\\.(html?|jsp|php|do|action|aspx?)[\"']");
    private static final Pattern PATH_BASE   = Pattern.compile("[\"'](/[a-z][a-z0-9_-]{0,30}/)[\"']");
    private static final Pattern ROUTE_TOKEN = Pattern.compile("[\"']([a-z][a-z0-9]{2,}(?:-[a-z0-9]+)*)[\"']");

    private List<String> assembleRoutes(String body) {
        List<String> out = new ArrayList<>();
        if (body == null) return out;
        java.util.LinkedHashSet<String> exts = new java.util.LinkedHashSet<>();
        Matcher me = EXT_CONCAT.matcher(body);
        while (me.find()) exts.add("." + me.group(1).toLowerCase());
        if (exts.isEmpty()) return out;                       // only when the app concats base + X + ".ext"
        java.util.LinkedHashSet<String> bases = new java.util.LinkedHashSet<>();
        Matcher mb = PATH_BASE.matcher(body);
        while (mb.find() && bases.size() < 3) bases.add(mb.group(1));
        if (bases.isEmpty()) return out;
        java.util.LinkedHashSet<String> tokens = new java.util.LinkedHashSet<>();
        Matcher mt = ROUTE_TOKEN.matcher(body);
        while (mt.find() && tokens.size() < 40) tokens.add(mt.group(1));
        for (String base : bases)
            for (String tok : tokens)
                for (String ext : exts)
                    out.add(base + tok + ext);                // e.g. /bank/transfer-funds.html
        return out;
    }

    /**
     * Generic RequireJS/AMD module-graph resolver (no browser, no per-app paths). A RequireJS app references
     * its modules as bare, extensionless names resolved at RUNTIME via {@code require.config({baseUrl,paths})},
     * so a static crawler can't follow them. We replicate the resolution: read the config from the data-main
     * file, then BFS the {@code define([...])/require([...])} dependency graph — resolving each module to
     * {@code <baseUrl>/<paths[m]|m>.js} — fetching every module into the site map. Along the way, every module
     * body is scanned for server-path/route string literals (via the same token patterns) and those are
     * fetched too (recursively one level), so an app-code literal like {@code "service/lessonmenu.mvc"} pulls
     * the menu, and the menu's {@code #route/x} fragments pull their forms. Bounded; runs once per host.
     */
    private void resolveAmdGraph(String host, String dataMainUrl) {
        if (amdWalked) return;
        amdWalked = true;
        try {
            HttpRequestResponse mainRr = fetchFollowingRedirects(dataMainUrl);
            if (mainRr == null || mainRr.response() == null || statusOf(mainRr) != 200) return;
            api.siteMap().add(mainRr);
            String mainUrl = mainRr.request().url();
            String amdBase = dirOf(mainUrl);
            String mainBody = mainRr.response().bodyToString();
            if (mainBody == null) return;
            Map<String, String> paths = parseAmdPaths(mainBody);

            Deque<String> modQ = new ArrayDeque<>(parseAmdDeps(mainBody));
            Set<String> modSeen = new LinkedHashSet<>();
            Set<String> pathSeen = new LinkedHashSet<>();
            fetchServerPaths(host, mainUrl, mainBody, pathSeen, 0);

            int fetched = 0, MAX_MODULES = 160;
            while (!modQ.isEmpty() && fetched < MAX_MODULES) {
                String mod = modQ.poll();
                if (mod == null) continue;
                mod = mod.trim();
                if (mod.isEmpty() || mod.startsWith("http") || mod.contains("!") || !modSeen.add(mod)) continue;
                String rel = paths.getOrDefault(mod, mod);
                String url = amdBase + rel + (rel.endsWith(".js") ? "" : ".js");
                if (!sameHost(url, host)) continue;
                HttpRequestResponse rr = fetchFollowingRedirects(url);
                if (rr == null || rr.response() == null || statusOf(rr) != 200) continue;
                api.siteMap().add(rr);
                fetched++;
                String body = rr.response().bodyToString();
                if (body == null) continue;
                for (String d : parseAmdDeps(body)) if (!modSeen.contains(d)) modQ.add(d);
                fetchServerPaths(host, url, body, pathSeen, 0);
            }
            scanLog.log("AMD module graph: fetched " + fetched + " module(s), "
                    + pathSeen.size() + " server path(s) → site map.");
        } catch (Throwable t) { scanLog.debug("AMD resolver error: " + t); }
    }

    /** Fetch server-path/route string literals found in a body (recurse one extra level so a fetched menu's
     *  fragment routes pull their forms too). Bounded by a shared visited set (cap 120). */
    private static final int SERVER_PATH_CAP = 700;
    private void fetchServerPaths(String host, String base, String body, Set<String> seen, int depth) {
        if (depth > 4 || seen.size() > SERVER_PATH_CAP || body == null) return;
        List<String> tokens = new ArrayList<>();
        collectGroup1(PATH_TOKEN, body, tokens);
        collectGroup1(HASH_ROUTE, body, tokens);
        collectGroup1(REL_TEMPLATE, body, tokens);
        // Fetch likely ENDPOINTS/fragments (service/API/.mvc/.lesson/menu-ish) before static templates, so a
        // budget cap can't crowd out the endpoint that unlocks content (e.g. a menu → its content fragments).
        tokens.sort((a, b) -> Integer.compare(endpointRank(b), endpointRank(a)));
        for (String tok : tokens) {
            if (seen.size() > SERVER_PATH_CAP) return;
            for (String abs : candidateUrls(base, tok, host)) {
                if (isScript(abs) || SKIP.matcher(abs).matches() || SESSION_RESET.matcher(abs).matches()) continue;
                if (!sameHost(abs, host) || !seen.add(abs)) continue;
                HttpRequestResponse rr = fetchFollowingRedirects(abs);
                if (rr == null || rr.response() == null) continue;
                int st = statusOf(rr);
                if (st < 200 || st >= 400) continue;
                api.siteMap().add(rr);
                scanLog.debug("  amd server-path: " + st + " " + rr.request().url());
                fetchServerPaths(host, rr.request().url(), rr.response().bodyToString(), seen, depth + 1);
            }
        }
    }

    // A content-view fragment token: has a dot-extension that is NOT a static asset / html / js / css / mvc —
    // i.e. an app-specific server-rendered view (e.g. *.lesson, *.view, *.action). These carry the interactive
    // forms, so they're the highest-value fetch. Generic: keyed on "unusual dotted extension", not on ".lesson".
    private static final Pattern CONTENT_FRAGMENT = Pattern.compile(
            "(?i).*\\.(?!html?$|js$|css$|json$|xml$|mvc$|do$|png$|jpe?g$|gif$|svg$|ico$|woff2?$|ttf$|map$)[a-z]{2,10}$");

    /** Prioritize endpoint-ish tokens (service/API + content-view fragments) over static templates. */
    private static int endpointRank(String t) {
        String s = t.toLowerCase();
        if (CONTENT_FRAGMENT.matcher(s).matches()) return 4;                                // interactive views (highest)
        if (s.contains("service/") || s.contains("/api/") || s.endsWith(".mvc")) return 3;
        if (s.contains("menu") || s.contains("content") || s.contains("list")) return 2;   // generic nav keywords
        if (s.endsWith(".html") || s.endsWith(".htm")) return 0;   // static template — lowest
        return 1;
    }

    private static Map<String, String> parseAmdPaths(String body) {
        Map<String, String> out = new HashMap<>();
        Matcher pm = AMD_PATHS.matcher(body);
        if (pm.find()) {
            Matcher e = AMD_PAIR.matcher(pm.group(1));
            while (e.find()) out.put(e.group(1), e.group(2));
        }
        return out;
    }

    private static List<String> parseAmdDeps(String body) {
        List<String> out = new ArrayList<>();
        // Every quoted module-path reference (array-form AND single/inline requires + config maps).
        Matcher mt = MODULE_TOKEN.matcher(body);
        int mcap = 0;
        while (mt.find() && mcap < 400) { out.add(mt.group(1)); mcap++; }
        Matcher m = AMD_DEPS.matcher(body);
        int cap = 0;
        while (m.find() && cap < 200) {
            Matcher q = QUOTED.matcher(m.group(1));
            while (q.find()) { out.add(q.group(1)); cap++; }
        }
        return out;
    }

    private static String dirOf(String url) {
        String u = stripFragment(Net.stripQuery(url));
        int s = u.lastIndexOf('/');
        return s >= 0 ? u.substring(0, s + 1) : u + "/";
    }

    /**
     * Absolute URL candidates for a reference. Rooted/absolute refs resolve doc-relative as usual. A BARE
     * relative token (e.g. a hash-route fragment "SqlInjection.lesson" mined from a JSON menu at /ctx/service/
     * /menu.mvc) is ALSO resolved against the host root and the app-context root (first path segment) — because
     * SPA fragment routes are served from the app base, not the document's directory. Wrong candidates simply
     * 404 (no forms extracted); the right one enters the site map. Generic — no per-app paths.
     */
    private static List<String> candidateUrls(String base, String ref, String host) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        try {
            URI b = URI.create(base);
            boolean bare = !ref.startsWith("/") && !ref.contains("://");
            // Doc-relative resolution is only sound for a genuine document-relative ref. A BARE token mined from
            // deep inside a JS bundle (e.g. a webpack chunk name "static/chunks/app.js" referenced from a script
            // ALREADY under /static/chunks/) is NOT document-relative — resolving it against the script's dir
            // produces a doubled path (/static/chunks/static/chunks/app.js) that only ever 404s. So we take the
            // doc-relative candidate only when it does NOT collapse a repeated segment run; the context-root and
            // host-root candidates below cover the real location.
            String docRel = stripFragment(b.resolve(ref).toString());
            if (!hasRepeatedSegmentRun(docRel)) addUnique(out, seen, docRel);
            if (bare) {
                String origin = b.getScheme() + "://" + b.getAuthority();
                String path = b.getPath();
                int s1 = path.indexOf('/', 1);
                if (s1 > 0) addUnique(out, seen, stripFragment(origin + path.substring(0, s1 + 1) + ref));  // context root (likely)
                addUnique(out, seen, stripFragment(origin + "/" + ref));                          // host root
            }
        } catch (Exception ignore) { }
        return out;
    }

    private static void addUnique(List<String> out, Set<String> seen, String url) {
        if (url != null && !hasRepeatedSegmentRun(url) && seen.add(url)) out.add(url);
    }

    /** True if the URL path contains the same path segment twice in a row, or a repeated multi-segment run
     *  (e.g. .../static/chunks/static/chunks/x) — the signature of a mis-resolved bundle-relative token. */
    static boolean hasRepeatedSegmentRun(String url) {
        try {
            String path = URI.create(stripFragment(Net.stripQuery(url))).getPath();
            if (path == null || path.isEmpty()) return false;
            String[] segs = path.split("/");
            List<String> s = new ArrayList<>();
            for (String seg : segs) if (!seg.isEmpty()) s.add(seg);
            for (int i = 0; i + 1 < s.size(); i++) if (s.get(i).equals(s.get(i + 1))) return true;   // aa
            for (int i = 0; i + 3 < s.size(); i++)                                                    // ab…ab
                if (s.get(i).equals(s.get(i + 2)) && s.get(i + 1).equals(s.get(i + 3))) return true;
            return false;
        } catch (Exception e) { return false; }
    }

    private static List<String> extractPathTokens(String body) {
        List<String> out = new ArrayList<>();
        collectGroup1(PATH_TOKEN, body, out);
        collectGroup1(HASH_ROUTE, body, out);      // SPA #seg/<path> fragment routes
        collectGroup1(REL_TEMPLATE, body, out);    // relative dotted templates/fragments
        return out;
    }

    private static void collectGroup1(Pattern p, String body, List<String> out) {
        Matcher m = p.matcher(body);
        int cap = 0;
        while (m.find() && cap < 300) {
            String v = m.group(1);
            if (v == null || v.isBlank() || v.startsWith("//")) continue;   // skip protocol-relative externals
            out.add(v);
            cap++;
        }
    }

    // ---- helpers ----

    private static boolean isHtml(HttpRequestResponse rr) {
        try {
            String ct = safeHeader(rr, "Content-Type");
            if (ct != null) return ct.toLowerCase().contains("html");
            String u = rr.request().url().toLowerCase();
            return u.endsWith(".html") || u.endsWith("/") || !u.matches(".*\\.[a-z0-9]{1,5}($|\\?).*");
        } catch (Exception e) { return false; }
    }

    private static boolean isScript(String url) {
        return url != null && url.toLowerCase().contains(".js");
    }

    private static String trunc(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }
    private static String reqCookie(HttpRequestResponse rr) {
        try { String c = rr.request().headerValue("Cookie"); return c == null ? "(none)" : c; }
        catch (Exception e) { return "(none)"; }
    }
    private static String respSetCookie(HttpRequestResponse rr) {
        try {
            StringBuilder sb = new StringBuilder();
            rr.response().cookies().forEach(c -> {
                if (sb.length() > 0) sb.append("; ");
                sb.append(c.name()).append('=').append(c.value());
            });
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    private static boolean isHtmlUrl(String url) {
        String u = url.toLowerCase();
        int q = u.indexOf('?');
        String bare = q < 0 ? u : u.substring(0, q);
        return bare.endsWith(".html") || bare.endsWith(".htm") || bare.endsWith("/")
                || !bare.matches(".*\\.[a-z0-9]{1,5}$");
    }

    private static int statusOf(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; }
        catch (Throwable t) { return -1; }
    }


    private static String safeHeader(HttpRequestResponse rr, String name) {
        try { return rr.response().headerValue(name); } catch (Exception e) { return null; }
    }

    private static boolean sameHost(String url, String host) {
        try { return host.equalsIgnoreCase(Net.authority(url)); } catch (Exception e) { return false; }
    }

    private static String stripFragment(String url) {
        int i = url.indexOf('#');
        return i < 0 ? url : url.substring(0, i);
    }
}
