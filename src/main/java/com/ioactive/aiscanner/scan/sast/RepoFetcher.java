package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.ui.ScanLog;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Resolves a source repo to a LOCAL directory for the SAST pass — WITHOUT git or any subprocess. A value that
 * is already a local directory is returned as-is; a git/GitHub/GitLab URL is downloaded as an archive .zip over
 * HTTP and extracted with the JDK's {@link ZipInputStream} (zip-slip- and size-guarded, top-level dir stripped).
 * This lets the extension "clone" a URL itself while staying pure-Java / no-subprocess. Cached per-URL per run.
 * A private repo can be reached with a token via -Daiscanner.gitToken / AISCANNER_GIT_TOKEN.
 */
public final class RepoFetcher {
    private RepoFetcher() {}

    private static final ConcurrentHashMap<String, String> CACHE = new ConcurrentHashMap<>();
    // Temp dirs WE created by extracting a downloaded archive (never user-supplied local checkouts). Cleaned up
    // on extension unload — a session-scoped cache keeps re-scans of the same repo from re-downloading.
    private static final java.util.Set<Path> TEMP_DIRS = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private static final long MAX_TOTAL_BYTES = 300L * 1024 * 1024;   // extracted-size cap (zip-bomb guard)
    private static final int  MAX_ENTRIES     = 60_000;
    private static final int  MAX_FILE_BYTES  = 5 * 1024 * 1024;      // skip files larger than this

    /** A local directory for {@code repoOrPath} (URL → downloaded+extracted). null if it can't be resolved. */
    public static String ensureLocal(String repoOrPath, ScanLog log) {
        if (repoOrPath == null || repoOrPath.isBlank()) return null;
        String r = repoOrPath.trim();
        // Already a local dir (the launcher may pre-clone, or the operator points at a checkout). Still unpack any
        // nested source archive here — NOT only on the download path — so a raw URL handed straight to the
        // extension AND a local clone both get {README + code.zip}-style repos (e.g. vegabird/xvna) made analyzable.
        try { Path p = Paths.get(r); if (Files.isDirectory(p)) { extractNestedZips(p, log); return r; } } catch (Exception ignore) { }
        if (!isRemote(r)) { log.log("[AI Scanner] source repo is neither a local directory nor a URL: " + r); return null; }
        String cached = CACHE.get(r);
        if (cached != null) { try { if (Files.isDirectory(Paths.get(cached))) return cached; } catch (Exception ignore) { } }
        String local = fetch(r, log);
        if (local != null) CACHE.put(r, local);
        return local;
    }

    private static boolean isRemote(String s) {
        return s.matches("(?i)^(https?|git|ssh|git\\+https?)://.*") || s.startsWith("git@");
    }

    private static String fetch(String url, ScanLog log) {
        for (String zipUrl : archiveUrls(url)) {
            try {
                byte[] zip = httpGet(zipUrl);
                if (zip == null || zip.length < 64) continue;
                log.log("[AI Scanner] fetched source archive over HTTP (no git): " + zipUrl + " (" + zip.length + " bytes)");
                Path dir = extract(zip);
                extractNestedZips(dir, log);   // repos that ship source as a nested .zip (e.g. vegabird/xvna = README + xvna.zip)
                long files;
                try (var s = Files.walk(dir)) { files = s.filter(Files::isRegularFile).count(); }
                log.log("[AI Scanner] extracted " + files + " file(s) → " + dir);
                return dir.toString();
            } catch (Exception e) {
                log.debug("[AI Scanner] source archive attempt failed (" + zipUrl + "): " + e);
            }
        }
        log.log("[AI Scanner] could not fetch a source archive for " + url + " — only public GitHub/GitLab HTTP "
                + "archives are auto-fetched (for private/other repos set AISCANNER_GIT_TOKEN, or clone and "
                + "associate a local path). Continuing black-box.");
        return null;
    }

    /** Candidate archive-zip URLs for a repo URL (GitHub default branch first, then main/master; GitLab; generic). */
    private static List<String> archiveUrls(String url) {
        List<String> out = new ArrayList<>();
        String u = url.replaceFirst("(?i)^git\\+", "").replaceFirst("(?i)\\.git$", "").replaceFirst("/+$", "")
                      .replaceFirst("(?i)^git@github\\.com:", "https://github.com/");
        Matcher gh = Pattern.compile("(?i)github\\.com[/:]([^/]+)/([^/#?]+)").matcher(u);
        if (gh.find()) {
            String o = gh.group(1), r = gh.group(2);
            out.add("https://api.github.com/repos/" + o + "/" + r + "/zipball");        // default branch (no guessing)
            out.add("https://codeload.github.com/" + o + "/" + r + "/zip/refs/heads/main");
            out.add("https://codeload.github.com/" + o + "/" + r + "/zip/refs/heads/master");
            return out;
        }
        Matcher gl = Pattern.compile("(?i)gitlab\\.com/(.+)$").matcher(u);
        if (gl.find()) {
            String path = gl.group(1), name = path.substring(path.lastIndexOf('/') + 1);
            out.add("https://gitlab.com/" + path + "/-/archive/main/" + name + "-main.zip");
            out.add("https://gitlab.com/" + path + "/-/archive/master/" + name + "-master.zip");
            return out;
        }
        out.add(u + "/archive/refs/heads/main.zip");
        out.add(u + "/archive/refs/heads/master.zip");
        return out;
    }

    private static byte[] httpGet(String url) throws Exception {
        // Pin HTTP/1.1: the JDK HttpClient defaults to HTTP/2, and some auth/reverse proxies mishandle it
        // (dropped bodies on POST, occasional GET quirks). This is a plain GET so the body-drop bug doesn't
        // apply, but forcing 1.1 keeps every JDK-transport path in this project consistent and proxy-safe.
        HttpClient hc = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20)).build();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(120))
                .header("User-Agent", "ai-scanner")
                .header("Accept", "application/zip, application/octet-stream, */*");
        String tok = System.getProperty("aiscanner.gitToken", System.getenv("AISCANNER_GIT_TOKEN"));
        if (tok != null && !tok.isBlank()) b.header("Authorization", "token " + tok.trim());
        HttpResponse<byte[]> resp = hc.send(b.GET().build(), HttpResponse.BodyHandlers.ofByteArray());
        return resp.statusCode() == 200 ? resp.body() : null;
    }

    /** Extract an archive zip to a temp dir, stripping the single top-level dir; zip-slip + size guarded. */
    private static Path extract(byte[] zip) throws Exception {
        Path root = Files.createTempDirectory("aiscanner-src-");
        TEMP_DIRS.add(root);   // track for unload-time cleanup (only ever a dir we created)
        long total = 0;
        int entries = 0;
        byte[] buf = new byte[8192];
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES || total > MAX_TOTAL_BYTES) break;
                String name = stripTop(e.getName());
                if (name.isEmpty()) continue;
                Path target = root.resolve(name).normalize();
                if (!target.startsWith(root)) continue;             // zip-slip guard
                if (e.isDirectory()) { Files.createDirectories(target); continue; }
                Files.createDirectories(target.getParent());
                try (OutputStream os = Files.newOutputStream(target)) {
                    long fbytes = 0;
                    int n;
                    while ((n = zis.read(buf)) > 0) {
                        if (fbytes + n > MAX_FILE_BYTES || total + n > MAX_TOTAL_BYTES) break;
                        os.write(buf, 0, n);
                        fbytes += n; total += n;
                    }
                }
            }
        }
        return root;
    }

    /** Some repos ship their ACTUAL source as a nested archive (vegabird/xvna is literally just README.md +
     *  xvna.zip). The SAST analyzers walk files on disk, so an un-extracted .zip is invisible → 0 route/sink
     *  signals → 0 hints. Extract any nested .zip in place (ONE level, same zip-slip/size guards) so the code
     *  becomes analyzable. Generic: helps any repo that vendors its code as a zip. */
    private static void extractNestedZips(Path root, ScanLog log) {
        List<Path> zips = new ArrayList<>();
        try (var s = Files.walk(root)) {
            s.filter(Files::isRegularFile)
             .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".zip"))
             .forEach(zips::add);
        } catch (Exception ignore) { return; }
        for (Path zp : zips) {
            try {
                byte[] data = Files.readAllBytes(zp);
                if (data.length < 64) continue;
                Path dest = zp.resolveSibling(zp.getFileName().toString().replaceFirst("(?i)\\.zip$", "") + "-unzipped");
                if (Files.isDirectory(dest)) continue;                  // already unpacked (idempotent re-scan)
                if (dest.startsWith(root) && zp.getParent() != null && zp.getParent().getFileName() != null
                        && zp.getParent().getFileName().toString().endsWith("-unzipped")) continue;  // don't recurse into our own output
                int n = unzipInto(data, dest, root);
                if (n > 0) log.log("[AI Scanner] SAST: extracted nested archive " + root.relativize(zp) + " → " + n + " file(s)");
            } catch (Exception e) { log.debug("[AI Scanner] nested-zip extract failed for " + zp + ": " + e); }
        }
    }

    /** Unzip {@code zip} under {@code dest} (created), NOT stripping any top-level dir. zip-slip + size guarded;
     *  {@code boundary} confines writes. Returns the number of regular files written. */
    private static int unzipInto(byte[] zip, Path dest, Path boundary) throws Exception {
        Files.createDirectories(dest);
        long total = 0; int entries = 0, written = 0;
        byte[] buf = new byte[8192];
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES || total > MAX_TOTAL_BYTES) break;
                String name = e.getName().replace('\\', '/');
                if (name.isEmpty()) continue;
                Path target = dest.resolve(name).normalize();
                if (!target.startsWith(boundary)) continue;             // zip-slip guard
                if (e.isDirectory()) { Files.createDirectories(target); continue; }
                Files.createDirectories(target.getParent());
                try (OutputStream os = Files.newOutputStream(target)) {
                    long fbytes = 0; int n;
                    while ((n = zis.read(buf)) > 0) {
                        if (fbytes + n > MAX_FILE_BYTES || total + n > MAX_TOTAL_BYTES) break;
                        os.write(buf, 0, n); fbytes += n; total += n;
                    }
                }
                written++;
            }
        }
        return written;
    }

    /** Drop the leading "REPO-BRANCH/" component GitHub/GitLab archives wrap everything in (clean rel paths). */
    private static String stripTop(String name) {
        String n = name.replace('\\', '/');
        int i = n.indexOf('/');
        return i >= 0 ? n.substring(i + 1) : "";
    }

    /** Recursively delete every archive we extracted this session and clear the cache. Call on extension unload
     *  (BApp filesystem hygiene). Only removes temp dirs WE created — a user-supplied local checkout is returned
     *  as-is and never tracked here, so it can never be deleted. Returns the number of dirs removed. */
    public static int cleanup() {
        int removed = 0;
        for (Path dir : TEMP_DIRS) {
            try (var s = Files.walk(dir)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (Exception ignore) { }
                });
                removed++;
            } catch (Exception ignore) { }
        }
        TEMP_DIRS.clear();
        CACHE.clear();
        return removed;
    }
}
