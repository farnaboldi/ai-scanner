package com.ioactive.aiscanner.scan.sast;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * A curated, on-demand knowledge base of per-framework and per-vulnerability-class testing skills, loaded from
 * bundled Markdown resources ({@code /aiscanner/sast/skills/*.md}).
 *
 * <p><b>Steering only.</b> Excerpts are injected into the SAST analyzer prompts so a local model gets expert
 * attack-surface / methodology heuristics it would otherwise re-derive every call. This class never decides
 * anything — it only enriches the prompt that PRODUCES {@link StaticHint}s; the deterministic oracles still
 * decide every verdict. It is generic by construction: skills are keyed by framework/technology and by vuln
 * class, NEVER by target application (no per-app rules / fingerprinting).</p>
 */
public final class SkillLibrary {
    private SkillLibrary() {}

    private static final String BASE = "/aiscanner/sast/skills/";
    private static final Pattern HEAD = Pattern.compile("^##\\s+([\\w-]+)\\s*$");
    private static final int DEFAULT_BUDGET = 4000;

    // Lazily-parsed section maps (slug -> body). Loaded once from the classpath resource.
    private static volatile Map<String, String> FRAMEWORK;
    private static volatile Map<String, String> VULN;

    private static Map<String, String> framework() {
        Map<String, String> m = FRAMEWORK;
        if (m == null) synchronized (SkillLibrary.class) { if ((m = FRAMEWORK) == null) FRAMEWORK = m = parse(BASE + "framework.md"); }
        return m;
    }

    private static Map<String, String> vuln() {
        Map<String, String> m = VULN;
        if (m == null) synchronized (SkillLibrary.class) { if ((m = VULN) == null) VULN = m = parse(BASE + "vuln.md"); }
        return m;
    }

    /** Parse a `## slug`-delimited Markdown resource into an ordered slug→body map. Missing resource → empty. */
    static Map<String, String> parse(String resource) {
        Map<String, String> m = new LinkedHashMap<>();
        try (InputStream in = SkillLibrary.class.getResourceAsStream(resource)) {
            if (in == null) return m;
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            String slug = null;
            StringBuilder body = new StringBuilder();
            for (String line : text.split("\n", -1)) {
                Matcher mm = HEAD.matcher(line);
                if (mm.matches()) {
                    if (slug != null) m.put(slug, body.toString().trim());
                    slug = mm.group(1).toLowerCase();
                    body.setLength(0);
                } else if (slug != null) {
                    body.append(line).append('\n');
                }
            }
            if (slug != null) m.put(slug, body.toString().trim());
        } catch (Exception ignore) { /* any problem → empty KB; SAST degrades to today's generic prompts */ }
        return m;
    }

    /** Skill body for a framework slug (e.g. {@code "django"}), or {@code ""} if unknown. */
    public static String forFramework(String slug) {
        return slug == null ? "" : framework().getOrDefault(slug.trim().toLowerCase(), "");
    }

    /** Skill body for a vuln slug (e.g. {@code "sqli"}), or {@code ""} if unknown. */
    public static String forVuln(String slug) {
        return slug == null ? "" : vuln().getOrDefault(slug.trim().toLowerCase(), "");
    }

    /** Skill body for a canonical vuln id as produced by {@link StaticHint} (e.g. {@code "SQL Injection"}). */
    public static String forVulnClass(String canonical) {
        return forVuln(slugForVulnClass(canonical));
    }

    /** Map a canonical vuln id (see {@code StaticHint.canonicalVulnClass}) to a vuln.md slug, or {@code ""}. */
    public static String slugForVulnClass(String canonical) {
        if (canonical == null) return "";
        String x = canonical.toLowerCase();
        if (x.contains("sql injection")) return "sqli";
        if (x.contains("nosql")) return "nosql";
        if (x.equals("idor")) return "idor";
        if (x.equals("bfla")) return "bfla";
        if (x.contains("mass-assign") || x.contains("mass assign")) return "mass-assignment";
        if (x.contains("path travers") || x.contains("lfi") || x.contains("file inclusion")) return "path-traversal";
        if (x.contains("command inj")) return "command-injection";
        if (x.equals("ssrf")) return "ssrf";
        if (x.equals("xxe")) return "xxe";
        if (x.contains("deserial")) return "deserialization";
        if (x.contains("open redirect")) return "open-redirect";
        if (x.contains("cross-site") || x.contains("xss")) return "xss";
        return "";
    }

    /**
     * Detect the backend framework(s)/technologies present under {@code root} by ecosystem MARKER files
     * (manifests, entrypoints, schema files) — never by application name. Returns the framework slugs that have a
     * skill, in discovery order.
     */
    public static List<String> detectFrameworks(Path root) {
        LinkedHashSet<String> found = new LinkedHashSet<>();
        if (root == null) return new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root, 4)) {
            List<Path> files = new ArrayList<>();
            walk.filter(Files::isRegularFile).limit(20_000).forEach(files::add);
            for (Path p : files) {
                String rel = safeRel(root, p);
                if (rel.matches("(?i).*(^|/)(\\.git|node_modules|vendor|dist|build|target|\\.venv|venv)(/).*")) continue;
                String name = p.getFileName().toString().toLowerCase();
                // Extension marker: any GraphQL schema file.
                if (name.endsWith(".graphql") || name.endsWith(".graphqls") || name.endsWith(".gql")) found.add("graphql");
                // Entrypoint / manifest markers (some need a content check to disambiguate).
                switch (name) {
                    case "manage.py":      found.add("django"); break;
                    case "artisan":        found.add("laravel"); break;
                    case "settings.py":    if (readSmall(p).contains("INSTALLED_APPS")) found.add("django"); break;
                    case "gemfile":        if (readSmall(p).toLowerCase().contains("rails")) found.add("rails"); break;
                    case "composer.json":  if (readSmall(p).toLowerCase().contains("laravel")) found.add("laravel"); break;
                    case "wp-config.php":
                    case "wp-config-sample.php": found.add("wordpress"); break;
                    default:
                        if (name.endsWith(".php") && !found.contains("wordpress")) {
                            String c = readSmall(p);
                            if (c.contains("Plugin Name:") || c.contains("add_action") && c.contains("wp_ajax"))
                                found.add("wordpress");
                        }
                        break;
                    case "pom.xml":
                    case "build.gradle":
                    case "build.gradle.kts":
                        if (readSmall(p).toLowerCase().contains("spring")) found.add("spring"); break;
                    case "requirements.txt":
                    case "pyproject.toml":
                    case "pipfile": {
                        String c = readSmall(p).toLowerCase();
                        if (c.contains("django")) found.add("django");
                        if (c.contains("flask") || c.contains("fastapi")) found.add("flask-fastapi");
                        break;
                    }
                    case "package.json": {
                        String c = readSmall(p).toLowerCase();
                        if (c.contains("\"express\"") || c.contains("express@") || c.contains("@nestjs")) found.add("express-node");
                        if (c.contains("graphql") || c.contains("apollo")) found.add("graphql");
                        break;
                    }
                }
            }
        } catch (Exception ignore) { }
        // keep only slugs we actually have a skill for
        List<String> out = new ArrayList<>();
        for (String s : found) if (!forFramework(s).isBlank()) out.add(s);
        return out;
    }

    /**
     * Build the prompt guidance for a repo: the detected-framework skills (up to 2, most valuable) plus a compact
     * vuln attack-surface digest, budgeted to {@code maxChars}. Empty string when nothing is detected/available.
     */
    public static String promptExcerpt(Path root, int maxChars) {
        int budget = maxChars <= 0 ? DEFAULT_BUDGET : maxChars;
        StringBuilder sb = new StringBuilder();
        int fwCount = 0;
        for (String fw : detectFrameworks(root)) {
            String body = forFramework(fw);
            if (body.isBlank()) continue;
            String block = "### Stack: " + fw + "\n" + body + "\n\n";
            if (sb.length() + block.length() > budget) break;
            sb.append(block);
            if (++fwCount >= 2) break;
        }
        String digest = vulnDigest(budget - sb.length());
        if (!digest.isBlank()) sb.append("### Vuln attack-surface cues\n").append(digest);
        return sb.toString().trim();
    }

    /** One line per vuln class: its **Attack surface**, budgeted. */
    static String vulnDigest(int budget) {
        if (budget <= 0) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : vuln().entrySet()) {
            String as = lineWith(e.getValue(), "**Attack surface:**");
            if (as.isBlank()) continue;
            String txt = as.replace("**Attack surface:**", "").trim();
            String line = "- " + e.getKey() + ": " + txt + "\n";
            if (sb.length() + line.length() > budget) break;
            sb.append(line);
        }
        return sb.toString();
    }

    /**
     * Append stack-specific guidance to a system prompt. No-op (returns {@code base}) when the excerpt is empty,
     * so behavior is identical to today when nothing is detected.
     */
    public static String augment(String base, String excerpt) {
        if (excerpt == null || excerpt.isBlank()) return base;
        return base
                + "\n\nSTACK-SPECIFIC GUIDANCE (expert heuristics for where routes/params/sinks live in THIS "
                + "codebase's frameworks — use them to find real attacker-reachable inputs; still ONLY emit "
                + "directives evidenced by the code):\n"
                + excerpt;
    }

    // ---- helpers ----

    private static String lineWith(String body, String prefix) {
        if (body == null) return "";
        for (String ln : body.split("\n", -1)) if (ln.trim().startsWith(prefix)) return ln.trim();
        return "";
    }

    private static String safeRel(Path root, Path p) {
        try { return root.relativize(p).toString().replace('\\', '/'); } catch (Exception e) { return p.toString(); }
    }

    private static String readSmall(Path p) {
        try {
            if (Files.size(p) > 200_000) return "";
            return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        } catch (Exception e) { return ""; }
    }

    /** Test/diagnostic accessors. */
    static Set<String> frameworkSlugs() { return framework().keySet(); }
    static Set<String> vulnSlugs() { return vuln().keySet(); }
}
