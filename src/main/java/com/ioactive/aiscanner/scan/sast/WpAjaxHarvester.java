package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.ui.ScanLog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Deterministic WordPress AJAX route harvester (no LLM). Extracts {@code add_action('wp_ajax[_nopriv]_ACTION',
 * 'handler')} registrations and, for each, scans the handler function body to pick the correct HTTP method
 * (GET vs POST), the tainted param key, and the sink class.
 *
 * <p>Lives in the MODE-INDEPENDENT deterministic layer (next to {@link RouteHarvester} / PostmanParser, invoked
 * from AiScanner) rather than inside one LLM analyzer — it is deterministic, so it must run in EVERY SAST mode
 * (coarse / iterative / agentic) and even with no LLM at all, not just whichever analyzer happened to embed it.
 */
public final class WpAjaxHarvester {
    private WpAjaxHarvester() {}

    private static final Pattern WP_AJAX_REG = Pattern.compile(
            "add_action\\s*\\(\\s*['\"]wp_ajax(?:_nopriv)?_([^'\"]+)['\"]\\s*,\\s*['\"]([^'\"]+)['\"]",
            Pattern.CASE_INSENSITIVE);
    // String-literal key: $_GET['foo'] or $_POST['foo']
    private static final Pattern GET_PARAM_KEY  = Pattern.compile("\\$_GET\\s*\\[\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern POST_PARAM_KEY = Pattern.compile("\\$_POST\\s*\\[\\s*['\"]([^'\"]+)['\"]");
    // Any GET/POST access including variable keys: $_GET[$var] — determines method even without knowing key
    private static final Pattern GET_ANY  = Pattern.compile("\\$_GET\\s*\\[");
    private static final Pattern POST_ANY = Pattern.compile("\\$_POST\\s*\\[");
    // Pagination/control params that are not injection targets — skip when picking paramName.
    private static final Set<String> PAGINATION_PARAMS = new HashSet<>(Arrays.asList(
            "nb", "page", "limit", "offset", "num", "count", "p", "paged", "start", "from", "to", "per_page"));
    // WordPress-CORE AJAX actions present on EVERY WordPress install — framework-generic noise, safe to skip.
    private static final Pattern WP_AJAX_SKIP = Pattern.compile(
            "(?i)^(heartbeat|autosave|save-post|inline-save|closed-postboxes|meta-box-order|"
            + "query-attachments|upload-attachment|get-post-thumbnail-html|dismiss-wp-pointer|"
            + "wp-link-ajax|wp-remove-post-lock|delete-post|trash-post|untrash-post|health-check)$");
    // Generic PHP/WordPress sink vocab to CLASSIFY an ajax handler body (so we don't blanket-label everything SQLi).
    private static final Pattern WP_SINK_SQL  = Pattern.compile("(?i)(\\$wpdb->|mysqli?_query|->query\\s*\\(|->get_(results|row|var|col)\\s*\\()");
    private static final Pattern WP_SINK_FILE = Pattern.compile("(?i)(file_get_contents|fopen|readfile|include(_once)?\\s*\\(|require(_once)?\\s*\\(|fwrite|move_uploaded_file)");
    private static final Pattern WP_SINK_EXEC = Pattern.compile("(?i)(shell_exec|passthru|proc_open|\\bsystem\\s*\\(|\\bexec\\s*\\(|popen|`)");
    private static final Pattern WP_SINK_DESER= Pattern.compile("(?i)(unserialize|maybe_unserialize)");

    /** Harvest WP AJAX routes from a local checkout. Empty when there are none / repo unreadable. Never throws. */
    public static SourceFindings harvest(String repoPath, ScanLog log) {
        if (repoPath == null || repoPath.isBlank()) return SourceFindings.empty();
        Path root;
        try { root = Paths.get(repoPath).toRealPath(); } catch (Exception e) { return SourceFindings.empty(); }
        return new SourceFindings(hints(root, log));
    }

    private static List<StaticHint> hints(Path root, ScanLog log) {
        List<StaticHint> out = new ArrayList<>();
        if (root == null || !Files.isDirectory(root)) return out;
        // action → handler function name, handler → file source
        Map<String, String> actionToHandler = new LinkedHashMap<>();
        Map<String, String> handlerToSrc    = new LinkedHashMap<>();
        try (Stream<Path> walk = Files.walk(root, SastFiles.MAX_DEPTH)) {
            walk.filter(Files::isRegularFile)
                .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".php"))
                .filter(p -> { try { return Files.size(p) < 500_000; } catch (Exception e) { return false; } })
                .forEach(p -> {
                    try {
                        String src = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                        if (src.indexOf('\0') >= 0) return;
                        Matcher m = WP_AJAX_REG.matcher(src);
                        while (m.find()) {
                            String action  = m.group(1).trim();
                            String handler = m.group(2).trim();
                            if (WP_AJAX_SKIP.matcher(action).find()) continue;
                            actionToHandler.putIfAbsent(action, handler);
                            handlerToSrc.putIfAbsent(handler, src);
                        }
                    } catch (Exception ignore) { }
                });
        } catch (Exception ignore) { }

        for (Map.Entry<String, String> ae : actionToHandler.entrySet()) {
            String action = ae.getKey();
            String handlerName = ae.getValue();
            String path = "/wp-admin/admin-ajax.php?action=" + action;
            String src  = handlerToSrc.getOrDefault(handlerName, "");
            String method = "POST";
            String paramName = null;                 // only set when a literal key is actually extracted
            String handlerBody = "";
            // Extract the handler function body and determine method + param + sink class FROM THE CODE.
            if (!src.isEmpty()) {
                Matcher fb = Pattern.compile(
                        String.format("function\\s+%s\\s*\\([^)]*\\)\\s*\\{(.{0,3000})", Pattern.quote(handlerName)),
                        Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher(src);
                if (fb.find()) {
                    handlerBody = fb.group(1);
                    // Collect all string-literal GET keys, skip pagination params, pick first useful one.
                    Matcher gp = GET_PARAM_KEY.matcher(handlerBody);
                    Matcher pp = POST_PARAM_KEY.matcher(handlerBody);
                    String bestGetKey = null;
                    while (gp.find()) {
                        String k = gp.group(1);
                        if (!PAGINATION_PARAMS.contains(k.toLowerCase()) && bestGetKey == null) bestGetKey = k;
                    }
                    boolean hasPostLiteral = pp.find();
                    boolean hasGetAny  = bestGetKey != null || GET_ANY.matcher(handlerBody).find();
                    boolean hasPostAny = hasPostLiteral || POST_ANY.matcher(handlerBody).find();
                    if (hasGetAny && !hasPostAny) {
                        method = "GET";
                        paramName = bestGetKey;             // null if only a variable-keyed $_GET[$x] was seen
                    } else if (hasPostAny) {
                        method = "POST";
                        paramName = hasPostLiteral ? pp.group(1) : null;
                    } else if (hasGetAny) {
                        method = "GET";
                    }
                }
            }
            // Classify the vuln from the ACTUAL handler body — never blanket-label SQLi. Empty class = pure
            // reachability hint (the full probe battery still tests it; the deterministic oracle still decides).
            String vulnClass = "", sinkType = "";
            if (WP_SINK_SQL.matcher(handlerBody).find())        { vulnClass = "SQL Injection"; sinkType = "sql"; }
            else if (WP_SINK_EXEC.matcher(handlerBody).find())  { vulnClass = "Command injection"; sinkType = "command"; }
            else if (WP_SINK_FILE.matcher(handlerBody).find())  { vulnClass = "Path traversal / File inclusion (LFI)"; sinkType = "path"; }
            else if (WP_SINK_DESER.matcher(handlerBody).find()) { vulnClass = "Insecure deserialization"; sinkType = "deser"; }
            List<String> params = new ArrayList<>();
            if (paramName != null && !paramName.isBlank()) params.add(paramName);
            out.add(new StaticHint(method, path, params, paramName == null ? "" : paramName,
                    vulnClass, sinkType, path + (paramName == null ? "" : ":" + paramName), 0.5, ""));
            if (log != null) log.debug("SAST(wp-ajax): " + method + " " + path
                    + " param=" + (paramName == null ? "(mine)" : paramName)
                    + (vulnClass.isEmpty() ? "" : " class=" + vulnClass));
        }
        return out;
    }
}
