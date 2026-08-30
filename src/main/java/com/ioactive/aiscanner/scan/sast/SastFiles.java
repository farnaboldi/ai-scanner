package com.ioactive.aiscanner.scan.sast;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Shared repo-file selection for the SAST analyzers: which source files to consider and in what READ-PRIORITY
 * order, so a large repo's route/sink-bearing server files win the bounded snippet budget over bundled
 * frontend/assets. Extracted so {@link CoarseSourceAnalyzer} and {@link AgenticSourceAnalyzer} share one copy.
 */
final class SastFiles {
    private SastFiles() {}

    static final int MAX_DEPTH = 12;
    private static final long MAX_FILES = 30_000;   // candidate PATHS enumerated (reads stay budget-bounded by callers)

    static final Pattern INTERESTING_EXT = Pattern.compile(
            "(?i)\\.(java|kt|js|mjs|cjs|ts|tsx|jsx|py|rb|php|go|cs|jsp|scala|clj|rs|c|h|cc|cpp|cxx|hpp|m|mm|swift)$");
    private static final Pattern SKIP_DIR = Pattern.compile(
            "(?i)(^|/)(\\.git|node_modules|dist|build|target|out|vendor|\\.venv|venv|__pycache__|"
            + "\\.idea|\\.gradle|coverage|bower_components|migrations|\\.next|\\.nuxt)(/|$)");
    private static final Pattern ROUTEY_PATH = Pattern.compile(
            "(?i)(controller|route|handler|\\bapi\\b|view|rest|endpoint|servlet|\\burls?\\b|\\broutes?\\b|"
            + "index\\.php|main\\.|/app\\.|/server|vuln|\\bschema\\b|\\bmodel\\b|\\bserializ)");
    private static final Pattern SERVER_EXT = Pattern.compile("(?i)\\.(java|kt|py|rb|php|go|rs|cs|scala|c|cc|cpp|jsp)$");

    /** Interesting code files under {@code root}, route/sink-bearing server files first. Never throws. */
    static List<Path> candidates(Path root) {
        List<Path> cands = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root, MAX_DEPTH)) {   // default: does NOT follow symlinked dirs
            walk.filter(Files::isRegularFile)
                .filter(p -> !SKIP_DIR.matcher(root.relativize(p).toString().replace('\\', '/')).find())
                .filter(p -> INTERESTING_EXT.matcher(p.getFileName().toString()).find())
                .limit(MAX_FILES)
                .forEach(cands::add);
        } catch (Exception ignore) { }
        cands.sort(Comparator.comparingInt(p -> priority(root, p)));
        return cands;
    }

    private static int priority(Path root, Path p) {
        String rel = root.relativize(p).toString().replace('\\', '/').toLowerCase();
        if (ROUTEY_PATH.matcher(rel).find()) return 0;   // controllers/routes/views/urls/index.php…
        if (SERVER_EXT.matcher(rel).find()) return 1;    // other server-side source
        return 2;                                        // frontend/assets last
    }
}
