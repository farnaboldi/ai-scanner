package com.ioactive.aiscanner.scan.sast;

import com.ioactive.aiscanner.engine.DirectLlmHttp;
import com.ioactive.aiscanner.engine.EngineConfig;
import com.ioactive.aiscanner.engine.LocalAiEngine;
import com.ioactive.aiscanner.ui.ScanLog;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.function.Supplier;

/**
 * Headless INTEGRATION test for the SAST route-discovery chain, with NO Burp/crawl/native-audit overhead.
 * Runs the REAL analyzers ({@link CoarseSourceAnalyzer} / {@link IterativeRouteScanner}) against a local repo
 * through a direct (non-Burp) LLM transport ({@link DirectLlmHttp}), and prints route/param/sink metrics — so
 * a context/model/prompt change can be measured in ~30s instead of ~10min. Realizes the GUI-free test seam the
 * {@code LlmHttp} interface was designed for. The {@code table} mode dumps the harvested route table only (no LLM).
 *
 * <pre>usage: SastItest &lt;repoPath&gt; [coarse|iterative|both|table] [host]</pre>
 * Env: AISCANNER_BASE_URL, AISCANNER_MODEL, AISCANNER_API_KEY, ITEST_TEMP, ITEST_RUNS, ITEST_ARM, ITEST_VERBOSE.
 * Pair with {@code /tmp/itest-analysis/validate.py} to score valid-unique-paths against a target's real routes.
 */
public final class SastItest {

    private static LocalAiEngine engine;

    public static void main(String[] args) throws Exception {
        String repo = arg(args, 0, null);
        String mode = arg(args, 1, "both");                 // coarse | iterative | both | table
        String host = arg(args, 2, "itest.local");
        if (repo == null) { System.err.println("usage: SastItest <repoPath> [coarse|iterative|both|table] [host]"); System.exit(2); }

        if (mode.equals("table")) {                          // no-LLM: dump the harvested ROUTE TABLE for inspection
            Path r = Paths.get(repo);
            SastRouteTable.Result rt = SastRouteTable.build(r, SastFiles.candidates(r));
            System.out.println("### ROUTE TABLE (" + rt.routes + " routes, handler=" + rt.handlerType + ")");
            for (String ln : rt.context.split("=== HANDLER")[0].split("\n"))
                if (ln.matches("[A-Z]+ /.*")) System.out.println(ln);
            return;
        }

        String base  = env("AISCANNER_BASE_URL", "http://pgx:8000/v1");
        String model = env("AISCANNER_MODEL", "qwen3.6-nvfp4");
        String key   = env("AISCANNER_API_KEY", "");
        double temp  = Double.parseDouble(env("ITEST_TEMP", "0.0"));
        int    runs  = Integer.parseInt(env("ITEST_RUNS", "1"));
        String arm   = env("ITEST_ARM", "?");

        boolean verbose = !env("ITEST_VERBOSE", "1").equals("0");
        java.util.function.Consumer<String> diag = verbose ? s -> System.err.println("[diag] " + s) : s -> { };
        EngineConfig cfg = new EngineConfig(base, model, key, temp, 8192, true, 600);
        engine = new LocalAiEngine(cfg, new DirectLlmHttp(), diag);
        ScanLog log = new ScanLog(diag);   // background-AWT (run with -Dapple.awt.UIElement=true); log/debug → stderr

        System.out.println("### SastItest arm=" + arm + " mode=" + mode + " repo=" + repo);
        System.out.println("### model=" + model + " base=" + base + " temp=" + temp + " runs=" + runs);

        if (mode.equals("coarse") || mode.equals("both"))
            for (int i = 0; i < runs; i++)
                run("COARSE", () -> new CoarseSourceAnalyzer(engine, log).analyze(host, repo), i);
        if (mode.equals("iterative") || mode.equals("both"))
            for (int i = 0; i < runs; i++)
                run("ITERATIVE", () -> new IterativeRouteScanner(engine, log).analyze(host, repo), i);
    }

    private static void run(String tag, Supplier<SourceFindings> fn, int i) {
        long t0 = System.currentTimeMillis();
        SourceFindings f;
        try { f = fn.get(); }
        catch (Exception e) { System.out.println(tag + " run#" + i + " FAILED: " + e); return; }
        metrics(tag + " run#" + i, f, System.currentTimeMillis() - t0);
    }

    private static void metrics(String tag, SourceFindings f, long ms) {
        List<StaticHint> hs = f.all();
        long withParam = hs.stream().filter(h -> h.hasParam() || !h.params.isEmpty()).count();
        long withSink  = hs.stream().filter(h -> h.sinkLocation != null && !h.sinkLocation.isBlank()).count();
        long endpoints = hs.stream().filter(StaticHint::hasEndpoint).count();
        long paths     = hs.stream().map(h -> h.path).distinct().count();
        double conf    = hs.stream().mapToDouble(h -> h.confidence).average().orElse(0);
        System.out.printf("%-16s total=%-3d uniqPaths=%-3d withParam=%-3d withSink=%-3d endpoints=%-3d avgConf=%.2f  %dms%n",
                tag, hs.size(), paths, withParam, withSink, endpoints, conf, ms);
        for (StaticHint h : hs)
            System.out.printf("    %-5s %-42s params=%-22s sink=%-22s vc=%-10s c=%.2f%n",
                    blank(h.method, "GET"), trunc(h.path, 42), trunc(String.join(",", h.params), 22),
                    trunc(h.sinkLocation, 22), trunc(h.vulnClass, 10), h.confidence);
    }

    private static String blank(String s, String d) { return s == null || s.isBlank() ? d : s; }
    private static String trunc(String s, int n) { if (s == null) return ""; return s.length() <= n ? s : s.substring(0, n - 1) + "…"; }
    private static String arg(String[] a, int i, String d) { return i < a.length ? a[i] : d; }
    private static String env(String k, String d) { String v = System.getenv(k); return v != null && !v.isBlank() ? v : d; }
}
