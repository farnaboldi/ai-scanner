package com.ioactive.aiscanner.scan.sast;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * The result of a source-analysis pass: an immutable bag of {@link StaticHint} directives plus lookup
 * helpers used to steer discovery, the probes, and the flow engine. Empty is the graceful "no repo /
 * nothing found" case — every consumer must behave exactly like today when this is empty.
 */
public final class SourceFindings {

    private final List<StaticHint> hints;

    public SourceFindings(List<StaticHint> hints) {
        this.hints = hints == null ? new ArrayList<>() : hints;
    }

    public static SourceFindings empty() { return new SourceFindings(new ArrayList<>()); }

    /** Union two hint sets, deduped by (method,path,paramName,class,PARAMS); {@code a} wins ties (e.g. LLM over
     *  harvested). The full param LIST is part of the key so a richer hint (e.g. a Postman route carrying its query
     *  param {@code [url]}) is NOT collapsed into a same-path param-less hint from another source — losing the very
     *  param that is the sink (an SSRF {@code ?url=}). Two same-path hints with different params now BOTH survive. */
    public static SourceFindings combine(SourceFindings a, SourceFindings b) {
        LinkedHashMap<String, StaticHint> m = new LinkedHashMap<>();
        if (a != null) for (StaticHint h : a.all()) m.putIfAbsent(key(h), h);
        if (b != null) for (StaticHint h : b.all()) m.putIfAbsent(key(h), h);
        return new SourceFindings(new ArrayList<>(m.values()));
    }

    private static String key(StaticHint h) {
        java.util.TreeSet<String> ps = new java.util.TreeSet<>(h.params);
        return (h.method + "|" + h.path + "|" + h.paramName + "|" + h.vulnClass + "|" + ps).toLowerCase();
    }

    public boolean isEmpty() { return hints.isEmpty(); }
    public int size() { return hints.size(); }
    public List<StaticHint> all() { return hints; }

    /** Hints that name a route/path — candidates to add to the dynamic attack surface. */
    public List<StaticHint> hiddenEndpoints() {
        List<StaticHint> out = new ArrayList<>();
        for (StaticHint h : hints) if (h.hasEndpoint()) out.add(h);
        return out;
    }

    /**
     * Best hint for a concrete (url, paramName) a probe is about to test: highest-confidence hint whose
     * paramName matches, preferring one whose path also matches the url. null if none applies.
     */
    public StaticHint bestForParam(String url, String paramName) {
        if (paramName == null || paramName.isBlank()) return null;
        StaticHint best = null;
        for (StaticHint h : hints) {
            if (!h.hasParam() || !h.paramName.equalsIgnoreCase(paramName)) continue;
            boolean urlOk = !h.hasEndpoint() || h.matchesUrl(url);
            if (!urlOk) continue;
            if (best == null || h.confidence > best.confidence
                    || (h.confidence == best.confidence && h.hasEndpoint() && !best.hasEndpoint())) best = h;
        }
        return best;
    }

    /** Any hint of a given canonical vuln class touches this url? (coarse gate for a probe). */
    public boolean touches(String url, String canonicalVulnClass) {
        for (StaticHint h : hints) {
            if (!h.vulnClass.equalsIgnoreCase(canonicalVulnClass)) continue;
            if (!h.hasEndpoint() || h.matchesUrl(url)) return true;
        }
        return false;
    }

    /** Compact, prompt-budgeted summary handed to the FlowEngine goal so the planner targets these first. */
    public String hintText(int maxItems) {
        if (hints.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (StaticHint h : hints) {
            if (n >= maxItems) break;
            sb.append(n == 0 ? "" : "; ")
              .append(h.method.isBlank() ? "" : h.method + " ")
              .append(h.hasEndpoint() ? h.path : "")
              .append(h.hasParam() ? " param=" + h.paramName : "")
              .append(h.vulnClass.isBlank() ? "" : " (" + h.vulnClass + ")");
            n++;
        }
        return sb.toString().trim();
    }
}
