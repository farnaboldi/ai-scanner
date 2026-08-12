package com.ioactive.aiscanner.scan.sast;

/**
 * Turns an associated source checkout into {@link SourceFindings} testing directives.
 *
 * <p>MVP implementation is {@link CoarseSourceAnalyzer} (a bounded, single-shot LLM pass). The interface
 * exists so a future agentic, tool-using analyzer (repo-navigation loop) can drop in without touching any
 * of the DAST-driving code that consumes {@link SourceFindings}.</p>
 */
public interface SourceAnalyzer {

    /**
     * @param host      the target host being scanned (for the model's context; never used to write files)
     * @param repoPath  a LOCAL directory path (the launcher clones URLs; this is only ever read)
     * @return directives to steer the scan; {@link SourceFindings#empty()} on any problem (never null)
     */
    SourceFindings analyze(String host, String repoPath);
}
