# AI Scanner — Bench

The benchmark harness is **`bench/e2e-matrix.sh`**. It brings each target up on demand (pulls a
public image or starts a pre-built container), runs the AI Scanner against it, and scores the
findings. Targets are declared in the `ALL_TARGETS` registry near the top of that script
(`name|kind|image|hostport|containerport|path|repo`).

## Quick start

```bash
# 0) pre-flight only (builds the ext jar, checks LLM reachability + Burp jars) — scans nothing
bench/e2e-matrix.sh --verify

# 1) PARALLEL: scan N targets concurrently in ONE Burp (per-target session/log/report, isolated)
bench/e2e-matrix.sh pair vulnlab webgoatnet          # 2 targets
bench/e2e-matrix.sh pair goof nodevuln               # 2 targets

# 2) MATRIX: one target at a time, per configuration
TARGETS="juice dvwa" bench/e2e-matrix.sh             # default configs: comm-ext pro-ext
CONFIGS="pro-ext" TARGETS="juice" bench/e2e-matrix.sh

# 3) BASELINE A/B: findings WITH the extension vs bare native Burp (no extension)
RUN_PRO_BARE=1 CONFIGS="pro-bare pro-ext" TARGETS="dvwa" bench/e2e-matrix.sh

# 4) SAST A/B: black-box vs source-assisted (the target's `repo` field drives -Daiscanner.sourceRepo)
WEB_SRC=both CONFIGS="pro-ext" TARGETS="snapstore" bench/e2e-matrix.sh
```

Reports land in `bench/results/compare/` — `<target>__<config>.report.txt` for the matrix, and
`pair-<host_port>.report.txt` for `pair` runs (per-target, port-distinct so concurrent
`localhost:PORT` targets never collide). A findings count is derived by counting
`^VULNERABILITY:|^HIGH |^MED ` lines; the CSV summary is `bench/results/compare/e2e-matrix.csv`.

## LLM engine

The extension needs an OpenAI-compatible endpoint (default is the local Qwen). Override per run:

```bash
export AISCANNER_BASE_URL=http://127.0.0.1:8000/v1/
export AISCANNER_MODEL=your-model
export AISCANNER_API_KEY=...        # if the endpoint requires it
```

## Notes
- `kind=docker` targets are pulled/built and spun fresh per cell; `kind=running` targets are
  pre-built containers the harness starts on demand (with their compose siblings); `kind=external`
  are live public sites.
- Per-target setup (DB create, register, security level, etc.) lives in the harness `setup_*`
  functions — the scanner itself stays generic (no per-app logic).
- `bench/ollama-shim.py` fronts the local LLM as an Ollama API for targets whose LLM labs expect
  one (AspGoat). `bench/noext.sh` is the standalone no-extension baseline runner.
- Expected/denominator lists live in `bench/expected/<target>.txt` (one id per line, `#` comments;
  matched case-insensitive, word-boundary substring against the report).
