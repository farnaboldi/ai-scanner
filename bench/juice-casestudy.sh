#!/usr/bin/env bash
# =============================================================================
# Juice Shop 3-way case study runner (conference benchmark).
#
#   C1 = Burp Pro baseline      : native crawl + Burp's built-in active checks only
#                                 (AISCANNER_NATIVE_ONLY=1 — no auth/discovery/probes/LLM)
#   C2 = AI Scanner DAST        : full extension, black-box (no source)
#   C3 = AI Scanner DAST + SAST : full extension + Juice Shop source repo (RouteHarvester + LLM SAST)
#
# ONE run per config on a FRESH Juice Shop container (challenge state reset to 0).
# Captures, identically for all three:
#   - wall-clock scan time (parsed from the extension's own "time: …" tally)
#   - GROUND TRUTH: Juice Shop challenges solved  (GET /api/Challenges → solved=true)  + their names
#   - reported findings: deterministic-oracle + native-Burp, by severity
#   - HTTP audit requests sent
#
# Usage:   bench/juice-casestudy.sh c1|c2|c3
#          bench/juice-casestudy.sh all          # c1 then c2 then c3, sequentially
#
# Results land in $RES (default /tmp/juice-casestudy): <cfg>.log, <cfg>.result, <cfg>.challenges.json
# =============================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE" || exit 1

JUICE_URL="http://localhost:3000/"
JUICE_API="http://localhost:3000/api/Challenges"
JUICE_SRC="${JUICE_SRC:-/tmp/juice-shop}"
RES="${RES:-/tmp/juice-casestudy}"; mkdir -p "$RES"
COMPOSE="bench/docker-compose.yml"
MAX_WAIT_SEC="${MAX_WAIT_SEC:-3600}"          # hard ceiling per run (the watchdog inside the extension is the real guard)

# LLM engine (C2/C3 only; C1 needs no LLM). Override via env; never hardcode a secret in the repo history.
export AISCANNER_BASE_URL="${AISCANNER_BASE_URL:-http://pgx:8000/v1/}"
export AISCANNER_MODEL="${AISCANNER_MODEL:-qwen3.6-35b}"
# AISCANNER_API_KEY must be provided by the caller's environment.

say(){ printf '%s\n' "$*"; }

fresh_juice(){
  say "  [juice] recreating fresh container (challenge state → 0)…"
  docker rm -f aiscanner-juice >/dev/null 2>&1
  docker compose -f "$COMPOSE" up -d juice-shop >/dev/null 2>&1 \
    || docker run -d --name aiscanner-juice -p 3000:3000 bkimminich/juice-shop >/dev/null 2>&1
  local n=0
  while [ $n -lt 40 ]; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$JUICE_URL" 2>/dev/null)" = "200" ] && break
    n=$((n+1)); sleep 3
  done
  local solved; solved=$(challenge_solved_count)
  say "  [juice] up; challenges solved at start = ${solved:-?}"
}

# Count solved challenges via the server-truth oracle.
challenge_solved_count(){
  curl -s --max-time 8 "$JUICE_API" 2>/dev/null | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin); ch=d.get("data",d) if isinstance(d,dict) else d
    print(sum(1 for c in ch if c.get("solved")))
except Exception: print("?")' 2>/dev/null
}

# Dump solved challenge names (for the cross-config Venn matrix).
challenge_solved_names(){
  curl -s --max-time 8 "$JUICE_API" 2>/dev/null | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin); ch=d.get("data",d) if isinstance(d,dict) else d
    for c in ch:
        if c.get("solved"): print(c.get("name"),"|",c.get("difficulty"),"|",c.get("category"))
except Exception: pass' 2>/dev/null
}

run_one(){
  local cfg="$1"; local log="$RES/$cfg.log"; local out="$RES/$cfg.result"
  say "==================================================================="
  say " CONFIG $cfg"
  say "==================================================================="
  pkill -9 -f 'burpsuite.jar' 2>/dev/null; sleep 2
  fresh_juice

  unset AISCANNER_NATIVE_ONLY AISCANNER_SOURCE_REPO AISCANNER_ONLY
  case "$cfg" in
    c1) export AISCANNER_NATIVE_ONLY=1;                     local label="Burp Pro baseline (native crawl + built-in checks)";;
    c2) :;                                                  local label="AI Scanner DAST (black-box)";;
    c3) [ -d "$JUICE_SRC/.git" ] || git clone -q --depth 1 https://github.com/juice-shop/juice-shop "$JUICE_SRC" 2>/dev/null
        export AISCANNER_SOURCE_REPO="$JUICE_SRC";          local label="AI Scanner DAST + SAST (source: $JUICE_SRC)";;
    *)  say "  unknown config $cfg"; return 1;;
  esac
  say "  [$cfg] $label"

  : > "$log"
  local t0; t0=$(date +%s)
  nohup ./ai-scanner.sh "$JUICE_URL" > "$log" 2>&1 &
  say "  [$cfg] launched; waiting for SCAN COMPLETE (max ${MAX_WAIT_SEC}s)…"
  local waited=0
  while ! grep -q 'SCAN COMPLETE' "$log" 2>/dev/null; do
    sleep 10; waited=$((waited+10))
    if [ $waited -ge "$MAX_WAIT_SEC" ]; then say "  [$cfg] TIMEOUT after ${waited}s"; break; fi
    if ! pgrep -f 'burpsuite.jar' >/dev/null 2>&1; then say "  [$cfg] Burp exited (waited ${waited}s)"; break; fi
  done
  local t1; t1=$(date +%s)

  # --- measure ---
  local solved names score det nat reqs sev walltime
  solved=$(challenge_solved_count)
  names=$(challenge_solved_names); printf '%s\n' "$names" > "$RES/$cfg.challenges.txt"
  walltime="$(grep -oE 'time: [0-9]+m [0-9]+s \([0-9]+s\)' "$log" | tail -1)"
  [ -z "$walltime" ] && walltime="$((t1-t0))s (wall)"
  score="$(grep -oE 'BENCHMARK SCORE .*= [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')"
  det="$(grep -oE 'deterministic-oracle: [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')"
  nat="$(grep -oE 'native-Burp-audit: [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')"
  reqs="$(grep -oE 'audit requests: [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')"
  sev="$(grep -oE 'issues: [0-9]+.*INFO: [0-9]+' "$log" | tail -1)"

  {
    echo "config     : $cfg — $label"
    echo "scan_time  : ${walltime:-?}"
    echo "challenges : ${solved:-?} solved (server-truth /api/Challenges)"
    echo "score      : ${score:-0}  (deterministic=${det:-0} + native-Burp=${nat:-0})"
    echo "severity   : ${sev:-n/a}"
    echo "requests   : ${reqs:-?}"
    echo "--- solved challenge names ---"
    printf '%s\n' "$names"
  } | tee "$out"
  say ""
}

case "${1:-}" in
  c1|c2|c3) run_one "$1";;
  all)      run_one c1; run_one c2; run_one c3
            say "=== SUMMARY ==="; for c in c1 c2 c3; do sed -n '1,6p' "$RES/$c.result" 2>/dev/null; echo; done;;
  *) say "usage: bench/juice-casestudy.sh c1|c2|c3|all"; exit 1;;
esac
