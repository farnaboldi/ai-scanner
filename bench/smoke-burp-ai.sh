#!/usr/bin/env bash
#
# One-command Burp-AI smoke test.
#
# Brings up the easiest benchmark (Juice Shop — single container + a server-truth scoreboard), runs AI Scanner
# with Burp's BUILT-IN AI (api.ai(), no local LLM), waits for the scan to finish and Burp to self-exit, then
# asserts against the app's OWN scoreboard (GET /api/Challenges solved:true). Returns 0 iff >=1 new challenge
# was solved during the run — proof the full bring-up -> auth -> Burp-AI -> scan -> scoreboard loop works.
#
#   bench/smoke-burp-ai.sh            # target = juice (default)
#   bench/smoke-burp-ai.sh juice
#
# Prereqs (one-time, human): a Burp AI subscription/credits on this Burp Pro. On the very first run Burp may
# show a one-time "enable AI for this extension" consent — approve it once; subsequent runs are unattended.
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RES="$HERE/results"; mkdir -p "$RES"
COMPOSE="docker compose -f $HERE/docker-compose.yml"

TARGET_APP="${1:-juice}"
[ "$TARGET_APP" = "juice" ] || { echo "!! this smoke test only supports 'juice' (the easiest target); got '$TARGET_APP'" >&2; exit 2; }
JUICE_URL="${JUICE_URL:-http://localhost:3000}"
REPORT="$RES/juice.report.txt"
LOG="$RES/juice.smoke.log"
MAX_WAIT="${MAX_WAIT:-3000}"          # hard cap (s) so the wrapper never hangs; Burp self-exits well before this
# Burp AI needs NO resident local model, so a small heap is fine on the 4GB box (override with HEAP=...).
export HEAP="${HEAP:-2g}"

say(){ printf '%s\n' "$*"; }
solved_count(){ curl -s "$JUICE_URL/api/Challenges/" 2>/dev/null \
  | python3 -c "import sys,json;print(sum(1 for c in json.load(sys.stdin).get('data',[]) if c.get('solved')))" 2>/dev/null; }

# ---- 0. best-effort free memory: prune only DEAD orphan Burp session markers (never touch a live Burp) ----
SESS_DIR="$HOME/.BurpSuite/sessions"
if [ -d "$SESS_DIR" ]; then
  for f in "$SESS_DIR"/*.run; do
    [ -e "$f" ] || continue
    pid="${f##*-}"; pid="${pid%.run}"
    case "$pid" in (*[!0-9]*|"") : ;; (*) kill -0 "$pid" 2>/dev/null || rm -f "$f" ;; esac
  done
fi

# ---- 1. bring up Juice Shop + wait for the scoreboard oracle ----
say "== bringing up Juice Shop =="
$COMPOSE up -d juice-shop || { say "!! docker compose up failed"; exit 1; }
for i in $(seq 1 60); do
  n="$(solved_count)"; [ -n "$n" ] && { say "  scoreboard live: $n challenges already solved, $(curl -s "$JUICE_URL/api/Challenges/" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"]))' 2>/dev/null) total"; break; }
  sleep 2
done
BEFORE="$(solved_count)"; BEFORE="${BEFORE:-0}"
say "  solved BEFORE scan: $BEFORE"

# ---- 2. run AI Scanner with Burp's built-in AI, self-exiting on completion (foreground, blocking) ----
say "== launching Burp + AI Scanner (provider=BURP_AI, exitOnComplete) — a Burp window will open =="
say "   log: $LOG"
: > "$LOG"
AISCANNER_PROVIDER=BURP_AI \
AISCANNER_EXIT_ON_COMPLETE=true \
AISCANNER_REPORT="$REPORT" \
  "$ROOT/ai-scanner.sh" "$JUICE_URL/" >>"$LOG" 2>&1 &
scan_pid=$!

waited=0
while kill -0 "$scan_pid" 2>/dev/null; do
  sleep 10; waited=$((waited+10))
  if [ $((waited % 60)) -eq 0 ]; then say "  ...scanning (${waited}s elapsed)"; fi
  if [ "$waited" -ge "$MAX_WAIT" ]; then
    say "!! timeout after ${MAX_WAIT}s — killing scanner (pid $scan_pid)"
    kill "$scan_pid" 2>/dev/null; sleep 3; kill -9 "$scan_pid" 2>/dev/null; break
  fi
done
say "== Burp exited (after ${waited}s) =="

# ---- 3. preflight sanity: did Burp AI actually come up? (surfaces the one-time-consent / no-subscription case) ----
if grep -q "AI preflight .*available=false" "$LOG" 2>/dev/null; then
  say "!! WARNING: Burp AI reported NOT available during the run (see log). If this was the first run, approve"
  say "   the one-time 'enable AI for this extension' consent in Burp and re-run."
fi
grep -E "AI preflight|SCAN COMPLETE|exitOnComplete" "$LOG" 2>/dev/null | sed 's/^/  log> /' | tail -5

# ---- 4. measure against the server scoreboard + assert ----
AFTER="$(solved_count)"; AFTER="${AFTER:-0}"
say ""
say "== RESULT =="
"$HERE/run.sh" measure juice 2>/dev/null || true
NEW=$(( AFTER - BEFORE ))
say ""
say "  solved: BEFORE=$BEFORE  AFTER=$AFTER  NEW=$NEW"
if [ "$NEW" -ge 1 ]; then
  say "  PASS ✅  Burp AI end-to-end works — $NEW new challenge(s) solved this run."
  exit 0
else
  say "  FAIL ❌  no new challenges solved. Check $LOG (Burp-AI availability, auth, scan completion)."
  say "  last 20 log lines:"; tail -20 "$LOG" 2>/dev/null | sed 's/^/    /'
  exit 1
fi
