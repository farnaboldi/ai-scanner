#!/usr/bin/env bash
#
# Multi-app Burp-AI benchmark driver. Runs AI Scanner with Burp's BUILT-IN AI against one or more benchmark
# targets, ONE AT A TIME (this box can't hold several targets + Burp at once), and after each: measures
# found/expected and prints the estimated Burp AI credit burn from the scan log. Burp AI is PAID — every scan
# spends credits — so the per-scan token tally is echoed prominently.
#
#   bench/burp-ai-bench.sh juice              # one app
#   bench/burp-ai-bench.sh juice webgoat      # several, sequentially (each app stopped before the next)
#   bench/burp-ai-bench.sh all                # juice webgoat  (scoreboard apps — objective measurement)
#
# Env: MAX_WAIT (per-scan cap, s, default 3000) · HEAP (default 2g) · KEEP_UP=1 (don't stop the app after)
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RES="$HERE/results"; mkdir -p "$RES"
COMPOSE="docker compose -f $HERE/docker-compose.yml"
export HEAP="${HEAP:-2g}"
MAX_WAIT="${MAX_WAIT:-3000}"

say(){ printf '%s\n' "$*"; }
http_code(){ curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }
# REAL Burp AI credit balance — Burp caches it locally and refreshes it on sync (incl. on exit). Reading it
# before/after a scan gives the ACTUAL credits spent (vs our ~chars/4 token estimate). "?" if unavailable.
credit_balance(){ python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.BurpSuite/WorkspaceConfig.json'))).get('ai_credits',{}).get('last_known_balance','?'))" 2>/dev/null || echo "?"; }

url_for(){ case "$1" in
  juice)   echo "http://localhost:3000";;
  webgoat) echo "http://localhost:8090/WebGoat";;
  dvwa)    echo "http://localhost:4280";;
  vapi)    echo "http://localhost:9000";;
  *) echo ""; esac; }
svc_for(){ case "$1" in
  juice)   echo "juice-shop";;
  webgoat) echo "webgoat";;
  dvwa)    echo "dvwa dvwa-db";;
  vapi)    echo "vapi";;
  *) echo ""; esac; }
# readiness URL that returns non-000 when the app is serving
ready_url(){ case "$1" in
  juice)   echo "http://localhost:3000/";;
  webgoat) echo "http://localhost:8090/WebGoat/login";;
  dvwa)    echo "http://localhost:4280/login.php";;
  vapi)    echo "http://localhost:9000/";;
  *) echo ""; esac; }

APPS="${*:-juice}"; [ "$APPS" = "all" ] && APPS="juice webgoat"

overall=0
for app in $APPS; do
  url="$(url_for "$app")"; svc="$(svc_for "$app")"; rurl="$(ready_url "$app")"
  if [ -z "$url" ]; then say "!! unknown app '$app' (juice|webgoat|dvwa|vapi)"; overall=1; continue; fi
  log="$RES/$app.smoke.log"; report="$RES/$app.report.txt"; : > "$log"
  say ""; say "================ [$app] =================="

  # --- bring up ONLY this app (+ its DB); DVWA also needs a DB reset/login/security=low ---
  say "[$app] up: $svc"
  $COMPOSE up -d $svc >/dev/null 2>&1
  for i in $(seq 1 120); do c="$(http_code "$rurl")"; [ "$c" != "000" ] && { say "[$app] serving (HTTP $c)"; break; }; sleep 2; done
  # DVWA needs a one-time DB create + login + security=low. Reuse run.sh's dvwa_setup, but pass a no-op
  # subcommand ('measure __noop__') so sourcing run.sh does NOT trigger its default 'report' action.
  if [ "$app" = "dvwa" ]; then say "[$app] DVWA needs DB+login+security=low — using run.sh dvwa_setup";
    ( cd "$ROOT" && DVWA_URL="$url" bash -c 'source bench/run.sh measure __noop__ >/dev/null 2>&1; dvwa_setup' ) || say "[$app] (dvwa_setup best-effort)"; fi

  # --- scoreboard apps: snapshot solved BEFORE (juice/webgoat have server truth) ---
  before=""; case "$app" in
    juice)   before="$(curl -s "$url/api/Challenges/" 2>/dev/null | python3 -c 'import sys,json;print(sum(1 for c in json.load(sys.stdin).get("data",[]) if c.get("solved")))' 2>/dev/null)";;
  esac

  # --- scan with Burp AI, foreground/blocking (Burp self-exits via exitOnComplete) ---
  cbefore="$(credit_balance)"
  say "[$app] Burp AI credits BEFORE: $cbefore"
  say "[$app] scanning with Burp AI (a Burp window opens; credits are being spent)…"
  AISCANNER_PROVIDER=BURP_AI AISCANNER_EXIT_ON_COMPLETE=true AISCANNER_REPORT="$report" \
    "$ROOT/ai-scanner.sh" "$url/" >>"$log" 2>&1 &
  pid=$!; waited=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 10; waited=$((waited+10))
    [ $((waited % 60)) -eq 0 ] && say "[$app] …scanning (${waited}s)"
    if [ "$waited" -ge "$MAX_WAIT" ]; then say "[$app] !! timeout ${MAX_WAIT}s — killing"; kill "$pid" 2>/dev/null; sleep 3; kill -9 "$pid" 2>/dev/null; break; fi
  done
  say "[$app] scan process exited after ${waited}s"

  # --- credit visibility: REAL balance delta (from Burp's local cache) ---
  cafter="$(credit_balance)"
  say "[$app] --- Burp AI usage ---"
  calls="$(grep -c 'Burp AI \$\$' "$log" 2>/dev/null)"
  grep -E "Burp AI usage|AI preflight|Burp AI call failed|not enabled" "$log" | tail -3 | sed 's/^/    /' || say "    (no AI usage line — check $log)"
  say "    Burp AI calls this scan: ${calls:-0} (successful)"
  # Pass values as argv (NO string interpolation into python source) so decimals never break the parse.
  python3 - "$cbefore" "$cafter" "${calls:-0}" <<'PY'
import sys
b, a, c = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    bf, af = float(b), float(a); sp = bf - af; cc = max(int(c or 0), 1)
    print(f"    REAL credits: BEFORE={bf:.4f}  AFTER={af:.4f}  SPENT={sp:.4f}")
    if sp > 0:
        print(f"    => ~{sp/cc:.1f} credits/call | ~{10000/sp:.1f} scans per 10k credits | ~{af/sp:.1f} scans left in balance")
except Exception as e:
    print(f"    REAL credits: BEFORE={b}  AFTER={a}  (delta unavailable: {e})")
PY

  # --- measure found/expected ---
  say "[$app] --- measure ---"
  "$HERE/run.sh" measure "$app" 2>/dev/null || true
  case "$app" in
    juice) after="$(curl -s "$url/api/Challenges/" 2>/dev/null | python3 -c 'import sys,json;print(sum(1 for c in json.load(sys.stdin).get("data",[]) if c.get("solved")))' 2>/dev/null)"
           say "[$app] solved BEFORE=$before AFTER=$after";;
  esac

  # --- free memory for the next app unless asked to keep it up ---
  [ "${KEEP_UP:-0}" = "1" ] || { say "[$app] stopping $svc to free RAM"; $COMPOSE stop $svc >/dev/null 2>&1; }
done
say ""; say "== done. logs in $RES/<app>.smoke.log, reports in $RES/<app>.report.txt =="
exit $overall
