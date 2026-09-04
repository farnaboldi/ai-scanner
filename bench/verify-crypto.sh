#!/bin/bash
# verify-crypto.sh: post-scan log analysis for crypto.com. Checks key improvements hold.
# Usage: bench/verify-crypto.sh [/tmp/aiscanner.log]
LOG="${1:-/tmp/aiscanner.log}"
[ -f "$LOG" ] || { echo "ERROR: log not found: $LOG"; exit 1; }

LAST_START=$(grep -n '=== run start' "$LOG" | tail -1 | cut -d: -f1)
LAST_END=$(grep -n 'Idle.*scan complete' "$LOG" | tail -1 | cut -d: -f1)
[ -z "$LAST_START" ] && { echo "ERROR: no completed run in log"; exit 1; }
echo "=== verify-crypto: run lines $LAST_START to ${LAST_END:-END} of $LOG ==="

pass=0; fail=0

# Extract lines from last run into a temp file for repeated grepping
TMP=$(mktemp /tmp/vcrun.XXXXXX)
TOTAL=$(wc -l < "$LOG")
AFTER_START=$((TOTAL - LAST_START + 1))
RANGE=$((${LAST_END:-$TOTAL} - LAST_START + 1))
tail -n "$AFTER_START" "$LOG" | head -n "$RANGE" > "$TMP"
trap 'rm -f "$TMP"' EXIT

check() {
  local label="$1" val="${2:-0}"
  if [ "$val" -eq 0 ]; then echo "  PASS  $label"; pass=$((pass+1))
  else echo "  FAIL  $label (got $val)"; fail=$((fail+1)); fi
}
checkgt() {
  local label="$1" actual="${2:-0}" thresh="$3"
  if [ "$actual" -gt "$thresh" ]; then echo "  PASS  $label ($actual > $thresh)"; pass=$((pass+1))
  else echo "  FAIL  $label ($actual <= $thresh)"; fail=$((fail+1)); fi
}
cnt() { grep -c "$1" "$TMP" 2>/dev/null | tr -d '[:space:]' || echo 0; }
val() { grep -oE "$1" "$TMP" | grep -oE '[0-9]+' | tail -1; }

echo
echo "-- Cloudflare evasion --"
check "No WAF-evasion spam on challenge-platform"  "$(cnt 'WAF-evasion.*challenge-platform')"
checkgt "WAF auto-detection logged"                "$(cnt 'WAF detected:.*auto-enabled')" 0
CF_SAMP=$(grep 'WAF-blocked:' "$TMP" | grep -c 'challenge-platform' 2>/dev/null | tr -d '[:space:]' || echo 0)
check "challenge-platform excluded from WAF-blocked samples" "${CF_SAMP:-0}"

echo
echo "-- Auth discovery quality --"
JUNK=$(grep 'auth discovery:' "$TMP" | grep -c 'applewebkit\|/chrome/\|/mage/\|/embed/\|/debug/' 2>/dev/null | tr -d '[:space:]' || echo 0)
check "No UA-token junk in auth candidates" "${JUNK:-0}"
ENDPOINTS=$(val 'union now [0-9]+')
ENDPOINTS=${ENDPOINTS:-0}
checkgt "Endpoints discovered (union)" "$ENDPOINTS" 20

echo
echo "-- Audit coverage --"
AUDIT=$(grep 'submitted.*to Burp active audit' "$TMP" | grep -oE '[0-9]+ request' | grep -oE '[0-9]+' | head -1 || echo 0)
AUDIT=${AUDIT:-0}
checkgt "Audit requests submitted" "$AUDIT" 50

echo
echo "-- Debug signal/noise --"
TOTAL_WAF=$(cnt '\[WAF-evasion\]')
echo "  INFO  [WAF-evasion] debug lines: $TOTAL_WAF"
BYPASS=$(cnt 'WAF-evasion.*bypass\|ct-swap bypassed\|slipped WAF')
echo "  INFO  Evasion bypasses confirmed: $BYPASS"
SCORE=$(val 'BENCHMARK SCORE.*= [0-9]+')
SCORE=${SCORE:-0}
echo "  INFO  Benchmark score (VULN+HIGH+MED): $SCORE"
HIGH=$(cnt '>>> HIGH')
echo "  INFO  HIGH findings: $HIGH"

echo
echo "-- Result: $pass PASS  $fail FAIL --"
[ "$fail" -eq 0 ]
