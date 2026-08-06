#!/usr/bin/env bash
#
# AI Scanner — "Strix for Burp" launcher.
#
# Opens Burp Suite (GUI), loads the AI Scanner extension, points it at your local LLM,
# and auto-starts crawl-and-scan on a target. Burp stays fully interactive after.
#
#   ./ai-scanner.sh                         # scan http://juice.local:3000/ (default)
#   ./ai-scanner.sh http://target.tld/      # scan another target
#
# Everything is overridable via env vars (see below).
#
set -euo pipefail

# ---- parameters ----
# One or more targets are REQUIRED — as separate args, or AISCANNER_TARGET (comma/space-separated). No default.
# Multiple targets are scanned SEQUENTIALLY in one Burp session (session + findings reset between each).
# Bare hosts (no scheme) get https:// added by the extension.
if [ "$#" -gt 0 ]; then TARGET="$(IFS=,; echo "$*")"; else TARGET="${AISCANNER_TARGET:-}"; fi
if [ -z "$TARGET" ]; then
  echo "usage: ./ai-scanner.sh <target-url> [more-targets…]" >&2
  echo "   e.g. ./ai-scanner.sh http://juice.local:3000/" >&2
  echo "   e.g. ./ai-scanner.sh api.dev.example.com app.dev.example.com   # sequential batch" >&2
  exit 2
fi
# Count targets (commas + whitespace separate them) → batch mode writes one report per host into a dir.
TARGET_COUNT="$(printf '%s' "$TARGET" | tr ', \t' '\n\n\n\n' | grep -c .)"
REPORT_DIR="${AISCANNER_REPORT_DIR:-}"
BASE_URL="${AISCANNER_BASE_URL:-http://127.0.0.1:8000/v1/}"   # your OpenAI-compatible LLM endpoint
MODEL="${AISCANNER_MODEL:-}"                                  # set to the model your endpoint serves
API_KEY="${AISCANNER_API_KEY:-}"
# Optional operator-supplied login credentials — used when autonomous sign-up is blocked (prod/staging that
# rejects disposable-email registration). The scanner POSTs these to the discovered login endpoint via Burp.
LOGIN_EMAIL="${AISCANNER_LOGIN_EMAIL:-}"
LOGIN_PASS="${AISCANNER_LOGIN_PASSWORD:-}"
HEAP="${HEAP:-4g}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Batch mode (>1 target) with no explicit dir → default one report file per host under bench/results/batch.
if [ "$TARGET_COUNT" -gt 1 ] && [ -z "$REPORT_DIR" ]; then REPORT_DIR="$HERE/bench/results/batch"; fi
[ -n "$REPORT_DIR" ] && mkdir -p "$REPORT_DIR" 2>/dev/null || true
BURP_JAR="${BURP_JAR:-/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar}"
BUNDLED_JRE="/Applications/Burp Suite.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
EXT_JAR="${EXT_JAR:-$HERE/target/ai-scanner-0.1.0.jar}"

# ---- sanity checks ----
[ -f "$BURP_JAR" ] || { echo "!! Burp jar not found: $BURP_JAR  (set BURP_JAR=...)" >&2; exit 1; }

# ---- pick a Java that ACTUALLY RUNS ----
# Prefer Burp's bundled JRE (best-tested), but a Burp upgrade can leave an embedded JRE that keeps its +x bit
# yet won't execute (e.g. 2026.7.1: `java -version` → no output, exit 1). So TEST each candidate by running it,
# and fall back to a system JDK (17+). An explicit JAVA=... override is honored as-is.
java_works() { [ -n "$1" ] && "$1" -version >/dev/null 2>&1; }
if [ -n "${JAVA:-}" ]; then
  java_works "$JAVA" || echo "!! (warning) JAVA=$JAVA did not run cleanly — using it anyway" >&2
else
  JAVA=""
  for cand in "$BUNDLED_JRE" "$(command -v java 2>/dev/null)" "/usr/bin/java" ${JAVA_HOME:+"$JAVA_HOME/bin/java"}; do
    if java_works "$cand"; then JAVA="$cand"; break; fi
  done
  [ -n "$JAVA" ] || { echo "!! no working java found (tried Burp's bundled JRE, PATH java, /usr/bin/java, JAVA_HOME). Install a JDK 17+ or set JAVA=..." >&2; exit 1; }
  [ "$JAVA" = "$BUNDLED_JRE" ] || echo ".. Burp's bundled JRE unavailable/broken — using system Java: $JAVA" >&2
fi
[ -f "$EXT_JAR" ] || { echo "!! AI Scanner jar not found: $EXT_JAR  (run ./build.sh first)" >&2; exit 1; }

# ---- best-effort target prep (non-fatal) ----
host="$(printf '%s' "$TARGET" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
if [ "$host" = "juice.local" ]; then
  grep -q "juice.local" /etc/hosts 2>/dev/null || \
    echo "!! (warning) no 'juice.local' alias in /etc/hosts — run: echo '127.0.0.1 juice.local' | sudo tee -a /etc/hosts" >&2
  if command -v docker >/dev/null 2>&1 && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^juiceshop$'; then
    echo ".. starting Juice Shop container…"
    docker start juiceshop >/dev/null 2>&1 || \
      docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop >/dev/null 2>&1 || true
  fi
fi

# ---- generate a Burp user-config that loads AI Scanner ----
# Clone the user's real Burp config (preserving all their settings) and inject our extension
# under the correct path: user_options.extender.extensions. A minimal/top-level config does NOT load.
BASE_CONF=""
for c in "$HOME/.BurpSuite/UserConfigPro.json" "$HOME/.BurpSuite/UserConfig.json"; do
  [ -f "$c" ] && BASE_CONF="$c" && break
done
CONF="${TMPDIR:-/tmp}/aiscanner-burp-conf.$$.json"
CONF_PROJECT="${TMPDIR:-/tmp}/aiscanner-proj-conf.$$.json"
PROJECT="${TMPDIR:-/tmp}/aiscanner-project.$$.burp"
trap 'rm -f "$CONF" "$CONF_PROJECT"' EXIT

# Burp's default proxy listener is 127.0.0.1:8080 — which COLLIDES with any target served on host port 8080
# (e.g. a local Spring API). On the collision the extension's own HTTP (auth/probes/discovery) hits Burp's own
# proxy port and gets the "Burp Suite" welcome page instead of the app, so nothing on :8080 is actually tested.
# Move the proxy off 8080 by default (the embedded browser follows Burp's listener port automatically).
PROXY_PORT="${AISCANNER_PROXY_PORT:-8085}"
python3 - "$BASE_CONF" "$CONF" "$EXT_JAR" "$PROXY_PORT" "$CONF_PROJECT" <<'PY'
import json, sys
base, out, jar, proxy_port, projout = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
cfg = json.load(open(base)) if base else {}
uo = cfg.setdefault("user_options", {})
ext = uo.setdefault("extender", {})
ext["extensions"] = [{
    "errors": "console", "extension_file": jar, "extension_type": "java",
    "loaded": True, "name": "AI Scanner", "output": "console",
}]
ext.setdefault("settings", {})["automatically_reload_extensions_on_startup"] = True
json.dump(cfg, open(out, "w"), indent=2)
# Move Burp's proxy listener off the default 8080 so it can't collide with a target on host port 8080
# (the embedded browser auto-uses this listener; the extension's direct HTTP then reaches the real app).
# Proxy listeners are a PROJECT option → SEPARATE file loaded via --config-file (a user_options.proxy entry,
# or the same file passed to both flags, is silently ignored). Burp's --config-file expects the project_options
# content at TOP LEVEL (not wrapped), unlike --user-config-file's user_options wrapper.
listeners = [{
    "certificate_mode": "per_host", "listen_mode": "loopback_only",
    "listener_port": proxy_port, "running": True,
}]
# Hedge the exact schema Burp's --config-file expects: provide BOTH the project_options-wrapped form and the
# bare top-level form; Burp reads whichever it recognizes and ignores the other.
proj = {"proxy": {"request_listeners": listeners},
        "project_options": {"proxy": {"request_listeners": listeners}}}
json.dump(proj, open(projout, "w"), indent=2)
print("config: cloned %s + injected AI Scanner extension (proxy listener → 127.0.0.1:%d)" % (base or "(defaults)", proxy_port))
PY

# ---- preflight: when the LOCAL_LLM provider is used, the model MUST answer before we launch ----
# The entire scan degrades silently if the model is unreachable/unauthorized (endpoint discovery, signup
# verification, and signing-function location all no-op) — so fail fast HERE instead of discovering it from
# the /log tab mid-run. A real chat round-trip is used (not just /models) so a wrong/missing API key is caught
# too. Only enforced for the local-LLM provider; override with AISCANNER_SKIP_LLM_CHECK=1.
if [ "${AISCANNER_PROVIDER:-LOCAL_LLM}" = "LOCAL_LLM" ] && [ "${AISCANNER_SKIP_LLM_CHECK:-0}" != "1" ]; then
  echo "preflight: testing LLM ${BASE_URL%/}/chat/completions (model=$MODEL)…"
  PF_CODE=$(curl -s -o /tmp/aiscanner-preflight.json -w "%{http_code}" --max-time 30 \
    -X POST "${BASE_URL%/}/chat/completions" \
    -H "Content-Type: application/json" \
    -H "ngrok-skip-browser-warning: 1" \
    ${API_KEY:+-H "Authorization: Bearer ${API_KEY}"} \
    -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"reply OK\"}],\"max_tokens\":5}" || echo "000")
  if [ "$PF_CODE" != "200" ]; then
    echo "ERROR: LLM preflight FAILED — HTTP $PF_CODE from ${BASE_URL%/}/chat/completions" >&2
    echo "  body: $(head -c 200 /tmp/aiscanner-preflight.json 2>/dev/null)" >&2
    if [ "$PF_CODE" = "401" ] || [ "$PF_CODE" = "403" ]; then
      echo "  → the endpoint requires a key: set AISCANNER_API_KEY." >&2
    fi
    echo "  Refusing to launch a LOCAL_LLM scan against a non-working model." >&2
    echo "  Fix the endpoint/key, or re-run with AISCANNER_SKIP_LLM_CHECK=1 to launch anyway." >&2
    exit 1
  fi
  echo "preflight: LLM OK (HTTP 200)."
fi

cat <<EOF
AI Scanner launcher (Strix-for-Burp)
  target(s): $TARGET   ($TARGET_COUNT target(s)$([ "$TARGET_COUNT" -gt 1 ] && echo ", sequential batch"))
  reports  : $([ -n "$REPORT_DIR" ] && echo "$REPORT_DIR/<host>.report.txt" || echo "${AISCANNER_REPORT:-<none>}")
  base url : $BASE_URL
  model    : $MODEL
  api key  : $([ -n "$API_KEY" ] && echo set || echo '<none>')
  ext jar  : $EXT_JAR
  burp     : $BURP_JAR
  project  : $PROJECT
Launching Burp (GUI). It will auto-start the scan ~5s after load; the /log tab shows progress.
EOF

# ---- avoid Burp's "last session didn't close cleanly — start without extensions?" safe-mode prompt ----
# Burp writes ~/.BurpSuite/sessions/<hash>-<pid>.run on start and removes it on a CLEAN exit. A hard-killed
# Burp (SIGKILL) leaves the marker orphaned; on the next launch Burp sees it, decides the prior run crashed,
# and shows the recovery/disable-extensions dialog — which stalls our headless auto-scan and can drop us
# into extension-less safe mode (no AI Scanner). Prune ONLY orphans whose PID is dead, so a live Burp's
# marker is never touched.
SESS_DIR="$HOME/.BurpSuite/sessions"
if [ -d "$SESS_DIR" ]; then
  for f in "$SESS_DIR"/*.run; do
    [ -e "$f" ] || continue
    pid="${f##*-}"; pid="${pid%.run}"
    case "$pid" in
      (*[!0-9]*|"") : ;;                                   # not a plain PID → leave it
      (*) kill -0 "$pid" 2>/dev/null || { rm -f "$f" && echo "  pruned stale Burp session marker: $(basename "$f")"; } ;;
    esac
  done
fi

# ---- launch Burp (GUI, interactive) with AI Scanner self-configured + auto-scan ----
# Fully built-in: Burp's OWN native crawler (api.scanner().startCrawl) + pure-Java auth/discovery/probes.
# No external binaries (no Node/Playwright) — BApp-store compliant.
exec "$JAVA" \
  "-Xmx${HEAP}" \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  "-Daiscanner.provider=${AISCANNER_PROVIDER:-LOCAL_LLM}" \
  "-Daiscanner.legacyMining=${AISCANNER_LEGACY_MINING:-false}" \
  "-Daiscanner.baseUrl=${BASE_URL}" \
  "-Daiscanner.model=${MODEL}" \
  "-Daiscanner.disableThinking=${AISCANNER_DISABLE_THINKING:-true}" \
  "-Daiscanner.maxTokens=${AISCANNER_MAX_TOKENS:-2048}" \
  "-Daiscanner.synthEndpoints=${AISCANNER_SYNTH:-true}" \
  "-Daiscanner.discoveryOnly=${AISCANNER_DISCOVERY_ONLY:-false}" \
  "-Daiscanner.verbose=${AISCANNER_VERBOSE:-false}" \
  "-Daiscanner.wafEvasion=${AISCANNER_WAF_EVASION:-false}" \
  "-Daiscanner.exitOnComplete=${AISCANNER_EXIT_ON_COMPLETE:-false}" \
  ${API_KEY:+-Daiscanner.apiKey="${API_KEY}"} \
  ${LOGIN_EMAIL:+-Daiscanner.loginEmail="${LOGIN_EMAIL}"} \
  ${LOGIN_PASS:+-Daiscanner.loginPassword="${LOGIN_PASS}"} \
  ${REPORT_DIR:+-Daiscanner.reportDir="${REPORT_DIR}"} \
  "-Daiscanner.autoscan=${TARGET}" \
  -jar "$BURP_JAR" \
  --project-file="$PROJECT" \
  --config-file="$CONF_PROJECT" \
  --user-config-file="$CONF" \
  --unpause-spider-and-scanner
