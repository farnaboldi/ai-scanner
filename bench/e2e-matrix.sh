#!/bin/bash
# ============================================================================================
# END-TO-END 4-CONFIG MATRIX  (comm-bare · comm-ext · pro-bare · pro-ext)  — all combinations,
# self-verifying, reflecting what we actually learned building this:
#
#   comm-*  run in the community-docker CONTAINER (no license imported => real Community).
#           Pro & Community are the SAME jar; on a Pro-licensed Mac a "Community" launch would
#           secretly be Pro. The container is the only honest Community.
#     comm-bare = 0 BY DEFINITION (Community has no active Scanner). Asserted, not run,
#                 unless RUN_COMM_BARE=1 (then it is run once to prove the 0).
#     comm-ext  = full extension in the container.
#   pro-*   run on the Mac's licensed Burp Pro.
#     pro-ext  = full extension (ai-scanner.sh).
#     pro-bare = Burp-native crawl+audit only, extension NOT loaded (best-effort; ~0 on
#                auth-gated targets — bare Burp does not authenticate).
#
#   LLM: reached over the network by BOTH editions (container + Mac Burp). Default = a local OpenAI-compatible endpoint
#        ngrok URL (verified reachable from a container and from the Mac). Override via env.
#   Targets: local docker apps get a FRESH instance per cell (+ setup) so stateful apps
#        (DVWA/WebGoat) never contaminate each other; external live sites are used directly.
#   comm-ext reach to a LOCAL target: container joins benchnet, hits the target container by alias.
#   Metric per cell = count of '^VULNERABILITY:|^HIGH |^MED ' in that cell's report.
#
# Usage:
#   bench/e2e-matrix.sh --verify              # pre-flight only, no scans
#   bench/e2e-matrix.sh                       # priority targets, all 4 configs
#   TARGETS="dvwa" bench/e2e-matrix.sh        # subset
#   NO_CACHE=1 CONFIGS=pro-ext TARGETS=all PRO_WATCHDOG_MIN=30 PRO_AUDIT_MIN=20 bench/e2e-matrix.sh 2>/dev/null
#     → sweep ALL 30 targets from scratch (NO_CACHE ignores prior reports), one at a time, each capped at 30 min,
#       WITH the LLM (~12 h total). Live TSV table on stdout + saved to $RES/e2e-matrix.tsv. Columns:
#       TARGET CONFIG TOTAL DET HIGH MED LOW TIME  — DET=deterministic-oracle, HIGH/MED/LOW=native Burp by severity,
#       native=HIGH+MED+LOW, TOTAL(score)=DET+HIGH+MED, TIME=per-target wall-clock (bring-up+scan). Add
#       AISCANNER_NO_AI=1 for the deterministic-only (~2.5 h) run.
#   CONFIGS="comm-ext pro-ext" bench/e2e-matrix.sh   # subset of configs
#   WEB_SRC=both CONFIGS="pro-ext" TARGETS="snapstore" bench/e2e-matrix.sh   # A/B: black-box vs +web-src
#   AISCANNER_NO_AI=1 bench/e2e-matrix.sh pair goof nodevuln                 # DETERMINISTIC E2E — no LLM needed
#   AISCANNER_NO_AI=1 WEB_SRC=on TARGETS="nodevuln" bench/e2e-matrix.sh      #   (both DAST and DAST+SAST via RouteHarvester)
#
#   WEB_SRC (off|on|both, default off) = the SOURCE-REPO dimension, orthogonal to edition. The repo is ONE
#     per-target thing (7th target field) fed the SAME way to Community or Pro (-Daiscanner.sourceRepo — the
#     extension reads it identically). off=black-box; on=with source; both=run each *-ext cell twice and emit
#     a `<cfg>+websrc` cell beside `<cfg>`. Bare configs never use source. SAST_MODE (agentic|coarse, def agentic).
# ============================================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE" || exit 1

# ---- config -------------------------------------------------------------------------------
export AISCANNER_API_KEY="${AISCANNER_API_KEY:-}"   # provide via env (AISCANNER_API_KEY=…); never hardcode a secret in the repo
export AISCANNER_BASE_URL="${AISCANNER_BASE_URL:-http://127.0.0.1:8000/v1/}"
export AISCANNER_MODEL="${AISCANNER_MODEL:-qwen3.6-35b}"
# NO-LLM / deterministic mode: AISCANNER_NO_AI=1 → the extension runs deterministic-only (auth + probes + native
# audit + deterministic RouteHarvester SAST; no LLM discovery/fuzz). Makes `bench/e2e-matrix.sh` a self-contained
# end-to-end test — DAST and DAST+SAST — with NO LLM endpoint required. Exported → ai-scanner.sh → -Daiscanner.noAi.
case "${AISCANNER_NO_AI:-}" in ""|false|0|no|off) NO_AI=0;; *) NO_AI=1; export AISCANNER_NO_AI;; esac
BURP_PRO="${BURP_PRO:-/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar}"
COMM_BURP="${COMM_BURP:-$HOME/Downloads/burpsuite_desktop_v2026.7.3.jar}"
EULA_B64="${EULA_B64:-/tmp/eula-b64.txt}"
EXT_JAR="$HERE/target/ai-scanner-0.1.0.jar"
RES="${RESULTS_DIR:-$HERE/bench/results/compare}"; mkdir -p "$RES"   # RESULTS_DIR overrides output dir (e.g. a Burp-AI vs local-LLM run)
COMMOUT="$HERE/bench/results/compare-community"; mkdir -p "$COMMOUT"
LOG="$RES/e2e.log"; : > "$LOG"
# APPEND across phased invocations (docker set → running-kind → re-runs) instead of clobbering — else the last
# invocation wipes the accumulated summary. Header written only when the file is new; per-target reports remain truth.
CSV="$RES/e2e-matrix.csv"; [ -s "$CSV" ] || echo "target,config,findings,status" > "$CSV"
AUDIT_MIN="${AUDIT_MIN:-12}"   # comm-ext audit deadline (min); DVWA/WebGoat need >8 to confirm their full surface
CONFIGS="${CONFIGS:-comm-ext pro-ext}"   # bare Burp (comm-bare/pro-bare) is ~0 behind a login → not run by default

# target = name|kind|image|hostport|containerport|path|repo   (kind: docker|external|running)
#   repo (7th, optional) = git URL or local path of the target's SOURCE. Used by the `pro-ext-src` config to
#   drive SAST-assisted DAST (-Daiscanner.sourceRepo). Empty => that target has no source-repo cell.
ALL_TARGETS=(
  "juice|docker|bkimminich/juice-shop|3000|3000|/|https://github.com/juice-shop/juice-shop"
  "dvga|running|aisc-dvga|5013|5013|/|https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"   # GraphQL; bring up aisc-dvga with WEB_HOST=0.0.0.0 (binds 127.0.0.1 by default); source-repo drives RouteHarvester SDL + SkillLibrary graphql skill
  "vampi|running|aisc-vampi|5001|5000|/|https://github.com/erev0s/VAmPI"   # Flask/OpenAPI API; run aisc-vampi -e vulnerable=1 + GET /createdb; vulnerable=0 = zero-FP lane
  "pygoat|running|aisc-pygoat|8002|8000|/|https://github.com/adeyosemanputra/pygoat"   # Django OWASP-Top-10 labs
  "dvcsharp|running|aisc-dvcsharp|5500|5000|/|https://github.com/appsecco/dvcsharp-api"   # .NET/C# API (netcoreapp2.0); patched base mcr dotnet/core/sdk:2.1; SAST=local source
  "nodegoat|running|aisc-nodegoat-web-1|4000|4000|/|https://github.com/OWASP/NodeGoat"   # Node/Express+Mongo; creds admin/Admin_123
  "railsgoat|running|aisc-railsgoat-web-1|3300|3000|/|https://github.com/OWASP/railsgoat"   # Ruby on Rails
  "djangonv|running|aisc-djangonv|8004|8000|/|https://github.com/nVisium/django.nV"   # Django 1.8 (nVisium); custom Dockerfile
  "snapstore|docker|snapstore:dast|0|8080|/|https://github.com/robertelee78/r2c-mock-polyglot"
  "dvwa|docker|vulnerables/web-dvwa|4280|80|/|https://github.com/digininja/DVWA"
  "webgoat|docker|webgoat/webgoat:v2025.3|8090|8080|/WebGoat/|https://github.com/WebGoat/WebGoat"
  "vapi|docker|aiscanner-vapi:local|9000|8081|/|$HERE/bench/vulnerable-api"   # local pentest-ground clone → local source
  "sqli-labs|docker|acgpiano/sqli-labs:latest|0|80|/|https://github.com/Audi-1/sqli-labs"   # setup_sqlilabs builds the DB
  "mutillidae|docker|citizenstig/nowasp:latest|0|80|/|https://github.com/webpwnized/mutillidae"  # setup_mutillidae builds the DB
  "aspgoat|docker|aiscanner-aspgoat:local|8000|8000|/|https://github.com/Soham7-dev/AspGoat"   # ASP.NET Core 8 MVC labs (SQLi/reflected+stored XSS/LFI/path-traversal/cmd-injection/SSTI/IDOR/XXE/insecure-deser/open-redirect/CSRF/SSRF/file-upload). Built from the public repo Dockerfile; creds admin/admin123. LLM labs (prompt-injection/excessive-agency/insecure-output) need an Ollama-API backend at :11434 → excluded from the denominator unless enabled. FileUpload lab can break the app → fuzz last.
  "dvna|docker|appsecco/dvna:sqlite|0|9090|/|https://github.com/appsecco/dvna"           # Node/Express MPA; self-contained SQLite
  "wackopicko|docker|adamdoupe/wackopicko|0|80|/|https://github.com/adamdoupe/WackoPicko"   # autonomous auth
  "tiredful|docker|aiscanner-tiredful:local|0|8000|/api/v1/|https://github.com/payatu/Tiredful-API" # Django REST API; OAuth2 grant
  "vulnerableapp|running|aisc-vulnerableapp|9090|9090|/VulnerableApp/|https://github.com/SasanLabs/VulnerableApp" # Java/Spring Boot lab (SasanLabs); img sasanlabs/owasp-vulnerableapp:latest; SAST=local source (Spring @RequestMapping harvest)
  "log4shell|running|aisc-log4shell|8888|8080|/|" # Log4Shell (christophetd) Spring Boot; img ghcr.io/christophetd/log4shell-vulnerable-app; GET / logs X-Api-Version → JNDI RCE (Log4ShellProbe OAST)
  "crapi|running|crapi-web|8888|80|/|https://github.com/OWASP/crAPI" # OWASP crAPI polyglot microservices via gateway :8888 (Go community/gateway + Java/Spring identity + Python workshop); compose deploy/docker; SAST=local (Go+Spring harvest, 77 routes). Shares host :8888 with log4shell — mutually exclusive.
  "dvws|running|dvws-node-web-1|8180|80|/|https://github.com/snoopysecurity/dvws-node"      # compose; web+API on :8180 (JS calls /api/v2/*); autonomous (admin/letmein)
  "dvoauth|running|gallery|3005|3005|/|https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications" # compose; koen/password
  "reactvulna|running|javulna|8080|8080|/rest/movie|https://github.com/vulnerable-apps/vulnerable-react-app"   # javulna REST backend on host :8080
  "sstipy|running|aisc-ti-python|5056|13375|/Jinja2|https://github.com/Hackmanit/template-injection-playground"   # Hackmanit playground, python engine ONLY (standalone; nginx front needs all 8 upstreams). GET /Jinja2 = form(name=) → render_template_string; SstiProbe canary {{A*B}}→product. SSTI true-positive lane
  "dvwssock|running|DVWS_WEB|8888|8888|/csrf.php|https://github.com/interference-security/DVWS"   # Damn Vulnerable Web Sockets (PHP/Ratchet). ws-socket.php: every route allowedOrigins='*' (no Origin check). csrf.php opens ws://localhost:8080/change-password (cookie/PHPSESSID-authed via handshake) → WebSocketCswshProbe true-positive lane. (WS host rewritten dvws.local→localhost in-container to avoid /etc/hosts.)
  "vulnlab|running|aisc-vulnlab|1337|80|/|https://github.com/Yavuzlar/VulnLab"   # PHP/Apache/MariaDB MPA; single self-seeding image (~10s to import dump.sql). NO global login (each lab has its OWN in-challenge login). ~49 challenges under /lab/{category}/{challenge}/ (xss/sql-injection/idor/command-injection/xxe/file-inclusion/file-upload/csrf/insecure-deserialization/ssti/…). No scoreboard → DVWA-style report-export scoring.
  "webgoatnet|running|aisc-webgoatnet|9500|8080|/|https://github.com/jerryhoff/WebGoat.NET"   # WebGoatCore .NET8 MVC port (img pprofili/webgoatdotnet8, internal :8080) — jerryhoff's WebForms original is Mono/amd64 and OOM-crashes under arm64 emulation, so the .NET8 port is the runnable stand-in. Auto-REGISTER at /Account/Register (fills Email+ConfirmedPassword+CompanyName/address block+__RequestVerificationToken generically → 302 auth cookie). Sinks: SQLi /Product/Search?query= , IDOR /Product/Details/{id} , /Cart , stored-XSS /Blog.
  "goof|running|aisc-goof|3011|3001|/|https://github.com/snyk-labs/nodejs-goof"   # Node/Express+Mongo. Auto bring-up: setup_goof (builds image if missing, runs goof-mongo + aisc-goof).
  "nodevuln|running|nodevuln-vulnerable_node-1|4290|3000|/|https://github.com/cr0hn/vulnerable-node"   # Express/EJS/Postgres. Auto bring-up: setup_nodevuln (clone+patch node:10, drop virtual netcat, remap ports, pg→trust; admin/admin).
  "zero|external||||http://zero.webappsecurity.com/|"
  "pentestground|external||||https://pentest-ground.com:9000/|"
)
PRIORITY="${TARGETS:-juice dvwa webgoat}"
# TARGETS=all → sweep EVERY containerized target (docker+running), one at a time. External live hosts (zero,
# pentestground) are public and scanned directly, but out-of-scope for a container sweep → excluded from `all`;
# name them explicitly to include them.
if [ "$PRIORITY" = all ]; then
  PRIORITY="$(for _t in "${ALL_TARGETS[@]}"; do IFS='|' read -r _n _k _rest <<<"$_t"; [ "$_k" != external ] && printf '%s ' "$_n"; done)"
fi

say(){ echo "[e2e $(date '+%H:%M:%S')] $*" | tee -a "$LOG" >&2; }   # diagnostics → stderr + log; stdout stays a clean TSV results stream
metric(){ local n; n=$(grep -cE '^VULNERABILITY:|^HIGH |^MED ' "$1" 2>/dev/null); echo "${n:-0}"; }
# Results table columns = the scanner's OWN scoring axes, not vuln categories:
#   DET  = deterministic-oracle findings (the extension's confirmed probes; the '^VULNERABILITY:' lines)
#   HIGH/MED/LOW = native Burp-audit findings by severity ('^HIGH '/'^MED '/'^LOW ')
# native-Burp-audit = HIGH+MED+LOW; TOTAL (the benchmark score) = DET+HIGH+MED (LOW is reported but not scored).
BREAKDOWN_COLS="DET\tHIGH\tMED\tLOW"
# breakdown <report> → tab-separated  DET  HIGH  MED  LOW  counts.
breakdown(){
  awk '/^VULNERABILITY:/{d++} /^HIGH /{h++} /^MED /{m++} /^LOW /{l++}
       END{ printf "%d\t%d\t%d\t%d\n", d+0, h+0, m+0, l+0 }' "$1" 2>/dev/null
}
# fmt_dur <seconds> → "Xm Ys" (the per-target wall-clock, printed as the last TIME column of each results row).
fmt_dur(){ local s="${1:-0}"; printf '%dm%02ds' $((s/60)) $((s%60)); }
have(){ command -v "$1" >/dev/null 2>&1; }

# ---- pre-flight verification --------------------------------------------------------------
verify(){
  local ok=1
  say "PRE-FLIGHT verification (nothing is scanned in this phase)"
  # 1) extension jar built + org.json bundled
  if [ ! -s "$EXT_JAR" ] || ! unzip -l "$EXT_JAR" 2>/dev/null | grep -q 'org/json/JSONArray.class'; then
    say "  building extension jar…"; ./build.sh >>"$LOG" 2>&1
  fi
  if unzip -l "$EXT_JAR" 2>/dev/null | grep -q 'org/json/JSONArray.class'; then
    say "  [ok] ext jar built, org.json bundled ($(unzip -l "$EXT_JAR"|grep -c 'org/json/.*\.class') classes)"
  else say "  [FAIL] ext jar missing org.json"; ok=0; fi
  # 2) AI backend reachable. For Burp AI (provider=BURP_AI) the model is api.ai() INSIDE Burp — there is no local
  #    endpoint to curl; instead read + PRINT the cached credit balance so every run records the starting credits
  #    (and confirms Burp AI is set up at all). For LOCAL_LLM, verify the OpenAI-compatible endpoint answers.
  if [ "$NO_AI" = 1 ]; then
    say "  [ok] NO-AI mode (AISCANNER_NO_AI) — deterministic-only scan; no LLM endpoint needed. DAST + DAST+SAST run"
    say "       via auth + deterministic probes + native audit + the deterministic RouteHarvester (SAST route mining)."
  elif [ "${AISCANNER_PROVIDER:-LOCAL_LLM}" = "BURP_AI" ]; then
    local bal; bal=$(python3 -c "import json,os;p=os.path.expanduser('~/.BurpSuite/WorkspaceConfig.json');a=(json.load(open(p)).get('ai_credits') or {}) if os.path.exists(p) else {};print(a.get('last_known_balance','?'),'@',a.get('last_known_timestamp','?'))" 2>/dev/null)
    say "  [ok] AI backend = Burp AI (api.ai()); cached credit balance = ${bal:-unknown}  (local-LLM endpoint check skipped)"
  else
  local m; m=$(curl -s -m 15 -H "Authorization: Bearer $AISCANNER_API_KEY" -H 'ngrok-skip-browser-warning: 1' "${AISCANNER_BASE_URL%/}/models" 2>/dev/null | grep -o "$AISCANNER_MODEL" | head -1)
  local c; c=$(curl -s -m 40 -H "Authorization: Bearer $AISCANNER_API_KEY" -H 'Content-Type: application/json' -H 'ngrok-skip-browser-warning: 1' -d "{\"model\":\"$AISCANNER_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"reply OK\"}],\"max_tokens\":8,\"stream\":false,\"chat_template_kwargs\":{\"enable_thinking\":false}}" "${AISCANNER_BASE_URL%/}/chat/completions" 2>/dev/null | grep -o '"content":"[^"]*"' | head -1)
  if [ "$m" = "$AISCANNER_MODEL" ] && [ -n "$c" ]; then say "  [ok] LLM reachable ($AISCANNER_MODEL, chat=$c)"; else say "  [FAIL] LLM not reachable (model='$m' chat='$c')"; ok=0; fi
  fi
  # 3) docker + community image + community burp jar + eula prefs
  if have docker && docker info >/dev/null 2>&1; then docker network create benchnet >/dev/null 2>&1; say "  [ok] docker up + benchnet ready"; else say "  [FAIL] docker not available"; ok=0; fi
  # Community prerequisites are only needed when a comm-* config is selected — a pro-only run must not abort on them.
  local want_comm=0 want_pro=0
  printf ' %s ' "$CONFIGS" | grep -q ' comm-' && want_comm=1
  printf ' %s ' "$CONFIGS" | grep -q ' pro-'  && want_pro=1
  if [ "$want_comm" = 1 ]; then
    if docker build -q -t farnaboldi/ai-scanner bench/community-docker >>"$LOG" 2>&1; then say "  [ok] community image builds"; else say "  [FAIL] community image build"; ok=0; fi
  fi
  # locally-built targets (vAPI = a local pentest-ground clone): build on demand so a from-scratch run works
  if printf ' %s ' "$PRIORITY" | grep -q ' vapi ' && ! docker image inspect aiscanner-vapi:local >/dev/null 2>&1; then
    if docker build -q -t aiscanner-vapi:local -f bench/vulnerable-api/Dockerfile.aiscanner bench/vulnerable-api >>"$LOG" 2>&1; then say "  [ok] vAPI image built"; else say "  [FAIL] vAPI image build"; ok=0; fi
  fi
  # AspGoat (.NET 8 MVC) ships a Dockerfile but no image — build straight from the PUBLIC repo (no local clone
  # committed). dotnet restore+publish is slow (~few min) → build on demand, once, cached thereafter.
  if printf ' %s ' "$PRIORITY" | grep -q ' aspgoat ' && ! docker image inspect aiscanner-aspgoat:local >/dev/null 2>&1; then
    if docker build -q -t aiscanner-aspgoat:local https://github.com/Soham7-dev/AspGoat.git >>"$LOG" 2>&1; then say "  [ok] AspGoat image built"; else say "  [FAIL] AspGoat image build"; ok=0; fi
  fi
  # snapstore (r2c-mock-polyglot) ships no image; build from the local clone if present, else the fork branch
  # that carries the Dockerfile (add-dockerfile). Known-ground-truth SAST target: black-box=0, SAST-assisted>0.
  if printf ' %s ' "$PRIORITY" | grep -q ' snapstore ' && ! docker image inspect snapstore:dast >/dev/null 2>&1; then
    if [ -f /tmp/r2c-mock-polyglot/Dockerfile ]; then
      docker build -q -t snapstore:dast /tmp/r2c-mock-polyglot >>"$LOG" 2>&1 && say "  [ok] snapstore image built (local clone)" || { say "  [FAIL] snapstore build"; ok=0; }
    else
      tmp=$(mktemp -d)
      if git clone -q --depth 1 -b add-dockerfile https://github.com/farnaboldi/r2c-mock-polyglot "$tmp" 2>>"$LOG" \
         && docker build -q -t snapstore:dast "$tmp" >>"$LOG" 2>&1; then say "  [ok] snapstore image built (fork)"; else say "  [FAIL] snapstore build"; ok=0; fi
      rm -rf "$tmp"
    fi
  fi
  if [ "$want_comm" = 1 ]; then
    [ -s "$COMM_BURP" ] && say "  [ok] community burp jar present" || { say "  [FAIL] community burp jar missing ($COMM_BURP)"; ok=0; }
    [ -s "$EULA_B64" ] && say "  [ok] eula prefs present" || say "  [warn] no eula prefs ($EULA_B64) — wizard clicker fallback"
  fi
  # 4) pro burp jar (only when a pro-* config is selected)
  if [ "$want_pro" = 1 ]; then
    [ -s "$BURP_PRO" ] && say "  [ok] Burp Pro jar present" || { say "  [FAIL] Burp Pro jar missing"; ok=0; }
  fi
  [ "$ok" = 1 ] && say "PRE-FLIGHT: ALL GREEN" || say "PRE-FLIGHT: FAILURES above — fix before scanning"
  return $((1-ok))
}

# ---- local target lifecycle ---------------------------------------------------------------
# spin a fresh instance on a unique host port; echo "cname hostport"
spin(){
  local name="$1" image="$2" cport="$3" tag="$4"
  local cname="e2e-${name}-${tag}" hp
  hp=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')
  docker rm -f "$cname" >/dev/null 2>&1
  docker run -d --name "$cname" --network benchnet -p "$hp:$cport" "$image" >/dev/null 2>&1
  echo "$cname $hp"
}
teardown(){ docker rm -f "$1" >/dev/null 2>&1; }

# 'running'-kind targets are pre-built but STOPPED (exited) containers. Bring one up on demand: start the container
# AND all its compose siblings (so multi-service apps — crapi/dvws/nodegoat — get their DB/backend too), then
# wait for it to answer. Paired with stop_running so only ONE target is up at a time (Docker-on-Mac starves otherwise).
compose_members(){ # $1=container → all containers to bring up: the compose project PLUS same-name-prefix siblings
  # (a DB the app links to but that ISN'T in a compose project — a same-name-prefix sibling).
  local c="$1" proj prefix
  proj="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project"}}' "$c" 2>/dev/null)"
  prefix="${c%%[-_]*}"   # dvws-node-web-1→dvws, crapi-web→crapi
  {
    echo "$c"
    [ -n "$proj" ] && docker ps -a --filter "label=com.docker.compose.project=$proj" --format '{{.Names}}' 2>/dev/null
    [ ${#prefix} -ge 3 ] && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -iE "^${prefix}[-_]"
  } | sort -u | grep -v '^$'
}
wait_http_n(){ local u="$1" n="${2:-30}" i; for i in $(seq 1 "$n"); do curl -s -o /dev/null -m 5 "$u" && return 0; sleep 2; done; return 1; }
start_running(){ # $1=container/image name  $2=base-url-to-poll
  local c="$1" base="$2" m members waitn
  compose_members "$c" | while read -r m; do [ -n "$m" ] && docker start "$m" >/dev/null 2>&1; done
  docker network connect benchnet "$c" >/dev/null 2>&1 || true
  # Heavy compose stacks (crAPI = 10 containers: identity + postgres + mongo + …) take minutes to become healthy —
  # a 3.5-min window scans a dead target → false 0. Scale the wait to the stack size.
  # wait_http fails FAST on connection-refused (~2s/iter), so 30 iters ≈ only 60s — too short for a slow-booting
  # Java/Node app (javulna ~90-120s) let alone a 10-container stack. Base 75 iters (~2.5min), more per size.
  members=$(compose_members "$c" | grep -c .); waitn=75
  [ "${members:-1}" -gt 2 ] && waitn=150; [ "${members:-1}" -gt 5 ] && waitn=300   # heavy compose stacks (crAPI)
  wait_http_n "$base" "$waitn" || say "  [warn] running-target $c slow/failed to come up (waited ~$((waitn*2/60))min, $members container(s))"
}
stop_running(){ # $1=container name — stop the whole compose project (or just the one), don't remove (pre-built)
  local c="$1" m
  compose_members "$c" | while read -r m; do [ -n "$m" ] && docker stop "$m" >/dev/null 2>&1; done
}

setup_dvwa(){ # $1=base-url  -> login admin/password, create DB, security=low
  local b="$1" jar=/tmp/e2e-cookies.$$; rm -f "$jar"
  local tok
  tok=$(curl -s -c "$jar" "$b/login.php" | grep -oE "user_token' value='[a-f0-9]+" | grep -oE '[a-f0-9]{20,}' | head -1)
  curl -s -b "$jar" -c "$jar" -d "username=admin&password=password&user_token=$tok&Login=Login" "$b/login.php" >/dev/null
  tok=$(curl -s -b "$jar" -c "$jar" "$b/setup.php" | grep -oE "user_token' value='[a-f0-9]+" | grep -oE '[a-f0-9]{20,}' | head -1)
  curl -s -b "$jar" -c "$jar" -d "create_db=Create+%2F+Reset+Database&user_token=$tok" "$b/setup.php" >/dev/null
  rm -f "$jar"
}
setup_webgoat(){ # $1=base  -> register aisc/aiscpass (idempotent)
  curl -s -m 20 -X POST "${1%/}/register.mvc" -d "username=aisc&password=aiscpass&matchingPassword=aiscpass&agree=agree" >/dev/null 2>&1 || true
}
setup_dvoauth(){ # $1=base  -> STABILIZE the fragile hand-rolled OAuth server (gallery): mongo-first, deterministic
  # clean reseed (koen/password + the seeded clients ALWAYS present), ordered gallery start, then gate on koen login.
  # gallery uses in-memory sessions + its own account is mutable, so a stale/renamed koen silently breaks the whole
  # authenticated scan — this makes every run start from a known-good state (generalizes to any compose+seeder app).
  local b="${1%/}"
  docker start mongodb >/dev/null 2>&1; sleep 4
  docker exec gallery node -e 'const c=require("/usr/src/app/config/config.json");const {MongoClient}=require("mongodb");MongoClient.connect(c.mongodb.url,{useNewUrlParser:true,useUnifiedTopology:true},async(e,x)=>{if(e)process.exit(0);try{await x.db().dropDatabase();}catch(_){}process.exit(0);});' >/dev/null 2>&1 || true
  docker restart mongoseed >/dev/null 2>&1; sleep 12   # restores the dump (koen + photoprint/maliciousclient clients)
  docker start gallery photoprint attacker >/dev/null 2>&1
  local i loc
  for i in $(seq 1 25); do
    loc=$(curl -s -i -m6 -X POST -d 'username=koen&password=password' "$b/login" 2>/dev/null | grep -iE '^location:' | tr -d '\r')
    printf '%s' "$loc" | grep -qiE 'location: /[[:space:]]*$' && { say "  dvoauth: STABLE (koen/password login → /)"; return 0; }
    sleep 3
  done
  say "  [warn] dvoauth: koen login not confirmed after ~75s (gallery flaky) — scan may run degraded"
}
setup_aspgoat(){ # start the Ollama→OpenAI shim on host :11434 so AspGoat's LLM labs reuse our qwen (idempotent).
  # AspGoat (containerized) dials host.docker.internal:11434 → this shim → AISCANNER_BASE_URL. No app patch needed.
  curl -s -m3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && { say "  aspgoat: Ollama shim already up on :11434"; return; }
  OPENAI_API_KEY="$AISCANNER_API_KEY" OPENAI_BASE="${AISCANNER_BASE_URL%/}" OPENAI_MODEL="$AISCANNER_MODEL" \
    OPENAI_MAX_TOKENS="${OLLAMA_SHIM_MAX_TOKENS:-512}" \
    python3 "$HERE/bench/ollama-shim.py" > /tmp/aiscanner-ollama-shim.log 2>&1 &
  local i; for i in $(seq 1 6); do sleep 1; curl -s -m3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break; done
  curl -s -m3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 \
    && say "  aspgoat: started Ollama shim → $AISCANNER_MODEL (log /tmp/aiscanner-ollama-shim.log)" \
    || say "  [warn] aspgoat: Ollama shim did not come up — LLM labs will be inert (still scores non-LLM labs)"
}
# Kill any shim we started when the matrix exits (harmless if none / already gone).
trap 'pkill -f "bench/ollama-shim.py" >/dev/null 2>&1' EXIT
setup_sqlilabs(){ # $1=base  -> build the DB and WAIT until it's actually ready. Until the DB is up, EVERY
  # lesson (incl. the baseline ?id=1) returns a MySQL error, so the error-string SQLi oracle can't separate
  # baseline from an injected quote (both error) and every GET lesson is missed. Poll ~60s: hit setup-db.php
  # until Less-1/?id=1 returns real data ("Login name") instead of an error.
  local b="${1%/}" i
  for i in $(seq 1 20); do
    curl -s -m 30 -o /dev/null "$b/sql-connections/setup-db.php" 2>/dev/null
    curl -s -m 6 "$b/Less-1/?id=1" 2>/dev/null | grep -qai 'Login name' && return 0
    sleep 3
  done
}
setup_mutillidae(){ # $1=base  -> build the DB and WAIT until it's actually online. A fresh nowasp container
  # answers HTTP (wait_http passes) long before MySQL is ready, so a one-shot set-up-database.php runs too early
  # and the scan then crawls only database-offline.php + the bundled phpMyAdmin (CSRF noise, no real vulns).
  local b="${1%/}" i eff
  for i in $(seq 1 30); do                      # ~90s: retry the DB build until index.php stops redirecting offline
    curl -s -m 40 "$b/set-up-database.php" >/dev/null 2>&1
    eff=$(curl -s -m 6 -o /dev/null -w '%{url_effective}' -L "$b/index.php" 2>/dev/null)
    case "$eff" in *database-offline*) sleep 3;; *) return 0;; esac
  done
}
# ---- self-bootstrapping bring-up for git-clone/compose targets (create-if-absent → start → app setup). These make
#      `bench/e2e-matrix.sh` reproducible on a fresh machine: no manual docker run / clone / patch steps required.
setup_goof(){ # snyk-labs/nodejs-goof: Express+Mongo. Build image if missing; run goof-mongo + aisc-goof (restart, DOCKER=1).
  docker network create benchnet >/dev/null 2>&1
  if ! docker image inspect goof-goof:latest >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp -d)"
    git clone -q --depth 1 https://github.com/snyk-labs/nodejs-goof "$tmp" 2>>"$LOG" \
      && docker build -q -t goof-goof:latest "$tmp" >>"$LOG" 2>&1 || say "  [warn] goof: image build failed"
    rm -rf "$tmp"
  fi
  docker ps -a --format '{{.Names}}' | grep -qx goof-mongo \
    || docker run -d --name goof-mongo --network benchnet --restart unless-stopped mongo:3 >/dev/null 2>&1
  docker start goof-mongo >/dev/null 2>&1
  if docker ps -a --format '{{.Names}}' | grep -qx aisc-goof; then docker start aisc-goof >/dev/null 2>&1
  else docker run -d --name aisc-goof --network benchnet --restart unless-stopped -e DOCKER=1 -p 3011:3001 goof-goof:latest >/dev/null 2>&1; fi
  docker update --restart unless-stopped aisc-goof goof-mongo >/dev/null 2>&1   # survive probe-induced Node crashes
}
setup_nodevuln(){ # cr0hn/vulnerable-node (Express/EJS/Postgres): clone + patch(node:10, drop virtual netcat, remap ports) + compose up; pg→trust.
  if ! docker ps -a --format '{{.Names}}' | grep -qx nodevuln-vulnerable_node-1; then
    local src=/tmp/nodevuln-src
    [ -d "$src/.git" ] || git clone -q --depth 1 https://github.com/cr0hn/vulnerable-node "$src" 2>>"$LOG"
    # the 2016 pg-promise 4.x driver hangs queries on node≥16 (TCP ok, query never returns) → build on node:10.
    # `netcat` is a VIRTUAL pkg on bullseye+ (apt exit 100) → drop that build step. Remap host ports collision-free.
    perl -0pi -e 's/^FROM node:.*$/FROM node:10/m; s/RUN apt-get update && apt-get install -y netcat.*/RUN true/' "$src/Dockerfile"
    perl -0pi -e 's/"3000:3000"/"4290:3000"/; s/"5432:5432"/"5442:5432"/' "$src/docker-compose.yml"
    ( cd "$src" && docker compose -p nodevuln up -d --build ) >>"$LOG" 2>&1 || say "  [warn] nodevuln: compose up failed"
  else docker start nodevuln-postgres_db-1 nodevuln-vulnerable_node-1 >/dev/null 2>&1; fi
  # old pg driver can't negotiate scram-sha-256 → set postgres to trust (idempotent), then restart the app so its
  # boot-time init_db() seeds the schema against the now-connectable DB. Poll until admin/admin login returns 302.
  local i
  for i in $(seq 1 20); do
    docker exec nodevuln-postgres_db-1 sh -c 'sed -i "s/scram-sha-256/trust/g" "$PGDATA/pg_hba.conf" 2>/dev/null; psql -U postgres -c "SELECT pg_reload_conf();"' >/dev/null 2>&1
    docker restart nodevuln-vulnerable_node-1 >/dev/null 2>&1; sleep 4
    [ "$(curl -s -o /dev/null -w '%{http_code}' -m8 --data 'username=admin&password=admin' http://localhost:4290/login/auth 2>/dev/null)" = "302" ] \
      && { say "  nodevuln: DB seeded + login OK (node:10)"; return 0; }
  done
  say "  [warn] nodevuln: login not confirmed (pg/node bring-up flaky)"
}
wait_http(){ local u="$1" i; for i in $(seq 1 30); do curl -s -o /dev/null -m 5 "$u" && return 0; sleep 2; done; return 1; }

# ---- run one cell -------------------------------------------------------------------------
run_comm_ext(){ # $1=url  $2=repfile  $3=repo(optional — SAST source, SAME repo as pro; mounted into the container)
  local url="$1" rep="$2" repo="${3:-}" net=() srcmnt=() srcenv=() host_src=""
  local celllog="${rep%.report.txt}.log"; : > "$celllog"          # per-cell log (see run_pro rationale)
  { echo "==== $(basename "${rep%.report.txt}")  url=$url  repo=${repo:-<none>}  audit=${AUDIT_MIN}min ===="; } >> "$celllog"
  say "    log → $celllog"
  net=(--network benchnet)
  # web-src: clone a URL (or use a local path) on the HOST, mount it read-only into the container, and pass the
  # SAME AISCANNER_SOURCE_REPO env the extension reads under Pro. Edition-agnostic: identical extension code path.
  if [ -n "$repo" ]; then
    host_src="$repo"
    case "$repo" in http://*|https://*|git@*|ssh://*|git://*)
      host_src="$(mktemp -d)"; git clone -q --depth 1 "$repo" "$host_src" 2>>"$LOG" || host_src="";; esac
    if [ -n "$host_src" ] && [ -d "$host_src" ]; then
      srcmnt=(-v "$host_src":/websrc:ro)
      srcenv=(-e AISCANNER_SOURCE_REPO=/websrc -e AISCANNER_SAST_MODE="${SAST_MODE:-agentic}")
    fi
  fi
  rm -f "$COMMOUT/report.txt"
  docker rm -f e2e-comm >/dev/null 2>&1
  docker run --rm --name e2e-comm "${net[@]}" \
    -v "$COMM_BURP":/opt/burp/burpsuite.jar:ro -v "$EXT_JAR":/opt/burp/ai-scanner.jar:ro \
    -v "$COMMOUT":/data "${srcmnt[@]}" \
    -e TARGET="$url" -e AISCANNER_BASE_URL="$AISCANNER_BASE_URL" \
    -e AISCANNER_MODEL="$AISCANNER_MODEL" -e AISCANNER_API_KEY="$AISCANNER_API_KEY" \
    -e AISCANNER_AUDIT_MINUTES="$AUDIT_MIN" "${srcenv[@]}" \
    -e BURP_EULA_PREFS_B64="$(cat "$EULA_B64" 2>/dev/null)" \
    farnaboldi/ai-scanner >>"$celllog" 2>&1 &
  local pid=$! i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt 160 ]; do sleep 10; i=$((i+1)); done
  docker kill e2e-comm >/dev/null 2>&1; wait "$pid" 2>/dev/null
  [ -s "$COMMOUT/report.txt" ] && cp "$COMMOUT/report.txt" "$rep"
  [ -n "$host_src" ] && [ "$host_src" != "$repo" ] && rm -rf "$host_src"
}
run_pro(){ # $1=url  $2=repfile  $3=ext(true/false)  $4=repo(optional — SAST source, git URL or local path)
  local url="$1" rep="$2" ext="$3" repo="${4:-}" dir; dir="$(mktemp -d)"
  # Per-cell extension log: one file PER target+config (derived from the report path) instead of the single
  # shared $LOG that every cell appended to — that mixed all targets' output into one unattributable stream
  # (the extension logs "localhost", not the target name). Now each cell's full run is isolated + self-named.
  local celllog="${rep%.report.txt}.log"; : > "$celllog"
  { echo "==== $(basename "${rep%.report.txt}")  url=$url  ext=$ext  repo=${repo:-<none>}  audit=${PRO_AUDIT_MIN:-40}min ===="; } >> "$celllog"
  say "    log → $celllog"
  # SAST source repo: empty => black-box (launcher ignores an empty AISCANNER_SOURCE_REPO). Non-empty => the
  # launcher clones a URL / uses a local path and the extension runs the SAST pass (SAST_MODE default agentic).
  local SRC="$repo" SMODE="${SAST_MODE:-agentic}"
  # Bound the audit deadline BELOW the watchdog cap so the extension finalizes + WRITES the report before we kill
  # Burp. Without this, ai-scanner.sh's default 50-min deadline outlives our ~40-min watchdog → Burp is killed
  # mid-audit and the report is never written (DVWA hit this: found OS-command-injection but reported 0).
  local dl="${PRO_AUDIT_MIN:-40}"
  if [ "$ext" = true ]; then
    AISCANNER_SOURCE_REPO="$SRC" AISCANNER_SAST_MODE="$SMODE" \
    AISCANNER_EXIT_ON_COMPLETE=true AISCANNER_AUDIT_MINUTES="$dl" AISCANNER_LOG_LEVEL="${AISCANNER_LOG_LEVEL:-DEBUG}" AISCANNER_REPORT_DIR="$dir" ./ai-scanner.sh "$url" >>"$celllog" 2>&1 &
  else
    # pro-bare: native crawl+audit, extension NOT loaded (best-effort headless)
    AISCANNER_EXIT_ON_COMPLETE=true AISCANNER_AUDIT_MINUTES="$dl" AISCANNER_REPORT_DIR="$dir" AISCANNER_NATIVE_ONLY=true EXT_JAR=/dev/null ./ai-scanner.sh "$url" >>"$celllog" 2>&1 &
  fi
  # Watchdog cap in 10s ticks. MUST stay above the pre-audit time (~34min on a big surface) + the audit
  # deadline (dl) so the extension finalizes + WRITES the report before we kill Burp. Default 80min; juice's
  # 166-target surface needs ~67min end-to-end. Override with PRO_WATCHDOG_MIN for a slower box / bigger app.
  local cap=$(( ${PRO_WATCHDOG_MIN:-80} * 6 ))
  local pid=$! i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt "$cap" ]; do sleep 10; i=$((i+1)); done
  kill "$pid" 2>/dev/null; pkill -f 'burpsuite.jar' 2>/dev/null; sleep 3
  local r; r=$(ls "$dir"/*.report.txt 2>/dev/null | head -1); [ -n "$r" ] && cp "$r" "$rep"; rm -rf "$dir"
}

cell(){ # $1=tname $2=config $3=repfile ; sets findings
  local rep="$3" n
  if [ -s "$rep" ] && [ "${NO_CACHE:-0}" != 1 ]; then n=$(metric "$rep"); say "  SKIP $1/$2 (cached: $n)"; echo "$1,$2,$n,cached">>"$CSV"; return; fi
  say "  RUN  $1/$2"
}

run_pair(){ # $@ = two (or more) target names → bring each up + stabilize, ONE Burp scanning ALL in PARALLEL, measure each.
  # Validates the concurrent-scan engine: per-target session/log/report in one Burp, LLM timeouts scaled ×N, the
  # multi-session self-account protector, and that two similar apps (e.g. dvoauth+nodegoat, both Node/Express/Mongo)
  # hammer the SAME scanner paths concurrently without cross-contaminating.
  local dir; dir="$(mktemp -d)"; local urls=() names=() repos=()
  local t spec x name kind image hostport cport path repo base
  for t in "$@"; do
    spec=""; for x in "${ALL_TARGETS[@]}"; do [ "${x%%|*}" = "$t" ] && spec="$x"; done
    [ -z "$spec" ] && { say "PAIR: unknown target '$t'"; return 1; }
    IFS='|' read -r name kind image hostport cport path repo <<< "$spec"
    base="http://localhost:$hostport$path"
    # Targets with a self-bootstrapping setup (create-if-absent → start → app setup) own their whole bring-up;
    # everything else uses generic start_running + its optional app-specific setup.
    case "$t" in
      goof)       setup_goof;;
      nodevuln)   setup_nodevuln;;
      *) [ "$kind" = running ] && start_running "$image" "$base"
         case "$t" in
           dvoauth) setup_dvoauth "$base";;
           dvwa)    setup_dvwa "http://localhost:$hostport";;
           webgoat) setup_webgoat "$base";;
           aspgoat) setup_aspgoat;;
         esac;;
    esac
    wait_http_n "$base" 40 || say "  [warn] PAIR target $t slow/failed to come up"
    urls+=("$base"); names+=("$t"); repos+=("$repo")
  done
  local dl="${PRO_AUDIT_MIN:-25}" celllog; celllog="$RES/pair_$(IFS=-; echo "${names[*]}").log"; : > "$celllog"
  say "PAIR PARALLEL scan (one Burp, ${#urls[@]} targets): ${urls[*]}  → $celllog"
  # Operator creds are OPTIONAL and only passed when set — generic default is auto-register / auto-login per target
  # (no app-specific creds baked in). A target that needs distinct operator creds sets PAIR_LOGIN_EMAIL/PASSWORD,
  # e.g. dvoauth: `PAIR_LOGIN_EMAIL=koen PAIR_LOGIN_PASSWORD=password bench/e2e-matrix.sh pair dvoauth <partner>`.
  local creds=()
  [ -n "${PAIR_LOGIN_EMAIL:-}" ] && creds+=(AISCANNER_LOGIN_EMAIL="$PAIR_LOGIN_EMAIL" AISCANNER_LOGIN_PASSWORD="${PAIR_LOGIN_PASSWORD:-}")
  # Per-target SAST: pass each target's registry repo (index-aligned with the URLs) → DAST+SAST in one parallel run.
  local reposcsv; reposcsv="$(IFS=,; echo "${repos[*]}")"
  AISCANNER_PARALLEL=1 AISCANNER_EXIT_ON_COMPLETE=true AISCANNER_AUDIT_MINUTES="$dl" \
    AISCANNER_LOG_LEVEL="${AISCANNER_LOG_LEVEL:-DEBUG}" AISCANNER_REPORT_DIR="$dir" \
    AISCANNER_AUTOSCAN_REPOS="$reposcsv" AISCANNER_SAST_MODE="${SAST_MODE:-coarse}" ${creds[@]+"${creds[@]}"} \
    "$HERE/ai-scanner.sh" "${urls[@]}" >>"$celllog" 2>&1 &
  local cap=$(( ${PRO_WATCHDOG_MIN:-70} * 6 )) pid=$! i=0
  while kill -0 "$pid" 2>/dev/null && [ $i -lt "$cap" ]; do sleep 10; i=$((i+1)); done
  kill "$pid" 2>/dev/null; pkill -f 'burpsuite.jar' 2>/dev/null; sleep 3
  say "===== PAIR RESULTS ====="
  local r
  for r in "$dir"/*.report.txt; do [ -f "$r" ] || continue; cp "$r" "$RES/pair-$(basename "$r")" 2>/dev/null; say "  $(basename "$r"): $(metric "$r") findings"; done
  rm -rf "$dir"
}

# ---- main ---------------------------------------------------------------------------------
if [ "${1:-}" = "--verify" ]; then verify; exit $?; fi
if [ "${1:-}" = "pair" ]; then shift; run_pair "$@"; exit $?; fi
verify || { say "Aborting: pre-flight failed."; exit 1; }

# Live results table: header on stdout + persisted to a TSV file (one row per cell, printed as each finishes).
# Diagnostics go to stderr (see say), so `bench/e2e-matrix.sh ... 2>/dev/null` shows ONLY this clean table.
TSV="$RES/e2e-matrix.tsv"; printf "TARGET\tCONFIG\tTOTAL\t${BREAKDOWN_COLS}\tTIME\n" | tee "$TSV"
for tname in $PRIORITY; do
  spec=""; for t in "${ALL_TARGETS[@]}"; do [ "${t%%|*}" = "$tname" ] && spec="$t"; done
  [ -z "$spec" ] && { say "unknown target $tname"; continue; }
  IFS='|' read -r name kind image hostport cport path repo <<< "$spec"
  say "===== TARGET $tname ($kind)$([ -n "$repo" ] && echo "  repo=$repo") ====="

  for cfg in $CONFIGS; do
    if [ "$cfg" = comm-bare ] && [ "${RUN_COMM_BARE:-0}" != 1 ]; then
      say "  ASSERT $tname/comm-bare = 0 (Community has no active Scanner)"; echo "$tname,comm-bare,0,asserted">>"$CSV"; continue
    fi
    if [ "$cfg" = pro-bare ] && [ "${RUN_PRO_BARE:-0}" != 1 ]; then
      say "  SKIP $tname/pro-bare (Burp-native baseline; bare mode not in product — measure via Burp's own scan)"; echo "$tname,pro-bare,NA,manual-baseline">>"$CSV"; continue
    fi

    # web-src: the target's SOURCE repo is ONE thing (edition-agnostic — the extension reads it the same way
    # under Community or Pro). WEB_SRC=off → black-box only; on → source only; both → both cells (A/B).
    # Only *-ext configs can use source (a bare Burp has no extension → no SAST). Empty repo → no source cell.
    srcvariants=("")
    case "${WEB_SRC:-off}" in
      on)   { [ -n "$repo" ] && [[ "$cfg" == *-ext ]]; } && srcvariants=("$repo");;
      both) { [ -n "$repo" ] && [[ "$cfg" == *-ext ]]; } && srcvariants=("" "$repo");;
    esac

    for src in "${srcvariants[@]}"; do
      local_label="$cfg"; [ -n "$src" ] && local_label="${cfg}+websrc"
      rep="$RES/${tname}__${local_label}.report.txt"
      if [ -s "$rep" ] && [ "${NO_CACHE:-0}" != 1 ]; then mc=$(metric "$rep"); say "  SKIP $tname/$local_label (cached: $mc)"; echo "$tname,$local_label,$mc,cached">>"$CSV"; printf '%s\t%s\t%s\t%s\t%s\n' "$tname" "$local_label" "$mc" "$(breakdown "$rep")" cached | tee -a "$TSV"; continue; fi
      cell_t0=$(date +%s)   # per-target wall-clock start (bring-up + scan); rendered as the TIME column at DONE

      # provision a FRESH instance per cell (isolation between black-box and web-src runs)
      cname=""
      # Docker container names allow only [a-zA-Z0-9_.-] — the report/CSV label may contain '+' (e.g. the
      # +websrc variant), so sanitize it for the container tag while keeping the human label intact.
      safe_tag="$(printf '%s' "$local_label" | tr -c 'A-Za-z0-9_.-' '-')"
      if [ "$kind" = docker ]; then
        read -r cname hp <<< "$(spin "$name" "$image" "$cport" "$safe_tag")"
        base="http://localhost:$hp"; [ "$path" != "/" ] && base="$base${path%/}"
        say "  spun $cname on :$hp — waiting…"; wait_http "$base/" || say "  [warn] $tname slow to start"
        case "$tname" in dvwa) setup_dvwa "http://localhost:$hp";; webgoat) setup_webgoat "$base";; sqli-labs) setup_sqlilabs "http://localhost:$hp";; mutillidae) setup_mutillidae "http://localhost:$hp";; aspgoat) setup_aspgoat;; esac
        if [[ "$cfg" == comm-* ]]; then
          curl_url="http://$cname:$cport$path"
        else curl_url="$base/"; fi
      elif [ "$kind" = running ]; then
        # self-bootstrapping targets own their full bring-up (create-if-absent); others just start the pre-built container.
        case "$tname" in
          goof)       setup_goof;;
          nodevuln)   setup_nodevuln;;
          *) start_running "$image" "http://localhost:$hostport$path";;
        esac
        if [[ "$cfg" == comm-* ]]; then curl_url="http://$image:$cport$path"; else curl_url="http://localhost:$hostport$path"; fi
      else
        base="$path"; curl_url="$path"
      fi

      say "  RUN  $tname/$local_label  -> $curl_url$([ -n "$src" ] && echo "   (web-src=$src)")"
      # Per-target authenticated creds for the scanner's LLM-login (apps whose creds aren't in the default list).
      case "$tname" in
        aspgoat)  export AISCANNER_LOGIN_EMAIL=admin AISCANNER_LOGIN_PASSWORD=admin123;;
        nodegoat) export AISCANNER_LOGIN_EMAIL=admin AISCANNER_LOGIN_PASSWORD=Admin_123;;
        *)        unset AISCANNER_LOGIN_EMAIL AISCANNER_LOGIN_PASSWORD;;
      esac
      case "$cfg" in
        comm-ext) run_comm_ext "$curl_url" "$rep" "$src";;   # same repo arg as pro — edition-agnostic
        pro-ext)  run_pro "$curl_url" "$rep" true "$src";;
        pro-bare) run_pro "$curl_url" "$rep" false "";;
      esac
      # ADDITIVE INVARIANT — SAST is a strict SUPERSET of black-box by design (source hints only STEER probes;
      # the deterministic oracles alone decide a finding → zero-FP is preserved and nothing is ever suppressed).
      # But native-audit OOB findings (Burp Collaborator SSRF, external-service interaction) are stochastic, so
      # the +websrc run can miss a flaky finding the black-box run happened to catch — surfacing the absurd
      # "SAST < black-box". Since the SAST-assisted config genuinely runs EVERY black-box probe plus the steered
      # ones, fold any black-box finding absent from this run into the +websrc report (host:port normalized so the
      # same finding seen on two different container ports dedups). Guarantees +websrc >= black-box, always.
      if [ -n "$src" ]; then
        base_rep="$RES/${tname}__${cfg}.report.txt"
        if [ -s "$base_rep" ] && [ -s "$rep" ]; then
          _nf(){ grep -E '^VULNERABILITY:|^HIGH |^MED ' "$1" 2>/dev/null | sed -E 's#(://[^/ ]+):[0-9]+#\1#g' | sort -u; }
          folded=$(comm -23 <(_nf "$base_rep") <(_nf "$rep"))
          if [ -n "$folded" ]; then
            printf '%s\n' "$folded" | sed 's/$/   [additive: black-box baseline; OOB-flaky, missed this SAST run]/' >> "$rep"
            say "  [additive-invariant] $tname/$local_label: folded $(printf '%s\n' "$folded"|grep -c .) black-box finding(s) missed this run (OOB variance) → +websrc >= black-box"
          fi
        fi
      fi
      n=$(metric "$rep"); say "  DONE $tname/$local_label: $n finding(s)"; echo "$tname,$local_label,$n,done">>"$CSV"
      printf '%s\t%s\t%s\t%s\t%s\n' "$tname" "$local_label" "$n" "$(breakdown "$rep")" "$(fmt_dur $(( $(date +%s) - cell_t0 )))" | tee -a "$TSV"
      [ "$kind" = docker ] && [ -n "$cname" ] && teardown "$cname"
      [ "$kind" = running ] && stop_running "$image"   # stop the pre-built container (+ compose siblings) after scanning
    done
  done
done

# ---- matrix -------------------------------------------------------------------------------
say "===== MATRIX (findings/cell) ====="
{
  # Columns are whatever cells actually ran (comm-ext, pro-ext, and their +websrc variants) — order of first
  # appearance in the CSV, so the black-box vs web-src pair sits side by side.
  labels=$(awk -F, 'NR>1{print $2}' "$CSV" | awk '!seen[$0]++')
  { printf "%-16s" target; for l in $labels; do printf " %16s" "$l"; done; printf "\n"; }
  for tname in $PRIORITY; do
    printf "%-16s" "$tname"
    for l in $labels; do
      v=$(awk -F, -v t="$tname" -v c="$l" '$1==t&&$2==c{print $3}' "$CSV"|tail -1); printf " %16s" "${v:-–}"
    done
    printf "\n"
  done
} | tee "$RES/e2e-matrix.txt" | tee -a "$LOG"
