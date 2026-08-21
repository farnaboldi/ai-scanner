#!/bin/bash
# End-to-end benchmark matrix: run AI Scanner against the vulnerable-target registry and score each cell.
#
# Usage:
#   bench/e2e-matrix.sh --verify                              # pre-flight only (build jar, check LLM + Burp); scans nothing
#   bench/e2e-matrix.sh                                       # priority targets (juice dvwa webgoat), config pro-ext
#   TARGETS="dvwa juice" bench/e2e-matrix.sh                  # explicit subset
#   TARGETS=all NO_CACHE=1 bench/e2e-matrix.sh 2>/dev/null    # sweep every containerized target from scratch, one at a time
#   WEB_SRC=both TARGETS="snapstore" bench/e2e-matrix.sh      # per-target A/B: black-box vs +source (DAST vs DAST+SAST)
#   bench/e2e-matrix.sh pair goof nodevuln                    # scan N targets concurrently in ONE Burp
#   AISCANNER_NO_AI=1 bench/e2e-matrix.sh pair goof nodevuln  # deterministic-only (no LLM endpoint needed)
#
# Env knobs: CONFIGS (default "pro-ext"; also "pro-bare" = Burp-native crawl+audit, no extension) · WEB_SRC (off|on|both,
#   the source-repo dimension) · SAST_MODE (agentic|coarse) · NO_CACHE=1 (ignore cached reports) · PRO_WATCHDOG_MIN /
#   PRO_AUDIT_MIN (per-cell caps) · AISCANNER_BASE_URL/MODEL/API_KEY (LLM) · AISCANNER_NO_AI=1 (deterministic-only).
#
# Results: per-cell report at bench/results/compare/<target>__<config>.report.txt; live TSV at $RES/e2e-matrix.tsv.
#   Columns TARGET CONFIG TOTAL DET HIGH MED LOW TIME — DET=deterministic-oracle findings, HIGH/MED/LOW=native Burp by
#   severity, TOTAL(score)=DET+HIGH+MED. Per-report metric = count of '^VULNERABILITY:|^HIGH |^MED ' lines.
# ============================================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE" || exit 1

# ---- config -------------------------------------------------------------------------------
export AISCANNER_API_KEY="${AISCANNER_API_KEY:-}"   # provide via env; never hardcode a secret in the repo
export AISCANNER_BASE_URL="${AISCANNER_BASE_URL:-http://127.0.0.1:8000/v1/}"
export AISCANNER_MODEL="${AISCANNER_MODEL:-qwen3.6-35b}"
# AISCANNER_NO_AI=1 → deterministic-only (auth + probes + native audit + RouteHarvester SAST; no LLM) → self-contained.
case "${AISCANNER_NO_AI:-}" in ""|false|0|no|off) NO_AI=0;; *) NO_AI=1; export AISCANNER_NO_AI;; esac
BURP_PRO="${BURP_PRO:-/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar}"
EXT_JAR="$HERE/target/ai-scanner-0.1.0.jar"
RES="${RESULTS_DIR:-$HERE/bench/results/compare}"; mkdir -p "$RES"   # RESULTS_DIR overrides the output dir
LOG="$RES/e2e.log"; : > "$LOG"
# APPEND the CSV across phased invocations (header only when new) so a later run never wipes the accumulated summary.
CSV="$RES/e2e-matrix.csv"; [ -s "$CSV" ] || echo "target,config,findings,status" > "$CSV"
CONFIGS="${CONFIGS:-pro-ext}"   # pro-bare (Burp-native, no extension) is ~0 behind a login → not run by default

# target = name|kind|image|hostport|containerport|path|repo   (kind: docker|external|running)
#   repo (7th, optional) = git URL or local path of the target's SOURCE, drives -Daiscanner.sourceRepo (SAST). Empty = none.
ALL_TARGETS=(
  "juice|docker|bkimminich/juice-shop|3000|3000|/|https://github.com/juice-shop/juice-shop"
  "dvga|running|aisc-dvga|5013|5013|/|https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"
  "vampi|running|aisc-vampi|5001|5000|/|https://github.com/erev0s/VAmPI"
  "pygoat|running|aisc-pygoat|8002|8000|/|https://github.com/adeyosemanputra/pygoat"
  "dvcsharp|running|aisc-dvcsharp|5500|5000|/|https://github.com/appsecco/dvcsharp-api"
  "nodegoat|running|aisc-nodegoat-web-1|4000|4000|/|https://github.com/OWASP/NodeGoat"
  "railsgoat|running|aisc-railsgoat-web-1|3300|3000|/|https://github.com/OWASP/railsgoat"
  "djangonv|running|aisc-djangonv|8004|8000|/|https://github.com/nVisium/django.nV"
  "snapstore|docker|snapstore:dast|0|8080|/|https://github.com/robertelee78/r2c-mock-polyglot"
  "dvwa|docker|vulnerables/web-dvwa|4280|80|/|https://github.com/digininja/DVWA"
  "webgoat|docker|webgoat/webgoat:v2025.3|8090|8080|/WebGoat/|https://github.com/WebGoat/WebGoat"
  "vapi|docker|aiscanner-vapi:local|9000|8081|/|https://github.com/jorritfolmer/vulnerable-api"
  "sqli-labs|docker|acgpiano/sqli-labs:latest|0|80|/|https://github.com/Audi-1/sqli-labs"
  "mutillidae|docker|citizenstig/nowasp:latest|0|80|/|https://github.com/webpwnized/mutillidae"
  "aspgoat|docker|aiscanner-aspgoat:local|8000|8000|/|https://github.com/Soham7-dev/AspGoat"
  "dvna|docker|appsecco/dvna:sqlite|0|9090|/|https://github.com/appsecco/dvna"
  "wackopicko|docker|adamdoupe/wackopicko|0|80|/|https://github.com/adamdoupe/WackoPicko"
  "tiredful|docker|aiscanner-tiredful:local|0|8000|/api/v1/|https://github.com/payatu/Tiredful-API"
  "vulnerableapp|running|aisc-vulnerableapp|9090|9090|/VulnerableApp/|https://github.com/SasanLabs/VulnerableApp"
  "log4shell|running|aisc-log4shell|8899|8080|/|"
  "crapi|running|crapi-web|8888|80|/|https://github.com/OWASP/crAPI"
  "dvws|running|dvws-node-web-1|8180|80|/|https://github.com/snoopysecurity/dvws-node"
  "dvoauth|running|gallery|3005|3005|/|https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications"
  "reactvulna|running|javulna|8080|8080|/rest/movie|https://github.com/vulnerable-apps/vulnerable-react-app"
  "sstipy|running|aisc-ti-python|5056|13375|/Jinja2|https://github.com/Hackmanit/template-injection-playground"
  "dvwssock|running|DVWS_WEB|8888|8888|/csrf.php|https://github.com/interference-security/DVWS"
  "vulnlab|running|aisc-vulnlab|1337|80|/|https://github.com/Yavuzlar/VulnLab"
  "webgoatnet|running|aisc-webgoatnet|9500|8080|/|https://github.com/jerryhoff/WebGoat.NET"
  "goof|running|aisc-goof|3011|3001|/|https://github.com/snyk-labs/nodejs-goof"
  "nodevuln|running|nodevuln-vulnerable_node-1|4290|3000|/|https://github.com/cr0hn/vulnerable-node"
  "zero|external||||http://zero.webappsecurity.com/|"
  "pentestground|external||||https://pentest-ground.com:9000/|"
)
PRIORITY="${TARGETS:-juice dvwa webgoat}"
# TARGETS=all → every containerized target (docker+running). External live hosts are excluded from `all`; name them explicitly.
if [ "$PRIORITY" = all ]; then
  PRIORITY="$(for _t in "${ALL_TARGETS[@]}"; do IFS='|' read -r _n _k _rest <<<"$_t"; [ "$_k" != external ] && printf '%s ' "$_n"; done)"
fi

say(){ echo "[e2e $(date '+%H:%M:%S')] $*" | tee -a "$LOG" >&2; }   # diagnostics → stderr + log; stdout stays a clean TSV
metric(){ local n; n=$(grep -cE '^VULNERABILITY:|^HIGH |^MED ' "$1" 2>/dev/null); echo "${n:-0}"; }   # <report> → benchmark score (DET+HIGH+MED)
BREAKDOWN_COLS="DET\tHIGH\tMED\tLOW"
breakdown(){   # <report> → tab-separated  DET  HIGH  MED  LOW  counts
  awk '/^VULNERABILITY:/{d++} /^HIGH /{h++} /^MED /{m++} /^LOW /{l++}
       END{ printf "%d\t%d\t%d\t%d\n", d+0, h+0, m+0, l+0 }' "$1" 2>/dev/null
}
fmt_dur(){ local s="${1:-0}"; printf '%dm%02ds' $((s/60)) $((s%60)); }   # <seconds> → "Xm Ys" (the TIME column)
have(){ command -v "$1" >/dev/null 2>&1; }

# ---- pre-flight verification --------------------------------------------------------------
verify(){   # build the ext jar, confirm the AI backend + docker + on-demand target images + the Burp Pro jar
  local ok=1
  say "PRE-FLIGHT verification (nothing is scanned in this phase)"
  # 1) extension jar built + org.json bundled
  if [ ! -s "$EXT_JAR" ] || ! unzip -l "$EXT_JAR" 2>/dev/null | grep -q 'org/json/JSONArray.class'; then
    say "  building extension jar…"; ./build.sh >>"$LOG" 2>&1
  fi
  if unzip -l "$EXT_JAR" 2>/dev/null | grep -q 'org/json/JSONArray.class'; then
    say "  [ok] ext jar built, org.json bundled ($(unzip -l "$EXT_JAR"|grep -c 'org/json/.*\.class') classes)"
  else say "  [FAIL] ext jar missing org.json"; ok=0; fi
  # 2) AI backend reachable — Burp AI prints its cached credit balance; LOCAL_LLM curls the OpenAI-compatible endpoint.
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
  # 3) docker + benchnet
  if have docker && docker info >/dev/null 2>&1; then docker network create benchnet >/dev/null 2>&1; say "  [ok] docker up + benchnet ready"; else say "  [FAIL] docker not available"; ok=0; fi
  # locally-built target images, built on demand so a from-scratch run works: vAPI, AspGoat (public repo), snapstore.
  if printf ' %s ' "$PRIORITY" | grep -q ' vapi ' && ! docker image inspect aiscanner-vapi:local >/dev/null 2>&1; then
    if docker build -q -t aiscanner-vapi:local -f bench/vapi/Dockerfile.aiscanner bench/vapi >>"$LOG" 2>&1; then say "  [ok] vAPI image built"; else say "  [FAIL] vAPI image build"; ok=0; fi
  fi
  if printf ' %s ' "$PRIORITY" | grep -q ' aspgoat ' && ! docker image inspect aiscanner-aspgoat:local >/dev/null 2>&1; then
    if docker build -q -t aiscanner-aspgoat:local https://github.com/Soham7-dev/AspGoat.git >>"$LOG" 2>&1; then say "  [ok] AspGoat image built"; else say "  [FAIL] AspGoat image build"; ok=0; fi
  fi
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
  # 4) Burp Pro jar
  [ -s "$BURP_PRO" ] && say "  [ok] Burp Pro jar present" || { say "  [FAIL] Burp Pro jar missing"; ok=0; }
  [ "$ok" = 1 ] && say "PRE-FLIGHT: ALL GREEN" || say "PRE-FLIGHT: FAILURES above — fix before scanning"
  return $((1-ok))
}

# ---- local target lifecycle ---------------------------------------------------------------
spin(){   # $1=name $2=image $3=cport $4=tag → spin a fresh instance on a unique host port; echo "cname hostport"
  local name="$1" image="$2" cport="$3" tag="$4"
  local cname="e2e-${name}-${tag}" hp
  hp=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')
  docker rm -f "$cname" >/dev/null 2>&1
  docker run -d --name "$cname" --network benchnet -p "$hp:$cport" "$image" >/dev/null 2>&1
  echo "$cname $hp"
}
teardown(){ docker rm -f "$1" >/dev/null 2>&1; }

compose_members(){   # $1=container → itself + its compose project + same-name-prefix siblings (DB/backend to bring up)
  local c="$1" proj prefix
  proj="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project"}}' "$c" 2>/dev/null)"
  # "aisc" is shared by every bench target, so use the TWO-level app prefix (aisc-nodegoat-web-1 → aisc-nodegoat) there;
  # non-namespaced compose stacks keep the first-token prefix (dvws-node-web-1 → dvws).
  case "$c" in
    aisc-*) prefix="$(printf '%s' "$c" | sed -E 's/^(aisc-[A-Za-z0-9]+).*/\1/')";;
    *)      prefix="${c%%[-_]*}";;
  esac
  {
    echo "$c"
    [ -n "$proj" ] && docker ps -a --filter "label=com.docker.compose.project=$proj" --format '{{.Names}}' 2>/dev/null
    [ ${#prefix} -ge 3 ] && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -iE "^${prefix}[-_]"
  } | sort -u | grep -v '^$'
}
wait_http_n(){ local u="$1" n="${2:-30}" i; for i in $(seq 1 "$n"); do curl -s -o /dev/null -m 5 "$u" && return 0; sleep 2; done; return 1; }
start_running(){   # $1=container $2=base-url → start it + all compose siblings, join benchnet, wait for HTTP
  local c="$1" base="$2" m members waitn
  compose_members "$c" | while read -r m; do [ -n "$m" ] && docker start "$m" >/dev/null 2>&1; done
  docker network connect benchnet "$c" >/dev/null 2>&1 || true
  # Scale the wait to the stack size: heavy compose stacks (crAPI = 10 containers) take minutes to become healthy.
  members=$(compose_members "$c" | grep -c .); waitn=75
  [ "${members:-1}" -gt 2 ] && waitn=150; [ "${members:-1}" -gt 5 ] && waitn=300
  wait_http_n "$base" "$waitn" || say "  [warn] running-target $c slow/failed to come up (waited ~$((waitn*2/60))min, $members container(s))"
}
free_hostport(){   # $1=host port → stop any leftover/restart=always container squatting it (else we scan the wrong app)
  local port="$1" c nm
  { [ -z "$port" ] || [ "$port" = 0 ]; } && return 0
  for c in $(docker ps -q --filter "publish=$port" 2>/dev/null); do
    nm="$(docker inspect -f '{{.Name}}' "$c" 2>/dev/null | sed 's#^/##')"
    docker update --restart no "$c" >/dev/null 2>&1
    docker stop -t 3 "$c" >/dev/null 2>&1
    say "  [port-clear] :$port lo ocupaba '$nm' (leftover) → detenido para liberar el puerto del target"
  done
}
stop_running(){   # $1=container → stop the whole compose project (don't remove; these are pre-built)
  local c="$1" m
  compose_members "$c" | while read -r m; do [ -n "$m" ] && docker stop "$m" >/dev/null 2>&1; done
}

setup_dvwa(){   # $1=base → login admin/password, create DB, security=low
  local b="$1" jar=/tmp/e2e-cookies.$$; rm -f "$jar"
  local tok
  tok=$(curl -s -c "$jar" "$b/login.php" | grep -oE "user_token' value='[a-f0-9]+" | grep -oE '[a-f0-9]{20,}' | head -1)
  curl -s -b "$jar" -c "$jar" -d "username=admin&password=password&user_token=$tok&Login=Login" "$b/login.php" >/dev/null
  tok=$(curl -s -b "$jar" -c "$jar" "$b/setup.php" | grep -oE "user_token' value='[a-f0-9]+" | grep -oE '[a-f0-9]{20,}' | head -1)
  curl -s -b "$jar" -c "$jar" -d "create_db=Create+%2F+Reset+Database&user_token=$tok" "$b/setup.php" >/dev/null
  rm -f "$jar"
}
setup_webgoat(){ curl -s -m 20 -X POST "${1%/}/register.mvc" -d "username=aisc&password=aiscpass&matchingPassword=aiscpass&agree=agree" >/dev/null 2>&1 || true; }   # $1=base → register aisc/aiscpass (idempotent)
setup_dvoauth(){   # $1=base → deterministically reseed the fragile hand-rolled OAuth server (mongo-first), gate on koen login
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
setup_aspgoat(){   # start the Ollama→OpenAI shim on host :11434 so AspGoat's LLM labs reuse our qwen (idempotent)
  curl -s -m3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && { say "  aspgoat: Ollama shim already up on :11434"; return; }
  OPENAI_API_KEY="$AISCANNER_API_KEY" OPENAI_BASE="${AISCANNER_BASE_URL%/}" OPENAI_MODEL="$AISCANNER_MODEL" \
    OPENAI_MAX_TOKENS="${OLLAMA_SHIM_MAX_TOKENS:-512}" \
    python3 "$HERE/bench/ollama-shim.py" > /tmp/aiscanner-ollama-shim.log 2>&1 &
  local i; for i in $(seq 1 6); do sleep 1; curl -s -m3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break; done
  curl -s -m3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 \
    && say "  aspgoat: started Ollama shim → $AISCANNER_MODEL (log /tmp/aiscanner-ollama-shim.log)" \
    || say "  [warn] aspgoat: Ollama shim did not come up — LLM labs will be inert (still scores non-LLM labs)"
}
trap 'pkill -f "bench/ollama-shim.py" >/dev/null 2>&1' EXIT   # kill any shim we started when the matrix exits
setup_sqlilabs(){   # $1=base → build the DB and WAIT until Less-1/?id=1 returns real data (else every GET lesson errors)
  local b="${1%/}" i
  for i in $(seq 1 20); do
    curl -s -m 30 -o /dev/null "$b/sql-connections/setup-db.php" 2>/dev/null
    curl -s -m 6 "$b/Less-1/?id=1" 2>/dev/null | grep -qai 'Login name' && return 0
    sleep 3
  done
}
setup_mutillidae(){   # $1=base → build the DB and WAIT until index.php stops redirecting to database-offline
  local b="${1%/}" i eff
  for i in $(seq 1 30); do
    curl -s -m 40 "$b/set-up-database.php" >/dev/null 2>&1
    eff=$(curl -s -m 6 -o /dev/null -w '%{url_effective}' -L "$b/index.php" 2>/dev/null)
    case "$eff" in *database-offline*) sleep 3;; *) return 0;; esac
  done
}
# Self-bootstrapping bring-up (create-if-absent → start → app setup) so the matrix is reproducible on a fresh machine.
setup_goof(){   # snyk-labs/nodejs-goof (Express+Mongo): build image if missing; run goof-mongo + aisc-goof
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
setup_nodevuln(){   # cr0hn/vulnerable-node (Express/EJS/Postgres): clone+patch(node:10, drop netcat, remap ports) + compose up; pg→trust
  if ! docker ps -a --format '{{.Names}}' | grep -qx nodevuln-vulnerable_node-1; then
    local src=/tmp/nodevuln-src
    [ -d "$src/.git" ] || git clone -q --depth 1 https://github.com/cr0hn/vulnerable-node "$src" 2>>"$LOG"
    # 2016 pg-promise 4.x hangs queries on node≥16 → build on node:10; netcat is a virtual pkg on bullseye+ → drop it.
    perl -0pi -e 's/^FROM node:.*$/FROM node:10/m; s/RUN apt-get update && apt-get install -y netcat.*/RUN true/' "$src/Dockerfile"
    perl -0pi -e 's/"3000:3000"/"4290:3000"/; s/"5432:5432"/"5442:5432"/' "$src/docker-compose.yml"
    ( cd "$src" && docker compose -p nodevuln up -d --build ) >>"$LOG" 2>&1 || say "  [warn] nodevuln: compose up failed"
  else docker start nodevuln-postgres_db-1 nodevuln-vulnerable_node-1 >/dev/null 2>&1; fi
  # old pg driver can't do scram-sha-256 → set postgres to trust, restart the app so init_db() seeds, poll admin/admin login.
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
run_pro(){   # $1=url $2=repfile $3=ext(true/false) $4=repo(optional SAST source) → launch Burp Pro headless, salvage the report
  local url="$1" rep="$2" ext="$3" repo="${4:-}" dir; dir="$(mktemp -d)"
  local celllog="${rep%.report.txt}.log"; : > "$celllog"   # per-cell log (the extension logs "localhost", not the target name)
  { echo "==== $(basename "${rep%.report.txt}")  url=$url  ext=$ext  repo=${repo:-<none>}  audit=${PRO_AUDIT_MIN:-40}min ===="; } >> "$celllog"
  say "    log → $celllog"
  local SRC="$repo" SMODE="${SAST_MODE:-agentic}"
  # Bound the audit deadline BELOW the watchdog cap so the extension finalizes + writes the report before we kill Burp.
  local dl="${PRO_AUDIT_MIN:-40}"
  if [ "$ext" = true ]; then
    AISCANNER_SOURCE_REPO="$SRC" AISCANNER_SAST_MODE="$SMODE" \
    AISCANNER_EXIT_ON_COMPLETE=true AISCANNER_AUDIT_MINUTES="$dl" AISCANNER_LOG_LEVEL="${AISCANNER_LOG_LEVEL:-DEBUG}" AISCANNER_REPORT_DIR="$dir" ./ai-scanner.sh "$url" >>"$celllog" 2>&1 &
  else   # pro-bare: Burp-native crawl+audit, extension NOT loaded
    AISCANNER_EXIT_ON_COMPLETE=true AISCANNER_AUDIT_MINUTES="$dl" AISCANNER_REPORT_DIR="$dir" AISCANNER_NATIVE_ONLY=true EXT_JAR=/dev/null ./ai-scanner.sh "$url" >>"$celllog" 2>&1 &
  fi
  # Watchdog cap in 10s ticks — must exceed pre-audit time (~34min on a big surface) + the audit deadline.
  local cap=$(( ${PRO_WATCHDOG_MIN:-80} * 6 ))
  local pid=$! i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt "$cap" ]; do sleep 10; i=$((i+1)); done
  kill "$pid" 2>/dev/null; pkill -f 'burpsuite.jar' 2>/dev/null; sleep 3
  local r; r=$(ls "$dir"/*.report.txt 2>/dev/null | head -1)
  if [ -n "$r" ]; then cp "$r" "$rep"
  else   # Burp killed before finalizing → salvage the '>>> VULNERABILITY:' announcements from the cell log
    grep -hoE '>>> VULNERABILITY:.*' "$celllog" 2>/dev/null | sed -E 's/^>>> //' | sort -u > "$rep"
    [ -s "$rep" ] && say "  [salvage] $(basename "${rep%.report.txt}"): Burp no escribió el report — recuperados $(grep -c . "$rep") finding(s) del log"
  fi
  rm -rf "$dir"
}

run_pair(){   # $@ = target names → bring each up + stabilize, ONE Burp scanning ALL in parallel, measure each
  local dir; dir="$(mktemp -d)"; local urls=() names=() repos=()
  local t spec x name kind image hostport cport path repo base
  for t in "$@"; do
    spec=""; for x in "${ALL_TARGETS[@]}"; do [ "${x%%|*}" = "$t" ] && spec="$x"; done
    [ -z "$spec" ] && { say "PAIR: unknown target '$t'"; return 1; }
    IFS='|' read -r name kind image hostport cport path repo <<< "$spec"
    base="http://localhost:$hostport$path"
    case "$t" in   # self-bootstrapping targets own their bring-up; everything else = generic start_running + optional setup
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
  # Operator creds are optional — default is auto-register/auto-login per target; a target needing distinct creds sets PAIR_LOGIN_*.
  local creds=()
  [ -n "${PAIR_LOGIN_EMAIL:-}" ] && creds+=(AISCANNER_LOGIN_EMAIL="$PAIR_LOGIN_EMAIL" AISCANNER_LOGIN_PASSWORD="${PAIR_LOGIN_PASSWORD:-}")
  local reposcsv; reposcsv="$(IFS=,; echo "${repos[*]}")"   # per-target SAST repos, index-aligned with the URLs
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

# Live results table: header on stdout + persisted to TSV (one row per cell). Diagnostics go to stderr (see say).
TSV="$RES/e2e-matrix.tsv"; printf "TARGET\tCONFIG\tTOTAL\t${BREAKDOWN_COLS}\tTIME\n" | tee "$TSV"
for tname in $PRIORITY; do
  spec=""; for t in "${ALL_TARGETS[@]}"; do [ "${t%%|*}" = "$tname" ] && spec="$t"; done
  [ -z "$spec" ] && { say "unknown target $tname"; continue; }
  IFS='|' read -r name kind image hostport cport path repo <<< "$spec"
  say "===== TARGET $tname ($kind)$([ -n "$repo" ] && echo "  repo=$repo") ====="
  free_hostport "$hostport"   # clear any leftover container squatting this target's port (else we scan the wrong app)
  # Snapshot running containers BEFORE bring-up → the delta after the cell is exactly what THIS target started.
  cell_pre_containers="$(docker ps -q 2>/dev/null | sort)"

  for cfg in $CONFIGS; do
    if [ "$cfg" = pro-bare ] && [ "${RUN_PRO_BARE:-0}" != 1 ]; then
      say "  SKIP $tname/pro-bare (Burp-native baseline; not run by default)"; echo "$tname,pro-bare,NA,manual-baseline">>"$CSV"; continue
    fi

    # web-src (WEB_SRC): the target's SOURCE-repo dimension. off → black-box only; on → source only; both → both cells (A/B).
    # Only *-ext configs can use source (a bare Burp has no extension). Empty repo → no source cell.
    srcvariants=("")
    case "${WEB_SRC:-off}" in
      on)   { [ -n "$repo" ] && [[ "$cfg" == *-ext ]]; } && srcvariants=("$repo");;
      both) { [ -n "$repo" ] && [[ "$cfg" == *-ext ]]; } && srcvariants=("" "$repo");;
    esac

    for src in "${srcvariants[@]}"; do
      local_label="$cfg"; [ -n "$src" ] && local_label="${cfg}+websrc"
      rep="$RES/${tname}__${local_label}.report.txt"
      if [ -s "$rep" ] && [ "${NO_CACHE:-0}" != 1 ]; then mc=$(metric "$rep"); say "  SKIP $tname/$local_label (cached: $mc)"; echo "$tname,$local_label,$mc,cached">>"$CSV"; printf '%s\t%s\t%s\t%s\t%s\n' "$tname" "$local_label" "$mc" "$(breakdown "$rep")" cached | tee -a "$TSV"; continue; fi
      cell_t0=$(date +%s)   # per-target wall-clock start (bring-up + scan)

      cname=""   # provision a FRESH instance per cell (isolation between black-box and web-src runs)
      safe_tag="$(printf '%s' "$local_label" | tr -c 'A-Za-z0-9_.-' '-')"   # docker names allow only [a-zA-Z0-9_.-]
      if [ "$kind" = docker ]; then
        read -r cname hp <<< "$(spin "$name" "$image" "$cport" "$safe_tag")"
        base="http://localhost:$hp"; [ "$path" != "/" ] && base="$base${path%/}"
        say "  spun $cname on :$hp — waiting…"; wait_http "$base/" || say "  [warn] $tname slow to start"
        case "$tname" in dvwa) setup_dvwa "http://localhost:$hp";; webgoat) setup_webgoat "$base";; sqli-labs) setup_sqlilabs "http://localhost:$hp";; mutillidae) setup_mutillidae "http://localhost:$hp";; aspgoat) setup_aspgoat;; esac
        curl_url="$base/"
      elif [ "$kind" = running ]; then
        case "$tname" in   # self-bootstrapping targets own their full bring-up; others just start the pre-built container
          goof)       setup_goof;;
          nodevuln)   setup_nodevuln;;
          *) start_running "$image" "http://localhost:$hostport$path";;
        esac
        curl_url="http://localhost:$hostport$path"
      else
        base="$path"; curl_url="$path"
      fi

      say "  RUN  $tname/$local_label  -> $curl_url$([ -n "$src" ] && echo "   (web-src=$src)")"
      case "$tname" in   # per-target creds for the scanner's LLM-login (apps whose creds aren't in the default list)
        aspgoat)  export AISCANNER_LOGIN_EMAIL=admin AISCANNER_LOGIN_PASSWORD=admin123;;
        nodegoat) export AISCANNER_LOGIN_EMAIL=admin AISCANNER_LOGIN_PASSWORD=Admin_123;;
        *)        unset AISCANNER_LOGIN_EMAIL AISCANNER_LOGIN_PASSWORD;;
      esac
      case "$cfg" in
        pro-ext)  run_pro "$curl_url" "$rep" true "$src";;
        pro-bare) run_pro "$curl_url" "$rep" false "";;
      esac
      # Additive invariant: SAST is a strict superset of black-box (hints only steer probes; oracles alone decide). But
      # OOB/Collaborator findings are stochastic, so fold any black-box finding missing from the +websrc run into it
      # (host:port normalized) → +websrc >= black-box, always.
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
      # Delta-teardown: stop everything THIS cell started (prefix-agnostic), cancelling restart policies first so
      # crashed --restart containers (goof/nodevuln) don't respawn. Pre-existing unrelated containers are untouched.
      newly="$(docker ps -q 2>/dev/null | sort | comm -13 <(printf '%s\n' "$cell_pre_containers") -)"
      if [ -n "$newly" ]; then
        printf '%s\n' "$newly" | xargs docker update --restart no >/dev/null 2>&1
        printf '%s\n' "$newly" | xargs -P4 -n1 -I{} docker stop -t 3 {} >/dev/null 2>&1
      fi
      [ "$kind" = docker ] && [ -n "$cname" ] && teardown "$cname"   # rm the fresh-spun instance (avoids name reuse)
    done
  done
done

# ---- matrix -------------------------------------------------------------------------------
say "===== MATRIX (findings/cell) ====="
{
  # Columns = whatever cells actually ran (order of first appearance in the CSV) → black-box vs web-src sit side by side.
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
