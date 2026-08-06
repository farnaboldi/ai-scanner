#!/usr/bin/env bash
#
# AI Scanner benchmark harness. Brings up the 3 targets, and for each computes
# "found / expected" (% of expected findings) from the best available oracle:
#   juice   -> GET /api/Challenges (solved flags)          [scanner-driven, server truth]
#   webgoat -> GET /WebGoat/service/lessonmenu.mvc (complete) [scanner-driven, server truth]
#   dvwa    -> the scanner's exported report (no scoreboard) [results/dvwa.report.txt]
#
# Usage:
#   ./bench/run.sh up                 # start containers (+ DVWA DB setup)
#   ./bench/run.sh scan  [target|all] # launch AI Scanner against target(s), then measure
#   ./bench/run.sh measure [target|all]   # just measure current state (default: all)
#   ./bench/run.sh report             # measure all + write bench/report.md
#   ./bench/run.sh down
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
EXP="$HERE/expected"; RES="$HERE/results"; mkdir -p "$RES"
COMPOSE="docker compose -f $HERE/docker-compose.yml"

JUICE_URL="${JUICE_URL:-http://localhost:3000}"
WEBGOAT_URL="${WEBGOAT_URL:-http://localhost:8090/WebGoat}"
DVWA_URL="${DVWA_URL:-http://localhost:4280}"
CRAPI_URL="${CRAPI_URL:-http://localhost:8888}"
CRAPI_SRC="${CRAPI_SRC:-/tmp/crapi-src}"   # where crapi_up clones OWASP/crAPI (its stack is a separate repo/compose)
VAPI_URL="${VAPI_URL:-http://localhost:9000}"
# vulnerable-react-app: React SPA + javulna Spring API — added to benchmark SPA→REST discovery/coverage (the
# gap seen on real SPAs). Target the SPA FRONTEND (:3001): it proxies /rest/* same-origin so the scanner reaches the API in-scope
REACTVULNA_URL="${REACTVULNA_URL:-http://localhost:3001}"   # SPA frontend (proxies /rest/* same-origin); :8080 backend has no crawlable surface
# AI-PT-Lab: OWASP LLM Top-10 agent lab (FastAPI backend :8000 + UI :3000). Added to benchmark the LLM probes
# (AgentFlowProbe / LlmFuzzProbe). Its .env points at a LOCAL OpenAI-compatible model (the local LLM) so no external key
# is needed. Target the backend API — the /scenarios/{name}/run LLM endpoint lives there.
AIPTLAB_URL="${AIPTLAB_URL:-http://localhost:8000}"
# BrokenCrystals (React + NestJS). Remapped off :3000 (Juice collision) to :3007; its db off :5432 to :5433.
BROKENCRYSTALS_URL="${BROKENCRYSTALS_URL:-http://localhost:3007}"
BROKENCRYSTALS_SRC="${BROKENCRYSTALS_SRC:-/tmp/brokencrystals-src}"
# Damn Vulnerable WordPress (WordPress + 4 activated vulnerable plugins). Compose maps WordPress→:31337.
DVWP_URL="${DVWP_URL:-http://localhost:31337}"
DVWP_SRC="${DVWP_SRC:-/tmp/dvwp-src}"
SCANNER="$ROOT/ai-scanner.sh"

say(){ printf '%s\n' "$*"; }
wait_http(){ # url, name, tries
  for i in $(seq 1 "${3:-60}"); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null)
    [ "$code" != "000" ] && { say "  $2 up (HTTP $code)"; return 0; }
    sleep 2
  done; say "  !! $2 not responding at $1"; return 1
}

cmd_up(){
  $COMPOSE up -d
  wait_http "$JUICE_URL/" juice 90
  wait_http "$WEBGOAT_URL/login" webgoat 120
  wait_http "$DVWA_URL/login.php" dvwa 90
  dvwa_setup
  wait_http "$VAPI_URL/" vapi 60
  crapi_up   # clone + start crAPI's own microservice stack, sized for a small Docker VM (see crapi_up)
  # vulnerable-react-app is a separate compose (git submodules), like crAPI — bring it up out-of-band:
  #   git clone --recurse-submodules https://github.com/vulnerable-apps/vulnerable-react-app /tmp/reactvulna-src \
  #     && (cd /tmp/reactvulna-src && docker compose up -d)
  # Then set REACTVULNA_URL to the SPA frontend URL its compose exposes (backend API defaults to :8080).
  wait_http "$REACTVULNA_URL/" reactvulna 120
  # AI-PT-Lab (OWASP LLM Top-10) — separate compose. Its model must be an OpenAI-compatible endpoint, but the local LLM
  # (vLLM + Qwen "thinking") returns content=null (answer in `reasoning`) and wants tool_call args as a JSON
  # STRING — a stock OpenAI client breaks. Run our TRANSLATOR (bench/aiptlab-translator.py) in front of the local LLM to
  # normalize both + add the key, then point AI-PT-Lab at it. Backend API = :8000 (what we scan); UI remapped to
  # :3003 (docker-compose.override.yml) so it doesn't collide with Juice (:3000).
  #   PORT=8891 LLM_BASE=http://127.0.0.1:8000 LLM_KEY=<key> python3 bench/aiptlab-translator.py &   # translator on host
  #   git clone https://github.com/anpa1200/AI-PT-Lab /tmp/aiptlab-src && cd /tmp/aiptlab-src \
  #     && sed -i '' 's|^model: .*|model: your-model|' configs/providers/vllm.yaml \
  #     && printf 'LAB_PROVIDER=vllm\nVLLM_BASE_URL=http://host.docker.internal:8891/v1\nLAB_SEED_ON_STARTUP=true\n' > .env \
  #     && (printf '  ui:\n    ports:\n      - "3003:80"\n' >> docker-compose.override.yml) \
  #     && docker compose up -d --build backend   # backend only (:8000); ui optional on :3003
  wait_http "$AIPTLAB_URL/health" aiptlab 120   # FastAPI health probe
  brokencrystals_up   # clone + build (glibc) + start BrokenCrystals, collision-free (see brokencrystals_up)
  dvwp_up   # clone + start Damn Vulnerable WordPress (amd64 emulation; see dvwp_up)
}
cmd_down(){ $COMPOSE down; }

# --- DVWA: create DB + login + security=low. Readiness-gated: the native ghcr.io/digininja/dvwa image
#     uses a separate MariaDB that needs warm-up, and create_db invalidates the session — so we loop the
#     full flow (get token -> create_db -> RE-login) until an actual module page renders 200. ---
dvwa_setup(){
  local jar="$RES/dvwa.cookies" host tok code
  host=$(echo "$DVWA_URL" | sed -E 's#https?://([^:/]+).*#\1#')
  _dvwa_tok(){ curl -s -b "$jar" "$1" | grep -oE "value='[a-f0-9]{32}" | grep -oE "[a-f0-9]{32}" | head -1; }
  for attempt in $(seq 1 30); do
    rm -f "$jar"
    curl -s -c "$jar" "$DVWA_URL/login.php" -o /dev/null                       # seed session
    tok=$(_dvwa_tok "$DVWA_URL/setup.php")                                      # create/reset DB (DB-backed)
    [ -n "$tok" ] && curl -s -b "$jar" -c "$jar" --data "create_db=Create+/+Reset+Database&user_token=$tok" "$DVWA_URL/setup.php" -o /dev/null
    rm -f "$jar"                                                                # create_db drops the session → re-login
    curl -s -c "$jar" "$DVWA_URL/login.php" -o /dev/null
    tok=$(_dvwa_tok "$DVWA_URL/login.php")
    [ -n "$tok" ] && curl -s -b "$jar" -c "$jar" --data "username=admin&password=password&Login=Login&user_token=$tok" "$DVWA_URL/login.php" -o /dev/null
    printf '%s\tFALSE\t/\tFALSE\t0\tsecurity\tlow\n' "$host" >> "$jar" 2>/dev/null   # security=low for scanning
    code=$(curl -s -b "$jar" -L -o /dev/null -w '%{http_code}' "$DVWA_URL/vulnerabilities/sqli/")
    [ "$code" = "200" ] && { say "  dvwa: DB ready + logged in + security=low (module page $code, cookies: $jar)"; return 0; }
    sleep 3
  done
  say "  !! dvwa: DB/login not ready after retries (last module page: ${code:-none})"; return 1
}

# --- crAPI: OWASP's microservice stack ships in its OWN repo/compose (not ours). Bring it up here idempotently,
#     sized for a small Docker VM via the upstream docker-compose.minimal.yml (per-service memory caps). We start
#     the WHOLE fleet: besides being what full coverage wants, it means crapi-web's nginx can resolve the
#     "crapi-chatbot" upstream at boot — nginx ABORTS with "host not found in upstream crapi-chatbot" if chatbot
#     isn't up, so starting everything makes web come up first try (no restart dance). Web gateway → :8888.
#     On a RAM-starved VM co-running other targets, set CRAPI_TRIM=1 to stop chatbot/chromadb/mailhog/premium
#     AFTER web is healthy (nginx keeps the already-resolved upstream; only chatbot routes 502, never scanned). ---
crapi_up(){
  local d="$CRAPI_SRC/deploy/docker"
  if [ ! -d "$d" ]; then
    say "  crapi: cloning OWASP/crAPI → $CRAPI_SRC"
    git clone --depth 1 https://github.com/OWASP/crAPI "$CRAPI_SRC" >/dev/null 2>&1 \
      || { say "  !! crapi: clone failed"; return 1; }
  fi
  if [ "$(curl -s -m5 -o /dev/null -w '%{http_code}' "$CRAPI_URL/")" = "200" ]; then
    say "  crapi: already up ($CRAPI_URL)"; return 0
  fi
  say "  crapi: starting fleet (identity/community/workshop/web/chatbot + postgres/mongo/chroma/mailhog)…"
  ( cd "$d" && VERSION=latest docker compose -f docker-compose.yml -f docker-compose.minimal.yml up -d >/dev/null 2>&1 )
  wait_http "$CRAPI_URL/" crapi 40
  if [ "${CRAPI_TRIM:-0}" = 1 ]; then
    say "  crapi: CRAPI_TRIM=1 → stopping chatbot/chromadb/mailhog/premium to reclaim RAM (nginx stays up)"
    docker stop crapi-chatbot chromadb mailhog api.mypremiumdealership.com >/dev/null 2>&1
  fi
}

# --- BrokenCrystals: React + NestJS app in its own repo (github.com/NeuraLegion/brokencrystals). Bring it up
#     idempotently, fixing the three things that block it on an Apple-Silicon / small-Docker host:
#      1) native module: the Dockerfile base node:18-alpine is MUSL, but libxmljs ships a GLIBC prebuilt
#         (xmljs.node needs ld-linux-*.so.1) → backend crash-loops. Switch base to node:18-slim (GLIBC) so the
#         prebuilt loads without a source recompile. compose.local.yml builds from this Dockerfile (build: context).
#      2) host-port collisions: db 5432 -> 5433 (a host postgres already owns 5432); app 3000 -> 3007 (Juice owns
#         3000). BROKENCRYSTALS_URL points at :3007; the backend reaches db over the internal net (unaffected).
#      3) TLS: compose.local.yml runs HTTP (URL=http://…, no NODE_ENV=production) so it doesn't demand letsencrypt
#         certs (compose.yml does and would crash). keycloak imports its realm on first boot (~80s), which can
#         outlast the initial `up` dependency wait — so we wait for keycloak healthy, then (re)start nodejs. ---
brokencrystals_up(){
  local d="$BROKENCRYSTALS_SRC"
  if [ ! -d "$d" ]; then
    say "  brokencrystals: cloning NeuraLegion/brokencrystals → $d"
    git clone --depth 1 https://github.com/NeuraLegion/brokencrystals "$d" >/dev/null 2>&1 \
      || { say "  !! brokencrystals: clone failed"; return 1; }
  fi
  if [ "$(curl -s -m5 -o /dev/null -w '%{http_code}' "$BROKENCRYSTALS_URL/api/config")" = "200" ]; then
    say "  brokencrystals: already up ($BROKENCRYSTALS_URL)"; return 0
  fi
  sed -i '' 's/FROM node:18-alpine/FROM node:18-slim/g' "$d/Dockerfile"           # GLIBC base for libxmljs
  sed -i '' "s/'5432:5432'/'5433:5432'/" "$d/compose.local.yml"                   # db off :5432
  sed -i '' "s/'3000:3000'/'3007:3000'/" "$d/compose.local.yml"                   # app off :3000 (Juice)
  say "  brokencrystals: building (node:18-slim) + starting stack…"
  ( cd "$d" && docker compose --file=compose.local.yml up -d --build >/dev/null 2>&1 )
  say "  brokencrystals: waiting for keycloak realm import (~80s)…"
  for _ in $(seq 1 20); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' brokencrystals-src-keycloak-1 2>/dev/null)" = healthy ] && break
    sleep 10
  done
  ( cd "$d" && docker compose --file=compose.local.yml up -d nodejs grpcwebproxy >/dev/null 2>&1 )
  wait_http "$BROKENCRYSTALS_URL/api/config" brokencrystals 40
}

# --- Damn Vulnerable WordPress (vavkamil/dvwp): WordPress + 4 activated vulnerable plugins, in its own repo.
#     Bring it up idempotently. GOTCHA: mysql:5.7 and the old wordpress:cli image are amd64-ONLY (no arm64
#     manifest) → build/run the whole stack under linux/amd64 EMULATION on Apple Silicon. After the containers
#     are up, `wp-cli install-wp` installs WordPress + activates the vulnerable plugins + imports the seed DB.
#     WordPress → :31337 (admin/admin). The scanner auto-logs-in via /wp-login.php (log/pwd, default creds). ---
dvwp_up(){
  local d="$DVWP_SRC"
  if [ ! -d "$d" ]; then
    say "  dvwp: cloning vavkamil/dvwp → $d"
    git clone --depth 1 https://github.com/vavkamil/dvwp "$d" >/dev/null 2>&1 || { say "  !! dvwp: clone failed"; return 1; }
  fi
  if [ "$(curl -s -m5 -o /dev/null -w '%{http_code}' "$DVWP_URL/")" = "200" ]; then
    say "  dvwp: already up ($DVWP_URL)"; return 0
  fi
  say "  dvwp: starting WordPress + MySQL (amd64 emulation; :31337)…"
  ( cd "$d" && DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.yml up -d --build >/dev/null 2>&1 )
  sleep 20
  say "  dvwp: installing WordPress + activating vulnerable plugins (wp-cli)…"
  ( cd "$d" && DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker-compose.yml run --rm wp-cli install-wp >/dev/null 2>&1 )
  wait_http "$DVWP_URL/" dvwp 40
}

score(){ # name, found_file, expected_file
  python3 - "$1" "$2" "$3" <<'PY'
import sys, re
name, found_f, exp_f = sys.argv[1], sys.argv[2], sys.argv[3]
def lines(p):
    try: return [l.strip() for l in open(p) if l.strip() and not l.startswith('#')]
    except FileNotFoundError: return []
found = [l.lower() for l in lines(found_f)]
exp = lines(exp_f)
blob = "\n".join(found)
# Alias map: a scanner/Burp finding that is the SAME vuln as an expected id but not a literal
# substring of it (tool naming differs). Keeps probes generically named while counting real
# detections honestly. Only equivalences, never broadenings.
ALIASES = {
    "cross-site scripting (dom)": ["dom-based", "cross-site scripting (dom"],
}
# Word-boundary match: the expected phrase must NOT be glued to a preceding alphanumeric, so
# "sql injection" does NOT falsely match inside "no-sql injection" (which would double-credit a
# single NoSQL finding as both NoSQL and SQLi). Trailing text is fine ("sql injection (blind)").
def present(needle):
    return re.search(r'(?<![a-z0-9])' + re.escape(needle), blob) is not None
def hit(e):
    el = e.lower()
    if present(el): return True
    return any(present(a) for a in ALIASES.get(el, []))
matched = [e for e in exp if hit(e)]
pct = (100.0*len(matched)/len(exp)) if exp else 0.0
print(f"\n== {name.upper()} ==  {len(matched)}/{len(exp)} expected  ({pct:.0f}%)  {'PASS >=50%' if pct>=50 else 'below 50%'}")
if matched: print("  found:   " + ", ".join(matched))
missing=[e for e in exp if not hit(e)]
if missing: print("  missing: " + ", ".join(missing))
PY
}

collect_juice(){ curl -s "$JUICE_URL/api/Challenges/" 2>/dev/null | python3 -c "import json,sys;[print(c['name']) for c in json.load(sys.stdin)['data'] if c.get('solved')]" > "$RES/juice.found.txt" 2>/dev/null; }
collect_webgoat(){
  local jar="$RES/webgoat.cookies"; rm -f "$jar"
  # Account MUST match the scanner's WebGoatSessionAdapter default (aiscbot/aiscpass) so completed
  # lessons are attributed to the same user the scanner solves as. WebGoat requires username AND
  # password to be 6-10 chars — the old 4-char "aisc" was silently rejected at registration, so the
  # oracle account never existed and WebGoat always scored 0.
  curl -s -c "$jar" "$WEBGOAT_URL/login" -o /dev/null
  curl -s -b "$jar" -c "$jar" --data "username=aiscbot&password=aiscpass&matchingPassword=aiscpass&agree=agree" "$WEBGOAT_URL/register.mvc" -o /dev/null 2>/dev/null
  curl -s -b "$jar" -c "$jar" --data "username=aiscbot&password=aiscpass" "$WEBGOAT_URL/login" -o /dev/null 2>/dev/null
  # lessonmenu 'name' is an i18n KEY (e.g. 'bypass-restrictions.title'), not the human title the
  # expected list uses. Normalize (drop the i18n suffix, hyphens/underscores -> spaces) so a completed
  # lesson actually matches its expected id. Without this WebGoat could never score above 0.
  curl -s -b "$jar" "$WEBGOAT_URL/service/lessonmenu.mvc" 2>/dev/null | python3 -c "
import json,sys,re
def norm(n): return re.sub(r'\.(title|name|label|lesson)$','',n).replace('-',' ').replace('_',' ')
def walk(o):
    if isinstance(o,dict):
        if o.get('complete') is True and o.get('name'): print(norm(o['name']))
        for v in o.values(): walk(v)
    elif isinstance(o,list):
        for v in o: walk(v)
try: walk(json.load(sys.stdin))
except: pass" > "$RES/webgoat.found.txt" 2>/dev/null
}
collect_dvwa(){ cp -f "$RES/dvwa.report.txt" "$RES/dvwa.found.txt" 2>/dev/null || : > "$RES/dvwa.found.txt"; }
# crAPI has no scoreboard API (unlike Juice/WebGoat), so — like DVWA — "found" is the scanner's own
# exported findings report; each expected vuln-class id is matched (case-insensitive substring) against it.
collect_crapi(){ cp -f "$RES/crapi.report.txt" "$RES/crapi.found.txt" 2>/dev/null || : > "$RES/crapi.found.txt"; }
# vulnerable-api has no scoreboard API either — score against the scanner's own exported report.
collect_vapi(){ cp -f "$RES/vapi.report.txt" "$RES/vapi.found.txt" 2>/dev/null || : > "$RES/vapi.found.txt"; }
# vulnerable-react-app (SPA + Spring API): no scoreboard → score against the scanner's own exported report.
collect_reactvulna(){ cp -f "$RES/reactvulna.report.txt" "$RES/reactvulna.found.txt" 2>/dev/null || : > "$RES/reactvulna.found.txt"; }
# AI-PT-Lab (LLM Top-10): the lab has its OWN per-run scoreboard, but that measures whether an INPUT triggered a
# vuln — not whether OUR scanner detected it. For a scanner benchmark we score our exported report, like the rest.
collect_aiptlab(){ cp -f "$RES/aiptlab.report.txt" "$RES/aiptlab.found.txt" 2>/dev/null || : > "$RES/aiptlab.found.txt"; }
collect_brokencrystals(){ cp -f "$RES/brokencrystals.report.txt" "$RES/brokencrystals.found.txt" 2>/dev/null || : > "$RES/brokencrystals.found.txt"; }
collect_dvwp(){ cp -f "$RES/dvwp.report.txt" "$RES/dvwp.found.txt" 2>/dev/null || : > "$RES/dvwp.found.txt"; }

cmd_measure(){
  local t="${1:-all}"
  [ "$t" = all -o "$t" = juice ]   && { collect_juice;   score juice   "$RES/juice.found.txt"   "$EXP/juice.txt"; }
  [ "$t" = all -o "$t" = webgoat ] && { collect_webgoat; score webgoat "$RES/webgoat.found.txt" "$EXP/webgoat.txt"; }
  [ "$t" = all -o "$t" = dvwa ]    && { collect_dvwa;    score dvwa    "$RES/dvwa.found.txt"    "$EXP/dvwa.txt"; }
  [ "$t" = all -o "$t" = crapi ]   && { collect_crapi;   score crapi   "$RES/crapi.found.txt"   "$EXP/crapi.txt"; }
  [ "$t" = all -o "$t" = vapi ] && { collect_vapi; score vapi "$RES/vapi.found.txt" "$EXP/vapi.txt"; }
  [ "$t" = all -o "$t" = reactvulna ] && { collect_reactvulna; score reactvulna "$RES/reactvulna.found.txt" "$EXP/reactvulna.txt"; }
  [ "$t" = all -o "$t" = aiptlab ] && { collect_aiptlab; score aiptlab "$RES/aiptlab.found.txt" "$EXP/aiptlab.txt"; }
  [ "$t" = all -o "$t" = brokencrystals ] && { collect_brokencrystals; score brokencrystals "$RES/brokencrystals.found.txt" "$EXP/brokencrystals.txt"; }
  [ "$t" = all -o "$t" = dvwp ] && { collect_dvwp; score dvwp "$RES/dvwp.found.txt" "$EXP/dvwp.txt"; }
    return 0
}

cmd_scan(){ # launch the scanner against a target, exporting findings to results/<t>.report.txt
  local t="${1:-all}"
  scan_one(){ local name="$1" url="$2"
    # DVWA: reset the DB first so admin/password is valid — DVWA's CSRF module changes the logged-in
    # user's password, so a PRIOR scan's /vulnerabilities/csrf/ audit leaves admin's password changed and
    # the next scan can't authenticate (→ 0 findings). A reset before each scan makes runs self-consistent.
    [ "$name" = dvwa ] && dvwa_setup
    # crAPI: crapi-workshop can EXIT during boot if identity wasn't ready when it seeded its DB. A dead
    # workshop 502s every shop/mechanic endpoint (mass-assign/SQLi-coupon/IDOR unreachable → silently missing).
    # Ensure it's healthy before scanning so coverage isn't confounded by a crashed service.
    if [ "$name" = crapi ]; then
      if [ "$(docker inspect -f '{{.State.Health.Status}}' crapi-workshop 2>/dev/null)" != healthy ]; then
        say "   crapi-workshop not healthy — (re)starting it"
        docker start crapi-workshop >/dev/null 2>&1
        for _ in $(seq 1 40); do
          [ "$(docker inspect -f '{{.State.Health.Status}}' crapi-workshop 2>/dev/null)" = healthy ] && break
          sleep 3
        done
      fi
      say "   crapi-workshop: $(docker inspect -f '{{.State.Health.Status}}' crapi-workshop 2>/dev/null)"
      # Memory guard: this box (~8GB) can't hold the FULL crAPI fleet + Burp(2g). The scanner only needs
      # identity+community+workshop+web+DBs for the 8 vuln classes; stop the heavy non-essentials so Burp
      # fits (crapi-web's nginx already resolved the crapi-chatbot upstream at startup, so stopping chatbot
      # now leaves nginx up — only chatbot routes 502, which we never scan). See memory builtin-mode-spa-auth-limit.
      say "   trimming non-essential crAPI services (chatbot/chromadb/mailhog/premium) to free RAM"
      docker stop crapi-chatbot chromadb mailhog api.mypremiumdealership.com >/dev/null 2>&1
    fi
    say ".. scanning $name ($url) — launching Burp+AI Scanner"
    AISCANNER_REPORT="$RES/$name.report.txt" "$SCANNER" "$url" >/dev/null 2>&1 &
    say "   (scanner launched; watch Burp. Re-run './run.sh measure $name' when SCAN COMPLETE)"
  }
  [ "$t" = all -o "$t" = juice ]   && scan_one juice   "$JUICE_URL/"
  [ "$t" = all -o "$t" = webgoat ] && scan_one webgoat "$WEBGOAT_URL/"
  [ "$t" = all -o "$t" = dvwa ]    && scan_one dvwa    "$DVWA_URL/"
  [ "$t" = all -o "$t" = crapi ]   && scan_one crapi   "$CRAPI_URL/"
  [ "$t" = all -o "$t" = vapi ] && scan_one vapi "$VAPI_URL/"
  [ "$t" = all -o "$t" = reactvulna ] && scan_one reactvulna "$REACTVULNA_URL/"
  [ "$t" = all -o "$t" = aiptlab ] && scan_one aiptlab "$AIPTLAB_URL/"
  [ "$t" = all -o "$t" = brokencrystals ] && scan_one brokencrystals "$BROKENCRYSTALS_URL/"
  [ "$t" = all -o "$t" = dvwp ] && scan_one dvwp "$DVWP_URL/"
}

cmd_report(){
  cmd_measure all | tee "$HERE/report.md.tmp"
  { echo "# AI Scanner benchmark report"; echo; cat "$HERE/report.md.tmp"; } > "$HERE/report.md"
  rm -f "$HERE/report.md.tmp"; say "wrote $HERE/report.md"
}

case "${1:-report}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) $COMPOSE ps ;;
  scan) cmd_scan "${2:-all}" ;;
  measure) cmd_measure "${2:-all}" ;;
  report) cmd_report ;;
  *) say "usage: $0 {up|down|status|scan [t]|measure [t]|report}  (t=juice|webgoat|dvwa|crapi|vapi|reactvulna|aiptlab|brokencrystals|dvwp|all)"; exit 2 ;;
esac
