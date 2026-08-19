#!/usr/bin/env bash
# No extension baseline: launch Burp Pro with NO extension jar at all, enable its native REST API,
# drive Burp's OWN Crawl-and-Audit on the target via REST, and read Burp's own issues back via REST.
# Scoring mirrors AiTriage EXACTLY: drop INFORMATION severity + TENTATIVE confidence (keep FIRM/CERTAIN);
# BENCHMARK score = HIGH + MEDIUM. This is pure Burp Pro — the extension is never in the process.
set -u
TARGET="${1:-http://zero.webappsecurity.com/}"
BURP_JAR="${BURP_JAR:-/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar}"
# Pick a Java that ACTUALLY RUNS: Burp's bundled JRE is broken on 2026.7.x (java -version → no output, exit 137),
# so TEST each candidate and fall back to system Java (same logic as ai-scanner.sh — that's why the matrix worked).
java_works(){ [ -n "$1" ] && "$1" -version >/dev/null 2>&1; }
if [ -z "${JAVA:-}" ]; then
  for c in "/Applications/Burp Suite.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" "$(command -v java 2>/dev/null)" /usr/bin/java; do
    if java_works "$c"; then JAVA="$c"; break; fi
  done
fi
[ -n "${JAVA:-}" ] || { echo "[noext] no working java found"; exit 5; }
BASE_CONF="$HOME/.BurpSuite/UserConfigPro.json"; [ -f "$BASE_CONF" ] || BASE_CONF="$HOME/.BurpSuite/UserConfig.json"
PORT="${AISCANNER_REST_PORT:-13370}"   # 1337 is taken by a Docker-published container here; use a free port
DIR=/tmp/aisc-zero-noext; rm -rf "$DIR"; mkdir -p "$DIR"
UCONF="$DIR/user-config.json"; PROJ="$DIR/project.burp"
LOG="$DIR/run.log"; DEADLINE_MIN="${AISCANNER_AUDIT_MINUTES:-25}"

log(){ echo "[noext] $*" | tee -a "$LOG"; }

# 0) one Burp at a time — wait for any running Burp (the matrix) to finish
while pgrep -f burpsuite.jar >/dev/null 2>&1; do log "waiting for running Burp to finish…"; sleep 20; done

# 1) user-config = clone of the real one, REST API enabled on loopback:PORT (no key in config — the user ticks
#    "Allow access without API key" in the GUI once Burp is up), NO extension injected
python3 - "$BASE_CONF" "$UCONF" "$PORT" <<'PY'
import json,sys
base,out,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
try: d=json.load(open(base))
except Exception: d={}
uo=d.setdefault("user_options",{}); misc=uo.setdefault("misc",{})
misc["api"]={"address":"127.0.0.1","enabled":True,"insecure_mode":False,"keys":[],"listen_mode":"loopback_only","port":port}
# make sure NO extension is loaded
uo.setdefault("extender",{})["extensions"]=[]
json.dump(d,open(out,"w"))
print("wrote",out)
PY
log "config ready (REST API 127.0.0.1:$PORT enabled, no extension)"

# 2) launch Burp GUI, no -Daiscanner flags, no extension, NO --config-file (empty one made Burp exit;
#    we don't need a proxy listener — Burp crawls the target directly from the REST scan URL).
log "launching pure Burp Pro (no extension)…  target=$TARGET"
"$JAVA" -Xmx"${HEAP:-2g}" --add-opens=java.base/java.net=ALL-UNNAMED \
  -jar "$BURP_JAR" \
  --project-file="$PROJ" --user-config-file="$UCONF" \
  --unpause-spider-and-scanner >> "$DIR/burp.out" 2>&1 &
BURP_PID=$!
log "burp pid=$BURP_PID"

cleanup(){ kill "$BURP_PID" 2>/dev/null; pkill -f "project-file=$PROJ" 2>/dev/null; }
trap cleanup EXIT

# 3) wait for REST API to allow no-key access. While it 401s, prompt the user to tick the GUI toggle.
API="http://127.0.0.1:$PORT/v0.1"
up=0; warned=0
for i in $(seq 1 120); do   # up to ~20 min — gives time to flip the toggle
  if ! kill -0 "$BURP_PID" 2>/dev/null; then log "Burp process died during startup — abort (see burp.out)"; tail -20 "$DIR/burp.out"; exit 4; fi
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$API/scan/0" 2>/dev/null)
  if [ "$code" != "000" ] && [ "$code" != "401" ]; then log "Burp REST API open (HTTP $code) after ${i}0s — proceeding"; up=1; break; fi
  if [ "$code" = "401" ] && [ "$warned" = "0" ]; then
    log "############################################################"
    log "# ACTION NEEDED in the Burp window that just opened:        "
    log "#   User options  ->  Misc  ->  REST API                    "
    log "#   [x] Allow access without API key                        "
    log "# (Service is already running on 127.0.0.1:$PORT.)          "
    log "# Waiting for you to tick it… (polling every 10s)           "
    log "############################################################"
    warned=1
  fi
  sleep 10
done
[ "$up" != "1" ] && { log "REST never opened (last HTTP $code) — did you tick 'Allow access without API key'? abort"; exit 2; }

# 4) start Burp's own crawl-and-audit
TID=$(curl -s -m 10 -D - -o /dev/null -H 'Content-Type: application/json' \
      -d "{\"urls\":[\"$TARGET\"]}" "$API/scan" 2>/dev/null \
      | tr -d '\r' | awk -F'/' 'tolower($0) ~ /^location:/ {print $NF}')
[ -z "$TID" ] && { log "scan POST returned no task id — abort"; curl -s -m10 -D - -o /dev/null -d "{\"urls\":[\"$TARGET\"]}" "$API/scan"; exit 3; }
log "Burp scan started, task_id=$TID"

# 5) poll until terminal or deadline
START=$(date +%s); STATUS=""
while :; do
  J=$(curl -s -m 15 "$API/scan/$TID" 2>/dev/null)
  STATUS=$(printf '%s' "$J" | python3 -c "import sys,json;print(json.load(sys.stdin).get('scan_status',''))" 2>/dev/null)
  NEV=$(printf '%s' "$J" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('issue_events',[])))" 2>/dev/null)
  EL=$(( ($(date +%s)-START)/60 ))
  log "status=$STATUS  issue_events=$NEV  elapsed=${EL}m"
  printf '%s' "$J" > "$DIR/scan.json"
  case "$STATUS" in succeeded|failed|paused) break;; esac
  [ "$EL" -ge "$DEADLINE_MIN" ] && { log "deadline ${DEADLINE_MIN}m hit — stopping"; break; }
  sleep 20
done

# 6) score with the SAME filter as AiTriage (drop INFORMATION + TENTATIVE; score = HIGH+MED)
python3 - "$DIR/scan.json" "$TARGET" "$STATUS" "$START" <<'PY' | tee -a "$LOG"
import sys,json,time
j=json.load(open(sys.argv[1])); target,status,start=sys.argv[2],sys.argv[3],int(sys.argv[4])
seen={}
for ev in j.get("issue_events",[]):
    it=ev.get("issue") or {}
    name=it.get("name","?"); sev=(it.get("severity") or "").lower(); conf=(it.get("confidence") or "").lower()
    origin=it.get("origin",""); path=it.get("path","")
    key=(name, origin+path)
    if key in seen: continue
    seen[key]=(name,sev,conf)
kept=[v for v in seen.values() if v[1] not in ("info","information") and v[2]!="tentative"]
def bucket(s): return {"high":"HIGH","medium":"MEDIUM","low":"LOW"}.get(s,"INFO")
sc={"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}; cat={}
for n,s,c in kept:
    b=bucket(s); sc[b]+=1; cat[n]=cat.get(n,0)+1
score=sc["HIGH"]+sc["MEDIUM"]
el=int(time.time())-start; mm,ss=el//60,el%60
print("===== BENCHMARK SCORE (Burp-native HIGH+MED, FIRM/CERTAIN) = %d   →   deterministic-oracle: 0 | native-Burp-audit: %d   |   time: %dm %ds (%ds)  [status=%s] ====="%(score,score,mm,ss,el,status))
print("  by criticality:  HIGH: %d | MEDIUM: %d | LOW: %d | INFO: %d   (LOW/INFO shown, not scored)"%(sc["HIGH"],sc["MEDIUM"],sc["LOW"],sc["INFO"]))
print("  by category (%d classes):  %s"%(len(cat)," | ".join("%s: %d"%(k,v) for k,v in sorted(cat.items()))))
for n,s,c in sorted(kept,key=lambda x:x[1]):
    print("    [%s] %s (%s)"%(bucket(s),n,c))
print("===== END BENCHMARK SCORE (no-extension (pure Burp Pro) %s) ====="%target)
PY

log "done"
