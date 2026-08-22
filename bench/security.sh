#!/bin/bash
# Security SAST (ON DEMAND): run TWO Java security scanners over the extension and report findings.
#   * Semgrep              — SOURCE pattern SAST (registry security rulesets: p/java, p/security-audit, p/secrets).
#                            Install: brew install semgrep   (rulesets download from the registry on first run)
#   * SpotBugs + FindSecBugs — BYTECODE dataflow SAST, the dedicated Java security scanner (~135 patterns: SQLi, XSS,
#                            command injection, path traversal, weak crypto, SSRF, insecure deserialization, TLS).
#                            Install: brew install spotbugs   (the FindSecBugs plugin jar is auto-fetched to /tmp)
#
# IMPORTANT — this extension is ITSELF an offensive tool: it deliberately BUILDS SQLi/XSS/command-injection payloads
# and performs SSRF / raw socket I/O as its JOB. Both scanners will flag that payload/HTTP code as "vulnerable", but
# that is INTENDED behavior, not a flaw IN the extension. Read the output as: "does the SCANNER itself have a real
# weakness" — a hardcoded secret, deserialization of UNtrusted data, disabled TLS verification, an injectable path in
# its OWN control plane — and separate those from the attack payloads it is supposed to generate.
#
# Dev-only, READ-ONLY on the repo (Semgrep reads source; SpotBugs reads the already-compiled /tmp/aisbuild classes).
# Output: bench/results/security/{semgrep.json, spotbugs.xml, summary.txt}
# ============================================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE" || exit 1
SRC="$HERE/src/main/java/com/ioactive/aiscanner"
OUT="$HERE/bench/results/security"; mkdir -p "$OUT"
MONTOYA=/tmp/montoya-2025.5.jar; JSON=/tmp/json-20250107.jar; CLASSES=/tmp/aisbuild
FSB_VER="${FSB_VER:-1.13.0}"; FSB="/tmp/findsecbugs-plugin-$FSB_VER.jar"
say(){ echo "[security] $*" >&2; }
[ -d "$SRC" ] || { say "source dir not found: $SRC"; exit 1; }

# ---- 1) Semgrep (source pattern SAST) ------------------------------------------------------
# Resolve a WORKING semgrep: the Homebrew build is frequently missing python deps (e.g. 'attrs'), so prefer one that
# actually runs, then an isolated venv fallback. Create the venv once (if needed):
#   /opt/homebrew/opt/python@3.11/bin/python3.11 -m venv /tmp/sgvenv && /tmp/sgvenv/bin/pip install semgrep
# Override with SEMGREP=/path/to/semgrep bench/security.sh
SEMGREP="${SEMGREP:-}"
if [ -z "$SEMGREP" ]; then
  if command -v semgrep >/dev/null 2>&1 && semgrep --version >/dev/null 2>&1; then SEMGREP="semgrep"
  elif [ -x /tmp/sgvenv/bin/semgrep ]; then SEMGREP="/tmp/sgvenv/bin/semgrep"; fi
fi
SG_JSON="$OUT/semgrep.json"; : > "$SG_JSON"; SG_OK=0
if [ -n "$SEMGREP" ]; then
  say "running Semgrep (p/java + p/security-audit + p/secrets — downloads rules on first run)..."
  # prepend semgrep's OWN dir so its 'pysemgrep' helper resolves to the SAME install, not a broken one earlier on PATH
  PATH="$(dirname "$SEMGREP"):$PATH" "$SEMGREP" scan --config p/java --config p/security-audit --config p/secrets \
    --metrics off --json --output "$SG_JSON" "$SRC" >/dev/null 2>"$OUT/semgrep.err" || true
  [ -s "$SG_JSON" ] && SG_OK=1 || say "Semgrep produced no JSON (see $OUT/semgrep.err — network needed for the registry)"
else
  say "no working semgrep — skipping (see the venv one-liner in this script's comments)."
fi

# ---- 2) SpotBugs + FindSecBugs (bytecode dataflow SAST) ------------------------------------
SB_XML="$OUT/spotbugs.xml"; : > "$SB_XML"; SB_OK=0
if command -v spotbugs >/dev/null 2>&1; then
  [ -d "$CLASSES" ] || { say "compiling classes (build.sh) for SpotBugs..."; ./build.sh >/dev/null 2>&1 || true; }
  if [ ! -s "$FSB" ]; then
    say "fetching FindSecBugs plugin $FSB_VER..."
    curl -fsSL -o "$FSB" "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/$FSB_VER/findsecbugs-plugin-$FSB_VER.jar" || say "plugin download failed"
  fi
  if [ -d "$CLASSES" ]; then
    AUX="$MONTOYA:$JSON"; [ -s "$MONTOYA" ] || AUX="$JSON"
    # plain-string (not array) so an empty value can't trip macOS bash 3.2 under set -u; the /tmp path has no spaces.
    PLUG=""; [ -s "$FSB" ] && PLUG="-pluginList $FSB"   # without the plugin SpotBugs still runs its own bug patterns
    say "running SpotBugs${FSB:+ + FindSecBugs}..."
    spotbugs -textui -effort:max $PLUG -auxclasspath "$AUX" \
      -onlyAnalyze 'com.ioactive.-' -xml:withMessages -output "$SB_XML" "$CLASSES" 2>"$OUT/spotbugs.err" || true
    [ -s "$SB_XML" ] && SB_OK=1 || say "SpotBugs produced no XML (see $OUT/spotbugs.err)"
  else
    say "no compiled classes at $CLASSES — run ./build.sh first."
  fi
else
  say "spotbugs not found — skipping (install: brew install spotbugs)."
fi

# ---- 3) summarize (per tool + combined, security-first) ------------------------------------
python3 - "$SG_JSON" "$SB_XML" "$SG_OK" "$SB_OK" >"$OUT/summary.txt" <<'PY'
import json, os, sys
import xml.etree.ElementTree as ET
sg_json, sb_xml, sg_ok, sb_ok = sys.argv[1], sys.argv[2], sys.argv[3]=="1", sys.argv[4]=="1"

# --- Semgrep JSON ---
sg=[]  # (severity, rule, file, line)
if sg_ok:
    try:
        d=json.load(open(sg_json))
        for r in d.get("results", []):
            sev=r.get("extra",{}).get("severity","INFO")
            rule=r.get("check_id","?").split(".")[-1]
            sg.append((sev.upper(), rule, os.path.basename(r.get("path","?")), r.get("start",{}).get("line",0)))
    except Exception as e:
        print("semgrep parse error:", e)

# --- SpotBugs XML (priority 1=High 2=Medium 3=Low; FindSecBugs security bugs carry category SECURITY) ---
sb=[]  # (prio, category, type, file, line)
PRI={"1":"HIGH","2":"MEDIUM","3":"LOW"}
if sb_ok:
    try:
        root=ET.parse(sb_xml).getroot()
        for b in root.iter("BugInstance"):
            prio=PRI.get(b.get("priority","3"),"LOW"); cat=b.get("category","?"); typ=b.get("type","?")
            sl=None
            for s in b.iter("SourceLine"):
                sl=s; break
            f=os.path.basename(sl.get("sourcepath","?")) if sl is not None else "?"
            ln=sl.get("start","0") if sl is not None else "0"
            sb.append((prio, cat, typ, f, ln))
    except Exception as e:
        print("spotbugs parse error:", e)

def bar(): print("-"*70)
print("==== security SAST ====")

# Semgrep
print(f"\nSEMGREP : {'%d finding(s)' % len(sg) if sg_ok else 'not run'}")
if sg_ok and sg:
    from collections import Counter
    for sev in ("ERROR","WARNING","INFO"):
        n=[x for x in sg if x[0]==sev]
        if n: print(f"  {sev}: {len(n)}   top: " + ", ".join(f"{k}×{v}" for k,v in Counter(r for _,r,_,_ in n).most_common(5)))
    print("  --- ERROR/WARNING findings ---")
    for sev,rule,f,l in sorted([x for x in sg if x[0] in ("ERROR","WARNING")], key=lambda x:x[0]):
        print(f"    [{sev}] {rule}  @ {f}:{l}")

# SpotBugs — SECURITY category first (that's FindSecBugs)
print(f"\nSPOTBUGS+FINDSECBUGS : {'%d bug(s)' % len(sb) if sb_ok else 'not run'}")
if sb_ok and sb:
    sec=[x for x in sb if x[1]=="SECURITY"]
    print(f"  SECURITY-category (FindSecBugs): {len(sec)}")
    for prio,cat,typ,f,l in sorted(sec, key=lambda x:x[0]):
        print(f"    [{prio}] {typ}  @ {f}:{l}")
    other=[x for x in sb if x[1]!="SECURITY"]
    if other:
        from collections import Counter
        print(f"  other categories: {len(other)}   top: " + ", ".join(f"{k}×{v}" for k,v in Counter(t for _,_,t,_,_ in other).most_common(6)))

if not (sg_ok or sb_ok):
    print("\n(no scanner ran — install semgrep and/or spotbugs)")
PY
cat "$OUT/summary.txt"
say "reports written under $OUT"
