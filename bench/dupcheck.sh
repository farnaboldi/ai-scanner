#!/bin/bash
# Check with two run detectors over the extension source and report where they converge
#
# Usage:
#   bench/dupcheck.sh                  # min-tokens 50 (~ a small method)
#   MIN_TOKENS=100 bench/dupcheck.sh   # only larger clones (less noise)
#   bench/dupcheck.sh --open           # also open the jscpd HTML report in a browser
#
# Output: bench/results/dupcheck/{pmd-cpd.csv, jscpd/jscpd-report.json, jscpd/html/, convergence.txt}
# ============================================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE" || exit 1
SRC="$HERE/src/main/java/com/ioactive/aiscanner"
OUT="$HERE/bench/results/dupcheck"; mkdir -p "$OUT"
MIN_TOKENS="${MIN_TOKENS:-50}"
MIN_LINES="${MIN_LINES:-5}"
say(){ echo "[dupcheck] $*" >&2; }

[ -d "$SRC" ] || { say "source dir not found: $SRC"; exit 1; }
say "source: $SRC  (min-tokens=$MIN_TOKENS, min-lines=$MIN_LINES)"

# ---- 1) PMD CPD -----------------------------------------------------------------------------
PMD_CSV="$OUT/pmd-cpd.csv"; : > "$PMD_CSV"; PMD_OK=0
if command -v pmd >/dev/null 2>&1; then
  say "running PMD CPD…"
  # CPD exits 4 when duplicates ARE found — that is success for us, so ignore the exit code.
  pmd cpd --minimum-tokens "$MIN_TOKENS" --language java --dir "$SRC" --format csv >"$PMD_CSV" 2>"$OUT/pmd.err" || true
  [ -s "$PMD_CSV" ] && PMD_OK=1 || say "PMD produced no output (see $OUT/pmd.err)"
else
  say "PMD not found — skipping (install: brew install pmd). jscpd still runs."
fi

# ---- 2) jscpd (via npx, no global install) --------------------------------------------------
JSCPD_DIR="$OUT/jscpd"; rm -rf "$JSCPD_DIR"; mkdir -p "$JSCPD_DIR"; JSCPD_OK=0
if command -v npx >/dev/null 2>&1; then
  say "running jscpd (npx — may download the package on first run)…"
  npx --yes jscpd "$SRC" --min-tokens "$MIN_TOKENS" --min-lines "$MIN_LINES" --mode strict \
      --reporters json,html --output "$JSCPD_DIR" --silent >/dev/null 2>&1 || true
  [ -f "$JSCPD_DIR/jscpd-report.json" ] && JSCPD_OK=1 || say "jscpd produced no JSON"
else
  say "npx/Node not found — skipping jscpd (install Node)."
fi

# ---- 3) per-tool totals + CONVERGENCE (both tools agree) ------------------------------------
python3 - "$PMD_CSV" "$JSCPD_DIR/jscpd-report.json" "$PMD_OK" "$JSCPD_OK" >"$OUT/convergence.txt" <<'PY'
import csv, json, os, sys
pmd_csv, js_json, pmd_ok, js_ok = sys.argv[1], sys.argv[2], sys.argv[3]=="1", sys.argv[4]=="1"

pmd=[]
if pmd_ok:
    for r in csv.reader(open(pmd_csv)):
        if not r or not r[0].isdigit(): continue
        lines=int(r[0]); rest=r[3:]; locs=[]
        for i in range(0, len(rest)-1, 2):
            try: locs.append((os.path.basename(rest[i+1]), int(rest[i]), int(rest[i])+lines-1))
            except Exception: pass
        pmd.append((lines, locs))

js=[]
if js_ok:
    d=json.load(open(js_json))
    for c in d.get("duplicates", []):
        a,b=c["firstFile"], c["secondFile"]
        js.append((os.path.basename(a["name"]), a["start"], a["end"],
                   os.path.basename(b["name"]), b["start"], b["end"], c.get("lines",0)))

print("==== duplicate-code check ====")
print(f"PMD CPD : {'%d blocks' % len(pmd) if pmd_ok else 'not run'}")
print(f"jscpd   : {'%d clones' % len(js) if js_ok else 'not run'}")

if not (pmd_ok and js_ok):
    print("\n(convergence needs BOTH tools — install the missing one and re-run)")
    sys.exit(0)

def ov(s1,e1,s2,e2): return max(s1,s2) <= min(e1,e2)
conv=[]
for (fa,sa,ea,fb,sb,eb,ln) in js:
    for (pl,locs) in pmd:
        fs={f for f,_,_ in locs}
        if fa in fs and fb in fs \
           and any(f==fa and ov(sa,ea,ps,pe) for f,ps,pe in locs) \
           and any(f==fb and ov(sb,eb,ps,pe) for f,ps,pe in locs):
            conv.append((max(ln,pl), fa,sa,ea, fb,sb,eb)); break
conv.sort(key=lambda x:-x[0])
print(f"\nCONVERGENT (flagged by BOTH): {len(conv)} block(s) — the credible duplication\n")
for (ln,fa,sa,ea,fb,sb,eb) in conv:
    same=" (same file)" if fa==fb else ""
    print(f"  ~{ln:>3} lines  {fa}:{sa}-{ea}  <->  {fb}:{sb}-{eb}{same}")
PY
cat "$OUT/convergence.txt"
say "reports written under $OUT  (jscpd HTML: $JSCPD_DIR/html/index.html)"
[ "${1:-}" = "--open" ] && [ -f "$JSCPD_DIR/html/index.html" ] && open "$JSCPD_DIR/html/index.html" 2>/dev/null || true
