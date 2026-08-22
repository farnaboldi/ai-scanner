#!/bin/bash
# Lint with two Java linters
#
# Usage:
#   bench/lint.sh --gjf   also runs google-java-format
#
# Output: bench/results/lint/{checkstyle.txt, pmd.csv, convergence.txt}
# ============================================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE" || exit 1
SRC="$HERE/src/main/java/com/ioactive/aiscanner"
OUT="$HERE/bench/results/lint"; mkdir -p "$OUT"
say(){ echo "[lint] $*" >&2; }
[ -d "$SRC" ] || { say "source dir not found: $SRC"; exit 1; }

# ---- 1) Checkstyle (curated config) --------------------------------------------------------
CS_OUT="$OUT/checkstyle.txt"; : > "$CS_OUT"; CS_OK=0
if command -v checkstyle >/dev/null 2>&1; then
  say "running Checkstyle (bench/checkstyle.xml)…"
  checkstyle -c "$HERE/bench/checkstyle.xml" "$SRC" >"$CS_OUT" 2>"$OUT/checkstyle.err" || true
  # Checkstyle exits non-zero when violations exist — that is expected; success = it produced audit output.
  grep -q 'Starting audit' "$CS_OUT" && CS_OK=1 || say "Checkstyle produced no audit (see $OUT/checkstyle.err)"
else
  say "checkstyle not found — skipping (install: brew install checkstyle). PMD still runs."
fi

# ---- 2) PMD rule engine (quickstart ruleset) -----------------------------------------------
PMD_OUT="$OUT/pmd.csv"; : > "$PMD_OUT"; PMD_OK=0
if command -v pmd >/dev/null 2>&1; then
  say "running PMD check (bench/pmd-ruleset.xml)…"
  pmd check -d "$SRC" -R "$HERE/bench/pmd-ruleset.xml" -f csv >"$PMD_OUT" 2>"$OUT/pmd.err" || true
  [ -s "$PMD_OUT" ] && PMD_OK=1 || say "PMD produced no output (see $OUT/pmd.err)"
else
  say "pmd not found — skipping (install: brew install pmd)."
fi

# ---- 3) optional google-java-format dry-run (NOT part of convergence) ----------------------
if [ "${1:-}" = "--gjf" ]; then
  if command -v google-java-format >/dev/null 2>&1; then
    say "google-java-format --dry-run (Google 2-space style — informational, this repo is 4-space):"
    find "$SRC" -name '*.java' -print0 | xargs -0 google-java-format -n 2>/dev/null | sed 's#^#  would reformat: #' | head -20
    echo "  (…files above differ from Google style; expected — repo uses 4-space)" >&2
  else
    say "google-java-format not found (install: brew install google-java-format)"
  fi
fi

# ---- 4) per-tool totals + CONVERGENCE (both flag the same file:line) -----------------------
python3 - "$CS_OUT" "$PMD_OUT" "$CS_OK" "$PMD_OK" >"$OUT/convergence.txt" <<'PY'
import csv, os, re, sys
cs_file, pmd_csv, cs_ok, pmd_ok = sys.argv[1], sys.argv[2], sys.argv[3]=="1", sys.argv[4]=="1"

# Checkstyle plain output: "[WARN] /abs/File.java:LINE[:COL]: message [RuleName]"
cs=[]  # (basename, line, rule)
if cs_ok:
    rx=re.compile(r'([^/\s:]+\.java):(\d+)(?::\d+)?:\s*(.*?)\s*(?:\[(\w+)\])?\s*$')
    for ln in open(cs_file, errors="replace"):
        m=rx.search(ln)
        if m: cs.append((m.group(1), int(m.group(2)), m.group(4) or "?"))

# PMD check CSV: "Problem","Package","File","Priority","Line","Description","Rule set","Rule"
pmd=[]
if pmd_ok:
    r=list(csv.reader(open(pmd_csv)))
    if r:
        hdr=[h.strip('"').lower() for h in r[0]]
        fi = hdr.index("file") if "file" in hdr else 2
        li = hdr.index("line") if "line" in hdr else 4
        ri = hdr.index("rule") if "rule" in hdr else len(hdr)-1
        for row in r[1:]:
            if len(row)<=max(fi,li): continue
            try: pmd.append((os.path.basename(row[fi]), int(row[li]), row[ri] if len(row)>ri else "?"))
            except Exception: pass

def top(items):
    from collections import Counter
    c=Counter(rule for _,_,rule in items)
    return ", ".join(f"{k}×{v}" for k,v in c.most_common(6))

print("==== lint ====")
print(f"Checkstyle : {'%d violations' % len(cs) if cs_ok else 'not run'}")
if cs_ok and cs: print(f"   top: {top(cs)}")
print(f"PMD        : {'%d violations' % len(pmd) if pmd_ok else 'not run'}")
if pmd_ok and pmd: print(f"   top: {top(pmd)}")

if not (cs_ok and pmd_ok):
    print("\n(convergence needs BOTH linters — install the missing one and re-run)")
    sys.exit(0)

cs_at={(f,l) for f,l,_ in cs}
pmd_at={(f,l) for f,l,_ in pmd}
conv=sorted(cs_at & pmd_at)
print(f"\nCONVERGENT (BOTH flag the same file:line): {len(conv)}\n")
csr={(f,l):r for f,l,r in cs}; pmr={(f,l):r for f,l,r in pmd}
for (f,l) in conv:
    print(f"  {f}:{l}   checkstyle[{csr.get((f,l),'?')}]  +  pmd[{pmr.get((f,l),'?')}]")
if not conv:
    print("  (no exact file:line overlap — the two catch different things; see per-tool lists above)")
PY
cat "$OUT/convergence.txt"
say "reports written under $OUT"
