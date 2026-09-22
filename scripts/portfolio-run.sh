#!/usr/bin/env bash
# Portfolio demo runner.
#
#   ./scripts/portfolio-run.sh          list the scenes
#   ./scripts/portfolio-run.sh 2        run scene 2 only (screenshot this)
#   ./scripts/portfolio-run.sh all      run every scene in order
#
# Each scene clears the screen and prints one self-contained result, so a
# screenshot of the terminal needs no cropping or editing. Scenes are
# independent except 8, which seals a baseline and then breaks something.
set -uo pipefail
cd "$(dirname "$0")/.."

DATE="2026-09-22"
PY="python3 vra.py"

banner() {
  clear 2>/dev/null || true
  echo
  echo "════════════════════════════════════════════════════════════════════"
  echo "  SCENE $1 — $2"
  echo "════════════════════════════════════════════════════════════════════"
  echo
}

pause() { echo; echo "── screenshot now, then press enter ──"; read -r _; }

scene_1() {
  banner 1 "The test suite"
  python3 -m unittest discover -s tests -t . 2>&1 | tail -4
}

scene_2() {
  banner 2 "The blind spot — hash passes, signature fails"
  $PY cip gate --package SPS-421-4.7.2 --date "$DATE" --offline --no-color
  rc=$?   # capture immediately: any command in between resets $?
  echo
  echo "exit code: $rc   (1 = do not deploy)"
}

scene_3() {
  banner 3 "Negative control — a clean package is accepted"
  $PY cip gate --package KG-RTU-100-2.4.0 \
    --grid-dir sandbox/procurement/kestrel-grid --date "$DATE" --offline --no-color
  rc=$?
  echo
  echo "exit code: $rc   (0 = safe to deploy)"
}

scene_4() {
  banner 4 "A new plant's firmware delivery — 12 packages, 6 vendors"
  $PY cip commission --plant "Cypress Bend Energy Center" \
    --batch sandbox/commissioning/cypress-bend --date "$DATE" --no-color 2>&1 | head -28
}

scene_5() {
  banner 5 "Reading a vendor's contract — what the code refused to accept"
  $PY cip onboard --vendor "Kestrel Grid Systems" \
    --docs sandbox/procurement/kestrel-grid --date "$DATE" --offline --no-color 2>&1 | sed -n '1,34p'
}

scene_6() {
  banner 6 "Whole-estate assessment — two scoping populations"
  $PY cip --date "$DATE" --no-color 2>&1 | sed -n '1,14p'
}

scene_7() {
  banner 7 "Requirement coverage — every row has a denominator"
  $PY cip --date "$DATE" --no-color 2>&1 | sed -n '/Requirement coverage/,/^$/p' | head -24
}

scene_8() {
  banner 8 "Drift — seal the approved state, then change something"
  echo "1. sealing the current vendor posture"
  $PY cip seal --date "$DATE" --substations 300 --no-color >/dev/null 2>&1
  echo "   ✓ sealed"
  echo
  echo "2. simulating a vendor re-publishing a release under the same version"
  python3 - <<'PYEOF'
p = "sandbox/grid/firmware/HAL-MU-40-1.1.7.bin"
b = bytearray(open(p, "rb").read()); b[2048] ^= 0xFF
open(p, "wb").write(bytes(b))
print("   ✓ HAL-MU-40-1.1.7 re-published (one byte changed)")
PYEOF
  echo
  echo "3. next monitoring cycle:"
  $PY cip drift --date "$DATE" --substations 300 --no-color 2>&1 | grep -E "UNDECLARED|unchanged|undeclared change" | head -8
  git checkout -- sandbox/grid/ 2>/dev/null
}

scene_9() {
  banner 9 "The agent action ledger — auditing the AI itself"
  $PY cip gate --package SPS-421-4.7.2 --date "$DATE" --offline --no-color >/dev/null 2>&1
  $PY cip gate --package KG-RTU-100-2.4.0 --grid-dir sandbox/procurement/kestrel-grid \
    --date "$DATE" --offline --no-color >/dev/null 2>&1
  $PY cip agent-log --limit 4 --no-color
}

scene_10() {
  banner 10 "Proof the cryptography is real — flip one bit"
  python3 -m unittest tests.test_cip.CryptoIsReal -v 2>&1 | tail -12
}

scene_11() {
  banner 11 "The audit evidence pack"
  $PY cip --date "$DATE" --evidence --no-color >/dev/null 2>&1
  echo "  written to out/cip/"
  ls -la out/cip/
  echo
  echo "  open out/cip/evidence-pack.html in a browser and screenshot that page"
}

SCENES=(1 2 3 4 5 6 7 8 9 10 11)
TITLES=(
  "The test suite"
  "The blind spot — hash passes, signature fails   ★ MUST HAVE"
  "Negative control — clean package accepted       ★ MUST HAVE"
  "A new plant's firmware delivery                 ★ MUST HAVE"
  "Reading a vendor's contract                     ★ MUST HAVE"
  "Whole-estate assessment, two populations"
  "Requirement coverage with denominators"
  "Drift detection                                 ★ MUST HAVE"
  "The agent action ledger"
  "Proof the cryptography is real"
  "The audit evidence pack (browser shot)"
)

if [ $# -eq 0 ]; then
  echo
  echo "  Portfolio scenes — run one at a time and screenshot each"
  echo
  for i in "${!SCENES[@]}"; do
    printf "    %-3s %s\n" "${SCENES[$i]}" "${TITLES[$i]}"
  done
  echo
  echo "    ./scripts/portfolio-run.sh 2       one scene"
  echo "    ./scripts/portfolio-run.sh all     every scene, pausing between"
  echo
  exit 0
fi

if [ "$1" = "all" ]; then
  for n in "${SCENES[@]}"; do "scene_$n"; pause; done
  exit 0
fi

"scene_$1"
