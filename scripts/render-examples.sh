#!/usr/bin/env bash
# Regenerate the example reports and the README images.
#
# Everything here runs from the recorded fixtures, so it makes no network
# requests and produces the same output on every machine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${HTTPSEC_BIN:-$ROOT/bin/httpsec}"
EX="$ROOT/docs/examples"
IMG="$ROOT/docs/images"
mkdir -p "$EX" "$IMG"

GOOD="$ROOT/testdata/observations/github.com.json"
BAD="$ROOT/testdata/observations/example.com.json"

echo "example reports"
"$BIN" scan --from-observation "$GOOD" --format html     --output "$EX/report-good.html"     >/dev/null
"$BIN" scan --from-observation "$BAD"  --format html     --output "$EX/report-poor.html"     >/dev/null
"$BIN" scan --from-observation "$BAD"  --format json     --output "$EX/report-poor.json"     >/dev/null
"$BIN" scan --from-observation "$BAD"  --format markdown --output "$EX/report-poor.md"       >/dev/null
"$BIN" scan --from-observation "$GOOD" --format json     --output "$EX/report-good.json"     >/dev/null
"$BIN" remediate --report "$EX/report-poor.json" --server nginx --output "$EX/remediation-nginx.conf" >/dev/null
"$BIN" diff "$EX/report-poor.json" "$EX/report-good.json" --format markdown > "$EX/diff.md"

echo "README banner"
python3 "$ROOT/scripts/gen-banner.py"

echo "README images"
# --no-color is deliberately NOT passed: the renderer reads the real escape
# sequences so the picture matches what a terminal shows.
FORCE_COLOR=1 script -qec "$BIN scan --from-observation $BAD" /dev/null 2>/dev/null \
  | head -46 | python3 "$ROOT/scripts/ansi-to-svg.py" "$IMG/scan.svg" --title "httpsec scan example.com"

FORCE_COLOR=1 script -qec "$BIN scan --from-observation $BAD --explain-score" /dev/null 2>/dev/null \
  | sed -n '/SCORE EXPLANATION/,$p' | head -40 \
  | python3 "$ROOT/scripts/ansi-to-svg.py" "$IMG/explain-score.svg" --title "httpsec scan --explain-score"

FORCE_COLOR=1 script -qec "$BIN diff $EX/report-poor.json $EX/report-good.json" /dev/null 2>/dev/null \
  | head -32 | python3 "$ROOT/scripts/ansi-to-svg.py" "$IMG/diff.svg" --title "httpsec diff before.json after.json"

echo "done"
