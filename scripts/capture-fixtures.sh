#!/usr/bin/env bash
# Capture the Observation fixtures used by the analysis tests.
#
# These are recordings of real sites with deliberately varied postures: a few
# that get it right, one bare host, and the badssl.com family, which exists
# precisely so that tools like this one have broken TLS to test against.
#
# Re-run this only when you want to refresh the corpus. The tests never touch
# the network; they read what this script wrote.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${HTTPSEC_BIN:-$ROOT/bin/httpsec}"
OUT="$ROOT/testdata/observations"
mkdir -p "$OUT"

TARGETS=(
  "github.com"
  "mozilla.org"
  "cloudflare.com"
  "wikipedia.org"
  "stripe.com"
  "hstspreload.org"
  "example.com"
  "expired.badssl.com"
  "self-signed.badssl.com"
  "wrong.host.badssl.com"
  "tls-v1-0.badssl.com:1010"
  "no-sct.badssl.com"
)

for t in "${TARGETS[@]}"; do
  name="$(printf '%s' "$t" | tr -c 'a-zA-Z0-9._-' '_')"
  echo "capturing $t"
  "$BIN" scan "$t" --format json --output /dev/null \
      --save-observation "$OUT/$name.json" --budget 150s >/dev/null || \
      echo "  (captured with errors, which is often the point)"
done

python3 "$ROOT/scripts/anonymise-fixtures.py" "$OUT"
echo "done: $(ls -1 "$OUT" | wc -l) fixtures"
