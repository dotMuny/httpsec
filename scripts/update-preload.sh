#!/usr/bin/env bash
# Check a domain against the live Chrome HSTS preload list.
#
# data/hsts-preload.json is a curated subset — the full list has well over
# 100,000 entries and is not worth embedding in a CLI binary — so httpsec
# reports an absent domain as "not confirmed" rather than "not preloaded".
# This script answers the question properly, for one domain, by asking
# hstspreload.org.
#
#     ./scripts/update-preload.sh example.com
#
# With --add, the domain is appended to the embedded subset if it is preloaded,
# so the subset can be grown deliberately rather than by guesswork.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST="$ROOT/data/hsts-preload.json"
API="https://hstspreload.org/api/v2/status"

add=false
domain=""
for arg in "$@"; do
  case "$arg" in
    --add) add=true ;;
    -h|--help)
      sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *)  domain="$arg" ;;
  esac
done

if [ -z "$domain" ]; then
  echo "usage: $(basename "$0") <domain> [--add]" >&2
  exit 2
fi

echo "asking hstspreload.org about $domain"
response="$(curl -fsS --max-time 20 "$API?domain=$domain")" || {
  echo "could not reach $API" >&2
  exit 1
}

status="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","unknown"))')"
echo "live status: $status"

case "$status" in
  preloaded) ;;
  *)
    echo "$domain is not preloaded (status: $status)."
    echo "Submit it at https://hstspreload.org/ once every subdomain is HTTPS-only."
    exit 0 ;;
esac

if python3 - "$LIST" "$domain" <<'PY'
import json, sys
entries = json.load(open(sys.argv[1]))["domains"]
sys.exit(0 if any(d["name"] == sys.argv[2] for d in entries) else 1)
PY
then
  echo "$domain is already in the embedded subset."
  exit 0
fi

echo "$domain is preloaded but not in the embedded subset."
if ! $add; then
  echo "Re-run with --add to append it."
  exit 0
fi

python3 - "$LIST" "$domain" <<'PY'
import json, sys
path, domain = sys.argv[1], sys.argv[2]
with open(path) as fh:
    data = json.load(fh)
data["domains"].append({"name": domain, "include_subdomains": True})
data["domains"].sort(key=lambda d: d["name"])
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print(f"added {domain} to {path}")
PY

echo "Remember to update the \"updated\" date in $LIST and run: make test"
