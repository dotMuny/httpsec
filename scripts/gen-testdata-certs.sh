#!/usr/bin/env bash
# Generate the certificates the TLS tests serve.
#
# The tests need a server whose posture is deliberately wrong in specific
# ways, which no public host will reliably provide. Everything here is
# generated locally, is only ever bound to 127.0.0.1, and is committed so that
# `make test` works in a fresh clone without running this script.
#
# Re-run it if you need to refresh the fixtures:
#     ./scripts/gen-testdata-certs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/testdata/certs"
mkdir -p "$DIR"
cd "$DIR"

SUBJ_CA="/CN=httpsec test CA/O=httpsec testdata"
EXT="subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "generating a local CA"
openssl req -x509 -newkey rsa:2048 -keyout ca.key.pem -out ca.cert.pem \
  -days 3650 -nodes -sha256 -subj "$SUBJ_CA" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1

issue() {  # issue <name> <subject> <days> [extra openssl x509 args...]
  local name="$1" subj="$2" days="$3"; shift 3
  openssl req -newkey rsa:2048 -keyout "$name.key.pem" -out "$name.csr.pem" \
    -nodes -sha256 -subj "$subj" >/dev/null 2>&1
  openssl x509 -req -in "$name.csr.pem" -CA ca.cert.pem -CAkey ca.key.pem \
    -CAcreateserial -out "$name.cert.pem" -days "$days" \
    -extfile <(printf '%s\n' "$EXT") "$@" >/dev/null 2>&1
  rm -f "$name.csr.pem"
}

echo "good (valid, 2048-bit RSA, SHA-256)"
issue good "/CN=localhost/O=httpsec testdata" 3650 -sha256

echo "expiring (valid, expires in 10 days)"
issue expiring "/CN=localhost/O=httpsec testdata" 10 -sha256

echo "wronghost (valid chain, wrong SAN)"
openssl req -newkey rsa:2048 -keyout wronghost.key.pem -out wronghost.csr.pem \
  -nodes -sha256 -subj "/CN=not-the-host.invalid" >/dev/null 2>&1
openssl x509 -req -in wronghost.csr.pem -CA ca.cert.pem -CAkey ca.key.pem \
  -CAcreateserial -out wronghost.cert.pem -days 3650 -sha256 \
  -extfile <(printf '%s\n' "subjectAltName=DNS:not-the-host.invalid") >/dev/null 2>&1
rm -f wronghost.csr.pem

echo "selfsigned (chains to nothing)"
openssl req -x509 -newkey rsa:2048 -keyout selfsigned.key.pem -out selfsigned.cert.pem \
  -days 3650 -nodes -sha256 -subj "/CN=localhost/O=httpsec testdata selfsigned" \
  -addext "$EXT" >/dev/null 2>&1

echo "weakkey (1024-bit RSA)"
openssl req -newkey rsa:1024 -keyout weakkey.key.pem -out weakkey.csr.pem \
  -nodes -sha256 -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in weakkey.csr.pem -CA ca.cert.pem -CAkey ca.key.pem \
  -CAcreateserial -out weakkey.cert.pem -days 3650 -sha256 \
  -extfile <(printf '%s\n' "$EXT") >/dev/null 2>&1
rm -f weakkey.csr.pem

echo "sha1 (SHA-1 signature; OpenSSL 3 needs the legacy security level)"
openssl req -newkey rsa:2048 -keyout sha1.key.pem -out sha1.csr.pem \
  -nodes -sha256 -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in sha1.csr.pem -CA ca.cert.pem -CAkey ca.key.pem \
  -CAcreateserial -out sha1.cert.pem -days 3650 -sha1 \
  -extfile <(printf '%s\n' "$EXT") >/dev/null 2>&1 || \
  echo "  (SHA-1 issuance refused by this OpenSSL build; the SHA-1 test will skip)"
rm -f sha1.csr.pem

echo "expired (notAfter in the past)"
# openssl x509 cannot backdate before 3.2, so the expired certificate is issued
# through `openssl ca`, which takes explicit start and end dates everywhere.
cat > ca.cnf <<'CACNF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = .
database         = $dir/index.txt
serial           = $dir/serial
new_certs_dir    = $dir
certificate      = $dir/ca.cert.pem
private_key      = $dir/ca.key.pem
default_md       = sha256
policy           = policy_any
email_in_dn      = no
rand_serial      = no
unique_subject   = no
copy_extensions  = copy
[ policy_any ]
commonName = supplied
[ v3_ext ]
subjectAltName = DNS:localhost,IP:127.0.0.1
CACNF
: > index.txt
echo 1000 > serial
openssl req -newkey rsa:2048 -keyout expired.key.pem -out expired.csr.pem \
  -nodes -sha256 -subj "/CN=localhost" >/dev/null 2>&1
openssl ca -batch -config ca.cnf -in expired.csr.pem -out expired.cert.pem \
  -startdate 20200101000000Z -enddate 20210101000000Z -extensions v3_ext >/dev/null 2>&1 || \
  echo "  (this OpenSSL cannot backdate; the expiry test will skip)"

# openssl ca drops a copy of each issued certificate in new_certs_dir, named
# after its serial. Keep only the files the tests load.
for f in ./*.pem; do
  case "$(basename "$f")" in
    ca.cert.pem|ca.key.pem|good.*|expiring.*|wronghost.*|selfsigned.*|weakkey.*|sha1.*|expired.*) ;;
    *) rm -f "$f" ;;
  esac
done
rm -f ca.srl ca.cert.srl index.txt* serial* ca.cnf ./*.csr.pem
chmod 600 ./*.key.pem
echo "wrote $(ls -1 "$DIR" | wc -l) files to testdata/certs"
