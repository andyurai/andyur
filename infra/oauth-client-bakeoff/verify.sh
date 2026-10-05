#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v openssl >/dev/null
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install --disable-pip-version-check --require-hashes \
  -r "$HERE/requirements.txt"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1

OUTPUT="${ANDYUR_BAKEOFF_OUTPUT:-$WORK/result.json}"
"$WORK/venv/bin/python" "$HERE/bakeoff.py" \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
  --output "$OUTPUT" "${@}"
sha256sum "$OUTPUT" 2>/dev/null || shasum -a 256 "$OUTPUT"

echo "PASS: client TLS/concurrency smoke gate"
echo "Run semantic gates separately (they manage longer-lived infrastructure):"
echo "  $ROOT/run.sh u4-keycloak"
echo "  $ROOT/infra/reference-as/verify.sh"
