#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'find "$WORK" -type f -delete; find "$WORK" -depth -type d -empty -delete' EXIT

run_bounded() {
  local seconds="$1"
  shift
  python3 - "$seconds" "$@" <<'PY'
import subprocess
import sys
subprocess.run(sys.argv[2:], check=True, timeout=float(sys.argv[1]))
PY
}

command -v openssl >/dev/null
run_bounded 10 python3 "$HERE/exclusion_gate.py" "$ROOT"
run_bounded 30 python3 -m venv "$WORK/venv"
run_bounded 120 "$WORK/venv/bin/pip" install --disable-pip-version-check --require-hashes \
  -r "$HERE/requirements.txt"

run_bounded 15 openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1

OUTPUT="${ANDYUR_SENDER_BINDING_OUTPUT:-$WORK/result.json}"
run_bounded 40 "$WORK/venv/bin/python" "$HERE/phase1_gate.py" \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" --output "$OUTPUT"
sha256sum "$OUTPUT" 2>/dev/null || shasum -a 256 "$OUTPUT"

echo "PASS: disposable sender-binding Phase-1 capability gate"
