#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REF="$ROOT/infra/reference-as"
WORK="$(mktemp -d)"
AS_PID=""
port=""
stop_as() {
  [ -n "$AS_PID" ] || return 0
  kill "$AS_PID" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$AS_PID" 2>/dev/null || break; sleep 0.1; done
  if kill -0 "$AS_PID" 2>/dev/null; then kill -KILL "$AS_PID" 2>/dev/null || true; fi
  wait "$AS_PID" 2>/dev/null || true
  AS_PID=""
  if [ -n "$port" ] && (echo >/dev/tcp/127.0.0.1/${port}) 2>/dev/null; then return 1; fi
}
cleanup() {
  stop_as || true
  find "$WORK" -depth -delete
}
trap cleanup EXIT

run_bounded() {
  local seconds="$1"; shift
  python3 - "$seconds" "$@" <<'PY'
import os, signal, subprocess, sys, time
p = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    rc = p.wait(timeout=float(sys.argv[1]))
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGTERM)
    deadline=time.monotonic()+1
    while time.monotonic()<deadline:
        try: os.killpg(p.pid,0)
        except (ProcessLookupError, PermissionError): break
        time.sleep(0.02)
    try: os.killpg(p.pid,0)
    except (ProcessLookupError, PermissionError): pass
    else: os.killpg(p.pid,signal.SIGKILL)
    p.wait()
    deadline=time.monotonic()+1
    while time.monotonic()<deadline:
        try: os.killpg(p.pid,0)
        except (ProcessLookupError, PermissionError): break
        time.sleep(0.02)
    else: raise RuntimeError("timed-out process group survived SIGKILL")
    raise
if rc: raise subprocess.CalledProcessError(rc, sys.argv[2:])
PY
}

port="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
)"
# Failure-path teardown mutation: the shared stopper must kill a process that
# ignores TERM rather than hanging the EXIT trap forever.
python3 -c 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(20)' &
AS_PID=$!
sleep 0.1
stop_as || { echo "TERM-ignoring teardown mutation failed" >&2; exit 1; }
run_bounded 30 python3 -m venv "$WORK/venv"
run_bounded 120 "$WORK/venv/bin/pip" install --disable-pip-version-check --require-hashes -r "$HERE/requirements.txt"
run_bounded 15 openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1
rsync -a --exclude 'patches/go-oidc' "$REF/" "$WORK/reference-as-src/"
GOIDC_OUT="$WORK/reference-as-src/patches/go-oidc" run_bounded 120 "$WORK/reference-as-src/patches/apply.sh"
run_bounded 30 go test -C "$WORK/reference-as-src" ./...
run_bounded 60 go build -C "$WORK/reference-as-src" -o "$WORK/reference-as" .

base="https://localhost:$port"
ANDYUR_REFAS_ADDR="127.0.0.1:$port" ANDYUR_REFAS_ISSUER="$base" \
ANDYUR_REFAS_DATA="$WORK/reference-as-src/data" ANDYUR_REFAS_TLS_CERT="$WORK/cert.pem" \
ANDYUR_REFAS_TLS_KEY="$WORK/key.pem" ANDYUR_REFAS_DPOP_REQUIRED=1 \
  "$WORK/reference-as" >"$WORK/reference-as.log" 2>&1 &
AS_PID=$!
for _ in $(seq 1 30); do
  kill -0 "$AS_PID" 2>/dev/null || { cat "$WORK/reference-as.log" >&2; exit 1; }
  curl -sf --connect-timeout 1 --max-time 2 --cacert "$WORK/cert.pem" "$base/.well-known/openid-configuration" >/dev/null && break
  sleep 0.2
done
curl -sf --connect-timeout 1 --max-time 2 --cacert "$WORK/cert.pem" "$base/.well-known/openid-configuration" >/dev/null

in_progress="$WORK/result.json"
run_bounded 90 "$WORK/venv/bin/python" "$HERE/phase2b_gate.py" --as-base "$base" \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" --reference-dir "$WORK/reference-as-src" \
  --output "$in_progress"
stop_as || { rm -f "$in_progress"; echo "reference AS teardown failed" >&2; exit 1; }
output="${ANDYUR_SENDER_BINDING_PHASE2B_OUTPUT:-$WORK/final.json}"
mkdir -p "$(dirname "$output")"; mv "$in_progress" "$output"
sha256sum "$output" 2>/dev/null || shasum -a 256 "$output"
echo "PASS: disposable sender-binding Phase-2b resource-PEP gate"
