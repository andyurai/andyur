#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REF="$ROOT/infra/reference-as"
WORK="$(mktemp -d)"
PORT="${ANDYUR_PHASE2A_PORT:-$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()
PY
)}"
AS_PID=""
cleanup() {
  if [ -n "$AS_PID" ]; then
    kill "$AS_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$AS_PID" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$AS_PID" 2>/dev/null; then kill -KILL "$AS_PID" 2>/dev/null || true; fi
    wait "$AS_PID" 2>/dev/null || true
  fi
  find "$WORK" -depth -delete
}
trap cleanup EXIT

run_bounded() {
  local seconds="$1"; shift
  python3 - "$seconds" "$@" <<'PY'
import os, signal, subprocess, sys, time
process = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    returncode = process.wait(timeout=float(sys.argv[1]))
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        pass
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("timed-out process group survived SIGKILL")
    raise
if returncode:
    raise subprocess.CalledProcessError(returncode, sys.argv[2:])
PY
}

next_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()
PY
}

start_as() {
  local binary="$1" required="$2" log="$3"
  PORT="$(next_port)"
  BASE="https://localhost:$PORT"
  ANDYUR_REFAS_ADDR="127.0.0.1:$PORT" \
  ANDYUR_REFAS_ISSUER="$BASE" \
  ANDYUR_REFAS_DATA="$WORK/reference-as-src/data" \
  ANDYUR_REFAS_TLS_CERT="$WORK/cert.pem" \
  ANDYUR_REFAS_TLS_KEY="$WORK/key.pem" \
  ANDYUR_REFAS_DPOP_REQUIRED="$required" \
    "$binary" >"$log" 2>&1 &
  AS_PID=$!
  for _ in $(seq 1 30); do
    kill -0 "$AS_PID" 2>/dev/null || { cat "$log" >&2; exit 1; }
    if curl --silent --fail --connect-timeout 1 --max-time 2 --cacert "$WORK/cert.pem" "$BASE/.well-known/openid-configuration" >/dev/null; then return; fi
    sleep 0.2
  done
  echo "reference AS readiness deadline exceeded" >&2
  exit 1
}

stop_as() {
  kill "$AS_PID" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$AS_PID" 2>/dev/null || break; sleep 0.1; done
  if kill -0 "$AS_PID" 2>/dev/null; then
    kill -KILL "$AS_PID" 2>/dev/null || true
    wait "$AS_PID" 2>/dev/null || true
    AS_PID=""
    return 1
  fi
  wait "$AS_PID" 2>/dev/null || true
  AS_PID=""
  ! (echo >/dev/tcp/127.0.0.1/${PORT}) 2>/dev/null
}

run_gate() {
  local output="$1"
  run_bounded 40 "$WORK/venv/bin/python" "$HERE/phase2a_gate.py" \
    --base "$BASE" --cert "$WORK/cert.pem" --reference-dir "$WORK/reference-as-src" --output "$output"
}

command -v go >/dev/null
command -v openssl >/dev/null
if run_bounded 0.2 python3 -c \
  'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(20)"]); open(sys.argv[1],"w").write(str(p.pid)); time.sleep(20)' \
  "$WORK/grandchild.pid" >/dev/null 2>&1; then
  echo "process-group timeout mutation unexpectedly completed" >&2; exit 1
fi
grandchild_pid="$(cat "$WORK/grandchild.pid")"
if kill -0 "$grandchild_pid" 2>/dev/null; then
  echo "process-group timeout left a grandchild alive" >&2; exit 1
fi
if (echo >/dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then
  echo "port $PORT is already in use" >&2; exit 1
fi

run_bounded 30 python3 -m venv "$WORK/venv"
run_bounded 120 "$WORK/venv/bin/pip" install --disable-pip-version-check --require-hashes \
  -r "$HERE/requirements.txt"
run_bounded 15 openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1
rsync -a --exclude 'patches/go-oidc' "$REF/" "$WORK/reference-as-src/"
GOIDC_OUT="$WORK/reference-as-src/patches/go-oidc" \
  run_bounded 120 "$WORK/reference-as-src/patches/apply.sh"
run_bounded 30 go test -C "$WORK/reference-as-src" ./...
run_bounded 60 go build -C "$WORK/reference-as-src" -o "$WORK/reference-as" .

OUTPUT="${ANDYUR_SENDER_BINDING_PHASE2A_OUTPUT:-$WORK/final-result.json}"
IN_PROGRESS="$WORK/result-in-progress.json"

# Exact required-proof configuration mutation: the same gate must turn red.
start_as "$WORK/reference-as" 0 "$WORK/optional.log"
if run_gate "$WORK/optional-result.json" >"$WORK/optional-gate.log" 2>&1; then
  echo "required-DPoP mutation stayed green" >&2; exit 1
fi
grep -q 'negative missing_proof issued' "$WORK/optional-gate.log" || {
  cat "$WORK/optional-gate.log" >&2; exit 1;
}
stop_as || { echo "optional-profile AS teardown failed" >&2; exit 1; }

# Exact replay-enforcement mutation: remove the configured JTI consumer, prove
# replay issuance makes the gate red, restore the source byte-for-byte.
cp "$WORK/reference-as-src/main.go" "$WORK/main.go.original"
perl -0pi -e 's/\n\t\tprovider\.WithJTIConsumer\(consumeJTI\),/\n\t\t\/\/ MUTATION: JTI consumer removed/' "$WORK/reference-as-src/main.go"
grep -q 'MUTATION: JTI consumer removed' "$WORK/reference-as-src/main.go"
run_bounded 60 go build -C "$WORK/reference-as-src" -o "$WORK/reference-as-no-replay" .
start_as "$WORK/reference-as-no-replay" 1 "$WORK/no-replay.log"
if run_gate "$WORK/no-replay-result.json" >"$WORK/no-replay-gate.log" 2>&1; then
  echo "JTI-consumer mutation stayed green" >&2; exit 1
fi
grep -q 'negative replayed_jti issued' "$WORK/no-replay-gate.log" || {
  cat "$WORK/no-replay-gate.log" >&2; exit 1;
}
stop_as || { echo "replay-mutant AS teardown failed" >&2; exit 1; }
cp "$WORK/main.go.original" "$WORK/reference-as-src/main.go"
cmp "$WORK/main.go.original" "$WORK/reference-as-src/main.go"

# Restored positive run. Evidence is finalized only after bounded AS teardown.
start_as "$WORK/reference-as" 1 "$WORK/reference-as.log"
run_gate "$IN_PROGRESS"
stop_as || { rm -f "$IN_PROGRESS"; echo "reference AS teardown failed" >&2; exit 1; }
mkdir -p "$(dirname "$OUTPUT")"
mv "$IN_PROGRESS" "$OUTPUT"
sha256sum "$OUTPUT" 2>/dev/null || shasum -a 256 "$OUTPUT"
echo "PASS: disposable sender-binding Phase-2a reference-AS gate"
