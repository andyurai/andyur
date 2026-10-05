#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
SPIKE="$ROOT/infra/sender-binding-spike"
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
CONFIG="$SPIKE/envoy-feasibility.yaml"
GATE="$SPIKE/envoy_runtime_gate.py"
LOCK="$SPIKE/runtime-requirements.txt"
PREFLIGHT="$SPIKE/envoy_runtime_preflight.py"
SCHEMA_CHECKER="$SPIKE/envoy_feasibility_check.py"
SCHEMA_VERIFIER="$SPIKE/verify-envoy-feasibility.sh"
SCHEMA_RESULT="$SPIKE/result-envoy-feasibility-2026-08-14-macos-arm64.json"
IMAGE="docker.io/envoyproxy/envoy@sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66"
OUTPUT=${ANDYUR_ENVOY_RUNTIME_OUTPUT:-"$SPIKE/result-envoy-runtime-2026-08-14-macos-arm64.json"}
TMP=$(mktemp -d)
RUN_ID="gate-$$"
VERSION_CONTAINER="andyur-envoy-runtime-$RUN_ID-version"
export ANDYUR_ENVOY_RUNTIME_RUN_ID="$RUN_ID"

run_bounded() {
  seconds=$1
  shift
  "$PYTHON" - "$seconds" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

process = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    raise SystemExit(process.wait(timeout=float(sys.argv[1])))
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    limit = time.monotonic() + 1.0
    while time.monotonic() < limit:
        try:
            os.killpg(process.pid, 0)
        except (ProcessLookupError, PermissionError):
            break
        time.sleep(0.02)
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    limit = time.monotonic() + 1.0
    while time.monotonic() < limit:
        try:
            os.killpg(process.pid, 0)
        except (ProcessLookupError, PermissionError):
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("timed-out process group survived")
    raise
PY
}

cleanup() {
  ids=$(docker ps -aq --filter "name=^/andyur-envoy-runtime-$RUN_ID-" 2>/dev/null || true)
  if [ -n "$ids" ]; then
    # IDs are produced by Docker from the exact per-run name prefix.
    run_bounded 10 docker rm -f $ids >/dev/null 2>&1 || true
  fi
  find "$TMP" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$TMP" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

rm -f "$OUTPUT"
if [ "$(uname -m)" != "arm64" ]; then
  echo "this checked artifact requires an arm64 host" >&2
  exit 1
fi

run_bounded 20 "$PYTHON" -m venv "$TMP/venv"
run_bounded 45 "$TMP/venv/bin/python" -m pip install --disable-pip-version-check --require-hashes -r "$LOCK" >"$TMP/install.txt"
GATE_PYTHON="$TMP/venv/bin/python"

# Cross-artifact continuity is executable, including the stale-schema defect.
run_bounded 5 "$GATE_PYTHON" "$PREFLIGHT" "$CONFIG" "$SCHEMA_RESULT" "$SCHEMA_CHECKER" "$SCHEMA_VERIFIER" >"$TMP/preflight.json"
"$GATE_PYTHON" - "$SCHEMA_RESULT" "$TMP/stale-schema.json" <<'PY'
import json
from pathlib import Path
import sys
source, target = map(Path, sys.argv[1:])
value = json.loads(source.read_text())
value["checker_sha256"] = "0" * 64
target.write_text(json.dumps(value))
PY
if run_bounded 5 "$GATE_PYTHON" "$PREFLIGHT" "$CONFIG" "$TMP/stale-schema.json" "$SCHEMA_CHECKER" "$SCHEMA_VERIFIER" >"$TMP/stale.out" 2>&1; then
  echo "stale schema evidence mutation stayed green" >&2
  exit 1
fi
grep -F "does not bind the current checker_sha256" "$TMP/stale.out" >/dev/null

# Exact false-green mutation: optimized mode must be rejected before traffic.
if run_bounded 5 env PYTHONOPTIMIZE=1 "$GATE_PYTHON" "$GATE" --config "$CONFIG" --output "$TMP/optimized.json" >"$TMP/optimized.out" 2>&1; then
  echo "optimized Python mutation stayed green" >&2
  exit 1
fi
grep -F "security gate refuses optimized Python" "$TMP/optimized.out" >/dev/null

if run_bounded 5 env HTTP_PROXY=http://127.0.0.1:9 "$GATE_PYTHON" "$GATE" --config "$CONFIG" --output "$TMP/proxy.json" >"$TMP/proxy.out" 2>&1; then
  echo "ambient proxy mutation stayed green" >&2
  exit 1
fi
grep -F "unsealed transport/import environment" "$TMP/proxy.out" >/dev/null

run_bounded 20 docker run --name "$VERSION_CONTAINER" --rm --platform linux/arm64 "$IMAGE" envoy --version >"$TMP/version.txt"
grep -F '/1.39.0/Clean/RELEASE/BoringSSL' "$TMP/version.txt" >/dev/null
run_bounded 180 env -u PYTHONPATH -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u REQUESTS_CA_BUNDLE -u CURL_CA_BUNDLE \
  "$GATE_PYTHON" "$GATE" --config "$CONFIG" --output "$TMP/raw.json"

"$GATE_PYTHON" - "$CONFIG" "$GATE" "$0" "$LOCK" "$PREFLIGHT" "$SCHEMA_RESULT" "$TMP/version.txt" "$TMP/raw.json" "$OUTPUT" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

config, gate, verifier, lock, preflight, schema_result, version, raw, output = map(Path, sys.argv[1:])
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
result = json.loads(raw.read_text())
assert result["status"] == "pass"
result["evidence_inputs"] = {
    "config_sha256": sha(config),
    "gate_sha256": sha(gate),
    "verifier_sha256": sha(verifier),
    "requirements_sha256": sha(lock),
    "preflight_sha256": sha(preflight),
    "schema_artifact_sha256": sha(schema_result),
}
result["envoy_version"] = version.read_text().strip()
result["python"] = sys.version
result["python_packages"] = {"requests": __import__("requests").__version__, "PyYAML": __import__("yaml").__version__}
result["optimized_python_rejected"] = True
target = output.resolve()
target.parent.mkdir(parents=True, exist_ok=True)
temporary = target.with_suffix(target.suffix + ".tmp")
temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
os.replace(temporary, target)
print(json.dumps(result, sort_keys=True))
PY

shasum -a 256 "$OUTPUT"
echo "PASS: bounded real-Envoy runtime subset; listed composition blockers remain STOP"
