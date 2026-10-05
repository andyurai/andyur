#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
SPIKE="$ROOT/infra/sender-binding-spike"
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
CONFIG="$SPIKE/envoy-feasibility.yaml"
CHECKER="$SPIKE/envoy_feasibility_check.py"
IMAGE="docker.io/envoyproxy/envoy@sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66"
OUTPUT=${ANDYUR_ENVOY_FEASIBILITY_OUTPUT:-"$SPIKE/result-envoy-feasibility-2026-08-14-macos-arm64.json"}
TMP=$(mktemp -d)
VERSION_CONTAINER="andyur-envoy-feasibility-version-$$"
VALIDATE_CONTAINER="andyur-envoy-feasibility-validate-$$"

run_bounded() {
  seconds=$1
  shift
  "$PYTHON" - "$seconds" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

deadline = float(sys.argv[1])
process = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    raise SystemExit(process.wait(timeout=deadline))
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    limit = time.monotonic() + 1.0
    while time.monotonic() < limit:
        try:
            os.killpg(process.pid, 0)
        except (ProcessLookupError, PermissionError):
            break
        time.sleep(0.02)
    try:
        os.killpg(process.pid, 0)
    except (ProcessLookupError, PermissionError):
        pass
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
        raise RuntimeError("timed-out process group survived SIGKILL")
    raise
PY
}

cleanup() {
  run_bounded 10 docker rm -f "$VERSION_CONTAINER" "$VALIDATE_CONTAINER" >/dev/null 2>&1 || true
  find "$TMP" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$TMP" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

rm -f "$OUTPUT"
if [ "$(uname -m)" != "arm64" ]; then
  echo "this checked artifact requires an arm64 host" >&2
  exit 1
fi

# Exact timeout mutation: the child and its TERM-ignoring grandchild must both
# disappear when the process-group deadline fires.
if run_bounded 0.2 sh -c 'trap "" TERM; sleep 30 & echo $! >"$1"; wait' _ "$TMP/grandchild.pid" 2>"$TMP/timeout.txt"; then
  echo "timeout mutation unexpectedly completed" >&2
  exit 1
fi
grep -F "subprocess.TimeoutExpired" "$TMP/timeout.txt" >/dev/null
GRANDCHILD=$(cat "$TMP/grandchild.pid")
if kill -0 "$GRANDCHILD" 2>/dev/null; then
  echo "timeout mutation leaked a grandchild" >&2
  exit 1
fi

"$PYTHON" "$CHECKER" "$CONFIG" --self-test >"$TMP/policy.json"
run_bounded 30 docker buildx imagetools inspect "$IMAGE" >"$TMP/image.txt"
grep -F "Digest:    sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66" "$TMP/image.txt" >/dev/null
run_bounded 30 docker buildx imagetools inspect "$IMAGE" --raw >"$TMP/index.json"
run_bounded 30 docker run --name "$VERSION_CONTAINER" --rm --platform linux/arm64 "$IMAGE" envoy --version >"$TMP/version.txt"
grep -F '/1.39.0/Clean/RELEASE/BoringSSL' "$TMP/version.txt" >/dev/null
run_bounded 30 docker run --name "$VALIDATE_CONTAINER" --rm --platform linux/arm64 -v "$CONFIG:/config.yaml:ro" "$IMAGE" \
  envoy --mode validate -c /config.yaml --log-level error >"$TMP/validate.txt" 2>&1
grep -F "configuration '/config.yaml' OK" "$TMP/validate.txt" >/dev/null

"$PYTHON" - "$CONFIG" "$CHECKER" "$0" "$TMP/policy.json" "$TMP/version.txt" "$TMP/index.json" "$OUTPUT" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

config, checker, verifier, policy, version, index_file, output = map(Path, sys.argv[1:])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
index = json.loads(index_file.read_text())
platforms = {(m["platform"]["os"], m["platform"]["architecture"]): m["digest"] for m in index["manifests"]}
assert platforms[("linux", "amd64")] == "sha256:f6e2f57b1bef8235083a2553b523508cf97d8991c893fd2aae3a94a6b21096a2"
assert platforms[("linux", "arm64")] == "sha256:5edd669228659835ac243e3ffa5c08a65e92bb267d56da5c28317dbcf5a70292"
result = {
    "status": "pass",
    "scope": "schema-and-closed-policy-only",
    "image_index": "sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66",
    "linux_amd64_manifest": "sha256:f6e2f57b1bef8235083a2553b523508cf97d8991c893fd2aae3a94a6b21096a2",
    "linux_arm64_manifest": "sha256:5edd669228659835ac243e3ffa5c08a65e92bb267d56da5c28317dbcf5a70292",
    "envoy_version": version.read_text().strip(),
    "executed_platform": "linux/arm64",
    "config_sha256": sha(config),
    "checker_sha256": sha(checker),
    "verifier_sha256": sha(verifier),
    "policy_mutations": json.loads(policy.read_text())["mutations"],
    "schema_validation": "configuration /config.yaml OK",
    "runtime_feasibility": "not_tested",
}
target = output.resolve()
target.parent.mkdir(parents=True, exist_ok=True)
temporary = target.with_suffix(target.suffix + ".tmp")
temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
os.replace(temporary, target)
print(json.dumps(result, sort_keys=True))
PY

shasum -a 256 "$OUTPUT"
echo "PASS: Envoy schema/policy feasibility only; runtime remains STOP"
