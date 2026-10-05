#!/usr/bin/env bash
# Record ONE current exec/v1 conformance evidence file for a stock workload.
#
# `andyur agents conformance --evidence <path>` writes where it is told, and the
# RC gate tells it a DATED path -- so a second run leaves two files in
# demos/<name>/evidence/ and every consumer that says `[path] = sorted(glob)`
# breaks. That is not hypothetical: the first RC-gate run left a second file
# beside the first and the next suite run failed with "too many values to
# unpack (expected 1)", which names neither the demo nor the gate.
#
# One demo, one current conformance record. The old one is removed BEFORE the
# new one is produced, so a failed run leaves the directory empty rather than
# leaving stale evidence that would read as current.
set -euo pipefail
DEMO="${1:?usage: record-conformance.sh <demo-dir> <input-file>}"
INPUT="${2:?usage: record-conformance.sh <demo-dir> <input-file>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$HERE"
PY="${ANDYUR_PY:-$HERE/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

EVIDENCE_DIR="$DEMO/evidence"
mkdir -p "$EVIDENCE_DIR"
rm -f "$EVIDENCE_DIR"/result-exec-v1-*.json
EVIDENCE="$EVIDENCE_DIR/result-exec-v1-$(date +%Y-%m-%d)-$(uname -s | tr A-Z a-z)-$(uname -m).json"

"$PY" -m andyur.cli agents conformance "$DEMO/agent.json" \
  --evidence "$EVIDENCE" --input "$DEMO/$INPUT"

# The property the consumers rely on, asserted here rather than discovered by
# whichever test globs the directory next.
count="$(ls -1 "$EVIDENCE_DIR"/result-exec-v1-*.json | wc -l | tr -d ' ')"
[ "$count" = "1" ] || { echo "expected exactly one conformance record, found $count"; exit 1; }
echo "recorded $EVIDENCE"
