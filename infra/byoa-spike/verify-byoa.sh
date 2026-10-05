#!/bin/sh
# Run the BYOA runtime-v1 live gate (ADR-008 C1) with the repo venv.
# exec, no pipes: the gate's exit status IS the verdict, and piping it
# through anything is how false greens happen.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"
exec "$PLATFORM/.venv/bin/python" "$HERE/byoa_gate.py" "$@"
