#!/bin/sh
# Run the BYOA multi-framework proof (ADR-008 acceptance gate #7): real
# LangGraph and OpenAI Agents SDK agents through the same controls. exec, no
# pipes -- the gate's exit status IS the verdict.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"
exec "$PLATFORM/.venv/bin/python" "$HERE/framework_gate.py" "$@"
