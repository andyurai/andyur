#!/usr/bin/env bash
# Bring up the whole dual-control demo and run it with a REAL Andyur agent as the
# System Under Test. Starts: the app service (shared world), the Andyur control
# plane + a worker, then drives an episode. Tears everything down on exit.
#
#   ./demos/adsupport/run_demo.sh [scenario]      (default: payment_limit; 'all' for every one)
#
# Requires: ./run.sh setup already done, and ANTHROPIC_API_KEY in the repo .env.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # repo root
cd "$HERE"
PY="$HERE/.venv/bin/python"
SCEN="${1:-payment_limit}"

export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-$(grep -h '^ANTHROPIC_API_KEY=' "$HERE/.env" "$HERE/../.env" 2>/dev/null | head -1 | cut -d= -f2-)}"
export ANDYUR_LLM=api
export ANDYUR_AGENT_MODEL="${ANDYUR_AGENT_MODEL:-claude-haiku-4-5-20251001}"
export ADSUPPORT_MODEL="$ANDYUR_AGENT_MODEL"
export ADSUPPORT_APP_URL="http://127.0.0.1:8650"
export ANDYUR_DATA_DIR="$(mktemp -d)"
export ANDYUR_CONVERSATION_TURN_TTL_SECONDS=180
export PYTHONPATH="$HERE"

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
            pkill -f "demos.adsupport.mcp_support" 2>/dev/null || true; }
trap cleanup EXIT

echo "[demo] app service on :8650"
"$PY" -m uvicorn demos.adsupport.app_server:app --host 127.0.0.1 --port 8650 >/tmp/adsupport-appsvc.log 2>&1 & pids+=($!)
echo "[demo] andyur server on :8642"
"$PY" -m uvicorn andyur.server.app:app --host 127.0.0.1 --port 8642 >/tmp/adsupport-colserver.log 2>&1 & pids+=($!)
for _ in $(seq 1 30); do curl -sf http://127.0.0.1:8642/health >/dev/null 2>&1 && break; sleep 1; done
echo "[demo] andyur worker"
"$PY" -m andyur.daemon >/tmp/adsupport-daemon.log 2>&1 & pids+=($!)
sleep 3

"$PY" -m demos.adsupport.run_andyur --scenario "$SCEN" "${@:2}"
