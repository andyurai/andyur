#!/usr/bin/env bash
# Create an agent with TEN tools to test tool selection, in one command.
#
#   ./demos/select-tools/run.sh [agent-name]     (default: opsbot)
#
# Tracked files in this folder:
#   instructions.md   generic job (does NOT name any tool, so the agent must pick)
#   tool_server.py    ten tools (ci_status, get_oncall, rollback_deploy, ...)
# run.sh generates mcp.json (needs this machine's absolute paths).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
NAME="${1:-opsbot}"

cat > "$DIR/mcp.json" <<JSON
{ "mcpServers": { "ops": {
    "command": "$ROOT/.venv/bin/python",
    "args": ["$DIR/tool_server.py"] } } }
JSON

"$ROOT/andyur-cli" agents create "$NAME" \
  --description "ops assistant with ten tools" \
  --instructions-file "$DIR/instructions.md" \
  --mcp-file          "$DIR/mcp.json"

cat <<EOF

created '$NAME' with 10 tools. ask it different things and watch which it picks:
  ./andyur-cli agents trigger $NAME --reason 'What is the CI status of checkout-service?'   # -> ci_status
  ./andyur-cli agents trigger $NAME --reason 'Who is on call for the payments team?'        # -> get_oncall
  ./andyur-cli agents trigger $NAME --reason 'Roll back deploy-31.'                          # -> rollback_deploy
  ./andyur-cli agents trigger $NAME --reason 'What is the p99 latency of search-service?'    # -> query_metric
then read the exchange:
  ./andyur-cli agents runs $NAME
  ./andyur-cli agents transcript $NAME <run-id>
EOF
