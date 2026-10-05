#!/usr/bin/env bash
# Create a demo agent from the files in THIS folder, in one command.
#
#   ./demos/tool-agent/run.sh [agent-name]      (default: toolbot)
#
# All inputs are tracked files right here:
#   instructions.md   the agent's job
#   knowledge.md      what it knows
#   tool_server.py    its custom tool (ci_status)
# The one thing this script generates is mcp.json, because it needs THIS
# machine's absolute paths (an absolute path could not live in git).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # this folder
ROOT="$(cd "$DIR/../.." && pwd)"                        # repo root
NAME="${1:-toolbot}"

# generate mcp.json (tool config) with this machine's paths
cat > "$DIR/mcp.json" <<JSON
{ "mcpServers": { "ci": {
    "command": "$ROOT/.venv/bin/python",
    "args": ["$DIR/tool_server.py"] } } }
JSON

# the one command: create the agent from the files in this folder
"$ROOT/andyur-cli" agents create "$NAME" \
  --description "CI status bot" \
  --instructions-file "$DIR/instructions.md" \
  --knowledge-file    "$DIR/knowledge.md" \
  --mcp-file          "$DIR/mcp.json"

echo
echo "created '$NAME'. try it:"
echo "  ./andyur-cli agents trigger $NAME --reason 'What is the CI status of checkout-service?'"
echo "  ./andyur-cli agents runs $NAME"
echo "  ./andyur-cli agents transcript $NAME <run-id>"
