#!/usr/bin/env bash
# Create a demo agent whose tool is a REMOTE (HTTP) MCP server.
#
#   ./demos/tool-agent-http/run.sh [agent-name]     (default: cibot-http)
#
# Unlike demos/tool-agent/ (stdio: a local subprocess the harness launches on
# demand), the tool here is an HTTP service the agent connects to by URL. Its
# mcp.json is therefore just a URL with no machine paths, so mcp.json is a
# TRACKED file. This script starts the tool server, then creates the agent.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
NAME="${1:-cibot-http}"
PORT=8790

if ! curl -s -o /dev/null "http://127.0.0.1:$PORT/mcp"; then
  CI_HTTP_PORT=$PORT "$ROOT/.venv/bin/python" "$DIR/tool_server.py" \
    >"$DIR/tool_server.log" 2>&1 &
  echo $! > "$DIR/tool_server.pid"
  printf "starting HTTP tool server on :%s" "$PORT"
  for _ in $(seq 1 20); do
    if curl -s -o /dev/null "http://127.0.0.1:$PORT/mcp"; then break; fi
    printf "."; sleep 0.5
  done
  echo
fi

"$ROOT/andyur-cli" agents create "$NAME" \
  --description "CI status bot (HTTP tool)" \
  --instructions-file "$DIR/instructions.md" \
  --mcp-file          "$DIR/mcp.json"

cat <<EOF

created '$NAME'. Its tool is the HTTP server on :$PORT (keep it running).
try it:
  ./andyur-cli agents trigger $NAME --reason 'What is the CI status of checkout-service?'
  ./andyur-cli agents runs $NAME
  ./andyur-cli agents transcript $NAME <run-id>
stop the tool server when done:
  kill \$(cat "$DIR/tool_server.pid")
EOF
