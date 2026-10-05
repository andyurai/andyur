#!/usr/bin/env bash
# THE AGENT ASKED, for the second stock workload: Hermes Agent initiates the
# consequential action through the generic MCP tool path, and the platform
# decides it and moves the cluster. The same gate as Goose's
# (verify-agent-requested-action.sh), different data -- a separate artifact,
# because each one is a claim about the workload that actually ran.
#
# The model is gemma4-andyur for the reason in verify-exec-hermes.sh: Hermes
# refuses a context window below 64K tokens.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDYUR_ACTION_AGENT="${ANDYUR_HERMES_AGENT:-hermes-agent}"
export ANDYUR_ACTION_REGISTRY_ID="${ANDYUR_HERMES_REGISTRY_ID:-agt_hermes}"
export ANDYUR_ACTION_DEMO="demos/hermes"
export ANDYUR_ACTION_INPUT="rollback-input.json"
export ANDYUR_ACTION_MODEL="gemma4-andyur:latest"
export ANDYUR_ACTION_WORKLOAD="Hermes Agent"
export ANDYUR_ACTION_TIMEOUT="${ANDYUR_HERMES_TIMEOUT:-1500}"
export ANDYUR_ACTION_EVIDENCE="${ANDYUR_ACTION_EVIDENCE:-$HERE/result-agent-requested-action-hermes-$(date +%Y-%m-%d)-$(uname -s | tr A-Z a-z)-$(uname -m).json}"
exec bash "$HERE/verify-agent-requested-action.sh"
