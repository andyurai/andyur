#!/usr/bin/env bash
# Hermes Agent on exec/v1, in the cluster -- the THIRD stock workload, with zero
# platform change: the same generic gate as OpenSRE's and Goose's, different
# data. HERMES DONE is the line the task input asks for.
#
# The model differs from the other two on purpose. Hermes refuses a context
# window below 64K tokens, and qwen3-andyur is served at 32768 (its base model
# declares 40960), so this workload is granted gemma4-andyur: gemma4:31b, whose
# native window is 262144, served at 65536.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDYUR_WORKLOAD_DEMO="demos/hermes"
export ANDYUR_WORKLOAD_AGENT="${ANDYUR_HERMES_AGENT:-hermes-agent}"
export ANDYUR_WORKLOAD_REGISTRY_ID="${ANDYUR_HERMES_REGISTRY_ID:-agt_hermes}"
export ANDYUR_WORKLOAD_INPUT="input.json"
export ANDYUR_WORKLOAD_EXPECT="HERMES DONE"
export ANDYUR_WORKLOAD_MODEL="gemma4-andyur:latest"
export ANDYUR_WORKLOAD_GATE="exec-hermes-in-cluster"
export ANDYUR_WORKLOAD_TIMEOUT="${ANDYUR_HERMES_TIMEOUT:-1500}"
exec bash "$HERE/verify-exec-workload.sh"
