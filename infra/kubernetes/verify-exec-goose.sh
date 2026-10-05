#!/usr/bin/env bash
# Goose on exec/v1, in the cluster -- the SECOND stock workload, with zero
# platform change (docs/goose-wiring-plan.md): the same generic gate as
# OpenSRE's, different data. GOOSE DONE is the line the task input asks for.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDYUR_WORKLOAD_DEMO="demos/goose"
export ANDYUR_WORKLOAD_AGENT="${ANDYUR_GOOSE_AGENT:-goose-agent}"
export ANDYUR_WORKLOAD_REGISTRY_ID="${ANDYUR_GOOSE_REGISTRY_ID:-agt_goose}"
export ANDYUR_WORKLOAD_INPUT="input.json"
export ANDYUR_WORKLOAD_EXPECT="GOOSE DONE"
export ANDYUR_WORKLOAD_MODEL="qwen3-andyur:latest"
export ANDYUR_WORKLOAD_GATE="exec-goose-in-cluster"
export ANDYUR_WORKLOAD_TIMEOUT="${ANDYUR_GOOSE_TIMEOUT:-900}"
exec bash "$HERE/verify-exec-workload.sh"
