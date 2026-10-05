#!/usr/bin/env bash
# OpenSRE on exec/v1, in the cluster (ADR-011 acceptance #1): the generic
# stock-workload gate, parameterised. Data only -- see verify-exec-workload.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDYUR_WORKLOAD_DEMO="demos/opensre"
export ANDYUR_WORKLOAD_AGENT="${ANDYUR_OPENSRE_AGENT:-opensre-sre}"
export ANDYUR_WORKLOAD_REGISTRY_ID="${ANDYUR_OPENSRE_REGISTRY_ID:-agt_opensre}"
export ANDYUR_WORKLOAD_INPUT="alert.json"
export ANDYUR_WORKLOAD_EXPECT="root_cause"
export ANDYUR_WORKLOAD_MODEL="qwen3-andyur:latest"
export ANDYUR_WORKLOAD_GATE="exec-opensre-in-cluster"
export ANDYUR_WORKLOAD_TIMEOUT="${ANDYUR_OPENSRE_TIMEOUT:-900}"
exec bash "$HERE/verify-exec-workload.sh"
