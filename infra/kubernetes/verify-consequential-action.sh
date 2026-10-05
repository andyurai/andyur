#!/usr/bin/env bash
# The consequential action against a real cluster: DENY leaves it untouched,
# ALLOW moves it, APPROVAL holds it until a human consents. Needs a reachable
# Kubernetes context (k3s), the OTel collector and Jaeger (./run.sh jaeger).
set -euo pipefail
cd "$(dirname "$0")/../.."
exec env PYTHONPATH=. .venv/bin/python infra/kubernetes/bounded_exec.py 600 \
  .venv/bin/python infra/kubernetes/verify-consequential-action.py
