#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec env PYTHONPATH=. .venv/bin/python infra/kubernetes/bounded_exec.py 150 \
  .venv/bin/python infra/kubernetes/verify-broker-lifecycle.py
