#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec env PYTHONPATH=. .venv/bin/python infra/kubernetes/bounded_exec.py 480 \
  .venv/bin/python infra/kubernetes/verify-exec-tool-call.py
