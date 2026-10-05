#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

exec "$ROOT/.venv/bin/python" "$HERE/verify-broker-semantic-wire.py"
