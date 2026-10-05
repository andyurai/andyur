#!/usr/bin/env bash
# Build one distinct executable per Andyur role so the SPIRE unix attestor can
# tell them apart by path.
#
# Why this exists: on macOS the framework Python re-execs into a shared
# app-bundle path, so copies of it all attest as the same executable and no
# path selector can distinguish roles. A standalone (non-framework) Python
# copied inside a tree where its loader can still resolve libpython + stdlib
# reports its own path. We give each role such a copy under infra/roles/bin/,
# sharing one lib/ symlink, and point registration entries at those paths.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROLES_DIR="$HERE/infra/roles"
VENV="$HERE/.venv"

command -v uv >/dev/null || { echo "uv is required (https://docs.astral.sh/uv/)"; exit 1; }
uv python install 3.12 >/dev/null 2>&1 || true
STD_BIN="$(uv python find --managed-python 3.12)"
STD_ROOT="$(cd "$(dirname "$STD_BIN")/.." && pwd)"

mkdir -p "$ROLES_DIR/bin"
ln -sfn "$STD_ROOT/lib" "$ROLES_DIR/lib"
for role in server worker runner operator broker; do
  cp "$STD_ROOT/bin/python3.12" "$ROLES_DIR/bin/andyur-$role"
  codesign -f -s - "$ROLES_DIR/bin/andyur-$role" >/dev/null 2>&1 || true
done
echo "role binaries built under $ROLES_DIR/bin"
