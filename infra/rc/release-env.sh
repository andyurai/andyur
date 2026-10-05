#!/usr/bin/env bash
# Create the release-tooling environment `build_release.py` needs.
#
# This exists because the release build previously worked on ONE MACHINE. The
# interpreter it wants, `.venv-release/bin/python`, is gitignored, nothing in
# the repo created it, and no file declared its contents -- so a second party
# checking out this tree could not produce a release artifact at all. That is
# an inability to reproduce, which is why it is fixed here rather than filed.
#
# Idempotent: safe to re-run, and re-running is how you pick up a pin change.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VENV="$ROOT/.venv-release"
REQ="$ROOT/requirements-release.txt"

[ -f "$REQ" ] || { echo "missing $REQ"; exit 1; }

PY="${ANDYUR_RELEASE_PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "no $PY on PATH"; exit 1; }

echo "creating $VENV from requirements-release.txt"
"$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$REQ"

# PROVE the two entry points build_release.py actually invokes are present and
# runnable, rather than trusting that pip exited 0. `cyclonedx-py` is a console
# script from cyclonedx-bom, so the package name and the command name differ --
# exactly the kind of gap that turns into "works on my machine" later.
"$VENV/bin/python" -m build --version >/dev/null || {
  echo "build did not install correctly"; exit 1; }
[ -x "$VENV/bin/cyclonedx-py" ] || {
  echo "cyclonedx-py is not in $VENV/bin (cyclonedx-bom provides it)"; exit 1; }
"$VENV/bin/cyclonedx-py" --version >/dev/null || {
  echo "cyclonedx-py is present but does not run"; exit 1; }

# The two NON-Python tools. Reported, never installed: a build script that
# silently installs signing tooling is a build script nobody should trust.
missing=0
for tool in syft cosign; do
  if command -v "$tool" >/dev/null; then
    printf '  %-8s %s\n' "$tool" "$(command -v "$tool")"
  else
    printf '  %-8s MISSING\n' "$tool"; missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo
  echo "syft and cosign are host tools, not pip packages. Install them"
  echo "(macOS: brew install syft cosign) and re-run this script to confirm."
  echo "Without them build_release.py refuses rather than skipping SBOMs or"
  echo "signatures, which is the correct behaviour and also means the release"
  echo "cannot be produced until they are present."
  exit 1
fi

echo
echo "release environment ready: $VENV"
echo "  build a release candidate with:"
echo "    python3 infra/rc/build_release.py --out <dir>"
