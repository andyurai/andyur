#!/usr/bin/env bash
# Return this Andyur to a clean slate: stop everything, then delete the state it
# accumulated. The counterpart to `./run.sh up`.
#
#   ./run.sh reset          show what would go, then ask
#   ./run.sh reset --yes    skip the prompt (CI, scripts)
#   ./run.sh reset --all    also delete SPIRE/TLS identity material
#
# IDENTITY MATERIAL IS KEPT BY DEFAULT. data/spire and data/tls are slow to
# regenerate, are unrelated to the agents and runs you are trying to clear, and
# losing them silently breaks every identity-on target afterwards. --all is there
# for when that is genuinely what you want.
#
# To remove ONE agent rather than everything, there is now a product operation for
# that and it is the better tool: ./andyur-cli agents delete <agent>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${ANDYUR_DATA_DIR:-$HERE/data}"

ALL=0; YES=0
for arg in "$@"; do
  case "$arg" in
    --all) ALL=1 ;;
    --yes|-y) YES=1 ;;
    *) echo "usage: ./run.sh reset [--all] [--yes]"; exit 1 ;;
  esac
done

# State that accumulates as you use Andyur. Identity material is handled below.
TARGETS=("$DATA/andyur.db" "$DATA/andyur.db-wal" "$DATA/andyur.db-shm"
         "$DATA/logs" "$DATA/runlogs" "$DATA/workspace" "$DATA/run")
[ "$ALL" = "1" ] && TARGETS+=("$DATA/spire" "$DATA/tls")

echo "this will delete:"
found=0
for t in "${TARGETS[@]}"; do
  if [ -e "$t" ]; then
    size=$(du -sh "$t" 2>/dev/null | cut -f1)
    printf '  %-28s %s\n' "${t#$HERE/}" "$size"
    found=1
  fi
done
[ "$found" = "0" ] && { echo "  (nothing; already clean)"; exit 0; }

if [ "$ALL" = "1" ]; then
  echo
  echo "  INCLUDING SPIRE/TLS identity material. Every identity-on target will"
  echo "  need to re-attest afterwards (./run.sh spire-setup)."
else
  echo
  echo "  keeping data/spire and data/tls (identity material). --all removes those too."
fi

if [ "$YES" != "1" ]; then
  echo
  printf "type 'reset' to confirm: "
  read -r reply
  [ "$reply" = "reset" ] || { echo "aborted; nothing was deleted"; exit 1; }
fi

# Stop first -- BUT ONLY THE STACK THIS RESET IS ABOUT. Deleting the database
# under a running server leaves it serving from a file that no longer exists,
# which looks like corruption rather than a reset, so the stop is right when
# $DATA is the checkout's own data directory.
#
# It was unconditional, and `run.sh down` reads its pids from $HERE/data/run
# regardless of ANDYUR_DATA_DIR -- so a reset pointed at a scratch directory
# stopped the DEVELOPER'S running control plane. The unit suite does exactly
# that (tests/test_demo_tooling.py sandboxes ANDYUR_DATA_DIR and then calls
# this script four times), which is how a full RC-gate run reported its console
# line as "control plane not up" eleven lines after the suite had silently
# taken the stack down.
if [ "$DATA" = "$HERE/data" ]; then
  bash "$HERE/run.sh" down >/dev/null 2>&1 || true
else
  echo "(ANDYUR_DATA_DIR is $DATA, not this checkout's; leaving any running stack alone)"
fi

for t in "${TARGETS[@]}"; do rm -rf "$t"; done
mkdir -p "$DATA"
echo
echo "reset. start again with: ./run.sh up"
echo "(Neo4j keeps its own volume; to clear the memory graph too:"
echo "   docker compose -f infra/docker-compose.yml down -v neo4j)"
