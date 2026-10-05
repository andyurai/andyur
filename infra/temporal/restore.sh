#!/usr/bin/env bash
# Restore the workflow engine's persistence from a backup.sh directory.
#
# THE ENGINE MUST BE STOPPED, and this refuses rather than trusts. A running
# Temporal holds shard leases and writes continuously; restoring underneath it
# does not produce the backed-up state, it produces a mixture of two. The
# refusal is the feature -- the operator scaling to zero is an explicit,
# reversible act, and doing it silently on their behalf is not this script's
# decision to make.
#
# WHAT A RESTORE MEANS. In-flight executions resume from where the dump was
# taken, so anything that happened after it is replayed or lost depending on
# where its effects landed. What makes that safe is that the engine performs no
# run lifecycle transition at all: a run starts and finishes through its own
# SVID-authenticated endpoints, never through an activity, so a replay cannot
# start or finish a run a second time. A replayed SCHEDULED ADMISSION is the
# one effect that can repeat, and it meets the one-live-run-per-agent rule:
# refused while the original run is live, a new run if it has finished.
set -euo pipefail

NS="${ANDYUR_NAMESPACE:-andyur-system}"
DIR="${1:-}"
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "usage: $0 <backup-directory>" >&2; exit 2; }

replicas="$(kubectl get deployment andyur-temporal -n "$NS" \
             -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)"
if [ "${replicas:-0}" != "0" ]; then
  echo "REFUSING: andyur-temporal has $replicas replica(s)." >&2
  echo "  Stop the engine first, then restore, then start it:" >&2
  echo "    kubectl scale deployment/andyur-temporal -n $NS --replicas=0" >&2
  echo "    $0 $DIR" >&2
  echo "    kubectl scale deployment/andyur-temporal -n $NS --replicas=1" >&2
  exit 1
fi

POD="$(kubectl get pod -n "$NS" -l app=andyur-temporal-db \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$POD" ] || { echo "no andyur-temporal-db pod in $NS" >&2; exit 1; }

for db in temporal temporal_visibility; do
  # THE NEWEST DUMP OF THIS DATABASE, named rather than assumed: a directory
  # holding two runs' worth of files must not restore halves of each.
  f="$(ls -1 "$DIR/$db-"*.sql 2>/dev/null | sort | tail -1)"
  [ -n "$f" ] || { echo "no dump for $db in $DIR" >&2; exit 1; }
  grep -q "PostgreSQL database dump complete" "$f" || {
    echo "the dump for $db is truncated; refusing to restore it: $f" >&2; exit 1; }

  echo "restoring $db from $(basename "$f")"
  kubectl exec -i -n "$NS" "$POD" -- sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -U temporal -d postgres -v ON_ERROR_STOP=1 \
       -c "DROP DATABASE IF EXISTS '"$db"'" -c "CREATE DATABASE '"$db"'"' >/dev/null
  kubectl exec -i -n "$NS" "$POD" -- sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -U temporal -d '"$db"' -v ON_ERROR_STOP=1 -q' \
    < "$f" >/dev/null
  echo "  restored"
done

echo "restore complete; start the engine with:"
echo "  kubectl scale deployment/andyur-temporal -n $NS --replicas=1"
