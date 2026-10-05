#!/usr/bin/env bash
# Back up the workflow engine's persistence.
#
# WHAT THIS PROTECTS, stated plainly so nobody over-trusts it: Temporal's two
# databases are the engine's memory of IN-FLIGHT work -- open executions, their
# histories, timers and task queues. Losing them loses the ability to resume
# runs that were mid-flight, NOT Andyur's own record: the coordinator's tables
# are the authority on what a run is and whether it is live, and they are
# backed up separately with the control plane's database.
#
# So this is a recovery time objective, not a system of record. A restore
# brings workflows back; it does not decide anything.
#
# CONSISTENCY. Both databases are dumped inside ONE `pg_dump` snapshot each,
# which is self-consistent per database but NOT consistent BETWEEN them. That
# is acceptable and the reason is worth knowing: visibility is a derived index
# over executions, so a visibility row without its execution is a stale search
# result, while an execution without its visibility row is invisible to search
# and still runnable. Neither loses work.
set -euo pipefail

NS="${ANDYUR_NAMESPACE:-andyur-system}"
OUT="${1:-}"
[ -n "$OUT" ] || { echo "usage: $0 <output-directory>" >&2; exit 2; }

POD="$(kubectl get pod -n "$NS" -l app=andyur-temporal-db \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$POD" ] || { echo "no andyur-temporal-db pod in $NS" >&2; exit 1; }

# OWNER-ONLY, because a dump holds every execution history, and payload
# hygiene is a guard on field names rather than a proof of what a field holds.
umask 077
mkdir -p "$OUT"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

for db in temporal temporal_visibility; do
  f="$OUT/$db-$stamp.sql"
  echo "dumping $db -> $f"
  # THE PASSWORD IS NEVER AN ARGUMENT. `--password` on a command line is
  # visible in the container's process table to anything that can read it;
  # PGPASSWORD is read from the pod's own environment, where it already is.
  kubectl exec -n "$NS" "$POD" -- sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U temporal -d '"$db"' --no-owner --no-acl' \
    > "$f"

  # A DUMP THAT IS NOT A DUMP IS THE FAILURE MODE THAT MATTERS. `pg_dump`
  # writing an error to stdout, or an empty file from a pod that vanished
  # mid-command, both leave a plausible-looking artifact that restores to
  # nothing -- and it is discovered during the restore, which is the worst
  # possible time.
  grep -q "PostgreSQL database dump complete" "$f" || {
    echo "the dump of $db is truncated or not a dump: $f" >&2; exit 1; }
  echo "  $(wc -c < "$f") bytes, complete"
done

echo "backup complete: $OUT"
