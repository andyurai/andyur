#!/usr/bin/env bash
# COORDINATION, AGAINST REAL POSTGRES AND REAL CONCURRENCY.
#
# Why this exists, specifically. The unit suite is SQLite-only -- conftest pops
# ANDYUR_DB_URL, deliberately -- and coordination is the area where that has
# hidden the most. Every one of these was invisible on SQLite and live on
# Postgres: `user` being a reserved word (so init_db could not run at all, and an
# unquoted SELECT returned the DATABASE ROLE NAME into an authorization
# comparison); three successive lock-order inversions, one of which made the
# operator's halt lose a deadlock 68% of the time; and a CI job named "the suite,
# against Postgres" that ran on SQLite and passed while testing nothing.
#
# So the new coordination paths get their own harness on the real engine, with
# real concurrent processes rather than one process pretending. It asserts
# BEHAVIOUR, not absence of errors: every check here has a failing input, and
# each was demonstrated to fail before it was committed.
#
#   ./run.sh coord-verify           # starts its own throwaway Postgres
#   ANDYUR_DB_URL=... ./run.sh coord-verify   # or point it at one you have
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
CONTAINER="andyur-coord-pg"
OWN_PG=0

PASS=0; FAIL=0
ok()   { printf '    \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
  [ "$OWN_PG" = "1" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

if [ -z "${ANDYUR_DB_URL:-}" ]; then
  step "starting a throwaway Postgres"
  command -v docker >/dev/null 2>&1 || { echo "docker required (or set ANDYUR_DB_URL)"; exit 1; }
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=andyur \
    -p 55433:5432 "${ANDYUR_PG_IMAGE:-postgres:16}" >/dev/null || exit 1
  OWN_PG=1
  for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 \
    || { echo "postgres never became ready"; exit 1; }
  export ANDYUR_DB_URL="postgresql://postgres:test@127.0.0.1:55433/andyur"
  ok "postgres up"
fi

export ANDYUR_PROFILE=dev
export ANDYUR_DATA_DIR="${ANDYUR_COORD_DIR:-/tmp/andyur-coord}"
rm -rf "$ANDYUR_DATA_DIR"; mkdir -p "$ANDYUR_DATA_DIR"

run_py() { "$VENV/bin/python" -c "$1"; }

step "schema: init_db is idempotent on Postgres, including the late migration"
# Greenfield verification is what missed the reserved-word bug: a fresh schema
# never exercises ALTER TABLE. So create, then re-create, then insert a row that
# predates the newest column, then migrate again.
out=$(run_py "
from andyur import db
db.init_db(); db.init_db()
with db.connect() as c:
    c.execute(\"DELETE FROM messages\"); c.execute(\"DELETE FROM tasks\")
    c.execute(\"DELETE FROM runs\"); c.execute(\"DELETE FROM agents\")
    c.execute(\"INSERT INTO agents (name, description, paused, created_at) \"
              \"VALUES ('legacy', '', 0, ?)\", (db.utcnow(),))
    c.execute(\"INSERT INTO tasks (id, assignee, creator, title, detail, state, \"
              \"created_at, updated_at) VALUES ('t-legacy','legacy','op','t','d','open',?,?)\",
              (db.utcnow(), db.utcnow()))
    # simulate a row written before notified_at existed
    c.execute(\"UPDATE tasks SET notified_at = NULL WHERE id = 't-legacy'\")
    # Simulate an agents table created before registry binding existed. Drop the
    # dependent index first; init_db must restore the column and index without
    # changing the pre-existing runtime agent.
    c.execute(\"DROP INDEX IF EXISTS idx_agents_registry_agent_id\")
    c.execute(\"ALTER TABLE agents DROP COLUMN registry_agent_id\")
db.init_db()
with db.connect() as c:
    row = c.execute(\"SELECT notified_at FROM tasks WHERE id = 't-legacy'\").fetchone()
    agent = c.execute(\"SELECT registry_agent_id FROM agents WHERE name = 'legacy'\").fetchone()
print('ok' if row is not None and row['notified_at'] is None
      and agent is not None and agent['registry_agent_id'] is None else 'lost')
" 2>&1 | tail -1)
[ "$out" = "ok" ] && ok "init_db x3 keeps pre-migration rows and leaves them eligible" \
                  || bad "migration lost or altered an existing row: $out"

step "the drain re-drives work handed to a busy agent"
out=$(run_py "
from andyur import db
from andyur.server import coordinator, heartbeat, tasks
with db.connect() as c:
    for t in ('messages','tasks','runs','agents'): c.execute(f'DELETE FROM {t}')
    for n in ('planner','helper'):
        c.execute('INSERT INTO agents (name, description, paused, created_at) '
                  'VALUES (?, ?, 0, ?)', (n, '', db.utcnow()))
blocker = coordinator.maybe_wakeup('helper', 'occupied')
coordinator.start_run(blocker)
tasks.create_task('helper', 'planner', 'delegated', 'd')
busy = heartbeat.drain_pending_work()
with db.connect() as c:
    c.execute(\"UPDATE runs SET state='cancelled', finished_at=? WHERE agent='helper' \"
              \"AND state IN ('pending','running')\", (db.utcnow(),))
freed = heartbeat.drain_pending_work()
# START the run the drain just made, as its runner would: work counts as
# offered when a run starts and renders the prompt, not when the row is
# inserted. Cancelling an unstarted run must leave the work eligible -- that is
# the fix for the stamp-without-delivery orphan -- so a harness that never
# starts anything would now (correctly) see the work re-driven forever.
with db.connect() as c:
    pend = c.execute(\"SELECT id FROM runs WHERE agent='helper' AND state='pending'\").fetchone()
if pend: coordinator.start_run(pend['id'])
# Free the agent AGAIN before re-draining. Without this the second drain is
# refused because the agent is busy with the run the FIRST drain just made, so
# the check passes without ever exercising notified_at -- it looked like a
# treadmill test and was really a re-test of the live-run guard.
with db.connect() as c:
    c.execute(\"UPDATE runs SET state='cancelled', finished_at=? WHERE agent='helper' \"
              \"AND state IN ('pending','running')\", (db.utcnow(),))
again = heartbeat.drain_pending_work()
print('busy=%d freed=%d again=%d' % (len(busy), len(freed), len(again)))
" 2>&1 | tail -1)
[ "$out" = "busy=0 freed=1 again=0" ] \
  && ok "refused while busy, driven once when free, not again ($out)" \
  || bad "drain behaved wrongly on Postgres: $out"

step "CONCURRENCY: N replicas draining at once wake the agent exactly ONCE"
# The real multi-node question. Every server replica runs this heartbeat loop, so
# eight of them see the same waiting work in the same tick. The partial unique
# index on runs(agent) WHERE state IN ('pending','running') is what has to
# arbitrate -- the same primitive S2 introduced -- and this is the first time the
# drain has been asked to prove it. Separate PROCESSES, not threads: one
# interpreter sharing one pool would not exercise the database's decision.
#
# Note what is and is not doing the work here, established by mutation: deleting
# the drain's own "agent is not already live" WHERE clause changes NOTHING. That
# clause is an optimization. The safety property is maybe_wakeup's claim against
# the index, which is the right place for it -- a filter selected in one
# transaction and acted on in another is advisory by construction.
run_py "
from andyur import db
with db.connect() as c:
    for t in ('messages','tasks','runs','agents'): c.execute(f'DELETE FROM {t}')
    for n in ('boss','target'):
        c.execute('INSERT INTO agents (name, description, paused, created_at) '
                  'VALUES (?, ?, 0, ?)', (n, '', db.utcnow()))
    c.execute(\"INSERT INTO tasks (id, assignee, creator, title, detail, state, \"
              \"created_at, updated_at) VALUES ('t1','target','boss','t','d','open',?,?)\",
              (db.utcnow(), db.utcnow()))
" >/dev/null 2>&1
for i in $(seq 1 8); do
  ( "$VENV/bin/python" -c "
from andyur.server import heartbeat
try:
    heartbeat.drain_pending_work()
except Exception as exc:
    print('ERR', type(exc).__name__, exc)
" >>"$ANDYUR_DATA_DIR/drain.log" 2>&1 ) &
done
wait
errs=$(grep -c "^ERR" "$ANDYUR_DATA_DIR/drain.log" 2>/dev/null | tr -d ' ')
runs=$(run_py "
from andyur import db
with db.connect() as c:
    n = c.execute(\"SELECT COUNT(*) AS n FROM runs WHERE agent='target'\").fetchone()['n']
print(n)" 2>&1 | tail -1)
[ "$runs" = "1" ] && ok "8 concurrent replicas produced exactly 1 run" \
                  || bad "8 concurrent replicas produced $runs runs (expected 1)"
[ "${errs:-0}" = "0" ] && ok "no replica raised (no deadlock, no unhandled error)" \
                       || bad "$errs replica(s) raised: $(grep '^ERR' "$ANDYUR_DATA_DIR/drain.log" | head -1)"

step "CONCURRENCY: the drain does not deadlock against delegation and the kill switch"
# The failure mode this repo keeps producing. drain_pending_work takes agents ->
# workflows -> runs (via maybe_wakeup) and then tasks/messages (mark_notified);
# create_task takes agents/workflows/tasks; halt_workflow takes workflows -> runs.
# Run all three against each other and require that everything finishes.
run_py "
from andyur import db
with db.connect() as c:
    for t in ('messages','tasks','runs','agents','workflows'): c.execute(f'DELETE FROM {t}')
    for n in ('a1','a2','a3','a4'):
        c.execute('INSERT INTO agents (name, description, paused, created_at) '
                  'VALUES (?, ?, 0, ?)', (n, '', db.utcnow()))
" >/dev/null 2>&1
: > "$ANDYUR_DATA_DIR/mixed.log"
for i in 1 2 3 4; do
  ( "$VENV/bin/python" -c "
import sys
from andyur import db
from andyur.server import coordinator, heartbeat, messages, tasks
try:
    for r in range(12):
        tasks.create_task('a%d' % ((r % 4) + 1), 'a1', 'task %d' % r, 'd')
        messages.send_message('a%d' % ((r % 4) + 1), 'a1', 'msg %d' % r)
        heartbeat.drain_pending_work()
        with db.connect() as c:
            wf = c.execute(\"SELECT workflow_id FROM runs WHERE workflow_id IS NOT NULL \"
                           \"LIMIT 1\").fetchone()
        if wf: coordinator.halt_workflow(wf['workflow_id'])
        with db.connect() as c:
            c.execute(\"UPDATE runs SET state='cancelled', finished_at=? \"
                      \"WHERE state IN ('pending','running')\", (db.utcnow(),))
    print('DONE')
except Exception as exc:
    print('ERR', type(exc).__name__, exc)
" >>"$ANDYUR_DATA_DIR/mixed.log" 2>&1 ) &
done
wait
done_n=$(grep -c "^DONE" "$ANDYUR_DATA_DIR/mixed.log" 2>/dev/null | tr -d ' ')
[ "${done_n:-0}" = "4" ] && ok "4 writers x 12 rounds of delegate/drain/halt all completed" \
  || bad "only ${done_n:-0}/4 writers finished: $(grep '^ERR' "$ANDYUR_DATA_DIR/mixed.log" | head -1)"

step "CONCURRENCY: non-force agent delete and run creation are one Postgres decision"
# Exercise the product paths, not a hand-written approximation: delete_agent owns
# the parent-row FOR UPDATE and maybe_wakeup owns run creation.  The barrier is
# immediately AFTER the real SELECT has acquired its lock.  Removing that SELECT
# means `locked` is never set and this check fails, which makes the regression
# mutation-sensitive to the control rather than merely to the final FK outcome.
out=$(run_py "
import threading
from fastapi import HTTPException
from andyur import db
from andyur.server import app, coordinator

def reset_agent():
    with db.connect() as c:
        for table in ('messages', 'tasks', 'runs', 'schedules', 'agents'):
            c.execute(f'DELETE FROM {table}')
        c.execute(\"INSERT INTO agents (name, description, paused, created_at) \"
                  \"VALUES ('delete-race', '', 0, ?)\", (db.utcnow(),))

# Positive ordering 1: run creation wins.  The actual non-force handler must see
# the live run and refuse, leaving both the parent and run intact.
reset_agent()
run_id = coordinator.maybe_wakeup('delete-race', 'run wins')
try:
    app.delete_agent('delete-race', force=False, _id='operator',
                     x_andyur_user_token=None)
    first = 'delete-wrongly-won'
except HTTPException as exc:
    with db.connect() as c:
        agent_n = c.execute(\"SELECT COUNT(*) AS n FROM agents WHERE name='delete-race'\").fetchone()['n']
        run_n = c.execute(\"SELECT COUNT(*) AS n FROM runs WHERE id=?\", (run_id,)).fetchone()['n']
    first = 'run-first-ok' if exc.status_code == 409 and agent_n == 1 and run_n == 1 else 'run-first-bad'

# Positive ordering 2: delete's parent lock wins.  Pause after the actual
# SELECT ... FOR UPDATE, start the real coordinator path, and prove it remains
# blocked until deletion commits.  It must then return None because its parent
# no longer exists; no orphan run may appear.
reset_agent()
real_connect = db.connect
locked = threading.Event()
release = threading.Event()

class BarrierConnection:
    def __init__(self):
        self.inner = real_connect()
    def __enter__(self):
        self.inner.__enter__()
        return self
    def __exit__(self, *args):
        return self.inner.__exit__(*args)
    def __getattr__(self, name):
        return getattr(self.inner, name)
    def execute(self, sql, params=()):
        result = self.inner.execute(sql, params)
        if (threading.current_thread().name == 'delete-path'
                and 'FROM agents WHERE name = ? FOR UPDATE' in sql):
            locked.set()
            if not release.wait(5):
                raise RuntimeError('delete barrier was not released')
        return result

db.connect = BarrierConnection
result = {}

def delete_now():
    try:
        result['delete'] = app.delete_agent(
            'delete-race', force=False, _id='operator',
            x_andyur_user_token=None)
    except Exception as exc:
        result['delete_error'] = '%s:%s' % (type(exc).__name__, exc)

def wake_now():
    try:
        result['wake'] = coordinator.maybe_wakeup('delete-race', 'delete wins')
    except Exception as exc:
        result['wake_error'] = '%s:%s' % (type(exc).__name__, exc)

deleter = threading.Thread(target=delete_now, name='delete-path')
deleter.start()
if not locked.wait(5):
    result['lock_missing'] = True
else:
    waker = threading.Thread(target=wake_now, name='wake-path')
    waker.start()
    # A completed wake while the delete transaction holds FOR UPDATE is the
    # exact regression: run creation crossed the guarded decision.
    waker.join(0.3)
    result['blocked'] = waker.is_alive()
    release.set()
    deleter.join(5); waker.join(5)

# Ensure a missing/mutated lock cannot strand the delete thread in this verifier.
release.set()
deleter.join(5)
db.connect = real_connect
with real_connect() as c:
    agent_n = c.execute(\"SELECT COUNT(*) AS n FROM agents WHERE name='delete-race'\").fetchone()['n']
    run_n = c.execute(\"SELECT COUNT(*) AS n FROM runs WHERE agent='delete-race'\").fetchone()['n']
second = ('delete-first-ok' if result.get('blocked') and not deleter.is_alive()
          and result.get('delete', {}).get('deleted') == 'delete-race'
          and result.get('wake') is None and not result.get('wake_error')
          and agent_n == 0 and run_n == 0 else 'delete-first-bad:%r' % result)
print(first + ' ' + second)
" 2>&1 | tail -1)
[ "$out" = "run-first-ok delete-first-ok" ] \
  && ok "run-first refuses delete; delete-first blocks then refuses run creation" \
  || bad "agent delete/run-create ordering failed on Postgres: $out"

step "CONCURRENCY: a refused schedule tick is retried, once, across replicas"
run_py "
from andyur import db
from andyur.server import coordinator, schedules
with db.connect() as c:
    for t in ('schedules','runs','agents'): c.execute(f'DELETE FROM {t}')
    c.execute('INSERT INTO agents (name, description, paused, created_at) '
              \"VALUES ('sched', '', 0, ?)\", (db.utcnow(),))
s = schedules.create_schedule('sched', '0 0 * * *', 'daily')   # sparse on purpose
with db.connect() as c:
    c.execute('UPDATE schedules SET next_run_at = ? WHERE id = ?',
              ('2000-01-01T00:00:00+00:00', s['id']))
coordinator.maybe_wakeup('sched', 'occupied')   # make the wakeup refuse
print(s['id'])
" >/dev/null 2>&1
: > "$ANDYUR_DATA_DIR/sched.log"
for i in $(seq 1 6); do
  ( "$VENV/bin/python" -c "
from andyur.server import schedules
try:
    for a in schedules.fire_due(): print(a)
except Exception as exc:
    print('ERR', type(exc).__name__, exc)
" >>"$ANDYUR_DATA_DIR/sched.log" 2>&1 ) &
done
wait
fired=$(grep -c "fired" "$ANDYUR_DATA_DIR/sched.log" 2>/dev/null | tr -d ' ')
deferred=$(grep -c "deferred" "$ANDYUR_DATA_DIR/sched.log" 2>/dev/null | tr -d ' ')
[ "${fired:-0}" = "0" ] && ok "a busy agent's tick fired no run (correctly refused)" \
                        || bad "$fired run(s) fired for a busy agent"
[ "${deferred:-0}" = "1" ] && ok "exactly one replica claimed and deferred the tick" \
                           || bad "expected 1 deferral across 6 replicas, saw ${deferred:-0}"
# and the retry must be soon, not tomorrow -- the whole point
soon=$(run_py "
from datetime import datetime, timedelta, timezone
from andyur import db
with db.connect() as c:
    nxt = c.execute('SELECT next_run_at FROM schedules').fetchone()['next_run_at']
limit = (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat(timespec='seconds')
print('soon' if nxt <= limit else 'tomorrow(%s)' % nxt)" 2>&1 | tail -1)
[ "$soon" = "soon" ] && ok "the deferred tick retries within the window, not at the next slot" \
                     || bad "the tick was pushed to the next cron slot: $soon"

step "the reaper distinguishes a dead runner from a queue"
out=$(run_py "
from andyur import db
from andyur.server import coordinator, heartbeat
with db.connect() as c:
    for t in ('runs','agents'): c.execute(f'DELETE FROM {t}')
    for n in ('claimed','queued'):
        c.execute('INSERT INTO agents (name, description, paused, created_at) '
                  'VALUES (?, ?, 0, ?)', (n, '', db.utcnow()))
r1 = coordinator.maybe_wakeup('claimed', 'w')
r2 = coordinator.maybe_wakeup('queued', 'w')
stale = heartbeat._cutoff(heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
with db.connect() as c:
    c.execute(\"UPDATE runs SET created_at=?, worker='w1' WHERE id=?\", (stale, r1))
    c.execute('UPDATE runs SET created_at=? WHERE id=?', (stale, r2))
heartbeat.recover_stuck_runs()
with db.connect() as c:
    s1 = c.execute('SELECT state FROM runs WHERE id=?', (r1,)).fetchone()['state']
    s2 = c.execute('SELECT state FROM runs WHERE id=?', (r2,)).fetchone()['state']
print('claimed=%s queued=%s' % (s1, s2))
" 2>&1 | tail -1)
[ "$out" = "claimed=failed queued=pending" ] \
  && ok "the stranded run is reaped, the queued one is left alone ($out)" \
  || bad "reaper verdict wrong on Postgres: $out"

echo
printf '%s\n' "----------------------------------------"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || { echo "logs in $ANDYUR_DATA_DIR"; exit 1; }
echo "COORDINATION ON POSTGRES: PASSED"
