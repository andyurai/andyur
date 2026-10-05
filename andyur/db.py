"""State store: agent registry, coordination state, run records.

Two backends behind one interface, chosen by ANDYUR_DB_URL:

- **SQLite** (default, empty URL): a local file. WAL journal mode lets the
  server, daemon, and runner processes on one machine share it.
- **Postgres** (a postgres:// URL): a shared networked database, which is what
  lets multiple stateless server replicas run across nodes.

The coordination logic is identical on both: state transitions go through
compare-and-swap UPDATEs (WHERE state = ...), so racing triggers cannot
double-claim an agent. Postgres does row-level locking, so it is in fact more
concurrent than SQLite's single global writer.

The service code is written once against `?` placeholders and the sqlite3-style
`conn.execute(...).fetchone()/.rowcount` surface; the connection wrapper below
translates `?` to `%s` and yields dict rows for the Postgres path.
"""

import os
import sqlite3
import threading
from datetime import datetime, timezone

from . import layout
from .config import DATA_DIR, DB_PATH, DB_URL

IS_POSTGRES = DB_URL.startswith("postgres")

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    name        TEXT PRIMARY KEY,
    registry_agent_id TEXT,
    description TEXT NOT NULL DEFAULT '',
    paused      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    agent       TEXT NOT NULL REFERENCES agents(name) ON DELETE CASCADE,
    run_type    TEXT NOT NULL DEFAULT 'work',
    state       TEXT NOT NULL DEFAULT 'pending',
    reason      TEXT NOT NULL DEFAULT '',
    summary     TEXT,
    error       TEXT,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_agent ON runs(agent, created_at);
-- Run history newest-first with a keyset cursor on (created_at, id). This
-- serves the UNFILTERED page (user-auth off, or an admin) as a pure keyset
-- walk: measured 0.11 ms per page at 100k runs on SQLite, no temp sort, at any
-- depth.
--
-- IT DOES NOT SERVE THE OWNER-FILTERED PAGE ON SQLITE, and no index on `runs`
-- can: the owner predicate lives on `agents`, so the planner drives the join
-- from there, reaches runs through idx_runs_agent, and materialises a temp
-- b-tree for the ORDER BY. Measured 20 ms per page at 100k runs / 5 owners --
-- unchanged when this index is dropped, which is how we know it is not the
-- one doing the work there. That cost grows with ONE OWNER's history, not with
-- the table, and Postgres plans the same query as an index scan with no sort
-- (0.15 ms at 200k). Making it a keyset walk on SQLite too means putting the
-- owner on `runs`; see ROADMAP.md.
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at, id);

-- AT MOST ONE LIVE RUN PER AGENT, enforced by the database.
--
-- This index IS the coordination primitive. Claiming an agent is inserting its
-- run: a second concurrent insert violates the index and loses, so the engine
-- decides the race. What this replaces was a compare-and-swap on a separate
-- `agent_status` table -- a second source of truth for something `runs` already
-- knows, kept coherent by hand across six writers, every one of which had to
-- take two table locks in an agreed order. That order was written as a comment,
-- the comment was wrong about itself twice, and three separate reviews found a
-- writer violating it. The deadlock class does not exist here, because there is
-- no second table to lock.
CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_one_live_per_agent
    ON runs(agent) WHERE state IN ('pending', 'running');

-- Coordination status is a VIEW, created in init_db: SQLite spells it
-- `CREATE VIEW IF NOT EXISTS` and Postgres `CREATE OR REPLACE VIEW`,
-- and neither accepts the other's form.


-- Workflows: the durable unit of work a run belongs to. One row per workflow,
-- created when its root run is sealed. `state` drives the kill-switch: a
-- 'halted' workflow spawns no further runs (see coordinator.maybe_wakeup).
CREATE TABLE IF NOT EXISTS workflows (
    id         TEXT PRIMARY KEY,
    state      TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

-- Worker daemons that launch runner processes. Rows are upserted on every
-- heartbeat; a worker whose heartbeat goes stale is considered dead and its
-- unstarted assignments are requeued by the server's recovery loop.
CREATE TABLE IF NOT EXISTS workers (
    id             TEXT PRIMARY KEY,
    slots          INTEGER NOT NULL,
    last_heartbeat TEXT NOT NULL
);

-- Cron schedules. The server heartbeat loop fires a schedule whose next_run_at
-- has passed, then advances next_run_at. Unattended autonomy for an agent.
CREATE TABLE IF NOT EXISTS schedules (
    id          TEXT PRIMARY KEY,
    agent       TEXT NOT NULL REFERENCES agents(name) ON DELETE CASCADE,
    cron        TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT 'scheduled run',
    enabled     INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT NOT NULL,
    last_run_at TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(enabled, next_run_at);

-- Tasks: the unit of delegated work. An agent (or the operator) creates a task
-- for an assignee; the assignee works it through open -> in_progress -> closed.
CREATE TABLE IF NOT EXISTS tasks (
    id         TEXT PRIMARY KEY,
    assignee   TEXT NOT NULL REFERENCES agents(name) ON DELETE CASCADE,
    creator    TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL DEFAULT 'open',
    result     TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee, state);

-- Inter-agent and operator messages. Sending a message wakes the recipient;
-- the recipient sees unread messages in its run context and handles them.
CREATE TABLE IF NOT EXISTS messages (
    id         TEXT PRIMARY KEY,
    recipient  TEXT NOT NULL,
    sender     TEXT NOT NULL,
    body       TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'unread',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient, state);

-- Lane A (board rows 7-8): one row per CONSEQUENTIAL action an agent requests.
--
-- Server-owned and queryable BY DESIGN. The console renders from the HTTP API,
-- and the MVP exit criterion is that the whole story can be shown "without
-- opening a database, kubectl, Jaeger or source code" -- so a decision that
-- lived only in a span or in stdout would fail that criterion by definition.
--
-- `decision` is a FIELD, never an inference. A console that derives "approval
-- required" from the absence of a result eventually renders the wrong one, and
-- this repository already settled that argument: if the platform decided
-- something, the platform says which (the `andyur.reason` rule).
--
-- The approver carries PROVENANCE beside the subject, the same pair `runs`
-- already uses for acting_user/user_asserted_by and subject_context/
-- pin_asserted_by. An asserted identity rendered as a proven one is the defect
-- this lane must not ship in the artifact we show people.
--
-- `result` is an OBSERVED cluster fact: 'succeeded' requires reading the
-- deployment back afterwards and recording what was observed in result_detail.
-- A 200 from the dispatch is not evidence that the cluster changed, and a
-- result asserted from our own request is a green that carries no information.
CREATE TABLE IF NOT EXISTS action_requests (
    id                       TEXT PRIMARY KEY,
    run_id                   TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool                     TEXT NOT NULL,
    target                   TEXT NOT NULL,
    requested_at             TEXT NOT NULL,
    decision                 TEXT,
    decision_reason          TEXT,
    decided_at               TEXT,
    approved_by              TEXT,
    approved_by_asserted_by  TEXT,
    approved_at              TEXT,
    result                   TEXT,
    result_detail            TEXT,
    finished_at              TEXT
);
CREATE INDEX IF NOT EXISTS idx_action_requests_run ON action_requests(run_id);

-- Mind versions: an immutable snapshot of every change to a versioned mind
-- file (the agent's editable self, knowledge + instructions, and its long-term
-- learnings), so an agent's mind has full history and can be rolled back.
-- Working memory (short-term scratchpad) is deliberately not versioned here.
-- Records which run and actor made the change.
CREATE TABLE IF NOT EXISTS mind_versions (
    id         TEXT PRIMARY KEY,
    agent      TEXT NOT NULL REFERENCES agents(name) ON DELETE CASCADE,
    path       TEXT NOT NULL,
    content    TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT 'agent',
    run_id     TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mind_versions_agent_path
    ON mind_versions(agent, path, created_at);

-- Conversational agents: a run of run_type='conversation' stays live across many
-- turns. Turns (human -> agent) and events (agent -> human) are DB-backed so the
-- operator and the session can rendezvous through any stateless server replica.
--
-- A turn is queued by the OPERATOR/owner and claimed FIFO by exactly one session
-- (compare-and-swap on state), so the agent can never inject its own turns and a
-- turn is never delivered twice. `kind` is 'message' (human text) or 'close'
-- (operator ended the session). seq is per-run, monotonic, assigned server-side.
CREATE TABLE IF NOT EXISTS conversation_turns (
    id         TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'message',
    sender     TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL
);
-- UNIQUE so a seq collision (a read-modify-write race on the SQLite path) is
-- rejected by the store rather than silently producing two rows with one seq
-- (which would drop an event past the operator's cursor or make FIFO ambiguous).
CREATE UNIQUE INDEX IF NOT EXISTS idx_conv_turns_run ON conversation_turns(run_id, seq);

-- Events are the agent's replies streamed back to the operator: 'chunk' (a piece
-- of the reply), 'turn_end' (the agent finished responding to a turn),
-- 'session_end' (the session closed), 'error'. The operator long-polls events
-- with seq greater than its cursor. Written only by the session (run-token scoped).
CREATE TABLE IF NOT EXISTS conversation_events (
    id         TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_conv_events_run ON conversation_events(run_id, seq);

-- Named singleton rows used purely as lock rendezvous points, so a cross-cutting
-- admission decision (e.g. the concurrent-conversation cap, which spans all agents
-- and workflows) can be serialized on ONE row on both backends: SELECT ... FOR
-- UPDATE on Postgres, a touch-write to take the write lock on SQLite.
CREATE TABLE IF NOT EXISTS singletons (
    id      TEXT PRIMARY KEY,
    touched INTEGER NOT NULL DEFAULT 0
);
"""

# Columns added after the initial schema shipped. Kept idempotent so init_db
# is safe to run against an existing database on either backend.
MIGRATION_COLUMNS = [
    ("runs", "worker", "TEXT"),
    # WHO DISPATCHES THIS RUN, decided at admission and written in the same
    # INSERT: NULL is the native assignment loop; 'engine' is the durable
    # provider's execution worker (Architecture B+, ADR-014 D11). The native
    # loop never selects an engine run, so the two cannot race for one run.
    ("runs", "dispatch", "TEXT"),
    # WHICH ORCHESTRATION PROVIDER the run is bound to, written at admission
    # (provider draft R11.1). The execution claim refuses any other provider.
    ("runs", "orchestration_provider", "TEXT"),
    # EVENTUAL DELIVERY (provider draft R6.6). The workflow kind a run was
    # admitted as, so a start can be offered again exactly as first requested;
    # and when the bound provider acknowledged it. A committed engine run with
    # no acknowledgement is re-offered until it has one or ends.
    ("runs", "workflow_kind", "TEXT"),
    ("runs", "provider_acked_at", "TEXT"),
    # The run's ONE execution generation, recorded when the engine first
    # claims it and presented by every retry. The Kubernetes run fence lets
    # exactly this generation adopt the run and refuses any other (D11).
    ("runs", "execution_generation", "TEXT"),
    # WHAT FIRES THIS SCHEDULE: NULL is the native poller (`fire_due`);
    # 'engine' is a durable Schedule in the engine under the same id (ADR-014
    # D11). Decided at creation and never both: the poller skips engine rows.
    ("schedules", "trigger", "TEXT"),
    # The SUBJECT TOKEN this run presents at the adopter's authorization server
    # (RFC 8693 `subject_token`). You cannot present a credential you did not
    # keep, and the run must present the user's leg fresh at each per-tool
    # exchange -- so, unlike acting_user (an assertion), this is the credential
    # itself and it is retained for the run's life.
    #
    # It is the user's own login token, stored ONLY when an external AS is
    # configured (nothing to present it to otherwise, so nothing is kept). It
    # is NOT exchanged/narrowed at trigger: the delegation exchange needs the
    # run's actor SVID, which is minted per RFC 8693 later, inside the run's
    # attested container -- the control plane never holds it (decisions.md #3).
    # Narrowing it to a run-bound intermediate at trigger is a tracked
    # architectural follow-up; see docs/threat-model.md.
    #
    # Returned by exactly one endpoint, GET /runs/{run_id}/subject-token, which
    # requires the RUN's own attested per-run SVID (require_svid) and refuses
    # any other run and every operator -- so a bare run token cannot lift it.
    # Inherited by delegated child runs (each needs its own subject leg) and
    # dropped to NULL on every terminal path.
    ("runs", "subject_token", "TEXT"),
    # W3C traceparent anchoring this run's distributed trace across processes
    ("runs", "trace_ctx", "TEXT"),
    # Durable workflow (transaction) identity: minted on a root trigger and
    # carried UNCHANGED through every delegated child run, so one user request's
    # whole fan-out shares a single id. Distinct from trace_ctx: trace_ctx is an
    # ephemeral per-run span link; workflow_id is stable business identity used
    # for audit, correlation, and per-workflow controls (kill-switch, budget).
    ("runs", "workflow_id", "TEXT"),
    ("tasks", "workflow_id", "TEXT"),
    # Delegation depth: a child run's depth is its parent's + 1 (fan-out guard).
    ("runs", "depth", "INTEGER DEFAULT 0"),
    # A delegated message carries its workflow so a halt can hide it (kill-switch
    # closes the message channel, not only tasks/runs).
    ("messages", "workflow_id", "TEXT"),
    # When this work was last OFFERED to a run of its assignee. Delivery is
    # best-effort (create_task/send_message wake the target and ignore a
    # refusal), so the drain in heartbeat.py re-drives work handed to a busy
    # agent. It needs to know "has a run had a chance at this yet?", and the
    # answer must not be inferred from timestamps: utcnow() has one-second
    # granularity, so a task and the run woken for it tie constantly, and a tie
    # has to be resolved as either "drop the work" or "wake forever".
    # When a worker CLAIMED this run. The stranded-run reaper measures from
    # here, not from created_at: a run that waited in the queue past its TTL was
    # otherwise failed as "never started" the instant a worker finally picked it
    # up, while a healthy runner was preparing to start it -- worst under load,
    # which is the failure the queue/claim split exists to prevent.
    ("runs", "assigned_at", "TEXT"),
    ("tasks", "notified_at", "TEXT"),
    ("messages", "notified_at", "TEXT"),
    # User delegation (U1): the user who OWNS an agent instance, and the user a run
    # acts for (inherited from the agent's owner). Null when user-auth is off.
    ("agents", "owner", "TEXT"),
    ("runs", "acting_user", "TEXT"),
    # HOW `acting_user` was established: "idp" when an identity provider
    # authenticated them, "asserted" when an authenticated API client merely said
    # so. Stored rather than derived, because deriving it from today's config
    # would mean an old run's tokens change meaning when an operator turns
    # ANDYUR_USER_AUTH on -- the provenance is a fact about the run, not about
    # the server's current settings. NULL on runs predating the column, which the
    # grant reads as "idp": before this, an IdP login was the only way to have a
    # user at all.
    ("runs", "user_asserted_by", "TEXT"),
    # Scoped least privilege (U2): the scope granted to this run (a JSON list), the
    # intersection of the user's entitlements and the task's declared need. Null =
    # unrestricted (no scope model active for this run).
    ("runs", "scope", "TEXT"),
    # --- Target identity design: the three terms authority is built from ---
    #
    # THE PIN (subject_context). What this piece of work is ABOUT: the canonical
    # resources it may touch, e.g. {"account": "447"}. Distinct from `scope` (what
    # the actor may DO) and `acting_user` (who it acts FOR). It is asserted by an
    # authenticated caller -- the IdP in a claim, or the application -- and sealed
    # here, because the one thing it must never be is model-supplied. Today the
    # only place a run's subject matter appears is inside the prompt, which is
    # exactly the case the design forbids.
    ("runs", "subject_context", "TEXT"),
    # PROVENANCE (G05). The digest of the signature-verified registry snapshot
    # that was in force when this run was claimed, copied onto the row so the
    # question "which approved definition did this run execute under" is
    # answerable from the run record alone, long after the process snapshot or
    # the files on disk have moved on. Null for unbound agents and for the
    # ungoverned manifest-directory mode, which has no provenance to claim.
    ("runs", "registry_digest", "TEXT"),
    # Complete frozen executable identity selected from that same verified
    # snapshot at admission. Canonical JSON of RuntimeResolution (including
    # command/resources), because every field can affect what executes.
    ("runs", "runtime_resolution", "TEXT"),
    ("runs", "ceiling_audiences", "TEXT"),
    # WHO asserted the pin, kept for audit: an application assertion is acceptable
    # but must be attributable, and an IdP claim is stronger than either.
    ("runs", "pin_asserted_by", "TEXT"),
    # THE CEILING. Per-agent limits the authorization server intersects at mint
    # time: which actions and which audiences this agent may EVER be granted,
    # independent of how entitled its user is. A read-only classifier in front of
    # a write-capable specialist is only safe because scope is re-derived against
    # each agent's own ceiling rather than passed hand to hand.
    ("agents", "ceiling_actions", "TEXT"),
    ("agents", "ceiling_audiences", "TEXT"),
    # Immutable definition identity. Runtime names may be prefixed or renamed;
    # authorization and manifest resolution bind through this key instead.
    ("agents", "registry_agent_id", "TEXT"),
    # THE PIN TRAVELS WITH THE WORK ITEM, not only with the run that created it.
    #
    # Delegation wakes its target BEST-EFFORT, so handing work to a BUSY agent is
    # normal, and the re-drive then happens later in heartbeat.drain_pending_work
    # -- which has no parent run to inherit from and therefore created an
    # UNPINNED run. A compromised agent could force that path simply by
    # delegating to an assignee that is already busy, and the work would execute
    # with the pin stripped off. Recording the pin ON the task or message closes
    # it at the only place that survives the deferral: the work item itself.
    ("tasks", "subject_context", "TEXT"),
    ("messages", "subject_context", "TEXT"),
    ("tasks", "delegated_user", "TEXT"),
    ("tasks", "delegated_scope", "TEXT"),
    ("messages", "delegated_user", "TEXT"),
    ("messages", "delegated_scope", "TEXT"),
    # TEARDOWN TOMBSTONE. A revoked run must stay distinguishable from one that
    # was evicted, is lagging, or never existed -- missing state is ambiguous
    # between all four, so a tombstone beats a delete. Retained past the maximum
    # token lifetime, since read-tier tokens stay valid to expiry by design.
    ("runs", "revoked_at", "TEXT"),
    # Verified action-time authority, not a reusable credential. Legacy queued
    # approvals lack this snapshot and must be requested again, never upgraded.
    ("action_requests", "authorization_snapshot", "TEXT"),
    ("action_requests", "grant_expires_at", "INTEGER"),
    # Conversation liveness: a conversation run legitimately runs far longer than
    # RUN_TTL, so it cannot be reaped by started_at age. The session beats this
    # column on every turn poll; the reaper reaps a conversation only when this
    # goes stale (the session process actually died).
    ("runs", "heartbeat_at", "TEXT"),
    # The operator's acknowledged read position in the conversation event stream,
    # advanced as the operator polls /events. Lets the backlog cap count only
    # UNREAD events (a non-reading operator), not total events (a healthy session).
    ("runs", "conv_read_cursor", "INTEGER"),
    # THE INPUT. One JSON value the trigger caller handed this run, canonical
    # text, sealed into the INSERT beside scope and the pin for the reason they
    # are. `reason` is the human WHY and stays; this is the WITH WHAT. Delivered
    # per interface -- a fenced prompt section, runtime-v1's `input.data`, or
    # the bytes an exec/v1 process reads -- and read by nothing that decides
    # authority. NULL means the run was a plain wakeup. See andyur/runinput.py.
    ("runs", "input", "TEXT"),
    # The run that woke this one (task or message delegation), so a workflow
    # graph is drawn from the record, not inferred from depth and timing.
    # NULL for a root run (trigger, schedule, drain).
    ("runs", "parent_run_id", "TEXT"),
    # THE RUN THAT CREATED THIS WORK ITEM. The API already accepts it -- it is
    # how the server resolves the workflow, server-authoritatively -- and then
    # discarded it. Keeping it is what lets a run woken LATER for this item
    # record a true parent: the heartbeat drain had nothing to record, so a run
    # that performed a delegated task drew as a second root in its workflow
    # graph (ROADMAP.md 28).
    ("tasks", "parent_run_id", "TEXT"),
    ("messages", "parent_run_id", "TEXT"),
    # WHICH ENGINE IS RUNNING THIS WORKFLOW, and what that engine calls it.
    #
    # A workflow is bound to one provider when it starts and stays there: the
    # providers do not offer the same guarantees, so silently continuing work
    # under a different one would change what was promised when it was admitted.
    # Recorded here rather than inferred from configuration, because
    # configuration is what CHANGES -- an operator switching providers must not
    # thereby re-home workflows that are already running.
    #
    # `provider_workflow_id` is the engine's own name for it and may equal the
    # Andyur id; that is a mapping decision, not identity equivalence, so it
    # gets its own column rather than being assumed. `provider_ref` is the
    # engine's handle for one execution and is OPAQUE: stored for correlation
    # when reading an engine's own console, never parsed and never compared for
    # meaning.
    ("workflows", "provider", "TEXT"),
    ("workflows", "provider_workflow_id", "TEXT"),
    ("workflows", "provider_ref", "TEXT"),
    # LAST-KNOWN provider state, and nothing may decide anything from it.
    #
    # It is a cache for reads that should not cost a call to the engine -- an
    # operator listing workflows -- and it is stale the moment it is written.
    # The live answer is `provider.describe()`. Governance decisions (halt,
    # admission, caps) read `workflows.state`, which is Andyur's and
    # authoritative; a test asserts nothing branches on this one.
    ("workflows", "provider_state", "TEXT"),
    # Lets the record's shape move without guessing which shape a row has.
    ("workflows", "schema_version", "INTEGER DEFAULT 1"),
    # The workflows table had created_at and nothing else, so "when did this
    # last change" was unanswerable -- which matters now that a row carries a
    # binding that is written after the row itself.
    ("workflows", "updated_at", "TEXT"),
]


def integrity_errors() -> tuple:
    """Exception types a unique/foreign-key violation raises, per backend, so
    callers can catch duplicates without knowing which store is active."""
    if IS_POSTGRES:
        import psycopg

        return (psycopg.errors.IntegrityError,)
    return (sqlite3.IntegrityError,)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _Conn:
    """Uniform connection wrapper. Presents the sqlite3 surface the service
    code expects (`.execute(sql, params)` returning a cursor with
    `.fetchone()/.fetchall()/.rowcount`, dict-convertible rows) over either
    backend, translating `?` placeholders to `%s` for Postgres, and committing
    or rolling back and closing on context-manager exit."""

    def __init__(self, raw, release=None):
        self._raw = raw
        self._release = release

    def execute(self, sql, params=()):
        if IS_POSTGRES:
            sql = sql.replace("?", "%s")
        return self._raw.execute(sql, params)

    def executescript(self, script):
        if IS_POSTGRES:
            # strip `--` comments first so semicolons inside a comment do not
            # break statement splitting, then run each statement
            clean = "\n".join(line.split("--")[0] for line in script.splitlines())
            for stmt in filter(str.strip, clean.split(";")):
                self._raw.execute(stmt)
        else:
            self._raw.executescript(script)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._raw.commit()
            else:
                self._raw.rollback()
        finally:
            # A pooled connection is RETURNED, not closed: closing it would
            # defeat the pool and put the handshake back on every request.
            if self._release is not None:
                self._release(self._raw)
            else:
                self._raw.close()


_pool = None
_pool_lock = threading.Lock()

# Bounds on the Postgres pool. The ceiling matters more than the floor: FastAPI
# runs this project's synchronous endpoints on a threadpool of ~40, so without a
# pool the server opened up to forty simultaneous connections, each doing a full
# SCRAM handshake, per burst.
POOL_MIN = int(os.environ.get("ANDYUR_DB_POOL_MIN", "1"))
POOL_MAX = int(os.environ.get("ANDYUR_DB_POOL_MAX", "10"))
# How long a caller may wait for a connection before failing. Deliberately short:
# see the note in _get_pool about what an unbounded wait does to the server.
POOL_TIMEOUT = float(os.environ.get("ANDYUR_DB_POOL_TIMEOUT", "5"))
# How many callers may queue for a connection at once. Roughly "one pool's worth
# of pending work"; beyond that, shed rather than accumulate.
POOL_MAX_WAITING = int(os.environ.get("ANDYUR_DB_POOL_MAX_WAITING", str(POOL_MAX * 4)))


def _get_pool():
    """The shared Postgres connection pool, opened once.

    Why this exists at all, beyond the obvious cost of a TCP connect and a SCRAM
    handshake per query: a burst of concurrent authentications is what crashed
    this process. `psycopg[binary]` bundles its own libpq AND its own OpenSSL,
    which then coexists with the OpenSSL that Python's own ssl module loaded --
    two copies with separate allocator state in one process. Under concurrent
    SCRAM the heap guard tripped and the interpreter aborted:

        nanov2_guard_corruption_detected <- CRYPTO_zalloc <- HMAC_Init_ex
                                         <- pg_hmac_init <- scram_exchange

    Pooling removes almost all of those handshakes. `psycopg[c]` in
    requirements.txt removes the duplicate library that made them dangerous.
    Both, because either alone leaves the other half of the problem.
    """
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                from psycopg.rows import dict_row
                from psycopg_pool import ConnectionPool

                # BOUND THE WAIT, or a database blip parks the whole server.
                # ConnectionPool(open=True) does not raise when the database is
                # unreachable -- it opens the pool and keeps trying in the
                # background -- so with no timeout every request thread blocked
                # in getconn() for the 30s default, and did it again on the next
                # request. One blip, every thread, repeatedly: the control plane
                # stops answering, the daemons' heartbeats time out, and their
                # runs start looking unaccountable to a server that is merely
                # waiting.
                #
                # timeout      fail a request in seconds, not half a minute. A
                #              500 is a better answer than a hang: the caller
                #              retries, the thread is freed, and the failure is
                #              visible instead of looking like slowness.
                # max_waiting  shed load rather than queue it without limit. An
                #              unbounded waiting list is how a brief outage
                #              becomes a thundering-herd recovery.
                # check        hand out connections that still work. Without it
                #              a connection killed by a restart or an idle
                #              timeout is returned from the pool and fails at
                #              the first query, which reads as a query bug.
                _pool = ConnectionPool(
                    DB_URL, min_size=POOL_MIN, max_size=POOL_MAX,
                    kwargs={"row_factory": dict_row}, open=True,
                    timeout=POOL_TIMEOUT, max_waiting=POOL_MAX_WAITING,
                    check=ConnectionPool.check_connection,
                )
    return _pool


def connect() -> _Conn:
    if IS_POSTGRES:
        pool = _get_pool()
        raw = pool.getconn()
        return _Conn(raw, release=pool.putconn)
    layout.create_data_dir(DATA_DIR)
    raw = sqlite3.connect(DB_PATH, timeout=10)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA journal_mode=WAL")
    raw.execute("PRAGMA foreign_keys=ON")
    return _Conn(raw)


AGENT_STATUS_VIEW = """SELECT a.name AS agent,
       CASE
           WHEN r.state = 'running' THEN 'running'
           WHEN r.state = 'pending' THEN 'queued'
           ELSE 'idle'
       END AS state,
       r.id AS run_id,
       COALESCE(r.started_at, r.created_at, a.created_at) AS updated_at
FROM agents a
LEFT JOIN runs r ON r.agent = a.name AND r.state IN ('pending', 'running');"""


def _create_agent_status_view(conn) -> None:
    """Create the derived coordination view, in each engine's own spelling.

    Kept out of SCHEMA because there is no syntax both accept: SQLite has
    `CREATE VIEW IF NOT EXISTS` and no `OR REPLACE`; Postgres has
    `CREATE OR REPLACE VIEW` and rejects `IF NOT EXISTS`. Writing it once in the
    shared schema looked fine and failed only on the backend with no test
    coverage, which is the same way the reserved-word bug survived.
    """
    if IS_POSTGRES:
        conn.execute("CREATE OR REPLACE VIEW agent_status AS " + AGENT_STATUS_VIEW)
    else:
        conn.execute("CREATE VIEW IF NOT EXISTS agent_status AS " + AGENT_STATUS_VIEW)


def _is_table(conn, name: str) -> bool:
    """Whether `name` exists as a TABLE (not a view), asked per backend."""
    if IS_POSTGRES:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = ? AND table_type = 'BASE TABLE'",
            (name,),
        ).fetchone()
        return row is not None
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def _has_column(conn, table: str, column: str) -> bool:
    """Whether a column exists, asked the same way on both backends."""
    if IS_POSTGRES:
        row = conn.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = ? AND column_name = ?",
            (table, column),
        ).fetchone()
        return row is not None
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


def init_db() -> None:
    with connect() as conn:
        if IS_POSTGRES:
            # Serialize schema creation across server replicas. Without this,
            # two replicas running init_db at once deadlock on concurrent
            # CREATE TABLE IF NOT EXISTS. A transaction-scoped advisory lock
            # makes one replica create the tables while the others wait, then
            # find them already there. Auto-released when this transaction ends.
            conn.execute("SELECT pg_advisory_xact_lock(?)", (91237,))
        conn.executescript(SCHEMA)
        for table, col, coltype in MIGRATION_COLUMNS:
            # Quote the column name. `user` is RESERVED in Postgres, so the
            # unquoted form is a syntax error and init_db could not run at all
            # there -- which meant the multi-node path was broken end to end.
            # Double quotes are the SQL standard for identifiers and mean the
            # same thing to SQLite, so one spelling works on both.
            quoted = f'"{col}"'
            if IS_POSTGRES:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {quoted} {coltype}"
                )
            elif not _has_column(conn, table, col):
                # Ask, rather than adding and swallowing the failure. A bare
                # `except sqlite3.OperationalError: pass` treats "database is
                # locked" as "column already exists": the column is then
                # absent, and the CREATE INDEX below -- which names a MIGRATION
                # column -- raises `no such column` OUT of init_db, so the
                # server does not start at all. Asking first means a real
                # failure is still raised, at the statement that caused it.
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {quoted} {coltype}")
        # These cover MIGRATION columns, so they can only be created after the
        # loop above adds them: a workflow's runs, tasks and messages resolve
        # by one index probe instead of a table scan (the flow graph reads all
        # three on every call). None of them carries created_at, so the small
        # ORDER BY inside one workflow is still a temp sort; that is bounded by
        # the workflow's size (measured 0.5 ms at 200 rows), not by the table.
        #
        # UPGRADE COST, measured: on Postgres these are built inside init_db's
        # transaction, which holds a ShareLock on each table, and CREATE INDEX
        # CONCURRENTLY cannot run in a transaction. The first replica to
        # restart after an upgrade blocks writes to runs/tasks/messages for
        # roughly 0.5 s per million rows per index while it builds them, with
        # the other replicas queued behind the advisory lock. Build them by
        # hand with CONCURRENTLY before restarting a large deployment.
        for name, table in (("idx_runs_workflow", "runs"),
                            ("idx_tasks_workflow", "tasks"),
                            ("idx_messages_workflow", "messages")):
            conn.execute(
                f"CREATE INDEX IF NOT EXISTS {name} ON {table}(workflow_id)")
        # Runtime instances resolve by immutable definition identity. This is
        # intentionally NON-UNIQUE: several prefixed instances may instantiate
        # the same approved definition at once.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agents_registry_agent_id "
            "ON agents(registry_agent_id)"
        )
        # GET /runs under user-auth filters on agents.owner, so without this the
        # planner drives the join from a full scan of `agents`. It does not make
        # the owner-scoped page a pure keyset walk -- see idx_runs_created in
        # SCHEMA for what that path actually costs -- but it does stop the scan.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(owner)"
        )
        # agent_status was a TABLE holding coordination state that `runs`
        # already determines. It is now a view, so an existing database has to
        # drop the table first -- the name cannot be both. Nothing is lost: every
        # column it held is derivable, and any row in it that disagreed with
        # `runs` was a coherence bug rather than data.
        if _is_table(conn, "agent_status"):
            conn.execute("DROP TABLE agent_status")
        _create_agent_status_view(conn)

        # One-time rename of a column that should never have been named after a
        # reserved word. `user` is reserved in Postgres, so every read had to be
        # quoted; miss one quote and the query does not fail, it silently returns
        # CURRENT_USER -- the database role name -- including where the value
        # feeds an authorization comparison. The defence was a static analysis
        # test policing every call site. Renaming the column deletes the hazard
        # instead of policing it, and the test with it.
        #
        # Data is carried across rather than dropped, and the copy runs only
        # while a legacy column is present, so this is idempotent.
        if _has_column(conn, "runs", "user"):
            conn.execute('UPDATE runs SET acting_user = "user" '
                         'WHERE acting_user IS NULL')
            try:
                conn.execute('ALTER TABLE runs DROP COLUMN "user"')
            except Exception:
                # Old SQLite cannot drop a column. Leaving it is harmless: it is
                # unread, and the data has already been copied.
                pass

        # Seed the lock-rendezvous singleton rows.
        #
        # Idempotent by CONFLICT CLAUSE, not by catching the error. Catching it
        # is what silently broke every migration on Postgres after the first
        # run: a failed statement aborts the whole transaction there, so the
        # commit that follows is converted to a rollback and everything init_db
        # just did -- including the ALTER TABLEs above -- is discarded, while
        # init_db returns success. The single-node path hid it completely,
        # because SQLite has no such rule.
        #
        # Both backends accept ON CONFLICT DO NOTHING, so the statement never
        # fails and there is no aborted transaction to recover from.
        for name in ("conversations",):
            conn.execute(
                "INSERT INTO singletons (id, touched) VALUES (?, 0) "
                "ON CONFLICT (id) DO NOTHING",
                (name,),
            )


def lock_singleton(conn, name: str) -> None:
    """Serialize a cross-cutting critical section on a named singleton row. On
    Postgres this is a row-level FOR UPDATE (concurrent lockers block); on SQLite
    a touch-write takes the database write lock, giving the same serialization on
    the single-writer backend. The caller must already be inside `conn`'s
    transaction; the lock releases when that transaction commits."""
    if IS_POSTGRES:
        conn.execute("SELECT 1 FROM singletons WHERE id = ? FOR UPDATE", (name,))
    else:
        conn.execute("UPDATE singletons SET touched = touched + 1 WHERE id = ?", (name,))
