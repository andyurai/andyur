"""Coordination: who may run, and when.

The state machine per agent:

    idle -> queued -> running -> idle

All transitions are compare-and-swap UPDATEs keyed on the current state, so
two concurrent triggers can never both claim the same agent: one UPDATE
matches the idle row, the other matches nothing and loses.
"""

import json
import logging
import os
import uuid

from .. import config, db, runinput
from ..registry.models import RUNTIME_PROTOCOL_EXEC_V1
from ..registry.runtime_wire import encode_runtime
from . import registry, runtoken

log = logging.getLogger("andyur.coordinator")

# Delegation guards (R7): a runaway or poisoned workflow cannot fan out forever.
# A child's depth is its parent's + 1; a workflow's live work items are capped.
MAX_DELEGATION_DEPTH = int(os.environ.get("ANDYUR_MAX_DELEGATION_DEPTH", "8"))
MAX_WORKFLOW_RUNS = int(os.environ.get("ANDYUR_MAX_WORKFLOW_RUNS", "200"))
# The conversation caps live in config.py (with every other conversation bound) and
# are read as config.X below, so there is a single source of truth for the default.

# runs that no longer consume the workflow's live budget
TERMINAL_RUN_STATES = ("done", "failed", "cancelled")

# WHY THERE IS NO LOCK-ORDER SECTION HERE ANY MORE.
#
# There used to be forty lines documenting the order in which every function
# took `workflows`, `runs` and `agent_status`, because coordination state lived
# in a second table that six writers kept in step by hand. That comment was
# wrong about itself twice, and three separate reviews each found another writer
# violating it -- including one where the operator's own kill switch was the side
# that lost the deadlock.
#
# `agent_status` is now a VIEW over `runs` (see db.SCHEMA), and claiming an agent
# is inserting its run, admitted by a partial unique index. A writer that touches
# one table cannot deadlock against itself on ordering, so the invariant is not
# documented, enforced or reviewed: it is absent. That is the difference between
# a rule people follow and a rule that cannot be broken.
#
# `_lock_workflow` remains, because the halt/start rendezvous is a genuine
# serialization need and not a coherence workaround.


class DelegationRefused(Exception):
    """New delegated work was refused: the workflow is halted, at its work-item
    cap, at max depth, or the parent run does not exist. Callers that create
    durable work (tasks/messages) raise this; the run-wakeup path returns None."""


class PinRefused(DelegationRefused):
    """A pin (subject_context) was refused: unusable in shape, unattributable, or
    -- the case that matters -- an attempt to set or change the pin on work that
    descends from an already-pinned run.

    A SUBCLASS of DelegationRefused so every existing delegation caller already
    turns it into a refusal (409) instead of a 500, but a DISTINCT type because
    it must never be mistaken for the ordinary 'agent is busy' refusal that
    maybe_wakeup answers with None. A retarget attempt is a security event: the
    one thing it must not do is look like backpressure and disappear."""


class InputRefused(DelegationRefused):
    """The run's input cannot be delivered to the agent's declared process:
    an exec/v1 manifest that takes no input was handed one, one that takes
    input was woken without one, or the input is over the manifest's bound.

    Same shape as PinRefused and for the same reasons: a DelegationRefused so
    the delegation callers already answer it as a refusal, and a DISTINCT type
    because it is a defect in the REQUEST, not backpressure. A retry of the
    same wakeup is refused forever, so it must never be mistaken for "busy"."""


def new_workflow_id() -> str:
    """Mint a fresh workflow (transaction) identity. Sealed at the root of a
    request and then carried unchanged by every downstream run/task."""
    return "wf-" + uuid.uuid4().hex[:12]


def workflow_of_run(conn, run_id: str | None) -> str | None:
    """The workflow a run belongs to (server-authoritative source of truth)."""
    if not run_id:
        return None
    row = conn.execute(
        "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)
    ).fetchone()
    return row["workflow_id"] if row else None


def is_halted(conn, workflow_id: str) -> bool:
    row = conn.execute(
        "SELECT state FROM workflows WHERE id = ?", (workflow_id,)
    ).fetchone()
    return row is not None and row["state"] == "halted"


def workflow_state(workflow_id: str) -> str | None:
    """Current state of a workflow ('active' | 'halted'), or None if unseen.
    Used by a running agent to poll whether it has been halted mid-run."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT state FROM workflows WHERE id = ?", (workflow_id,)
        ).fetchone()
    return row["state"] if row else None


def halt_workflow(workflow_id: str) -> bool:
    """Kill-switch. Marks the workflow halted AND tears down its queued work:
    frees agents stranded on a pending run, cancels those runs, closes open
    tasks, and marks unread messages handled. Destructive so that (a) an agent
    is never left stuck 'queued' on a run that will never be assigned, and
    (b) unhalt cannot resurrect a poisoned workflow's accumulated work."""
    now = db.utcnow()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO workflows (id, state, created_at) VALUES (?, 'halted', ?) "
            "ON CONFLICT(id) DO UPDATE SET state = 'halted'",
            (workflow_id, now),
        )
        # Cancelling the runs IS freeing the agents: an agent is busy only
        # while it has a live run, so there is nothing else to update. The
        # read-then-write dance this replaces existed solely to keep a second
        # table in step, and it was the writer whose lock order deadlocked
        # against every other one.
        conn.execute(
            "UPDATE runs SET state = 'cancelled', finished_at = ?, "
            "subject_token = NULL "
            "WHERE workflow_id = ? AND state = 'pending'",
            (now, workflow_id),
        )
        conn.execute(
            "UPDATE tasks SET state = 'closed', updated_at = ? "
            "WHERE workflow_id = ? AND state != 'closed'",
            (now, workflow_id),
        )
        conn.execute(
            "UPDATE messages SET state = 'handled' "
            "WHERE workflow_id = ? AND state = 'unread'",
            (workflow_id,),
        )
    return True


# Upper bound on how many in-flight run ids one worker may report per beat, and
# the batch size the query uses (SQLite's bind-parameter limit is the constraint).
_MAX_REPORTED_RUNS = 5000
_CHUNK = 400


def run_is_live(run_id: str) -> bool:
    """Whether a run is still executing. The one bit the broker needs to decide
    whether to keep spending on its behalf. Same answer for a finished run and a
    run that never existed, so it cannot be used to enumerate run ids."""
    if not run_id:
        return False
    with db.connect() as conn:
        row = conn.execute(
            "SELECT state FROM runs WHERE id = ?", (run_id,)).fetchone()
    return bool(row) and row["state"] in ("pending", "running")


def runs_to_kill(running: list[str]) -> list[str]:
    """Of the runs a worker reports as in flight, which must be destroyed now.

    The runner polls the halt flag itself and stops between tool calls, which is
    fast but not a boundary: it only lands between SDK messages, so a run sitting
    inside one long tool call keeps going, and a run whose process is wedged or
    whose agent has subverted its own loop never checks at all. Asking the
    process to stop is a request; destroying the container it runs in is the
    guarantee. This function decides who gets the guarantee.

    Two populations, and the second is easy to miss:
      halted   the operator pulled the kill switch on this run's workflow
      orphan   the run record is already terminal (or gone) while a process for
               it is still alive -- a reaped run, or a container left over from
               a previous daemon. An execution with no live run record is
               unaccountable by definition: nothing will record what it does.

    The run record is finalized HERE rather than by the process being killed.
    Never ask a process you are destroying to write its own obituary: it may not
    survive long enough, and if it has been subverted the obituary is a lie.
    """
    if not running:
        return []
    # De-duplicate, then query in CHUNKS rather than truncating. A cap alone
    # turned a denial-of-service into a silent kill-switch failure: a condemned
    # run past the cutoff was never killed and never logged, and the list is
    # attacker-influenceable through what a worker reports. Chunking keeps the
    # bind-parameter limit satisfied without dropping anyone.
    running = list(dict.fromkeys(running))
    if len(running) > _MAX_REPORTED_RUNS:
        # Still bounded, because an unbounded list is a resource attack. Dropping
        # is now LOUD: a truncated kill list is a safety failure and must never
        # look like a quiet success.
        log.error(
            "worker reported %d in-flight runs, above the %d cap; the excess is "
            "ignored and any condemned run among them will NOT be killed",
            len(running), _MAX_REPORTED_RUNS)
        running = running[:_MAX_REPORTED_RUNS]
    known: dict = {}
    halted: set = set()
    with db.connect() as conn:
        for start in range(0, len(running), _CHUNK):
            batch = running[start:start + _CHUNK]
            placeholders = ",".join("?" for _ in batch)
            known.update({
                r["id"]: r for r in conn.execute(
                    f"SELECT id, state, workflow_id FROM runs WHERE id IN ({placeholders})",
                    batch,
                ).fetchall()
            })
            halted.update(
                r["id"] for r in conn.execute(
                    f"SELECT id FROM runs WHERE id IN ({placeholders}) AND workflow_id IN "
                    "(SELECT id FROM workflows WHERE state = 'halted')",
                    batch,
                ).fetchall()
            )
    doomed = []
    for run_id in running:
        row = known.get(run_id)
        if row is None:                       # no record at all: unaccountable
            doomed.append(run_id)
        elif run_id in halted:
            doomed.append(run_id)
        elif row["state"] not in ("pending", "running"):
            doomed.append(run_id)             # already finalized, still executing
    if doomed:
        _finalize_condemned(doomed)
    return doomed


def _finalize_condemned(doomed: list[str]) -> None:
    """Write the obituaries for a whole batch in ONE connection.

    Calling finish_run per run opened a fresh connection each time, which put
    seconds of synchronous database work inside a heartbeat that every worker
    makes every ten seconds -- and raising the report cap multiplied it. On
    Postgres it is N sequential un-pooled connects in one request.

    Idempotent, like finish_run: the UPDATE matches only a live run, so
    re-issuing the kill on later beats (until the process is really gone) does
    not rewrite a record that is already terminal.
    """
    now = db.utcnow()
    reason = "halted: destroyed by the operator kill switch"
    with db.connect() as conn:
        for start in range(0, len(doomed), _CHUNK):
            batch = doomed[start:start + _CHUNK]
            placeholders = ",".join("?" for _ in batch)
            # Finalizing the run frees its agent, because "busy" is derived
            # from having a live run. One statement, one table, no ordering
            # question to get wrong.
            conn.execute(
                f"UPDATE runs SET state = 'failed', summary = NULL, error = ?, "
                f"finished_at = ?, subject_token = NULL "
                f"WHERE id IN ({placeholders}) AND state IN ('pending', 'running')",
                [reason, now, *batch],
            )


def live_run_ids(workflow_id: str) -> list[str]:
    """The runs in this workflow that have not reached a terminal state.

    Read by the facade AFTER it has written the governance halt, to tell the
    workflow provider which executions to signal. By then `halt_workflow` has
    cancelled every pending run, so this is in practice the runs already
    executing -- the ones a signal can still reach -- and a cancelled run's
    observer sees the terminal state and exits by itself.
    """
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id FROM runs WHERE workflow_id = ? "
            "AND state IN ('pending', 'running') ORDER BY created_at",
            (workflow_id,),
        ).fetchall()
    return [row["id"] for row in rows]


def unhalt_workflow(workflow_id: str) -> bool:
    """Reverse a halt (operator recoverability). Only re-opens the workflow for
    NEW work; halt already tore down what was queued, so nothing is resurrected."""
    now = db.utcnow()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO workflows (id, state, created_at) VALUES (?, 'active', ?) "
            "ON CONFLICT(id) DO UPDATE SET state = 'active'",
            (workflow_id, now),
        )
    return True


def set_paused(agent: str, paused: bool) -> bool:
    """Pause/resume an agent. A paused agent is never woken (agent-level kill).
    Pausing also stops already-queued work: it cancels the agent's pending run
    and frees its 'queued' status, so a runaway source's next wave is dropped,
    not just its future wakeups. (A run already 'running' finishes; use the
    workflow halt + in-flight poll to stop that.)"""
    now = db.utcnow()
    with db.connect() as conn:
        cur = conn.execute(
            "UPDATE agents SET paused = ? WHERE name = ?",
            (1 if paused else 0, agent),
        )
        if paused and cur.rowcount:
            # Lock the workflow of the agent's pending run first (Postgres), so
            # pause serializes with start_run/wakeup on the same rendezvous and
            # cannot ABBA-deadlock with start_run on (agent_status, runs). The
            # agent-row lock (taken by the UPDATE above and by maybe_wakeup) closes
            # the first-run race where a wakeup lands just as the agent is paused.
            if db.IS_POSTGRES:
                wf = conn.execute(
                    "SELECT workflow_id FROM runs WHERE agent = ? AND state = 'pending' "
                    "LIMIT 1",
                    (agent,),
                ).fetchone()
                if wf and wf["workflow_id"]:
                    conn.execute(
                        "SELECT id FROM workflows WHERE id = ? FOR UPDATE",
                        (wf["workflow_id"],),
                    )
            # Cancelling the pending run is the whole operation: the agent is
            # queued only because that run exists.
            conn.execute(
                "UPDATE runs SET state = 'cancelled', finished_at = ?, "
                "subject_token = NULL "
                "WHERE agent = ? AND state = 'pending'",
                (now, agent),
            )
    return cur.rowcount > 0


def resolve_workflow(conn, parent_run_id, workflow_id=None, depth_floor: int = 0):
    """Return (workflow_id, depth) for new work, SERVER-authoritatively.

    A child references `parent_run_id` and inherits that run's workflow with
    depth+1. An unknown/forged parent is REFUSED (raises DelegationRefused) --
    it must NOT fall through to a fresh depth-0 root, which would let a bogus
    parent id reset depth and bypass the cap. A root (no parent) seals a fresh
    workflow at depth 0.

    `depth_floor` is for work that HAS parents but no single one: the heartbeat
    drain renders all of an agent's waiting work at once, so two runs in the
    same workflow delegating to the same agent leave work with two parents and
    no honest `parent_run_id`. Without a floor that run joined the workflow at
    depth 0 -- a genuine depth-cap bypass, and one an agent triggers on demand
    by delegating twice to an assignee it keeps busy. The floor is the DEEPEST
    parent's depth + 1: the tightest bound that under-counts no chain. Refusing
    to join instead would be worse, because the run would fall back to a fresh
    workflow with a fresh work-item budget, which is the more permissive of the
    two escapes.
    """
    if parent_run_id:
        row = conn.execute(
            "SELECT workflow_id, depth FROM runs WHERE id = ?", (parent_run_id,)
        ).fetchone()
        if row is None:
            raise DelegationRefused(f"unknown parent run '{parent_run_id}'")
        return (workflow_id or row["workflow_id"]), max(
            (row["depth"] or 0) + 1, depth_floor)
    return (workflow_id or new_workflow_id()), depth_floor


# --- THE PIN (subject_context) ---------------------------------------------
#
# `scope` says what a run may DO and `acting_user` says who it acts FOR. Neither
# says what the work is ABOUT. Without that third term, a run entitled to write
# invoices for the user it acts for is entitled to write invoices for EVERY
# account that user can reach, and the only thing that keeps it on account 447 is
# a sentence in its prompt -- which is text, which the model can be argued out of
# by other text it ingests. The pin is that sentence turned into a claim: sealed
# on the run at creation, carried in the signed grant, never re-read from the
# prompt and never accepted from the model.

def canonical_pin(subject_context) -> str | None:
    """The one byte representation of a pin, or None for an unpinned run.

    Sorted keys and no whitespace, so that comparing a delegated pin against its
    parent's is a string comparison that cannot be defeated by re-ordering or
    re-spacing the same dict. Raises PinRefused for anything that is not a flat
    map of non-empty string ids.

    An EMPTY dict is refused rather than stored. `{}` would persist as a pin that
    constrains nothing while the caller believes the run is pinned, and that is
    the worst of the three possible readings -- worse than unpinned, which is at
    least honest about granting no narrowing.
    """
    if subject_context is None:
        return None
    if not isinstance(subject_context, dict):
        raise PinRefused(
            f"subject_context must be a map of canonical resource ids, "
            f"got {type(subject_context).__name__}")
    if not subject_context:
        raise PinRefused(
            "subject_context is empty; an empty pin constrains nothing and would "
            "read as pinned. Omit it to run unpinned.")
    for key, value in subject_context.items():
        if not isinstance(key, str) or not key:
            raise PinRefused(f"subject_context key {key!r} is not a non-empty string")
        if not isinstance(value, str) or not value:
            raise PinRefused(
                f"subject_context['{key}'] must be a non-empty string id, "
                f"got {value!r}")
    return json.dumps(subject_context, sort_keys=True, separators=(",", ":"))


def pin_of_run(conn, run_id):
    """The canonical pin sealed on a run, or None.

    Used where WORK is created, so a task or message can carry the pin of the run
    that produced it. Reads the sealed column rather than any request field: the
    creating agent is exactly the party that must not get a say.
    """
    if not run_id:
        return None
    row = conn.execute(
        "SELECT subject_context FROM runs WHERE id = ?", (run_id,)
    ).fetchone()
    return row["subject_context"] if row is not None else None


def resolve_pin(conn, parent_run_id, subject_context=None, asserted_by=None):
    """Return (pin_json, asserted_by) for new work, SERVER-authoritatively.

    Two cases, and the second is the security property:

      ROOT (no parent). The pin is whatever the authenticated caller asserted,
      and WHO asserted it is recorded. An unattributable pin is refused: an
      application assertion is acceptable, an anonymous one is not, because the
      audit answer "something set this run's target" is not an answer.

      DELEGATED (a parent run). The pin is the PARENT'S, copied unchanged, and
      the delegator gets no say. If the delegating side supplies a pin at all it
      must be byte-identical to the parent's, or the request is refused --
      including the case where the parent is unpinned and the child arrives with
      one, which is the same attack wearing the other hat. A compromised agent's
      whole play here is to hand its child a different account and let the child
      do, with full legitimate authority, what the parent was never pinned to;
      copying rather than accepting is what makes that impossible rather than
      merely disallowed.

    Note that "the delegator supplied a pin" is not reachable through today's
    task/message API -- there is no field for it. The check is here anyway,
    because the guarantee has to live at the seam where runs are created, not in
    the absence of a request field that any future endpoint could add back.
    """
    if parent_run_id:
        row = conn.execute(
            "SELECT subject_context, pin_asserted_by FROM runs WHERE id = ?",
            (parent_run_id,),
        ).fetchone()
        if row is None:
            raise DelegationRefused(f"unknown parent run '{parent_run_id}'")
        inherited = row["subject_context"]
        if subject_context is not None and canonical_pin(subject_context) != inherited:
            raise PinRefused(
                f"a delegated run inherits its parent's subject_context and cannot "
                f"set or change it (parent run '{parent_run_id}' is pinned to "
                f"{inherited or 'nothing'})")
        return inherited, row["pin_asserted_by"]
    pin = canonical_pin(subject_context)
    if pin is not None and not asserted_by:
        raise PinRefused(
            "a subject_context must name the authenticated caller that asserted "
            "it; an unattributable pin is refused")
    return pin, (asserted_by if pin is not None else None)


def _lock_workflow(conn, workflow_id, now) -> None:
    """Ensure the workflow row exists and, on Postgres, take a row lock. Every
    durable inserter (wakeup, task, message) locks the SAME workflow row before
    its count-check + insert, so they all serialize on one rendezvous point and
    the cap cannot be overshot by concurrent inserters. SQLite has a single
    writer, so its transaction already serializes."""
    conn.execute(
        "INSERT INTO workflows (id, state, created_at) VALUES (?, 'active', ?) "
        "ON CONFLICT(id) DO NOTHING",
        (workflow_id, now),
    )
    if db.IS_POSTGRES:
        conn.execute("SELECT id FROM workflows WHERE id = ? FOR UPDATE", (workflow_id,))


# WHY NEW WORK WAS REFUSED, by name. `admit` returned a bare bool, so every
# caller could say only "halted or at its work-item cap" -- one string for three
# controls with three different operator responses (resume the workflow, raise
# the depth, wait for the fan-out to finish). The names are the platform's
# existing reason vocabulary (observability._REASONS), so the span attribute,
# the metric label and the refusal text are one term and not three.
ADMITTED = None                 # not a refusal
REFUSED_HALTED = "refused"      # the kill switch: a deliberate operator act
REFUSED_DEPTH = "invalid"       # the delegation chain is longer than allowed
REFUSED_CAP = "exhausted"       # the workflow's work-item budget is spent

_REFUSAL_TEXT = {
    REFUSED_HALTED: "is halted",
    REFUSED_DEPTH: "is past its delegation depth",
    REFUSED_CAP: "is at its work-item cap",
}


def refusal_text(workflow_id, reason) -> str:
    return f"workflow '{workflow_id}' {_REFUSAL_TEXT[reason]}"


def admit(conn, workflow_id, depth, converting_agent: str | None = None) -> str | None:
    """May new work join this workflow? Checks the kill-switch, the depth cap,
    and the work-item cap (LIVE runs + still-open tasks). Call `_lock_workflow`
    first in the same transaction so the count is race-free.

    `converting_agent` names the agent whose waiting work this new run is ABOUT
    TO EXECUTE rather than add. It is not a discount and it does not raise the
    cap: an open task and the run performing that same task are ONE unit of
    work in flight, and counting both meant a workflow at its cap could not
    drain its own waiting work -- the wakeup meant to re-drive a task was
    refused by a budget the task itself was occupying, so the task never ran
    (ROADMAP.md 28).

    The fan-out this cap exists to bound is unaffected, because fan-out is
    CREATING tasks and messages and every one of those still counts. Converting
    an item already inside the budget into the run that performs it adds no
    reach.

    IT IS THE AGENT AND NOT A COUNT, because a count is a second source of
    truth. The drain took its number in an earlier transaction, one per agent
    on the platform, and nothing revalidated it here -- so any item closed or
    read in that window left a credit with nothing behind it, and the workflow
    finished above its cap (reproduced: cap 3, one stale credit, four units
    admitted). Recounted here, under the same workflow lock as the totals it
    corrects, the credit is by construction a SUBSET of them: open tasks are a
    subset of not-closed tasks and unread messages are exactly the messages
    counted, so the subtraction can never go negative and never credits work
    the count did not include.
    """
    if is_halted(conn, workflow_id):
        return REFUSED_HALTED
    if depth > MAX_DELEGATION_DEPTH:
        return REFUSED_DEPTH
    placeholders = ", ".join("?" for _ in TERMINAL_RUN_STATES)
    runs = conn.execute(
        f"SELECT COUNT(*) AS c FROM runs WHERE workflow_id = ? "
        f"AND state NOT IN ({placeholders})",
        (workflow_id, *TERMINAL_RUN_STATES),
    ).fetchone()["c"]
    open_tasks = conn.execute(
        "SELECT COUNT(*) AS c FROM tasks WHERE workflow_id = ? AND state != 'closed'",
        (workflow_id,),
    ).fetchone()["c"]
    # messages are a durable work channel too: count unread ones so a
    # send_message loop cannot fan out past the cap uncounted
    unread_msgs = conn.execute(
        "SELECT COUNT(*) AS c FROM messages WHERE workflow_id = ? AND state = 'unread'",
        (workflow_id,),
    ).fetchone()["c"]
    converting = 0
    if converting_agent:
        # The same predicates the heartbeat drain selects on, so what is
        # credited is exactly what that run is about to render: work in THIS
        # workflow, for THIS agent, never offered to a run before.
        converting = conn.execute(
            "SELECT (SELECT COUNT(*) FROM tasks WHERE workflow_id = ? "
            "        AND assignee = ? AND state = 'open' AND notified_at IS NULL) "
            "     + (SELECT COUNT(*) FROM messages WHERE workflow_id = ? "
            "        AND recipient = ? AND state = 'unread' AND notified_at IS NULL) "
            "AS c",
            (workflow_id, converting_agent, workflow_id, converting_agent),
        ).fetchone()["c"]
    counted = runs + open_tasks + unread_msgs - converting
    return ADMITTED if counted < MAX_WORKFLOW_RUNS else REFUSED_CAP


def guard_new_work(conn, parent_run_id, now, workflow_id=None):
    """Resolve the workflow (refusing an unknown parent), lock it, and admit --
    the single serialization point every durable-work path (create_task,
    send_message) uses before inserting, so the kill-switch and caps are enforced
    where the work is created, race-free. Returns (workflow_id, depth); raises
    DelegationRefused if refused."""
    wf, depth = resolve_workflow(conn, parent_run_id, workflow_id)
    _lock_workflow(conn, wf, now)
    refused = admit(conn, wf, depth)
    if refused:
        raise DelegationRefused(refusal_text(wf, refused))
    return wf, depth


def maybe_wakeup(*args, **kwargs) -> str | None:
    """The run id, or None if the agent could not be woken.

    The view most callers want. `wakeup_or_reason` is the same call with the
    refusal reason kept -- ONE implementation, two views, because returning a
    bare None from six different refusals is what left an operator unable to
    tell a kill switch from a spent budget from a lost race.
    """
    return wakeup_or_reason(*args, **kwargs)[0]


def wakeup_or_reason(
    agent: str,
    reason: str,
    run_type: str = "work",
    trace_ctx: str | None = None,
    parent_run_id: str | None = None,
    workflow_id: str | None = None,
    # The agent whose already-counted waiting work this run is about to EXECUTE
    # rather than add. Only the heartbeat drain sets it; see admit().
    converting_agent: str | None = None,
    # The lowest depth this run may be given, for work with parents but no
    # single one. Only the heartbeat drain sets it; see resolve_workflow().
    depth_floor: int = 0,
    user: str | None = None,
    scope: list | None = None,
    subject_context: dict | None = None,
    pin_asserted_by: str | None = None,
    user_asserted_by: str | None = None,
    subject_token: str | None = None,
    run_input: str | None = None,
    # WHO WILL DISPATCH IT: None for the native assignment loop, "engine" for
    # the durable provider's execution worker. Set by the facade from the
    # bound provider and written in the INSERT itself, so no instant exists in
    # which the native loop could claim a run the engine is about to dispatch.
    dispatch: str | None = None,
    # WHICH PROVIDER it is bound to, in the same INSERT: an engine run is
    # claimable only through the provider that admitted it.
    orchestration_provider: str | None = None,
    # The kind it was admitted as; a re-offer rebuilds the start from it.
    workflow_kind: str | None = None,
) -> str | None:
    """Try to claim an idle agent for a run. Returns run_id, or None if refused
    (agent not idle/paused, unknown parent, workflow halted, or a cap hit).

    `run_input` is the run's SEALED input (runinput.seal's canonical text, or
    None for a plain wakeup). It is written into the same INSERT as the scope
    and the pin. For a registry-bound exec/v1 agent it is also checked against
    the manifest's declared process here, at the door, so a run that could
    never be delivered is refused (InputRefused) rather than launched into a
    stdin wait that ends at the deadline.

    Workflow identity is SERVER-AUTHORITATIVE (see resolve_workflow): a caller
    cannot invent, relabel, or depth-reset a workflow. The workflow row is
    locked before the cap check + run insert so concurrent wakeups/tasks cannot
    overshoot; the agent claim folds the paused check into the CAS so a
    just-paused agent cannot be woken by a racing wakeup.

    The PIN is server-authoritative in the same way (see resolve_pin) and is
    sealed into the INSERT rather than updated afterwards -- for the reason
    already learned with `scope`: a worker heartbeat landing between the insert
    and an update would mint this run's grant from the columns as they stand,
    and an unpinned grant is a run that may touch anything its scope allows.
    A pin refusal RAISES (PinRefused), never returns None: an attempt to
    retarget work must not be indistinguishable from a busy agent."""
    # A run ID is the long-lived authorization principal carried by the
    # workload SPIFFE ID. Keep the full UUIDv4 value (122 random bits): truncating it
    # turns historical SVID/token overlap into a birthday-collision risk after
    # terminal rows are administratively removed.
    run_id = uuid.uuid4().hex
    now = db.utcnow()
    with db.connect() as conn:
        # lock the agent row (Postgres) so a concurrent set_paused serializes
        # against this wakeup -- neither can leak a run past a just-paused agent.
        # FOR NO KEY UPDATE (not FOR UPDATE): it still conflicts with set_paused's
        # non-key UPDATE of agents.paused, but does NOT conflict with the FK
        # KEY-SHARE lock that a concurrent create_task takes on the assignee's
        # agents row -- avoiding a workflows<->agents ABBA deadlock with task inserts.
        lock = " FOR NO KEY UPDATE" if db.IS_POSTGRES else ""
        exists = conn.execute(
            f"SELECT paused, ceiling_actions, ceiling_audiences FROM agents "
            f"WHERE name = ?{lock}", (agent,)
        ).fetchone()
        if exists is None or exists["paused"]:
            return None, ("unknown" if exists is None else "refused")

        # Conversation cap (interactive sessions each hold a slot for their whole
        # lifetime, so bound how many can run at once or they starve headless work).
        # The count spans ALL agents/workflows, so unlike the per-workflow work cap
        # there is no shared row to serialize on -- serialize on the singleton lock
        # so concurrent conversation triggers for DIFFERENT agents cannot each read
        # "under cap" and all insert (a multi-node overshoot).
        if run_type == "conversation":
            db.lock_singleton(conn, "conversations")
            active = conn.execute(
                "SELECT COUNT(*) AS n FROM runs "
                "WHERE run_type = 'conversation' AND state IN ('pending', 'running')"
            ).fetchone()["n"]
            if int(active) >= config.MAX_CONVERSATIONS:
                return None, "exhausted"
            # per-user fairness (under user-auth): one tenant cannot take every slot
            if user is not None:
                mine = conn.execute(
                    "SELECT COUNT(*) AS n FROM runs WHERE run_type = 'conversation' "
                    "AND state IN ('pending', 'running') AND acting_user = ?",
                    (user,),
                ).fetchone()["n"]
                if int(mine) >= config.MAX_CONVERSATIONS_PER_USER:
                    return None, "exhausted"

        try:
            wf, depth = resolve_workflow(conn, parent_run_id, workflow_id,
                                         depth_floor)
        except DelegationRefused:
            # unknown parent: refuse, do not reset to a depth-0 root
            return None, "invalid"

        # Deliberately NOT inside that try: a PinRefused must propagate to the
        # caller, not be flattened into the None that means "agent is busy".
        # Placed before anything is written, so a refused pin leaves no trace to
        # clean up (in particular no minted workflow row).
        pin, pin_by = resolve_pin(conn, parent_run_id, subject_context, pin_asserted_by)

        # Seal the agent's governed ceiling into the run before its token is
        # minted. The external-AS sidecar cannot query the control-plane DB, and
        # the adopter's AS cannot know Andyur's agent registry.
        ceiling = registry._ceiling_from_row(exists, agent)
        narrowed = registry.narrow(
            scope, json.loads(pin) if pin else None, ceiling, None)
        # The registry ceiling bounds DELEGATED (tool) authority. It must not
        # strip the run's INTERNAL control-plane authority -- reading its own
        # agent's context, writing its own memory -- or the run cannot even load
        # its own prompt (GET /agents/{name}/context needs files:read). ADR-010:
        # internal authority is Andyur's to grant from the run belonging to the
        # agent, never the tool ceiling's to deny. The tool mint re-narrows this
        # scope by the ceiling at exchange time, so a restored internal action
        # never reaches a tool token.
        scope = registry.with_internal_actions(scope, narrowed["actions"])
        ceiling_audiences = ceiling.get("audiences")

        # HOW this run's user was established. Read from the PARENT when there is
        # one, never from the caller -- the same rule the pin follows, and for the
        # same reason. A delegating run inherits its parent's user; if it could
        # also state the provenance of that user, delegation would be a laundering
        # step, and a subject nobody authenticated would come out of one hop
        # indistinguishable from a real login.
        user_by = user_asserted_by
        # The SUBJECT TOKEN follows the user: a delegated run acts for the same
        # person, so it presents the same credential. Inherited from the parent
        # row rather than accepted from the caller, for the same reason the pin
        # and the provenance are -- a hop that could restate it could delegate
        # for someone it never authenticated.
        tok = subject_token
        if parent_run_id:
            parent = conn.execute(
                "SELECT acting_user, user_asserted_by, subject_token FROM runs "
                "WHERE id = ?", (parent_run_id,)).fetchone()
            # ONLY WHEN THE SUBJECT AGREES. The credential and the identity it
            # is for come from two places -- the token from the parent run, the
            # user from the work row -- and nothing checked that they name the
            # same person. A task the operator parents to another user's run
            # produced a run holding that user's raw token with no acting_user
            # recorded, which GET /runs/{id}/subject-token would hand back.
            # `user is None` is the case, not the exception: the operator
            # branch of POST /tasks hands down no user precisely because the
            # operator is not a delegated subject, and a run acting for nobody
            # must therefore hold nobody's credential. Fails closed -- with no
            # token the exchange refuses, which is the right direction for a
            # disagreement about whose authority this is.
            if parent and parent["acting_user"] == user and user is not None:
                user_by = parent["user_asserted_by"] or runtoken.SUB_SRC_IDP
                tok = parent["subject_token"] or tok
        if user is None:
            user_by = None      # no subject, so nothing to say about its origin
        elif user_by is None:
            # A user with no recorded provenance predates this column, and back
            # then an IdP login was the only way to have one.
            user_by = runtoken.SUB_SRC_IDP

        # Did WE mint this workflow id? A rootless wakeup seals a fresh one, and
        # _lock_workflow inserts its row to have something to lock. If the wakeup
        # is then refused, that row is an orphan nothing will ever reference or
        # clean up -- and `return None` inside `with db.connect()` exits the
        # block normally, so it COMMITS. One row per refusal, permanently.
        #
        # Harmless at one per cron slot; not harmless now that a refused schedule
        # tick retries every 30s, which turns it into ~2,880 rows a day for a
        # single agent kept busy by one long conversation. The retry did not
        # create this leak, it changed its rate from negligible to chronic.
        minted = parent_run_id is None and workflow_id is None

        _lock_workflow(conn, wf, now)
        refused = admit(conn, wf, depth, converting_agent)
        if refused:
            _discard_minted_workflow(conn, wf, minted)
            return None, refused

        # Claiming the agent IS inserting its run: the partial unique index on
        # runs(agent) WHERE state IN ('pending','running') admits at most one, so
        # a concurrent wakeup loses at the database rather than at a
        # compare-and-swap on a second table. The paused re-check is safe against
        # a racing set_paused because this transaction already holds the agents
        # row (see the SELECT ... FOR NO KEY UPDATE above).
        agent_row = conn.execute(
            "SELECT paused, registry_agent_id FROM agents WHERE name = ?", (agent,)
        ).fetchone()
        if agent_row["paused"]:
            _discard_minted_workflow(conn, wf, minted)
            return None, "refused"
        # G05 provenance: a registry-bound agent's run records the digest of
        # the verified snapshot THAT DEFINES THIS AGENT. Taken from the
        # resolution, not the registry's process-wide digest property, so the
        # stamp is only ever a snapshot the agent actually resolves in -- a
        # stale binding whose agent was dropped from the current snapshot
        # stamps None (and 503s at launch) rather than claiming provenance
        # under a snapshot that never contained it. None in ungoverned mode.
        registry_digest = None
        runtime_resolution = None
        if agent_row["registry_agent_id"] is not None:
            from ..registry.service import configured_registry
            from ..registry.models import AgentNotFound, RegistryUnavailable
            try:
                resolution = configured_registry().resolve(
                    agent_row["registry_agent_id"])
                registry_digest = resolution.registry_digest
                if resolution.runtime is not None:
                    runtime_resolution = _canonical_runtime_resolution(
                        resolution.runtime)
                    if (resolution.runtime.interface_version
                            == RUNTIME_PROTOCOL_EXEC_V1):
                        # Deliverability is decided by the manifest, and the
                        # manifest is known here. Refusing at the launcher
                        # instead would mean a queued run, a claimed slot and a
                        # rolled-back Pod for a request that was unusable when
                        # it arrived. The launcher re-checks regardless.
                        try:
                            runinput.check_against_process(
                                run_input, resolution.runtime.process,
                                where=f"agent '{agent}'", error=InputRefused)
                        except InputRefused:
                            # No discard here: the raise leaves `with
                            # db.connect()` by exception and _Conn.__exit__
                            # rolls the transaction back, undoing the
                            # _lock_workflow insert. The return-None paths below
                            # commit and so must discard explicitly; the raise
                            # path must not (a discard would be dead).
                            raise
            except (AgentNotFound, RegistryUnavailable):
                registry_digest = None
        # ON CONFLICT DO NOTHING, not a caught IntegrityError. On Postgres a
        # failed statement aborts the whole transaction, so catching the error
        # and continuing would discard everything this transaction has already
        # done -- the workflow row, the admission accounting -- and the commit
        # that follows becomes a rollback while the caller sees a tidy `None`.
        # That is the same trap already removed from init_db and from the
        # conversation sequence allocator; a busy agent is an ordinary outcome
        # and must not be signalled by an exception.
        claimed = conn.execute(
            "INSERT INTO runs (id, agent, run_type, state, reason, created_at, "
            "trace_ctx, workflow_id, depth, acting_user, scope, subject_context, "
            "pin_asserted_by, user_asserted_by, subject_token, registry_digest, "
            "runtime_resolution, ceiling_audiences, input, parent_run_id, dispatch, "
            "orchestration_provider, workflow_kind) "
            "VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT DO NOTHING",
            (run_id, agent, run_type, reason, now, trace_ctx, wf, depth,
             user, json.dumps(scope) if scope is not None else None,
             pin, pin_by, user_by, tok, registry_digest, runtime_resolution,
             json.dumps(ceiling_audiences), run_input, parent_run_id, dispatch,
             orchestration_provider, workflow_kind),
        )
        if not claimed.rowcount:
            _discard_minted_workflow(conn, wf, minted)
            return None, "conflict"   # the agent already has a live run
    return run_id, None


def _discard_minted_workflow(conn, workflow_id: str, minted: bool) -> None:
    """Drop a workflow row this refused wakeup created and nothing else uses.

    Only for a workflow WE minted in this transaction: its id came from a fresh
    uuid moments ago, so no other caller can hold it and there is nothing to
    race. A workflow supplied by the caller or inherited from a parent is not
    ours to delete -- the guard is the whole safety argument.

    Belt and braces on the reference checks anyway: deleting a workflow that
    something points at would orphan the pointer, which is worse than the leak.
    """
    if not minted:
        return
    for table, column in (("runs", "workflow_id"), ("tasks", "workflow_id"),
                          ("messages", "workflow_id")):
        row = conn.execute(
            f"SELECT 1 FROM {table} WHERE {column} = ? LIMIT 1", (workflow_id,)
        ).fetchone()
        if row is not None:
            return
    conn.execute(
        "DELETE FROM workflows WHERE id = ? AND state = 'active'", (workflow_id,)
    )


def _canonical_runtime_resolution(runtime) -> str:
    """Canonical durable form of every executable-identity field.

    Sealed on the run row at admission and compared BYTE FOR BYTE on every
    later assignment, so a snapshot that moved on is caught rather than
    silently launched. encode_runtime owns which keys are present; it omits an
    unset additive field precisely because adding a key whose value is always
    null would make every row sealed before the deploy mismatch forever,
    reported as "no longer matches its admitted provenance" -- which reads as
    tampering.
    """
    return json.dumps(
        encode_runtime(runtime), sort_keys=True, separators=(",", ":"),
    )


def _launch_material(row, require_registry: bool):
    """What a launcher needs from a pending run's record, re-validated NOW.

    Returns ``(runtime, model, input)``, or None when the run must not be
    launched -- its registry agent cannot be resolved, or the resolution no
    longer matches the digest and runtime SEALED onto the run at admission.
    Shared by the native assignment loop and the engine's claim, so both
    dispatchers apply the same check at the same moment: immediately before
    handing out a launch.
    """
    runtime = None
    assignment_input = None
    assignment_model = None
    if require_registry:
        from ..registry.models import AgentNotFound, RegistryUnavailable
        from ..registry.service import configured_registry

        registry_agent_id = row["registry_agent_id"]
        try:
            resolution = configured_registry().resolve(registry_agent_id)
        except (AgentNotFound, RegistryUnavailable) as exc:
            log.error(
                "Kubernetes assignment skipped run %s: registry agent %s "
                "cannot be resolved: %s", row["id"], registry_agent_id, exc)
            return None
        if (not row["registry_digest"] or
                resolution.registry_digest != row["registry_digest"]):
            log.error(
                "Kubernetes assignment skipped run %s: run is bound to "
                "registry digest %r but current resolution is %r",
                row["id"], row["registry_digest"], resolution.registry_digest)
            return None
        if resolution.runtime is None:
            log.error(
                "Kubernetes assignment skipped run %s: registry agent %s "
                "has no governed runtime resolution", row["id"], registry_agent_id)
            return None
        current_runtime_resolution = _canonical_runtime_resolution(
            resolution.runtime)
        if (not row["runtime_resolution"] or
                current_runtime_resolution != row["runtime_resolution"]):
            log.error(
                "Kubernetes assignment skipped run %s: governed runtime "
                "resolution no longer matches its admitted provenance",
                row["id"],
            )
            return None
        runtime = encode_runtime(resolution.runtime)
        # The model the resolution GRANTED, for the exec/v1 launcher:
        # a stock workload cannot fetch the run's context, so
        # services.model.name is resolved from this at launch (it
        # resolved to nothing before -- fail-closed for any manifest
        # naming it). runtime-v1 keeps reading it from /context.
        assignment_model = resolution.model
        # Carry the sealed input inline ONLY for exec/v1, whose launcher
        # is the sole reader of the assignment copy. runtime-v1, builtin
        # and the host/docker runners re-fetch it from the run record,
        # so sending it here too would put a second copy of up to the
        # input ceiling on every heartbeat body for no reader. When
        # exec/v1 becomes launchable this already flows; until then it is
        # assigned (and refused at launch) carrying exactly what it will
        # one day consume, and nothing else is bloated.
        if resolution.runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1:
            assignment_input = row["input"]
    return runtime, assignment_model, assignment_input


def _assignment_payload(row, runtime, model, run_input) -> dict:
    """The launch payload for one claimed run, identical whichever dispatcher
    claimed it -- the native loop or the engine's execution worker."""
    return {
        "id": row["id"],
        "agent": row["agent"],
        "run_type": row["run_type"],
        "trace_ctx": row["trace_ctx"],
        "workflow_id": row["workflow_id"],
        "user": row["acting_user"],
        # HOW that user was established, carried with them so the
        # grant this assignment mints can say so
        "user_asserted_by": row["user_asserted_by"],
        "scope": row["scope"],
        # the sealed pin, so the token minted for this
        # assignment carries it (see app.worker_heartbeat)
        "pin": row["subject_context"],
        "ceiling_audiences": row["ceiling_audiences"],
        "registry_agent_id": row["registry_agent_id"],
        "runtime": runtime,
        "model": model,
        # The runtime SEALED ONTO THIS RUN at creation, not the
        # one just re-resolved above (which is populated only on
        # the Kubernetes path). The run token minted for this
        # assignment must cover the lifetime this run was
        # granted, and the reaper judges it by the same value.
        # One source of truth or the two disagree at the edges.
        "runtime_resolution": row["runtime_resolution"],
        # The sealed input, for the launcher to deliver. It
        # rides the assignment rather than being fetched
        # later so the launch is one authenticated payload,
        # bounded by runinput.MAX_RUN_INPUT_BYTES. Populated only
        # for exec/v1 (the sole reader); None for every runtime
        # that re-fetches it from the run record instead.
        "input": run_input,
    }


def assign_runs(
    worker_id: str, slots_free: int, *, require_registry: bool = False,
) -> list[dict]:
    """Hand up to slots_free unassigned pending runs to a worker.

    Kubernetes workers require a registry-bound executable snapshot. Resolve it
    before the CAS claim and require the run's stored registry digest to match
    the currently resolved definition. A stale or authority-only artifact is
    skipped, never claimed and never widened into a worker-global image.
    """
    if slots_free <= 0:
        return []
    assigned = []
    with db.connect() as conn:
        # Read more than one slot's worth because a heterogeneous queue may have
        # entries this worker cannot launch. Skipping an incompatible head item
        # must not starve compatible work behind it.
        candidate_limit = max(slots_free, min(slots_free * 4, 64))
        candidates = conn.execute(
            "SELECT r.id, r.agent, r.run_type, r.trace_ctx, r.workflow_id, "
            "r.acting_user, r.scope, r.subject_context, r.user_asserted_by, "
            "r.registry_digest, r.runtime_resolution, r.ceiling_audiences, "
            "r.input, a.registry_agent_id "
            "FROM runs r JOIN agents a ON a.name = r.agent "
            "WHERE r.state = 'pending' AND r.worker IS NULL "
            # NEVER an engine-dispatched run: that one is the execution
            # worker's, claimed by id (claim_for_execution).
            "AND r.dispatch IS NULL "
            "AND (? = 0 OR a.registry_agent_id IS NOT NULL) "
            "AND (r.workflow_id IS NULL OR r.workflow_id NOT IN "
            "     (SELECT id FROM workflows WHERE state = 'halted')) "
            "ORDER BY r.created_at LIMIT ?",
            (int(require_registry), candidate_limit),
        ).fetchall()
        for row in candidates:
            if len(assigned) >= slots_free:
                break

            material = _launch_material(row, require_registry)
            if material is None:
                continue
            runtime, assignment_model, assignment_input = material

            # assigned_at, so the stranded-run reaper can measure from the CLAIM
            # rather than from creation. Measuring from creation meant a run that
            # had waited in the queue past its TTL was failed as "never started"
            # on the first tick after a worker picked it up, while a healthy
            # runner was still preparing to start it.
            claimed = conn.execute(
                "UPDATE runs SET worker = ?, assigned_at = ? "
                "WHERE id = ? AND worker IS NULL",
                (worker_id, db.utcnow(), row["id"]),
            )
            if claimed.rowcount:
                assigned.append(_assignment_payload(
                    row, runtime, assignment_model, assignment_input))
    return assigned


# The claim marker an engine-dispatched run carries in runs.worker. Never a
# registered worker id: the daemon's heartbeat cannot report it, and the
# dead-worker requeue excludes engine runs by name besides.
ENGINE_WORKER = "engine"

class ExecutionRefused(Exception):
    """The engine asked to execute a run Andyur will not launch. PERMANENT: the
    engine must not retry it as if it were transient."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


# The only provider that dispatched runs before the binding was recorded on
# the run: an engine run admitted then carries no binding and is Temporal's.
LEGACY_DISPATCHING_PROVIDER = "temporal"


def claim_for_execution(run_id: str, *, require_registry: bool,
                        provider: str) -> dict:
    """The engine's claim of ONE admitted run, by id (Architecture B+, D11).

    The engine carries nothing but the run id, so everything here comes from
    Andyur's record, and every answer that is not "launch" or "adopt" is a
    refusal the engine must not retry:

      unknown      no run with this id: the engine cannot mint a run
      not_engine   the run is dispatched by the native loop, not the engine
      not_bound    the run is bound to a different orchestration provider
      terminal     the run has already ended
      halted       its workflow's kill switch is on
      unsealed     the registry no longer resolves to what was sealed on it

    IDEMPOTENT PER RUN. The first claim records the run's ONE execution
    generation; every retry, on any worker, gets the same one back, which is
    what lets the Kubernetes run fence admit exactly that generation to adopt
    and refuse any other. Launch material (and so credentials) is returned only
    while the run is still `pending` -- a crash-before-launch retry must be
    able to launch; a run that has started is adopted, never re-credentialed.
    """
    import secrets as _secrets

    for _ in range(2):
        with db.connect() as conn:
            row = conn.execute(
                "SELECT r.id, r.agent, r.run_type, r.trace_ctx, r.workflow_id, "
                "r.acting_user, r.scope, r.subject_context, r.user_asserted_by, "
                "r.registry_digest, r.runtime_resolution, r.ceiling_audiences, "
                "r.input, r.state, r.worker, r.dispatch, r.execution_generation, "
                "r.orchestration_provider, "
                "a.registry_agent_id, w.state AS workflow_state "
                "FROM runs r JOIN agents a ON a.name = r.agent "
                "LEFT JOIN workflows w ON w.id = r.workflow_id WHERE r.id = ?",
                (run_id,)).fetchone()
            if row is None:
                raise ExecutionRefused("unknown", f"no admitted run {run_id!r}")
            if row["dispatch"] != "engine":
                raise ExecutionRefused(
                    "not_engine", f"run {run_id!r} is dispatched by the native "
                    "assignment loop, not the engine")
            # THE PROVIDER IT WAS ADMITTED UNDER, and no other (run execution
            # draft, step 2). With two dispatching providers deployed, an
            # executor serving one could otherwise claim -- and launch -- a
            # run the other admitted and is about to dispatch.
            bound = row["orchestration_provider"] or LEGACY_DISPATCHING_PROVIDER
            if bound != provider:
                raise ExecutionRefused(
                    "not_bound", f"run {run_id!r} is bound to the {bound!r} "
                    f"orchestration provider, not {provider!r}")
            if row["state"] not in ("pending", "running"):
                raise ExecutionRefused(
                    "terminal", f"run {run_id!r} has already ended ({row['state']})")
            if row["workflow_state"] == "halted":
                raise ExecutionRefused("halted", f"run {run_id!r}'s workflow is halted")
            generation = row["execution_generation"]
            if row["state"] == "running":
                if not generation:
                    # Started, yet the engine never claimed it: something other
                    # than the engine launched it, and adopting would be a guess.
                    raise ExecutionRefused(
                        "not_engine", f"run {run_id!r} is running without an "
                        "engine claim")
                # ADOPT, never re-credential: no tokens, only what reaping an
                # exec/v1 run needs to bound its output (None if the registry
                # no longer resolves; the run is still adopted and watched).
                material = _launch_material(row, require_registry)
                return {"id": run_id, "generation": generation, "launch": None,
                        "runtime": material[0] if material else None}
            # pending: (re)validate NOW, immediately before handing out a launch
            if require_registry and row["registry_agent_id"] is None:
                raise ExecutionRefused(
                    "unsealed", f"run {run_id!r}'s agent is not registry-bound")
            material = _launch_material(row, require_registry)
            if material is None:
                raise ExecutionRefused(
                    "unsealed", f"run {run_id!r}'s registry resolution no longer "
                    "matches what was sealed on it at admission")
            if generation is None:
                candidate = f"exec-{_secrets.token_hex(8)}"
                claimed = conn.execute(
                    "UPDATE runs SET worker = ?, assigned_at = ?, "
                    "execution_generation = ? WHERE id = ? AND state = 'pending' "
                    "AND worker IS NULL AND execution_generation IS NULL "
                    "AND dispatch = 'engine'",
                    (ENGINE_WORKER, db.utcnow(), candidate, run_id))
                if not claimed.rowcount:
                    continue            # raced another claim: re-read its answer
                generation = candidate
            payload = _assignment_payload(row, *material)
            return {"id": run_id, "generation": generation, "launch": payload}
    raise ExecutionRefused(
        "conflict", f"run {run_id!r} changed underneath its claim twice")


def record_heartbeat(worker_id: str, slots: int) -> None:
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO workers (id, slots, last_heartbeat) VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET slots = excluded.slots, "
            "last_heartbeat = excluded.last_heartbeat",
            (worker_id, slots, db.utcnow()),
        )


def start_run(run_id: str) -> bool:
    now = db.utcnow()
    with db.connect() as conn:
        # Lock this run's workflow row FIRST (Postgres) so start serializes
        # against halt on the same rendezvous every other path uses. This both
        # closes the assign->start race (start now sees a committed halt) AND
        # makes the workflows row the universal first lock, so halt (which locks
        # workflows -> agent_status -> runs) and start can't ABBA-deadlock.
        if db.IS_POSTGRES:
            wf = conn.execute(
                "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            if wf and wf["workflow_id"]:
                conn.execute(
                    "SELECT id FROM workflows WHERE id = ? FOR UPDATE",
                    (wf["workflow_id"],),
                )
        # refuse to start a run whose workflow was halted between assignment and
        # start (closes the assign->start window the halt filter alone misses)
        started = conn.execute(
            "UPDATE runs SET state = 'running', started_at = ? "
            "WHERE id = ? AND state = 'pending' "
            "AND (workflow_id IS NULL OR workflow_id NOT IN "
            "     (SELECT id FROM workflows WHERE state = 'halted'))",
            (now, run_id),
        )
        if started.rowcount == 0:
            return False
        # THE RUN IS NOW GOING TO SEE ITS AGENT'S WAITING WORK, so this is where
        # that work is recorded as offered -- not at wakeup, where it was.
        #
        # Stamping when the run ROW was inserted recorded an intention, not a
        # delivery. Anything that cancels a pending run before it starts (a
        # pause/unpause window, a halt of the woken run's own workflow, the
        # stranded-run reaper) then left the task open, stamped, and invisible to
        # the drain forever: the agent sat idle beside work nobody would ever
        # hand it again. That is the bug the drain exists to fix, reintroduced in
        # the more durable form its own docstring warned about.
        #
        # Same transaction as the start, so there is no window in which a run is
        # running and its work is still unstamped.
        _mark_work_offered(conn, run_id, now)
    return True


def _mark_work_offered(conn, run_id: str, now: str) -> None:
    """Record that this starting run's agent has been shown its waiting work.

    Everything open and unstamped for that agent, because the prompt renders all
    of it: one run is one offer of the whole queue. Work created AFTER this point
    is deliberately left unstamped, so it is re-driven once this run ends -- the
    prompt was already built without it.
    """
    row = conn.execute("SELECT agent FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return
    agent = row["agent"]
    conn.execute(
        "UPDATE tasks SET notified_at = ? WHERE assignee = ? AND state = 'open' "
        "AND notified_at IS NULL",
        (now, agent),
    )
    conn.execute(
        "UPDATE messages SET notified_at = ? WHERE recipient = ? "
        "AND state = 'unread' AND notified_at IS NULL",
        (now, agent),
    )


def worker_finish_run(run_id: str, worker: str, summary: str | None,
                      error: str | None) -> str:
    """Finalize a run OWNED BY ``worker``, atomically. Returns one of
    ``'done'`` / ``'failed'`` (finalized), ``'not_owner'``, ``'not_active'``,
    ``'unknown'``.

    Ownership is IN the UPDATE's WHERE clause, not read first and checked after.
    runs.worker is NOT stable -- the stale-worker reaper nulls it for the pending
    runs of a worker it condemns (heartbeat.py) and assign_runs reclaims them
    (coordinator.assign_runs) -- so a read-then-write across two connections is a
    TOCTOU: worker A could finalize a run the server has since handed to worker
    B. Putting ``worker = ?`` in the same statement as the state guard closes it;
    the follow-up read only NAMES the failure (403 vs 409 vs 404), it does not
    gate the write.
    """
    now = db.utcnow()
    state = "failed" if error else "done"
    # THE DISPATCHER TOO, in the same statement: the engine's marker finishes
    # engine runs only, and a worker id finishes native runs only, so neither
    # side can finalize the other's even if a run ever carried the wrong owner
    # (B+ adversarial review).
    dispatch = ("dispatch = 'engine'" if worker == ENGINE_WORKER
                else "dispatch IS NULL")
    with db.connect() as conn:
        finished = conn.execute(
            "UPDATE runs SET state = ?, summary = ?, error = ?, finished_at = ?, "
            "subject_token = NULL "
            "WHERE id = ? AND worker = ? AND state IN ('pending', 'running') "
            f"AND {dispatch}",
            (state, summary, error, now, run_id, worker),
        )
        if finished.rowcount:
            return state
        row = conn.execute(
            "SELECT worker, state, dispatch FROM runs WHERE id = ?",
            (run_id,)).fetchone()
    if row is None:
        return "unknown"
    if row["worker"] != worker or (row["dispatch"] == "engine") != (worker == ENGINE_WORKER):
        return "not_owner"
    return "not_active"


def mark_provider_acked(run_id: str) -> None:
    """The bound orchestration provider has durably accepted this run."""
    with db.connect() as conn:
        conn.execute(
            "UPDATE runs SET provider_acked_at = ? WHERE id = ? "
            "AND provider_acked_at IS NULL", (db.utcnow(), run_id))


def unacknowledged_engine_runs(provider: str, older_than: str) -> list:
    """Committed engine runs this provider never acknowledged (R6.6).

    Bound to THIS provider (a run bound elsewhere is never re-homed), still
    pending, never claimed (a claim proves the provider started it), admitted
    before `older_than` (so a start still in flight is not raced), and admitted
    with a recorded binding -- rows from before the binding existed are left
    to the queue backstop rather than guessed at.
    """
    with db.connect() as conn:
        return conn.execute(
            "SELECT id, workflow_id, workflow_kind FROM runs "
            "WHERE dispatch = 'engine' AND orchestration_provider = ? "
            "AND provider_acked_at IS NULL AND execution_generation IS NULL "
            "AND state = 'pending' AND created_at <= ? ORDER BY created_at",
            (provider, older_than)).fetchall()


def abandon_unstarted_run(run_id: str, error: str) -> bool:
    """End a run that has NOT begun executing. Returns False if it has.

    `finish_run` matches 'pending' OR 'running', which is right for a runner
    reporting its own outcome and wrong for compensating a failed dispatch: a
    worker can claim and start a run between its admission and the dispatch
    call returning, and marking THAT run failed would record an obituary for a
    container still doing work -- and drop its subject token while it runs.

    Narrow by design. Nothing here decides whether a started run should end;
    that is the reaper's and the kill switch's business.
    """
    now = db.utcnow()
    with db.connect() as conn:
        done = conn.execute(
            "UPDATE runs SET state = 'failed', error = ?, finished_at = ?, "
            "subject_token = NULL WHERE id = ? AND state = 'pending'",
            (error, now, run_id))
    return done.rowcount > 0


def finish_run(run_id: str, summary: str | None, error: str | None) -> bool:
    now = db.utcnow()
    state = "failed" if error else "done"
    with db.connect() as conn:
        # The SUBJECT TOKEN is dropped here. db.py said "dropped when the run
        # ends" and nothing did it, so a terminated run kept a live user
        # credential at rest indefinitely. Cleared in the SAME statement that
        # ends the run, so there is no window and no second path to forget.
        finished = conn.execute(
            "UPDATE runs SET state = ?, summary = ?, error = ?, finished_at = ?, "
            "subject_token = NULL "
            "WHERE id = ? AND state IN ('pending', 'running')",
            (state, summary, error, now, run_id),
        )
        if finished.rowcount == 0:
            return False
    return True
