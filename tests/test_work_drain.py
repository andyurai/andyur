"""Work handed to a busy agent must still get done, and a schedule must not be
silently eaten by a long-running conversation.

Both of these are the same failure in different clothes: the platform's premise
is unattended operation, and in both cases a refusal at the moment of delivery
was treated as the end of the matter. Delegation woke its assignee best-effort
and never came back; a schedule advanced past a tick it never fired.
"""

import pytest

from andyur import db
from andyur.server import coordinator, heartbeat, messages, schedules, tasks


def _start_live_run(agent: str) -> str:
    """Start whatever live run this agent has, as its runner would.

    Work counts as OFFERED when a run starts and renders the prompt, not when
    the run row is inserted, so a test about the offer has to start the run.
    """
    with db.connect() as c:
        run = c.execute(
            "SELECT id FROM runs WHERE agent = ? AND state = 'pending'", (agent,)
        ).fetchone()
    assert run is not None, f"{agent} has no pending run to start"
    assert coordinator.start_run(run["id"])
    return run["id"]


# --- delegated work is re-driven ---------------------------------------------

def _wf_of(agent: str):
    with db.connect() as c:
        row = c.execute(
            "SELECT workflow_id FROM runs WHERE agent = ? AND state = 'pending'",
            (agent,)).fetchone()
    return row["workflow_id"] if row else None


def test_work_waiting_on_a_workflow_at_its_cap_still_drains(env, monkeypatch):
    """The drain must not be refused by the cap of the workflow it is draining.

    coordinator.admit counts open tasks AND non-terminal runs against
    MAX_WORKFLOW_RUNS, so a drained run that joins the work's workflow is
    refused by the very budget the waiting task is already counted in -- and
    the task then never drains at all. The fix is not to leave the workflow
    (that was the old answer, and it cost the graph) but to stop counting one
    unit of work twice: `converting_counted_work` says these items are being
    EXECUTED, not added. This pins the liveness half.
    """
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 3)
    env.agent("planner")
    env.agent("helper")
    env.agent("filler")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "the deferred task", "d", parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("INSERT INTO runs (id, agent, run_type, state, reason, created_at, "
                  "workflow_id, depth) VALUES ('filler-run','filler','work','running','f',"
                  "'2026-01-01T00:00:00',?,1)", (wf,))
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
        live = c.execute("SELECT COUNT(*) FROM runs WHERE workflow_id=? AND state NOT IN "
                         "('done','failed','cancelled')", (wf,)).fetchone()[0]
        open_tasks = c.execute("SELECT COUNT(*) FROM tasks WHERE workflow_id=? AND "
                               "state!='closed'", (wf,)).fetchone()[0]
    assert live + open_tasks >= coordinator.MAX_WORKFLOW_RUNS, "the cap must be reached"

    assert any("drained" in a and "helper" in a for a in heartbeat.drain_pending_work())
    assert _wf_of("helper") is not None, "the waiting task was stranded by its own cap"
    # and it drained INTO the workflow it belongs to. Asserting only that some
    # run exists passed under the old design too, which is what let the graph
    # defect sit behind a green test.
    assert _wf_of("helper") == wf, "drained out of the workflow it belongs to"


def test_a_task_given_to_a_busy_agent_is_driven_when_it_frees_up(env):
    env.agent("planner")
    env.agent("helper")
    busy = coordinator.maybe_wakeup("helper", "already working")
    assert busy, "helper should be busy for this test to mean anything"

    tasks.create_task("helper", "planner", "do the thing", "detail")
    # the wakeup inside create_task was refused: helper has a live run
    assert heartbeat.drain_pending_work() == [], "must not wake a busy agent"

    env.set_idle("helper")
    actions = heartbeat.drain_pending_work()

    assert any("helper" in a for a in actions), f"never re-driven: {actions}"
    with db.connect() as c:
        live = c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = 'helper' "
            "AND state IN ('pending', 'running')"
        ).fetchone()["n"]
    assert live == 1


def test_deferred_task_preserves_the_delegated_scope(env):
    import json
    env.agent("planner")
    env.agent("helper")
    coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task(
        "helper", "planner", "read only", deleg_user="alice",
        deleg_scope=["files:read"],
    )
    env.set_idle("helper")
    assert heartbeat.drain_pending_work()
    with db.connect() as c:
        run = c.execute(
            "SELECT acting_user, scope FROM runs WHERE agent = 'helper' "
            "AND state = 'pending'"
        ).fetchone()
    assert run["acting_user"] == "alice"
    assert json.loads(run["scope"]) == ["files:read"]


def test_an_unread_message_also_drives_a_run(env):
    env.agent("scout")
    env.agent("sender")
    busy = coordinator.maybe_wakeup("scout", "already working")
    assert busy
    messages.send_message("scout", "sender", "something happened")
    env.set_idle("scout")

    assert any("scout" in a for a in heartbeat.drain_pending_work())


def test_the_drain_does_not_become_a_treadmill(env):
    """An agent that leaves a task open must not be woken again every tick.

    Waking on "has an open task" would re-wake forever, and the agent that
    cannot finish a task is exactly the one that would burn a slot and a model
    budget on every heartbeat. The offer is exactly-once per work item.
    """
    env.agent("stuck")
    env.agent("boss")
    tasks.create_task("stuck", "boss", "impossible", "detail")
    # The run must actually START: that is when the prompt renders the task, and
    # therefore when the work counts as offered. Stamping at wakeup instead
    # recorded an intention -- see test_a_cancelled_run_does_not_consume_the_offer.
    _start_live_run("stuck")
    # ...then finish WITHOUT closing the task, which is the agent giving up
    env.set_idle("stuck")

    assert heartbeat.drain_pending_work() == [], "woken again for the same task"
    assert heartbeat.drain_pending_work() == []


def test_work_arriving_while_busy_earns_an_attempt_even_after_an_earlier_one(env):
    """An agent that has already been offered work, gave up on it, and is then
    handed something NEW while busy must still be re-driven. The first task
    being stamped must not suppress the second."""
    env.agent("worker")
    env.agent("boss")
    tasks.create_task("worker", "boss", "first", "d")     # delivered: was idle
    _start_live_run("worker")
    env.set_idle("worker")
    assert heartbeat.drain_pending_work() == []           # nothing new

    coordinator.maybe_wakeup("worker", "busy again")
    _start_live_run("worker")
    tasks.create_task("worker", "boss", "second", "d")    # refused: busy
    env.set_idle("worker")

    assert any("worker" in a for a in heartbeat.drain_pending_work())


def test_a_cancelled_run_does_not_consume_the_offer(env):
    """THE STAMP RECORDS A DELIVERY, NOT AN INTENTION.

    Stamping when the run ROW was inserted meant anything that cancelled a
    pending run before it started -- a pause/unpause window, a halt of the woken
    run's own workflow, the stranded-run reaper -- left the task open, stamped,
    and invisible to the drain forever. The agent then sat idle beside work
    nobody would ever hand it again: finding 6 reintroduced through a race, in
    the more durable form mark_notified's own docstring warned about.
    """
    env.agent("lonely")
    env.agent("boss")
    tasks.create_task("lonely", "boss", "t", "d")     # woken, run pending

    coordinator.set_paused("lonely", True)            # cancels the pending run
    coordinator.set_paused("lonely", False)

    with db.connect() as c:
        stamp = c.execute(
            "SELECT notified_at FROM tasks WHERE assignee = 'lonely'"
        ).fetchone()["notified_at"]
    assert stamp is None, "work was marked offered by a run that never started"
    assert any("lonely" in a for a in heartbeat.drain_pending_work()), \
        "the task is orphaned: open, stamped, and never re-driven"


def test_the_offer_is_stamped_only_on_a_SUCCESSFUL_wakeup(env):
    """Stamping on the attempt rather than the outcome would rebuild the bug in
    a more durable form: the refused delivery is exactly the case the drain
    exists to come back for."""
    env.agent("busy")
    env.agent("boss")
    coordinator.maybe_wakeup("busy", "occupied")
    tasks.create_task("busy", "boss", "t", "d")          # wakeup refused

    with db.connect() as c:
        stamp = c.execute(
            "SELECT notified_at FROM tasks WHERE assignee = 'busy'"
        ).fetchone()["notified_at"]
    assert stamp is None, "a refused delivery was recorded as an offer"


def test_an_agent_that_never_ran_is_driven(env):
    """The case the drain most needs to catch: an agent with no schedule, whose
    only source of work is delegation, handed a task while it was busy."""
    env.agent("newcomer")
    env.agent("boss")
    with db.connect() as c:      # a task with no wakeup at all
        c.execute(
            "INSERT INTO tasks (id, assignee, creator, title, detail, state, "
            "created_at, updated_at) VALUES ('t1', 'newcomer', 'boss', 't', 'd', "
            "'open', ?, ?)",
            (db.utcnow(), db.utcnow()),
        )
    assert any("newcomer" in a for a in heartbeat.drain_pending_work())


# THE NEXT THREE TEST THE DRAIN'S OWN GUARDS, and say so because their first
# versions did not. Each asserted an end-to-end property that ANOTHER layer
# already enforces -- halt_workflow closes the tasks, and maybe_wakeup refuses
# paused and busy agents -- so deleting the drain's filter left all three
# passing. The system was right and the tests were measuring something else,
# which is the same defect as an assertion that cannot fail: they would not have
# reported the guard being removed.
#
# So they query the drain's SELECT directly, with the other layers held out of
# the way. The end-to-end properties keep their own tests below.

def test_the_drain_itself_excludes_halted_workflows(env):
    """The kill switch must not be undone by the mechanism that re-drives work.

    halt_workflow ALSO closes the tasks, which is why an end-to-end version of
    this passes with the drain's own filter deleted. Here the workflow is halted
    WITHOUT that teardown, so only the drain's filter can refuse it.
    """
    env.agent("condemned")
    env.agent("boss")
    parent = coordinator.maybe_wakeup("boss", "work")
    wf = env.run_workflow(parent)
    tasks.create_task("condemned", "boss", "poison", "d", parent_run_id=parent)
    env.set_idle("condemned")
    with db.connect() as c:      # halt the workflow, leave the task OPEN
        c.execute("UPDATE workflows SET state = 'halted' WHERE id = ?", (wf,))
        still_open = c.execute(
            "SELECT state FROM tasks WHERE assignee = 'condemned'"
        ).fetchone()["state"]
    assert still_open == "open", "the fixture must leave the drain something to refuse"

    assert heartbeat.agents_with_waiting_work() == []


def test_the_drain_itself_excludes_paused_agents(env):
    """Asks the SELECTOR, not the drain: maybe_wakeup also refuses a paused
    agent, so an end-to-end version passes with `a.paused = 0` deleted."""
    env.agent("paused")
    env.agent("boss")
    tasks.create_task("paused", "boss", "t", "d")
    env.set_idle("paused")
    coordinator.set_paused("paused", True)

    assert heartbeat.agents_with_waiting_work() == []


def test_the_drain_itself_excludes_busy_agents(env):
    """Same reason: maybe_wakeup refuses a busy agent, so waking one is only
    ever a wasted transaction -- but a wasted transaction per agent per 30s is
    what this filter exists to avoid, and nothing else would report its loss."""
    env.agent("busy2")
    env.agent("boss")
    tasks.create_task("busy2", "boss", "t", "d")     # wakes it: now busy

    assert heartbeat.agents_with_waiting_work() == []


def test_the_kill_switch_still_holds_end_to_end(env):
    """The property, as opposed to the guard: halting a workflow must stop its
    delegated work being re-driven, by whatever combination of layers."""
    env.agent("condemned2")
    env.agent("boss")
    parent = coordinator.maybe_wakeup("boss", "work")
    wf = env.run_workflow(parent)
    tasks.create_task("condemned2", "boss", "poison", "d", parent_run_id=parent)
    env.set_idle("condemned2")
    coordinator.halt_workflow(wf)

    assert heartbeat.drain_pending_work() == []
    assert not any("condemned2" in a for a in heartbeat.drain_pending_work())


def test_a_paused_agent_is_not_woken_by_the_drain(env):
    env.agent("paused2")
    env.agent("boss")
    tasks.create_task("paused2", "boss", "t", "d")
    env.set_idle("paused2")
    coordinator.set_paused("paused2", True)

    assert heartbeat.drain_pending_work() == []


# --- a refused schedule tick is retried, not burned --------------------------

def _schedule_due(agent: str, cron: str = "* * * * *") -> str:
    s = schedules.create_schedule(agent, cron, "scheduled work")
    with db.connect() as c:      # make it due now
        c.execute("UPDATE schedules SET next_run_at = ? WHERE id = ?",
                  (heartbeat._cutoff(60), s["id"]))
    return s["id"]


def _next_run_at(sid: str) -> str:
    with db.connect() as c:
        return c.execute(
            "SELECT next_run_at FROM schedules WHERE id = ?", (sid,)
        ).fetchone()["next_run_at"]


def test_a_refused_tick_is_retried_soon_not_at_the_next_slot(env):
    """A busy agent used to consume the tick: next_run_at advanced before the
    wakeup was attempted, so a conversation lasting an hour silently ate ~60
    runs of a per-minute schedule."""
    env.agent("busy")
    sid = _schedule_due("busy")
    coordinator.maybe_wakeup("busy", "long conversation")   # occupy the agent

    actions = schedules.fire_due()

    assert any("deferred" in a for a in actions), actions
    assert _next_run_at(sid) <= schedules._iso_in(schedules.RETRY_SECONDS + 5), \
        "the tick was pushed to the next cron slot, not retried"


def test_the_retry_fires_once_the_agent_is_free(env):
    env.agent("busy")
    _schedule_due("busy")
    coordinator.maybe_wakeup("busy", "long conversation")
    schedules.fire_due()

    env.set_idle("busy")
    with db.connect() as c:      # the retry window has elapsed
        c.execute("UPDATE schedules SET next_run_at = ?", (heartbeat._cutoff(1),))

    assert any("fired" in a for a in schedules.fire_due())


def test_a_successful_tick_still_advances_to_the_next_slot(env):
    """The retry must not make a schedule fire more often than its cron says."""
    env.agent("free")
    sid = _schedule_due("free", "0 0 * * *")     # daily
    assert any("fired" in a for a in schedules.fire_due())
    # next_run_at is the next midnight, far beyond any retry window
    assert _next_run_at(sid) > schedules._iso_in(schedules.RETRY_SECONDS + 60)


def test_the_retry_never_delays_a_schedule_beyond_plain_cron(env, monkeypatch):
    """The CAS only pulls next_run_at IN, never out.

    The claim itself legitimately advances to the next cron slot before the
    wakeup is attempted -- that is what makes the fire replication-safe. What
    must not happen is the retry landing LATER than that, which would let a busy
    agent postpone its own schedule.

    RETRY_SECONDS is forced far beyond the cron interval so the assertion is
    decided by the CAS and nothing else. Written first with the default 30s and
    a per-minute cron, it passed or failed ON THE WALL-CLOCK SECOND THE SUITE
    RAN: before the half-minute the natural slot was further away than the retry
    window, so the mutated code (CAS guard deleted) landed inside the bound and
    survived. A test whose verdict depends on the time of day is a test that
    reports whatever CI's schedule happens to produce.
    """
    monkeypatch.setattr(schedules, "RETRY_SECONDS", 3600)
    env.agent("busy")
    sid = _schedule_due("busy", "* * * * *")     # next slot always within 60s
    coordinator.maybe_wakeup("busy", "occupied")

    schedules.fire_due()

    assert _next_run_at(sid) <= schedules._next("* * * * *"), \
        "the retry pushed the schedule past its own next cron slot"


def test_a_refused_tick_on_a_sparse_schedule_retries_within_the_window(env):
    """The case that motivated this: a daily schedule refused once must not wait
    another whole day."""
    env.agent("busy")
    sid = _schedule_due("busy", "0 0 * * *")
    coordinator.maybe_wakeup("busy", "occupied")

    schedules.fire_due()

    assert _next_run_at(sid) <= schedules._iso_in(schedules.RETRY_SECONDS + 5), \
        "a refused daily tick waits until tomorrow"


# --- the drained run is attributable (production-gaps 28) --------------------
#
# A run woken by the drain used to seal a FRESH workflow with no parent, so the
# originating workflow's flow view showed a task with no run against it and the
# run that actually performed it drew as an unrelated root. The graph could not
# be read from the record; it could only be inferred from timing.


def _run_row(agent: str):
    with db.connect() as c:
        return c.execute(
            "SELECT id, workflow_id, parent_run_id, depth FROM runs "
            "WHERE agent = ? AND state = 'pending'", (agent,)).fetchone()


def test_a_drained_run_records_the_run_that_created_the_work(env):
    """The graph half of gap 28, as a property of the record."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "the deferred task", "d",
                      parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute(
            "SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))

    assert any("drained" in a for a in heartbeat.drain_pending_work())
    row = _run_row("helper")
    assert row["workflow_id"] == wf, "drained into a workflow of its own"
    assert row["parent_run_id"] == parent, "no parent recorded for delegated work"


def test_an_unread_message_carries_its_creator_too(env):
    """Messages take the same path and had the same hole."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    messages.send_message("helper", "planner", "look at this",
                          parent_run_id=parent)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    assert any("drained" in a for a in heartbeat.drain_pending_work())
    assert _run_row("helper")["parent_run_id"] == parent


def test_the_drained_run_inherits_the_depth_of_the_work(env):
    """Attribution is also a BOUND, not only a picture.

    Depth is what caps a delegation chain. A drained run that rooted itself at
    depth 0 reset that cap, so delegating to a BUSY agent laundered depth while
    delegating to an idle one did not -- a fan-out bound that an attacker
    controls by keeping the assignee occupied.
    """
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "t", "d", parent_run_id=parent)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
        parent_depth = c.execute(
            "SELECT depth FROM runs WHERE id=?", (parent,)).fetchone()[0] or 0
    heartbeat.drain_pending_work()
    assert _run_row("helper")["depth"] == parent_depth + 1


def test_work_from_two_workflows_is_not_attributed_to_either(env):
    """A drained run renders ALL of the agent's waiting work, so work spanning
    two workflows belongs to neither. A fresh workflow is the honest answer;
    picking one would put the other workflow's task under a run that is not in
    it."""
    env.agent("a")
    env.agent("b")
    env.agent("helper")
    busy = coordinator.maybe_wakeup("helper", "already working")
    for creator in ("a", "b"):
        p = coordinator.maybe_wakeup(creator, "root")
        assert coordinator.start_run(p)
        tasks.create_task("helper", creator, f"from {creator}", "d",
                          parent_run_id=p)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
        wfs = {r[0] for r in c.execute(
            "SELECT DISTINCT workflow_id FROM tasks WHERE assignee='helper'")}
    assert len(wfs) == 2, "the fixture must present two workflows"
    heartbeat.drain_pending_work()
    row = _run_row("helper")
    assert row["workflow_id"] not in wfs, "claimed one workflow's work as both"
    assert row["parent_run_id"] is None


def test_crediting_the_drain_does_not_raise_the_cap_for_NEW_work(env, monkeypatch):
    """The security control this change touches, as a positive control.

    `converting_counted_work` must be a correction to double-counting, never a
    discount. The cap exists to bound fan-out, and fan-out is work being
    CREATED -- so once the drained run is running, the workflow's budget must
    refuse the next delegation exactly as before.
    """
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)
    env.agent("planner")
    env.agent("helper")
    env.agent("third")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "t", "d", parent_run_id=parent)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    heartbeat.drain_pending_work()
    drained = _run_row("helper")
    assert drained is not None and coordinator.start_run(drained["id"])
    # the workflow now holds the planner run and the drained run: at its cap
    with pytest.raises(coordinator.DelegationRefused):
        tasks.create_task("third", "helper", "one more", "d",
                          parent_run_id=drained["id"])


def test_a_pruned_creator_does_not_strand_the_work(env):
    """resolve_workflow REFUSES an unknown parent, correctly -- a forged parent
    id must not reset the depth cap. But retention prunes runs while their work
    rows remain, so a drain that named a pruned parent would raise every tick
    and the work would never run again."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "t", "d", parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute(
            "SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
        c.execute("DELETE FROM runs WHERE id = ?", (parent,))
    assert any("drained" in a for a in heartbeat.drain_pending_work())
    row = _run_row("helper")
    assert row["parent_run_id"] is None
    # ...and the WORKFLOW still holds, which is why the drain carries it as its
    # own argument rather than leaning on the parent to supply it. This is the
    # only case where that argument is load-bearing: with a provable parent the
    # workflow is inherited from it either way.
    assert row["workflow_id"] == wf


def test_two_indistinguishable_items_are_credited_twice(env, monkeypatch):
    """The credit is a COUNT of work being converted, so it must count rows,
    not distinct row shapes.

    Two tasks delegated by the same run to the same assignee with no pin agree
    on every column the drain query selects. Collapsing them credits one, the
    budget still sees the other, and the drain is refused at the cap it exists
    to clear -- with two items waiting instead of one, which is the case a cap
    is most likely to be reached in.
    """
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "first", "d", parent_run_id=parent)
    tasks.create_task("helper", "planner", "second", "d", parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute(
            "SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    # the cap is lowered AFTER the fan-out, as an operator tightening it would:
    # creating the second task under a cap of 2 would itself have been refused
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)
    assert any("drained" in a for a in heartbeat.drain_pending_work())
    assert _run_row("helper")["workflow_id"] == wf


def test_a_drain_that_is_refused_says_so(env, monkeypatch):
    """A refusal is a decision and gets written down. This loop appended
    nothing at all when a wakeup was declined, so a tick reported the same
    thing whether the platform was idle or a workflow was wedged at its cap."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "t", "d", parent_run_id=parent)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    # halting is not the lever here (halted work is filtered out of the query);
    # take the depth cap, which is the one the drain newly inherits
    monkeypatch.setattr(coordinator, "MAX_DELEGATION_DEPTH", 0)
    actions = heartbeat.drain_pending_work()
    assert any("not woken" in a and "helper" in a for a in actions), actions
    assert _run_row("helper") is None


# --- the drain is not a way out of the delegation cap ------------------------
#
# Found by the security fan-out on gap 28, and REPRODUCED: joining the work's
# workflow closed the graph defect but opened a depth bypass on the path where
# the work has parents and no single one. The attacker does not need the
# multi-parent case to be rare -- they create it.


def test_two_delegators_cannot_reset_the_depth_cap_by_keeping_an_agent_busy(env):
    """The exact attack: delegate to the same busy agent from TWO runs in one
    workflow, so the work has no single parent, and the drained run used to
    join that workflow at depth 0 -- restarting the delegation chain from the
    top of a workflow it was already deep inside.

    Refusing to join was the wrong fix: the run would fall back to a fresh
    workflow with a fresh work-item budget, which is the more permissive of the
    two escapes. The bound has to travel with the work.
    """
    env.agent("planner")
    env.agent("second")
    env.agent("helper")
    root = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(root)
    # a run deep in the chain, and a sibling in the SAME workflow
    with db.connect() as c:
        c.execute("UPDATE runs SET depth = 7 WHERE id = ?", (root,))
        wf = c.execute("SELECT workflow_id FROM runs WHERE id=?", (root,)).fetchone()[0]
        c.execute("INSERT INTO runs (id, agent, run_type, state, reason, created_at, "
                  "workflow_id, depth) VALUES ('sibling','second','work','running','s',"
                  "'2026-01-01T00:00:00',?,4)", (wf,))
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "from the deep run", "d", parent_run_id=root)
    tasks.create_task("helper", "second", "from the sibling", "d", parent_run_id="sibling")
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))

    heartbeat.drain_pending_work()
    row = _run_row("helper")
    assert row["workflow_id"] == wf, "fell back to a fresh workflow and its fresh budget"
    assert row["parent_run_id"] is None, "claimed one of two parents"
    # the DEEPEST waiting parent bounds it -- 7 and 4 waiting, so 8, not 5 and
    # certainly not 0
    assert row["depth"] == 8, f"depth reset to {row['depth']} inside the workflow"


def test_the_depth_floor_does_not_inflate_an_ordinary_root(env):
    """Positive control. Work with no parent at all is a genuine root, and must
    still be depth 0 -- otherwise the floor would eat the cap from the other
    end."""
    env.agent("helper")
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "operator", "unparented", "d")
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    heartbeat.drain_pending_work()
    assert _run_row("helper")["depth"] == 0


def test_an_unpinned_item_beside_a_pinned_one_is_a_mixed_pin(env):
    """SQL COUNT(DISTINCT) ignores NULL, so one unpinned item beside one pinned
    item counted as a SINGLE pin: the mixed-pin guard did not fire, and MIN
    picked the pinned value, so the unpinned work ran under a pin nobody set
    for it. Narrowing, so not an escalation -- but the guard was not measuring
    what its own comment claims, which is how it would have missed a widening.
    """
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup(
        "planner", "root run", subject_context={"account": "447"},
        pin_asserted_by="operator")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "pinned", "d", parent_run_id=parent)
    tasks.create_task("helper", "operator", "unpinned", "d")
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    actions = heartbeat.drain_pending_work()
    assert any("different" in a and "pins" in a for a in actions), actions
    assert _run_row("helper") is None, "ran mixed-pin work under one pin"


# --- the credit is bounded from ABOVE, not only from below -------------------
#
# Found by the concurrency fan-out: every test above proves the credit is LARGE
# ENOUGH (work at a full workflow's cap still drains). None proved it was not
# TOO LARGE, and a mutation that credited fifty phantom items passed all 118 of
# them. That is the half a fan-out cap exists for.


def _units(wf: str) -> int:
    """What admit() actually counts against MAX_WORKFLOW_RUNS."""
    with db.connect() as c:
        return sum(c.execute(q, (wf,)).fetchone()[0] for q in (
            "SELECT COUNT(*) FROM runs WHERE workflow_id=? AND state NOT IN "
            "('done','failed','cancelled')",
            "SELECT COUNT(*) FROM tasks WHERE workflow_id=? AND state!='closed'",
            "SELECT COUNT(*) FROM messages WHERE workflow_id=? AND state='unread'"))


def test_a_drain_never_leaves_a_workflow_above_its_cap(env, monkeypatch):
    """The upper bound, stated directly against the real count."""
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 3)
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "one", "d", parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    assert any("drained" in a for a in heartbeat.drain_pending_work())
    assert _units(wf) <= coordinator.MAX_WORKFLOW_RUNS, (
        f"the drain left {_units(wf)} units against a cap of "
        f"{coordinator.MAX_WORKFLOW_RUNS}")


def test_a_credit_cannot_outlive_the_work_it_was_counted_for(env, monkeypatch):
    """The race that made the credit a second source of truth.

    The drain reads its waiting work in one transaction and wakes in another,
    one wakeup per agent on the platform. Anything that closed the work in that
    window left a credit with nothing behind it, and the workflow finished
    ABOVE its cap. Passing the agent instead of a number moves the count under
    the same lock as the totals it corrects, so there is no window to race.

    The interleaving is injected where a second replica's transaction would
    commit, which is the only place it can happen.
    """
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 3)
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "one", "d", parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))

    real = heartbeat.agents_with_waiting_work

    def racing():
        rows = real()
        # between the two transactions: the assignee's work is closed and the
        # freed budget is legitimately spent by someone else
        with db.connect() as c:
            c.execute("UPDATE tasks SET state='closed' WHERE assignee='helper'")
        tasks.create_task("planner", "planner", "spends the freed unit", "d",
                          parent_run_id=parent)
        return rows

    monkeypatch.setattr(heartbeat, "agents_with_waiting_work", racing)
    heartbeat.drain_pending_work()
    assert _units(wf) <= coordinator.MAX_WORKFLOW_RUNS, (
        f"a stale credit admitted work past the cap: {_units(wf)} units "
        f"against {coordinator.MAX_WORKFLOW_RUNS}")


def test_work_already_offered_to_a_run_is_not_credited(env, monkeypatch):
    """The credit must match what this run will actually RENDER.

    `notified_at` marks work that has already been offered to a run. It still
    counts against the cap -- it is still open -- but the drain does not select
    it, so a drained run is not converting it. Crediting it anyway credits work
    nobody is executing, and admits past the cap.

    Asserted against `admit` directly, because that IS the decision. Read
    through a drained run instead, the workflow's unit count is already over
    the cap before the drain is even called, and the assertion would be
    measuring the fixture rather than the credit.
    """
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "already offered", "d", parent_run_id=parent)
    tasks.create_task("helper", "planner", "still waiting", "d", parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        # the first task was offered to a run that then died: open, but NOT
        # waiting, which is exactly the state the drain must not claim credit for
        c.execute("UPDATE tasks SET notified_at='2026-01-01T00:00:00' "
                  "WHERE title='already offered'")
        units = _units(wf)
        # the planner's run and the two open tasks; the helper's own run roots
        # a workflow of its own and is not in this budget
        assert units == 3, units

        # ONE item is waiting, so the credit is 1 and three units become two
        monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)
        assert coordinator.admit(c, wf, 0, converting_agent="helper") == \
            coordinator.REFUSED_CAP, "credited work it is not rendering"
        # positive control: one more unit of headroom and the same credit admits
        monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 3)
        assert coordinator.admit(c, wf, 0, converting_agent="helper") is \
            coordinator.ADMITTED


def test_a_run_never_holds_a_token_for_someone_it_is_not_acting_for(env):
    """The credential and the identity it is for came from two places.

    `maybe_wakeup` takes the subject token from the PARENT run and the acting
    user from the WORK ROW, and nothing checked they name the same person. A
    task the operator parents to another user's run produced a run holding that
    user's raw credential with no `acting_user` recorded -- which
    `GET /runs/{id}/subject-token` hands back.
    """
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run", user="alice")
    assert coordinator.start_run(parent)
    with db.connect() as c:
        c.execute("UPDATE runs SET subject_token='ALICE-TOKEN' WHERE id=?", (parent,))
    # the operator's branch of POST /tasks: a parent it chose, no delegated user
    # create_task wakes an idle assignee itself, so this IS the delegated run
    tasks.create_task("helper", "operator", "t", "d", parent_run_id=parent)
    with db.connect() as c:
        row = c.execute("SELECT acting_user, subject_token FROM runs "
                        "WHERE agent='helper'").fetchone()
    assert row is not None, "the delegation woke no run to inspect"
    if row["subject_token"]:
        assert row["acting_user"] == "alice", (
            "a run holds alice's credential without recording that it acts for her")
    # positive control: when the subject DOES agree, the token is still carried
    # -- the check must not have simply severed the inheritance
    env.agent("third")
    same = coordinator.maybe_wakeup(
        "third", "work was waiting", parent_run_id=parent, user="alice")
    assert same
    with db.connect() as c:
        carried = c.execute("SELECT acting_user, subject_token FROM runs WHERE id=?",
                            (same,)).fetchone()
    assert carried["acting_user"] == "alice"
    assert carried["subject_token"] == "ALICE-TOKEN", "the inheritance was severed"
