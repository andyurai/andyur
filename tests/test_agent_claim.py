"""Claiming an agent is inserting its run, and the database decides the race.

What this replaced: coordination state lived in an `agent_status` table that six
writers kept in step with `runs` by hand. Every one of them wrote two tables in
one transaction, so every one had to take them in an agreed order. That order
was documented in a comment; the comment was wrong about itself twice, and three
separate reviews each found another writer violating it -- including one where
the operator's kill switch was the side that lost the deadlock.

Now `agent_status` is a VIEW over `runs`, and a partial unique index on
`runs(agent) WHERE state IN ('pending','running')` admits at most one live run
per agent. There is no second table, so there is no ordering to get wrong.

These tests assert the behaviour that used to be the state machine's job, so a
future change that reintroduces a status table has to make them pass.
"""

import pytest
import re

from andyur import db
from andyur.server import coordinator


@pytest.fixture
def alice(env):
    env.agent("alice")
    return "alice"


def _status(agent):
    with db.connect() as c:
        return dict(c.execute(
            "SELECT * FROM agent_status WHERE agent = ?", (agent,)).fetchone())


# --- the derived view reports what the runs say -----------------------------

def test_a_new_agent_is_idle(alice):
    """Idle is the ABSENCE of a live run, not a row someone remembered to write.
    An agent created without a status row used to be invisible to the scheduler
    forever."""
    assert _status(alice)["state"] == "idle"
    assert _status(alice)["run_id"] is None


def test_a_woken_agent_is_queued(alice):
    run = coordinator.maybe_wakeup(alice, "work")
    assert _status(alice) | {"agent": alice} == {
        "agent": alice, "state": "queued", "run_id": run,
        "updated_at": _status(alice)["updated_at"]}


def test_run_id_keeps_the_full_128_bit_random_uuid_identity(alice):
    run = coordinator.maybe_wakeup(alice, "work")
    assert re.fullmatch(r"[0-9a-f]{32}", run), run


def test_a_started_agent_is_running(alice):
    run = coordinator.maybe_wakeup(alice, "work")
    coordinator.assign_runs("w1", 1)
    coordinator.start_run(run)
    assert _status(alice)["state"] == "running"


def test_a_finished_agent_is_idle_again(alice):
    run = coordinator.maybe_wakeup(alice, "work")
    coordinator.start_run(run)
    coordinator.finish_run(run, "done", None)
    assert _status(alice)["state"] == "idle"
    assert _status(alice)["run_id"] is None


# --- the claim is exclusive, and the loser loses cleanly --------------------

def test_a_busy_agent_cannot_be_woken_again(alice):
    first = coordinator.maybe_wakeup(alice, "first")
    second = coordinator.maybe_wakeup(alice, "second")
    assert first is not None
    assert second is None, "two live runs for one agent"


def test_the_database_enforces_it_even_around_the_coordinator(alice):
    """The exclusion is a constraint, not a convention: code that bypasses
    maybe_wakeup entirely still cannot create a second live run."""
    coordinator.maybe_wakeup(alice, "first")
    with pytest.raises(db.integrity_errors()):
        with db.connect() as c:
            c.execute(
                "INSERT INTO runs (id, agent, run_type, state, reason, created_at) "
                "VALUES (?, ?, 'work', 'pending', 'sneaky', ?)",
                ("r-sneaky", alice, db.utcnow()),
            )


def test_losing_the_claim_does_not_discard_the_transaction(alice):
    """The refusal must be an ordinary outcome, not an exception caught inside
    an open transaction. On Postgres a failed statement aborts the whole
    transaction, so catching it and carrying on silently rolls back everything
    that transaction had already done -- and the caller still sees a tidy None.
    Here: the workflow bookkeeping from the losing attempt must survive.

    The workflow is supplied by the CALLER, which matters. This used to let
    maybe_wakeup mint its own and then counted the leftover row as proof the
    transaction committed -- so the observable was an orphan nobody wanted, and
    cleaning up that leak broke the test without breaking the property. A
    caller-supplied workflow is not the wakeup's to discard, so it is a stable
    witness for the same thing.
    """
    coordinator.maybe_wakeup(alice, "first")
    assert coordinator.maybe_wakeup(alice, "second", workflow_id="wf-witness") is None
    with db.connect() as c:
        row = c.execute(
            "SELECT state FROM workflows WHERE id = 'wf-witness'"
        ).fetchone()
    assert row is not None, "the losing transaction was rolled back"
    assert row["state"] == "active"


def test_a_refused_wakeup_leaves_no_orphan_workflow(alice):
    """A rootless wakeup mints a workflow and inserts its row to lock it. When
    the wakeup is then refused, `return None` inside `with db.connect()` exits
    normally and COMMITS, so the row persisted forever with nothing referencing
    it. One per refusal -- negligible at one per cron slot, ~2,880 rows a day
    once a refused schedule tick retries every 30 seconds."""
    coordinator.maybe_wakeup(alice, "first")
    with db.connect() as c:
        before = c.execute("SELECT COUNT(*) AS n FROM workflows").fetchone()["n"]
    for _ in range(5):
        assert coordinator.maybe_wakeup(alice, "refused") is None
    with db.connect() as c:
        after = c.execute("SELECT COUNT(*) AS n FROM workflows").fetchone()["n"]
    assert after == before, f"{after - before} orphan workflow row(s) leaked"


def test_cleanup_never_touches_a_workflow_it_did_not_mint(alice, env):
    """The guard is the safety argument: a workflow inherited from a parent, or
    named by the caller, has other work pointing at it."""
    env.agent("child")
    parent = coordinator.maybe_wakeup(alice, "parent")
    wf = env.run_workflow(parent)
    coordinator.maybe_wakeup("child", "occupied")          # make child busy
    # a delegated wakeup that will be REFUSED, inheriting the parent's workflow
    assert coordinator.maybe_wakeup(
        "child", "delegated", parent_run_id=parent) is None
    with db.connect() as c:
        row = c.execute("SELECT state FROM workflows WHERE id = ?", (wf,)).fetchone()
    assert row is not None, "a refusal deleted the PARENT's workflow"


def test_finishing_frees_the_agent_for_the_next_run(alice):
    first = coordinator.maybe_wakeup(alice, "first")
    coordinator.finish_run(first, "done", None)
    assert coordinator.maybe_wakeup(alice, "second") is not None


def test_a_terminal_run_does_not_hold_the_agent(alice):
    """Only pending and running count. A cancelled or failed run must not keep
    an agent busy forever -- the partial index is what makes that true."""
    run = coordinator.maybe_wakeup(alice, "first")
    with db.connect() as c:
        c.execute("UPDATE runs SET state = 'cancelled' WHERE id = ?", (run,))
    assert _status(alice)["state"] == "idle"
    assert coordinator.maybe_wakeup(alice, "second") is not None


# --- the operations that used to need a second table ------------------------

def test_pausing_an_agent_releases_its_queued_run(alice):
    coordinator.maybe_wakeup(alice, "work")
    coordinator.set_paused(alice, True)
    assert _status(alice)["state"] == "idle"


def test_a_paused_agent_is_not_woken(alice):
    coordinator.set_paused(alice, True)
    assert coordinator.maybe_wakeup(alice, "work") is None


def test_halting_a_workflow_releases_the_agents_it_queued(env):
    env.agent("bob")
    run = coordinator.maybe_wakeup("bob", "work")
    wf = env.run_workflow(run)
    coordinator.halt_workflow(wf)
    assert _status("bob")["state"] == "idle"
    assert env.run_state(run) == "cancelled"


def test_condemning_a_run_releases_its_agent(env):
    env.agent("carol")
    run = coordinator.maybe_wakeup("carol", "work")
    wf = env.run_workflow(run)
    coordinator.start_run(run)
    coordinator.halt_workflow(wf)
    coordinator.runs_to_kill([run])
    assert _status("carol")["state"] == "idle", \
        "the kill switch must not leave an agent busy on a destroyed run"


# --- the view is not writable, so nothing can drift -------------------------

def test_coordination_state_cannot_be_written_directly(alice):
    """The point of the redesign: there is no way to set an agent's state to
    something the runs do not say."""
    with pytest.raises(Exception):
        with db.connect() as c:
            c.execute("UPDATE agent_status SET state = 'idle' WHERE agent = ?", (alice,))


# --- the operator can actually reach the controls ---------------------------

def test_the_cli_exposes_every_kill_switch_and_calls_the_right_endpoint(monkeypatch):
    """The server had pause, resume and halt; the CLI had none of them, so two
    kill switches were reachable only by hand-rolled curl while the README
    listed container destruction as an operator control. A control with no
    affordance is a claim, not a control.

    Drives the real argument parser and captures the request, rather than
    grepping the source for a subcommand name -- a test that reads source text
    passes when the call is commented out."""
    from andyur import cli

    calls = []

    class _Resp:
        status_code = 200

        def json(self):
            return {}

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, path, **kw):
            calls.append(path)
            return _Resp()

    monkeypatch.setattr(cli, "_client", lambda: _Client())

    for argv, expected in [
        (["agents", "pause", "alice"], "/agents/alice/pause"),
        (["agents", "resume", "alice"], "/agents/alice/resume"),
        (["halt", "wf-1"], "/workflows/wf-1/halt"),      # workflow control: top-level
        (["unhalt", "wf-1"], "/workflows/wf-1/unhalt"),
    ]:
        calls.clear()
        args = cli.build_parser().parse_args(argv)
        args.func(args)
        assert calls == [expected], f"andyur {argv[0]} called {calls}"



def test_a_paused_agent_is_not_displayed_as_merely_idle(env):
    """Pause is policy and idle/queued/running is lifecycle; they are genuinely
    orthogonal, so they stay separate in the data. But an operator reading
    'idle' reads 'available', which is the opposite of what a paused agent is.

    Renders the real status view and reads the output."""
    from andyur import cli
    from andyur.server import app as app_module
    from fastapi.testclient import TestClient

    client = TestClient(app_module.app)
    client.post("/agents", json={"name": "dozing", "description": "x"})
    client.post("/agents/dozing/pause")
    text = cli._render_status(client)
    line = next(ln for ln in text.splitlines() if ln.strip().startswith("dozing"))
    assert "idle" in line and "*" in line, f"paused not visible in: {line!r}"
    assert "paused" in text, "no legend explaining the marker"


# --- endpoints nothing ever called --------------------------------------------

def test_creating_a_schedule_works_at_all(env):
    """Cron scheduling was dead: the halted-run write guard had been pasted into
    create_schedule, which is operator-only and has neither `ctx` nor `relpath`,
    so every call raised NameError and returned 500.

    It survived because no test called the endpoint. Scheduling is what makes an
    agent unattended, which is the platform's whole premise, so a smoke test
    that merely CALLS it is worth more than its weight."""
    from fastapi.testclient import TestClient

    from andyur.server import app as app_module

    client = TestClient(app_module.app)
    client.post("/agents", json={"name": "cronned", "description": "x"})
    r = client.post("/agents/cronned/schedules",
                    json={"cron": "*/5 * * * *", "reason": "periodic"})
    assert r.status_code in (200, 201), f"{r.status_code}: {r.text[:200]}"
    assert client.get("/schedules").json(), "schedule was not persisted"
