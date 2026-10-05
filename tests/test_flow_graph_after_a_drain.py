"""The flow graph draws the run that PERFORMED a delegated task.

Gap 28's whole point was user-visible: a run woken by the heartbeat drain used
to seal a fresh workflow with no parent, so `GET /workflows/{id}/flow` rendered
the originating workflow with the task present and NO RUN against it, while the
run that actually performed it drew as an unrelated root somewhere else.

The gap-28 change is covered at the database level in `test_work_drain.py`. This
file covers the claim that was made ABOUT THE CONSOLE and never checked: that
the graph now shows the edge. Those are different assertions -- a correct
`parent_run_id` on a row proves nothing about what the endpoint renders, and the
endpoint is where the operator actually looks.

Written after the fact, which is the honest note to leave: the PR claimed the
console draws this edge before anything had rendered it.

Mutation coverage, and one equivalent mutant recorded so it is not re-derived:
dropping the drain's `parent_run_id` reddens these, and making the endpoint fall
back to "nearest run one level up" for a dangling pointer reddens these. Dropping
the drain's explicit `workflow_id` does NOT, and that is correct rather than a
gap -- with a provable parent `resolve_workflow` inherits the workflow from it,
so the argument is redundant on that path. It is load-bearing only when the
parent cannot be proved, which `test_work_drain.py` covers at the row level.
"""
import pytest

from fastapi.testclient import TestClient

from andyur import db
from andyur.server import app as app_module
from andyur.server import coordinator, heartbeat, tasks

client = TestClient(app_module.app)


def _flow(workflow_id):
    r = client.get(f"/workflows/{workflow_id}/flow")
    assert r.status_code == 200, r.text
    return r.json()


def _delegate_to_a_busy_agent(env):
    """A task handed to an agent that is already running -- the case the drain
    exists for, and the one that produced the orphaned task in the graph."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "investigate the alert", "detail",
                      parent_run_id=parent)
    with db.connect() as c:
        wf = c.execute(
            "SELECT workflow_id FROM tasks WHERE assignee='helper'").fetchone()[0]
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    return parent, wf


def test_the_drained_run_appears_in_the_workflow_it_performed_work_for(env):
    parent, wf = _delegate_to_a_busy_agent(env)

    before = _flow(wf)
    assert any(t["title"] == "investigate the alert" for t in before["tasks"])
    assert {n["agent"] for n in before["nodes"]} == {"planner"}, (
        "fixture is wrong: the helper must not be in the graph before the drain")

    assert any("drained" in a for a in heartbeat.drain_pending_work())

    after = _flow(wf)
    agents = [n["agent"] for n in after["nodes"]]
    assert "helper" in agents, (
        "the run that performed the task is still outside the workflow: the "
        f"graph shows only {agents}")


def test_and_the_graph_draws_the_edge_from_the_run_that_delegated(env):
    """The picture, not just the membership. A node in the workflow with no
    edge to it is the same defect one step along -- it draws as a second root
    inside the workflow rather than outside it."""
    parent, wf = _delegate_to_a_busy_agent(env)
    heartbeat.drain_pending_work()
    flow = _flow(wf)

    by_index = {n["index"]: n for n in flow["nodes"]}
    helper = next(i for i, n in by_index.items() if n["agent"] == "helper")
    planner = next(i for i, n in by_index.items() if n["agent"] == "planner")

    assert any(e["from"] == planner and e["to"] == helper for e in flow["edges"]), (
        "no edge from the delegating run to the run that performed the work; "
        f"edges were {flow['edges']}")


def test_a_dangling_parent_draws_no_edge_rather_than_the_nearest_run_above(env):
    """A recorded parent that does not resolve must draw NOTHING.

    The endpoint keeps a pre-column fallback -- "nearest preceding run, one
    level up" -- for rows written before `runs.parent_run_id` existed. Its own
    comment says a dangling pointer must not fall through to it, because the
    fallback would invent an edge from whichever run happens to sit above.

    An earlier version of this test claimed to cover that using a drained run
    with two creators. It did not: that run lands alone in a fresh workflow with
    nothing at the level below it, so the fallback has nothing to attach it to
    and the assertion held for the wrong reason. This builds the case the
    comment actually describes -- a dangling parent WITH a candidate one level
    up -- so the assertion can fail.
    """
    env.agent("planner")
    env.agent("helper")
    env.agent("bystander")
    root = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(root)
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM runs WHERE id=?", (root,)).fetchone()[0]
        # A run at depth 1 whose recorded parent has been pruned: exactly the
        # dangling pointer, with `root` one level up as bait for the fallback.
        # Dated AFTER the root, because the graph walks runs in created_at order
        # and builds its depth index as it goes -- a row dated in the past sorts
        # first and would find nothing above it, which is a fixture that cannot
        # exercise what it claims to.
        c.execute(
            "INSERT INTO runs (id, agent, run_type, state, reason, created_at, "
            "workflow_id, depth, parent_run_id) VALUES "
            "('orphan','helper','work','running','r','2027-01-01T00:00:01',?,1,'gone')",
            (wf,))

    flow = _flow(wf)
    orphan = next(n["index"] for n in flow["nodes"] if n["agent"] == "helper")
    planner = next(n["index"] for n in flow["nodes"] if n["agent"] == "planner")
    assert not any(e["to"] == orphan for e in flow["edges"]), (
        "a dangling parent was replaced by the nearest run one level up; "
        f"edges were {flow['edges']}")
    # positive control: the fallback is not simply dead -- a row with NO
    # recorded parent at all still gets its pre-column edge
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, run_type, state, reason, created_at, "
            "workflow_id, depth) VALUES "
            "('precolumn','bystander','work','running','r','2027-01-01T00:00:02',?,1)",
            (wf,))
    flow2 = _flow(wf)
    pre = next(n["index"] for n in flow2["nodes"] if n["agent"] == "bystander")
    assert any(e["to"] == pre and e["from"] == planner for e in flow2["edges"]), (
        "the pre-column fallback drew nothing, so the assertion above proves "
        f"nothing; edges were {flow2['edges']}")
