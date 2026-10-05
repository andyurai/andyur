"""Workflow (transaction) identity is SERVER-AUTHORITATIVE and ENFORCED at the
durable layer (R6/R7, hardened after red-team):

  - sealed at a request's root, COPIED (never client-asserted) onto every
    delegated run/task via the parent run;
  - an unknown/forged parent is REFUSED (no depth-0 reset);
  - the kill-switch and caps are enforced where durable work is CREATED
    (tasks/messages), not only at the synchronous wake, and cover already-queued
    runs and open tasks;
  - an agent can be paused to stop a runaway source across workflows.

Drives the real coordinator/tasks/messages against a live sqlite DB, so it also
exercises the workflows table + depth migration.
"""

import pytest

from andyur.server import coordinator, messages, tasks


# -- seal + carry (server-authoritative) -------------------------------------

def test_root_trigger_seals_a_workflow(env):
    env.agent("planner")
    rid = coordinator.maybe_wakeup("planner", "manual trigger")
    wf = env.run_workflow(rid)
    assert wf and wf.startswith("wf-")


def test_delegated_task_copies_parent_workflow_to_child_and_task(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)

    res = tasks.create_task(
        assignee="triage", creator="planner", title="dig in", parent_run_id=parent
    )
    assert env.latest_run_workflow("triage") == wf
    assert env.task_workflow(res["id"]) == wf


def test_message_carries_parent_workflow_to_recipient_run(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)

    messages.send_message("triage", "planner", "take a look", parent_run_id=parent)
    assert env.latest_run_workflow("triage") == wf


def test_independent_roots_get_distinct_workflows(env):
    env.agent("planner")
    wf1 = env.run_workflow(coordinator.maybe_wakeup("planner", "root a"))
    env.set_idle("planner")
    wf2 = env.run_workflow(coordinator.maybe_wakeup("planner", "root b"))
    assert wf1 != wf2


def test_operator_task_without_parent_seals_a_workflow(env):
    env.agent("triage")
    res = tasks.create_task(
        assignee="triage", creator="operator", title="do it", parent_run_id=None
    )
    task_wf = env.task_workflow(res["id"])
    assert task_wf and task_wf.startswith("wf-")
    assert env.latest_run_workflow("triage") == task_wf


def test_unknown_parent_run_is_refused(env):
    """A stale/forged parent_run_id must be refused, NOT treated as a fresh
    depth-0 root (which would bypass the depth cap)."""
    env.agent("triage")
    assert coordinator.maybe_wakeup("triage", "x", parent_run_id="nope") is None
    with pytest.raises(coordinator.DelegationRefused):
        tasks.create_task(assignee="triage", creator="x", title="o", parent_run_id="nope")
    with pytest.raises(coordinator.DelegationRefused):
        messages.send_message("triage", "x", "hi", parent_run_id="nope")


# -- kill-switch enforced at the DURABLE layer (R6, hardened) ----------------

def test_halted_workflow_spawns_no_child_runs(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)

    coordinator.halt_workflow(wf)
    assert coordinator.maybe_wakeup("triage", "child", parent_run_id=parent) is None
    assert env.latest_run_workflow("triage") is None


def test_halted_workflow_refuses_new_tasks_and_messages(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    coordinator.halt_workflow(env.run_workflow(parent))

    with pytest.raises(coordinator.DelegationRefused):
        tasks.create_task(assignee="triage", creator="planner", title="x", parent_run_id=parent)
    with pytest.raises(coordinator.DelegationRefused):
        messages.send_message("triage", "planner", "x", parent_run_id=parent)


def test_halted_workflow_hides_existing_open_tasks(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)
    res = tasks.create_task(
        assignee="triage", creator="planner", title="pending work", parent_run_id=parent
    )
    assert any(t["id"] == res["id"] for t in tasks.list_tasks(assignee="triage"))

    coordinator.halt_workflow(wf)
    assert all(t["id"] != res["id"] for t in tasks.list_tasks(assignee="triage"))


def test_halt_stops_already_queued_runs_in_assign(env):
    env.agent("a")
    env.agent("b")
    ra = coordinator.maybe_wakeup("a", "root a")   # pending run, workflow A
    rb = coordinator.maybe_wakeup("b", "root b")   # pending run, workflow B
    coordinator.halt_workflow(env.run_workflow(ra))

    assigned = {x["id"] for x in coordinator.assign_runs("w1", 10)}
    assert rb in assigned          # healthy run is handed out
    assert ra not in assigned      # halted-workflow run is skipped


def test_unhalt_reactivates_workflow(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)
    coordinator.halt_workflow(wf)
    assert coordinator.maybe_wakeup("triage", "child", parent_run_id=parent) is None

    coordinator.unhalt_workflow(wf)
    assert coordinator.maybe_wakeup("triage", "child", parent_run_id=parent) is not None


# -- caps (R7, hardened) -----------------------------------------------------

def test_delegation_depth_is_capped(env, monkeypatch):
    monkeypatch.setattr(coordinator, "MAX_DELEGATION_DEPTH", 1)
    env.agent("a")
    env.agent("b")
    env.agent("c")
    root = coordinator.maybe_wakeup("a", "root")                     # depth 0
    child = coordinator.maybe_wakeup("b", "d1", parent_run_id=root)  # depth 1, ok
    assert child is not None
    deep = coordinator.maybe_wakeup("c", "d2", parent_run_id=child)  # depth 2 > 1
    assert deep is None


def test_workflow_cap_counts_runs_and_open_tasks(env, monkeypatch):
    """The work-item cap bounds TASK creation, not only wakeups: it counts runs
    plus still-open tasks, so a flood of create_task cannot slip past it."""
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")    # workflow: 1 run
    # 1 run + 0 tasks = 1 < 2 -> allowed
    tasks.create_task(assignee="triage", creator="planner", title="t1", parent_run_id=parent)
    # 1 run + 1 open task = 2, not < 2 -> refused at task creation
    with pytest.raises(coordinator.DelegationRefused):
        tasks.create_task(assignee="triage", creator="planner", title="t2", parent_run_id=parent)


# -- agent-level kill-switch --------------------------------------------------

def test_paused_agent_is_not_woken(env):
    env.agent("planner")
    coordinator.set_paused("planner", True)
    assert coordinator.maybe_wakeup("planner", "root") is None
    coordinator.set_paused("planner", False)
    assert coordinator.maybe_wakeup("planner", "root") is not None


# -- destructive halt: no stranded agents, no resurrection -------------------

def test_halt_frees_agent_stranded_on_a_pending_run(env):
    """Regression: halting must not leave an agent stuck 'queued' on a run that
    assign_runs will now skip forever. Destructive halt cancels the pending run
    and frees the agent."""
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)
    child = coordinator.maybe_wakeup("triage", "child", parent_run_id=parent)
    assert child is not None  # triage now queued on a pending run in wf

    coordinator.halt_workflow(wf)
    # triage is freed, not stranded: it can be woken again (as a fresh root)
    assert coordinator.maybe_wakeup("triage", "later") is not None


def test_start_run_refuses_a_halted_run(env):
    env.agent("planner")
    root = coordinator.maybe_wakeup("planner", "root")
    coordinator.halt_workflow(env.run_workflow(root))  # cancels the pending run
    assert coordinator.start_run(root) is False


# -- cap counts LIVE work, not lifetime --------------------------------------

def test_finished_runs_do_not_count_against_cap(env, monkeypatch):
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 1)
    env.agent("planner")
    root = coordinator.maybe_wakeup("planner", "root")     # 1 live run == cap
    coordinator.finish_run(root, "done", None)             # terminal -> frees budget
    env.set_idle("planner")
    again = coordinator.maybe_wakeup("planner", "more", parent_run_id=root)
    assert again is not None


# -- kill-switch closes the message channel ----------------------------------

def test_message_is_stamped_and_hidden_on_halt(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)
    messages.send_message("triage", "planner", "look here", parent_run_id=parent)
    assert any(m["body"] == "look here"
               for m in messages.list_messages("triage", "unread"))

    coordinator.halt_workflow(wf)
    assert all(m["body"] != "look here"
               for m in messages.list_messages("triage", "unread"))


def test_workflow_cap_counts_unread_messages(env, monkeypatch):
    """A send_message loop cannot fan out past the cap: unread messages count as
    live work items too."""
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")   # 1 live run
    # 1 run + 0 tasks + 0 msgs = 1 < 2 -> stored (recipient not woken: that would
    # be the 2nd item); now 1 run + 1 unread msg = 2
    messages.send_message("triage", "planner", "m1", parent_run_id=parent)
    with pytest.raises(coordinator.DelegationRefused):
        messages.send_message("triage", "planner", "m2", parent_run_id=parent)


def test_operator_message_survives_halt(env):
    """The operator inbox is the human control/audit channel: a report an agent
    sends to the operator is NOT hidden or silenced by halting the workflow (only
    agent-to-agent messages are gated)."""
    env.agent("planner")
    parent = coordinator.maybe_wakeup("planner", "root")
    wf = env.run_workflow(parent)
    messages.send_message("operator", "planner", "status", parent_run_id=parent)
    coordinator.halt_workflow(wf)
    # the operator still sees the report after the halt
    assert any(m["body"] == "status"
               for m in messages.list_messages("operator", "unread"))


def test_pausing_cancels_the_agents_queued_run_and_frees_it(env):
    env.agent("planner")
    env.agent("triage")
    parent = coordinator.maybe_wakeup("planner", "root")
    child = coordinator.maybe_wakeup("triage", "child", parent_run_id=parent)
    assert child is not None                     # triage queued on a pending run

    coordinator.set_paused("triage", True)
    assert env.run_state(child) == "cancelled"   # queued work dropped
    assert coordinator.maybe_wakeup("triage", "x") is None   # paused: not woken

    coordinator.set_paused("triage", False)      # freed, not stranded
    assert coordinator.maybe_wakeup("triage", "y") is not None
