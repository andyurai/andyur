"""Halt: the operator's kill switch, and why cancellation is not containment.

This is the module where a provider is most likely to be wrong in a way that
matters. Every durable-execution engine has cancellation, and it is always
COOPERATIVE: the engine stops scheduling new steps and asks the running one to
wind down. That is a perfectly good mechanism for orchestration and a useless
one for containment, because the thing Andyur is halting may be a compromised or
wedged agent that will not cooperate.

So halt has two halves, and a provider may only ever supply the first:

    provider cancellation  stop making durable progress   (orchestration)
    runtime termination    destroy the execution          (containment)

The contract below fixes the ORCHESTRATION half and the CONDEMNATION SIGNAL that
drives the second. The destruction itself -- process groups, container handles,
pod deletion -- is deliberately not asserted here; `tests/test_kill_switch.py`
and the containment gates own that, and they should, because it is mechanism.

The threat model treats halt as a control. A provider that quietly downgrades it
to cooperative cancellation has removed a control while every test still passes,
which is why the signal is pinned here separately from the teardown.
"""

from andyur import db
from andyur.server import coordinator

from .conftest import is_free, live_run_of, run_state


def _workflow_of(run_id: str) -> str:
    with db.connect() as c:
        return c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()["workflow_id"]


# --- halting stops future work ----------------------------------------------

def test_a_halted_workflow_admits_no_new_runs(agent):
    run = coordinator.maybe_wakeup(agent, "work")
    workflow = _workflow_of(run)
    coordinator.finish_run(run, "done", None)

    coordinator.halt_workflow(workflow)

    assert coordinator.maybe_wakeup(agent, "more", workflow_id=workflow) is None


def test_halting_releases_agents_stranded_on_un_started_work(agent):
    """An agent held by a run that will now never execute must be freed, or the
    kill switch costs the operator the agent as well as the workflow."""
    run = coordinator.maybe_wakeup(agent, "work")

    coordinator.halt_workflow(_workflow_of(run))

    assert run_state(run) == "cancelled"
    assert is_free(agent)


def test_a_halted_workflow_refuses_to_start_work_already_dispatched(agent):
    """The dispatch-to-start window. A run handed to an executor before the
    halt must still refuse to begin, or the halt is merely advisory for
    anything already in flight."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.assign_runs("executor-1", 1)

    coordinator.halt_workflow(_workflow_of(run))

    assert coordinator.start_run(run) is False, "a halted run started anyway"


def test_start_refuses_a_run_whose_workflow_halted_before_its_cancellation_arrived(agent):
    """THE CLAUSE ITSELF, which the test above cannot reach.

    `start_run` refuses a run whose workflow is halted -- the guard for the
    assign-to-start window. The test above never exercises it: `halt_workflow`
    cancels every pending run, including an assigned one, so by the time
    `start_run` is called the run is no longer pending and the pending check
    refuses on its own. Deleting the halted-workflow clause left all fifteen
    tests in this file green.

    So the interleaving the clause exists for is constructed directly: the halt
    is committed, and its cancellation has not yet reached this run. Written to
    the row rather than through `halt_workflow`, because the point is the state
    `halt_workflow` would otherwise clean up.
    """
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.assign_runs("executor-1", 1)
    with db.connect() as c:
        c.execute("UPDATE workflows SET state = 'halted' WHERE id = ?",
                  (_workflow_of(run),))
        assert c.execute("SELECT state FROM runs WHERE id = ?",
                         (run,)).fetchone()["state"] == "pending", (
            "setup: the run must still be pending, or the pending check refuses "
            "it and this proves nothing about the halted-workflow clause")

    assert coordinator.start_run(run) is False, (
        "a run in a halted workflow started because only its own state was "
        "checked -- the halt is advisory for anything assigned before it")


def test_positive_control_start_admits_a_pending_run_in_a_live_workflow(agent):
    """Without this, a `start_run` that refuses everything passes the test above."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.assign_runs("executor-1", 1)

    assert coordinator.start_run(run) is True


def test_halting_is_reversible(agent):
    run = coordinator.maybe_wakeup(agent, "work")
    workflow = _workflow_of(run)
    coordinator.halt_workflow(workflow)

    assert coordinator.unhalt_workflow(workflow) is True
    assert coordinator.maybe_wakeup(agent, "after unhalt", workflow_id=workflow) is not None


def test_unhalting_does_not_resurrect_the_work_the_halt_tore_down(agent):
    """Halt is destructive on purpose. If unhalt restored the queue, an
    operator who halted a misbehaving workflow would re-release exactly the
    work they stopped the moment they reopened it."""
    run = coordinator.maybe_wakeup(agent, "work")
    workflow = _workflow_of(run)
    coordinator.halt_workflow(workflow)

    coordinator.unhalt_workflow(workflow)

    assert run_state(run) == "cancelled", "the halted run came back"
    assert is_free(agent)


# --- an executing run is CONDEMNED, not asked nicely ------------------------

def test_halting_does_not_itself_end_an_executing_run(agent):
    """CHARACTERIZATION, and the crux of this module.

    Halt cancels work that has not begun. A run that is already executing is
    NOT marked terminal by the halt itself, because the platform does not yet
    know the execution is gone -- the process is still out there. It is
    condemned, the executor destroys it, and the server writes the outcome.

    A provider that implemented halt as "mark everything cancelled" would
    satisfy a naive reading of the kill switch while leaving a live, unaccounted
    agent process running with no run record to attribute its actions to.
    """
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)

    coordinator.halt_workflow(_workflow_of(run))

    assert run_state(run) == "running", (
        "the halt marked an executing run terminal without anything having "
        "destroyed it -- the process would be unaccountable")


def test_an_executing_run_of_a_halted_workflow_is_condemned(agent):
    """The signal that drives containment. This is the half a provider must
    NOT be allowed to satisfy with cooperative cancellation alone."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    coordinator.halt_workflow(_workflow_of(run))

    assert coordinator.runs_to_kill([run]) == [run]


def test_a_healthy_run_is_not_condemned(agent):
    """The negative control: condemning everything would be containment too,
    and useless."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)

    assert coordinator.runs_to_kill([run]) == []


def test_an_execution_with_no_live_run_record_is_condemned(agent):
    """Orphans. An execution the platform has no live record for is
    unaccountable by definition -- nothing will record what it does -- so it is
    destroyed regardless of why it survived.

    This one matters more under a durable provider, not less: retries and
    replays create exactly this shape, an executor still working on something
    the platform has already finished.
    """
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    coordinator.finish_run(run, "done", None)

    assert coordinator.runs_to_kill([run]) == [run]


def test_an_execution_the_platform_never_heard_of_is_condemned():
    assert coordinator.runs_to_kill(["0" * 32]) == ["0" * 32]


def test_condemnation_is_decided_from_the_platforms_record(agent):
    """Nothing about the condemnation decision comes from the executor beyond
    the list of what it claims to be running. A provider cannot exempt its own
    work from the kill switch by reporting differently."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    coordinator.halt_workflow(_workflow_of(run))

    assert coordinator.runs_to_kill([run]) == [run]
    assert coordinator.runs_to_kill([]) == [], (
        "an executor that reports nothing is asked to kill nothing -- the "
        "platform cannot condemn what no executor claims to hold")


# --- liveness, as the credential path sees it -------------------------------

def test_a_live_run_reports_live_and_a_finished_one_does_not(agent):
    """The bit the broker spends money on. Revocation turns on run LIVENESS,
    so a provider that leaves a run looking live after it has ended extends
    the window in which credentials can still be minted for it."""
    run = coordinator.maybe_wakeup(agent, "work")
    assert coordinator.run_is_live(run) is True

    coordinator.start_run(run)
    assert coordinator.run_is_live(run) is True

    coordinator.finish_run(run, "done", None)
    assert coordinator.run_is_live(run) is False


def test_an_unknown_run_is_indistinguishable_from_a_finished_one():
    """Same answer for both, so liveness cannot be used to enumerate run ids."""
    assert coordinator.run_is_live("f" * 32) is False
    assert coordinator.run_is_live("") is False


# --- halting ahead of the work ----------------------------------------------

def test_halting_a_workflow_that_does_not_exist_yet_halts_it_pre_emptively(agent):
    """CHARACTERIZATION MISSED IN THE FIRST PASS, and it cost something: the
    provider interface was drafted refusing this case, and the conformance
    suite asserted the refusal, because neither had this behaviour written down
    to check against.

    An operator may halt a workflow id before anything has joined it. The row is
    inserted already halted, so work that later names that workflow is refused.
    That is what makes the kill switch usable against something that is
    starting rather than only against something already running.
    """
    coordinator.halt_workflow("wf-not-yet-real")

    assert coordinator.workflow_state("wf-not-yet-real") == "halted"
    assert coordinator.maybe_wakeup(
        agent, "work", workflow_id="wf-not-yet-real") is None, (
        "work joined a workflow that had been halted ahead of it")


def test_a_pre_emptive_halt_can_be_reversed(agent):
    """Otherwise halting ahead of the work would be a one-way door on an id
    the operator may simply have typed wrongly."""
    coordinator.halt_workflow("wf-not-yet-real")
    coordinator.unhalt_workflow("wf-not-yet-real")

    assert coordinator.maybe_wakeup(
        agent, "work", workflow_id="wf-not-yet-real") is not None
