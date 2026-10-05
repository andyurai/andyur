"""What the native engine does that the contract does not require.

Everything here is `local`-specific, and each test exists because the behaviour
is real and worth pinning but could NOT be asked of every provider.

The clearest example is the first one. `local` can refuse to start a workflow
whose run was never admitted, because it is looking at Andyur's own tables. A
durable engine has no view of those, so requiring it of every provider would be
requiring something unimplementable -- and a conformance suite that asks for the
impossible gets weakened until it asks for nothing.
"""

import pytest

from andyur import db
from andyur.orchestration import capabilities, errors, models
from andyur.orchestration.local import LocalWorkflowProvider
from andyur.server import coordinator

from .conftest import is_free, run_state


@pytest.fixture
def local():
    return LocalWorkflowProvider()


def _workflow_of(run_id):
    with db.connect() as c:
        return c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()["workflow_id"]


# --- the provider does not admit work ---------------------------------------

def test_starting_a_run_that_was_never_admitted_is_refused(local):
    """A provider that created the workflow here would be ADMITTING work, and
    admission is Andyur's decision. Refusing is what keeps the seam honest: the
    provider can only ever run something the platform already allowed."""
    with pytest.raises(errors.WorkflowNotFound):
        local.start(models.WorkflowStart(
            workflow_id="wf-invented", root_run_id="run-never-admitted",
            workflow_kind="single_agent"))


def test_starting_an_admitted_run_changes_nothing_about_it(local, agent):
    """`start` IS VERY NEARLY A NO-OP HERE, and that is the finding worth
    keeping visible.

    In the native engine, admitting a run and making it dispatchable are the
    same act: `maybe_wakeup` inserts the pending row and the row's existence is
    what a worker claims. There is no separate instruction to begin.

    A durable provider splits those, so the facade will call `start` on every
    path -- and on this provider that call does nothing. A facade bug that
    omitted it would therefore be invisible locally and appear only under a
    durable provider, which is exactly the kind of bug that reaches production.
    """
    run = coordinator.maybe_wakeup(agent, "work")
    before = run_state(run)

    local.start(models.WorkflowStart(
        workflow_id=_workflow_of(run), root_run_id=run,
        workflow_kind="single_agent"))

    assert run_state(run) == before, "start had a side effect on the run"


# --- halting means stop, not destroy ----------------------------------------

def test_halting_frees_an_agent_whose_run_had_not_begun(local, agent):
    """THROUGH THE FACADE, because the provider does not write governance.

    This called `local.halt` directly in the first draft and passed, because
    the provider was writing Andyur's halt itself -- which is exactly the bug
    the review found. Driving the platform is what makes the assertion mean
    what it says.
    """
    from andyur import orchestration

    f = orchestration.OrchestrationFacade(provider=local)
    run, _ = f.request_agent_run(agent, "work")

    outcome = f.halt_workflow(_workflow_of(run))

    assert outcome.accepted is True
    assert run_state(run) == "cancelled"
    assert is_free(agent)


def test_halting_reports_accepted_while_an_execution_is_still_running(
        local, agent):
    """THE POINT OF THE WHOLE DESIGN, asserted rather than described.

    `accepted` means durable progress has stopped. It does NOT mean anything was
    destroyed -- the run is still `running`, its container is still there, and
    the condemnation path will deal with it on the executor's next beat.

    A caller reading `accepted` as "the agent has stopped" would be wrong, and
    the day someone makes that mistake this test is the thing that says so.
    """
    from andyur import orchestration

    f = orchestration.OrchestrationFacade(provider=local)
    run, _ = f.request_agent_run(agent, "work")
    coordinator.start_run(run)

    outcome = f.halt_workflow(_workflow_of(run))

    assert outcome.accepted is True
    assert run_state(run) == "running", (
        "halt marked an executing run terminal; nothing had destroyed it yet")
    assert coordinator.runs_to_kill([run]) == [run], (
        "the run was not condemned, so nothing will ever destroy it")


def test_the_halt_outcome_says_out_loud_that_it_destroyed_nothing(
        local, agent):
    from andyur import orchestration

    f = orchestration.OrchestrationFacade(provider=local)
    run, _ = f.request_agent_run(agent, "work")

    outcome = f.halt_workflow(_workflow_of(run))

    assert "condemnation" in (outcome.detail or "").lower()


# --- describing -------------------------------------------------------------

def test_a_workflow_with_a_live_run_is_queued_then_running(local, agent):
    run = coordinator.maybe_wakeup(agent, "work")
    workflow = _workflow_of(run)

    assert (local.describe(workflow)).state is models.WorkflowState.QUEUED

    coordinator.start_run(run)

    assert (local.describe(workflow)).state is models.WorkflowState.RUNNING


def test_a_workflow_with_no_live_runs_is_idle_not_finished(local, agent):
    """THIS ASSERTED SUCCEEDED IN ITS FIRST DRAFT, and the assertion encoded a
    bug this method's own comment warns against.

    The native engine has no notion of a workflow COMPLETING: a workflow is open
    until it is halted, and an active one accepts more work. Deriving a terminal
    state from its runs' outcomes meant `is_terminal()` was true for something
    that was not finished -- so a caller could free it early. The
    halt-then-unhalt operator flow produces exactly that shape: every run
    cancelled, the workflow active again.
    """
    run = coordinator.maybe_wakeup(agent, "work")
    workflow = _workflow_of(run)
    coordinator.start_run(run)
    coordinator.finish_run(run, "done", None)

    described = local.describe(workflow)

    assert described.state is models.WorkflowState.WAITING
    assert not described.state.is_terminal(), (
        "an open workflow reported a terminal state")


def test_an_unhalted_workflow_is_not_reported_as_cancelled(local, agent):
    """The case that makes it concrete. After halt then unhalt the runs are all
    cancelled and the workflow is active again -- reporting CANCELLED would say
    a workflow that is accepting work has finished."""
    from andyur import orchestration

    f = orchestration.OrchestrationFacade(provider=local)
    run, _ = f.request_agent_run(agent, "work")
    workflow = _workflow_of(run)
    f.halt_workflow(workflow)
    f.unhalt_workflow(workflow)

    described = local.describe(workflow)

    assert described.state is not models.WorkflowState.CANCELLED
    assert not described.state.is_terminal()


def test_a_halted_workflow_is_terminal(local, agent):
    """The one state that IS closed: nothing more will join it until an
    operator reopens it."""
    from andyur import orchestration

    f = orchestration.OrchestrationFacade(provider=local)
    run, _ = f.request_agent_run(agent, "work")
    workflow = _workflow_of(run)

    f.halt_workflow(workflow)

    described = local.describe(workflow)
    assert described.state is models.WorkflowState.HALTED
    assert described.state.is_terminal()


# --- what this provider will not do -----------------------------------------

def test_signalling_is_refused_rather_than_silently_dropped(local):
    """A no-op signal is the tempting stub and the dangerous one: a durable
    approval waiting on a signal that was never delivered waits forever, and
    nothing anywhere reports a problem."""
    with pytest.raises(errors.ProviderCapabilityMissing):
        local.signal("wf-1", models.WorkflowSignal(name="approve"))


def test_the_local_provider_does_not_claim_durability_it_lacks(local):
    """Conservative by policy: a capability is a promise something will be
    built on. Note `durable_timers` is False even though a cron schedule really
    does survive a restart -- the capability means the general case, an
    arbitrary in-workflow wait resumed later, and there is no local
    implementation of that at all."""
    caps = local.capabilities()

    assert caps.durable_execution is False
    assert caps.durable_timers is False
    assert caps.durable_signals is False
    assert caps.long_running_waits is False
    assert caps.child_workflows is False
    assert caps.provider_failover is False
    assert caps.schedules is True


def test_the_local_provider_cannot_run_a_durable_approval(local):
    """Fails closed, loudly, naming what is missing -- rather than approximating
    a durable wait with polling and losing an approval on the one restart that
    happens mid-wait."""
    with pytest.raises(errors.ProviderCapabilityMissing) as caught:
        capabilities.check("durable_approval", local.capabilities())

    assert "durable_signals" in caught.value.missing


def test_the_quickstart_kinds_all_run_on_the_local_provider(local):
    """The ten-minute path must never require a durable engine, or the local
    provider stops being a real option and becomes a demo."""
    for kind in ("single_agent", "scheduled_agent", "deferred_work"):
        capabilities.check(kind, local.capabilities())
