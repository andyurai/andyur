"""The facade, and the bypasses that must not come back.

Section 60's exit criterion is the whole point of Stage 5:

> Pluggability is not achieved until the existing/native flow also goes through
> the provider-neutral facade.

A server with one route to the coordinator and another to a provider has two
orchestrators, and the one nobody is looking at is the one that drifts. So the
architecture tests below are not decoration -- they are the only thing that
stops the next person adding a sixth call site straight to the coordinator
because it was one line shorter.
"""

import ast
import inspect
import pathlib

import pytest

from andyur import orchestration
from andyur.orchestration.facade import OrchestrationFacade
from andyur.orchestration.local import LocalWorkflowProvider
from andyur.server import coordinator

from orchestration_contract.conftest import is_free, live_run_of, run_state

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "andyur"

# Operations that must now be reached through the facade. Naming them here
# rather than inferring them keeps the list reviewable: adding one is a
# deliberate act, not something a refactor does by accident.
ROUTED_OPERATIONS = {
    "maybe_wakeup", "wakeup_or_reason", "halt_workflow", "unhalt_workflow",
}

# Where calling them directly is still correct.
#
#   coordinator.py            defines them
#   orchestration/local/      IS the native provider; delegating is its job
#   orchestration/facade.py   the one caller the rest of Andyur goes through
ALLOWED = {
    "andyur/server/coordinator.py",
    "andyur/orchestration/local/provider.py",
    "andyur/orchestration/facade.py",
}


def _workflow_of_run(run_id):
    from andyur import db
    with db.connect() as c:
        return c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()["workflow_id"]


def _calls_to_coordinator(path):
    """Every `coordinator.<op>(...)` call in a file, by line."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr in ROUTED_OPERATIONS
                and isinstance(fn.value, ast.Name) and fn.value.id == "coordinator"):
            yield node.lineno, fn.attr


def test_nothing_reaches_the_coordinator_around_the_facade():
    """THE STAGE 5 EXIT CRITERION.

    Five call sites used to wake runs directly and two used to halt workflows.
    They now go through the facade, and this is what keeps it that way. If you
    are here because this failed: the fix is to call
    `orchestration.facade().request_agent_run(...)`, not to add your file to
    ALLOWED.
    """
    offenders = []
    for path in SOURCE.rglob("*.py"):
        rel = str(path.relative_to(ROOT))
        if rel in ALLOWED:
            continue
        for lineno, op in _calls_to_coordinator(path):
            offenders.append(f"{rel}:{lineno} calls coordinator.{op} directly")

    assert offenders == [], offenders


def test_the_allow_list_names_only_files_that_exist():
    """An allow-list entry for a deleted file is an exemption nobody can see is
    stale, and it silently widens the rule."""
    for rel in ALLOWED:
        assert (ROOT / rel).exists(), f"{rel} is allow-listed but does not exist"


def test_the_facade_signature_still_mirrors_the_coordinator():
    """POSITIONALLY, not just by keyword. The first draft of the facade made
    `run_type` keyword-only, and the trigger endpoint passes it positionally --
    so the busiest path in the platform type-errored.

    The suite caught it, but only after the fact and in 37 places at once. This
    says the same thing in one place, at the point where either signature
    changes.
    """
    theirs = inspect.signature(coordinator.wakeup_or_reason)
    ours = inspect.signature(OrchestrationFacade.request_agent_run)

    positional = [
        name for name, p in theirs.parameters.items()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    ours_positional = [
        name for name, p in ours.parameters.items()
        if name != "self" and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]

    assert ours_positional == positional[:len(ours_positional)], (
        f"the facade takes {ours_positional} positionally but the coordinator "
        f"takes {positional} -- a caller passing them positionally will break")

    # Everything else has to survive the pass-through.
    assert any(p.kind is p.VAR_KEYWORD for p in ours.parameters.values()), (
        "the facade must pass keyword arguments through, or it will silently "
        "drop one the coordinator accepts")


# --- the facade does what the call sites used to do --------------------------

def test_requesting_a_run_admits_it(env):
    agent = env.agent("alice")

    run_id, refusal = orchestration.facade().request_agent_run(agent, "work")

    assert run_id is not None
    assert refusal is None
    assert live_run_of(agent) == run_id


def test_a_refusal_comes_back_unchanged(env):
    """The refusal path is the one a caller branches on, so it must survive the
    move. `tasks.create_task` and `send_message` both rely on a refused wakeup
    leaving the work for the drain."""
    agent = env.agent("alice")
    orchestration.facade().request_agent_run(agent, "first")

    run_id, refusal = orchestration.facade().request_agent_run(agent, "second")

    assert run_id is None
    assert refusal is not None


def test_run_type_may_be_passed_positionally(env):
    """The regression that 37 tests found at once."""
    agent = env.agent("alice")

    run_id, _ = orchestration.facade().request_agent_run(agent, "work", "scheduled")

    assert run_id is not None


def test_halting_through_the_facade_stops_the_workflow(env):
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    from andyur import db
    with db.connect() as c:
        workflow = c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()["workflow_id"]

    outcome = orchestration.facade().halt_workflow(workflow)

    assert outcome.accepted is True
    assert run_state(run_id) == "cancelled"
    assert is_free(agent)


def test_unhalting_does_not_touch_the_provider(env, monkeypatch):
    """A halt stopped an execution; there is nothing to resume. Unhalt changes
    Andyur's governance record so new work may join, and that is all."""
    called = []

    class Watched(LocalWorkflowProvider):
        def halt(self, request):
            called.append("halt")
            return super().halt(request)

    f = orchestration.OrchestrationFacade(provider=Watched())
    agent = env.agent("alice")
    run_id, _ = f.request_agent_run(agent, "work")
    from andyur import db
    with db.connect() as c:
        workflow = c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()["workflow_id"]
    f.halt_workflow(workflow)
    called.clear()

    f.unhalt_workflow(workflow)

    assert called == [], "unhalt reached the provider"
    assert coordinator.workflow_state(workflow) == "active"


def test_a_provider_that_cannot_start_does_not_strand_the_agent(env):
    """The window the facade opens: the run is admitted, then the provider is
    told. If that second step fails the run would hold its agent with nothing
    coming for it -- until the 24-hour queue backstop, which is
    indistinguishable from forever.

    Cannot happen on the native provider, where `start` only verifies. It very
    much can under a durable one, which is why the compensation exists now
    rather than when it first bites.
    """
    class Broken(LocalWorkflowProvider):
        def start(self, request):
            raise orchestration.ProviderUnavailable("the engine is down")

    f = orchestration.OrchestrationFacade(provider=Broken())
    agent = env.agent("alice")

    with pytest.raises(orchestration.ProviderUnavailable):
        f.request_agent_run(agent, "work")

    assert is_free(agent), "a failed start stranded the agent"


def test_a_workflow_kind_the_provider_cannot_serve_is_refused_before_admission(env):
    """Refused BEFORE the run is admitted, so a capability failure never leaves
    a run behind."""
    f = orchestration.OrchestrationFacade(provider=LocalWorkflowProvider())
    agent = env.agent("alice")

    with pytest.raises(orchestration.ProviderCapabilityMissing):
        f.request_agent_run(agent, "work", workflow_kind="durable_approval")

    assert is_free(agent), "a capability refusal still admitted a run"


def test_halting_works_with_a_provider_that_writes_no_governance(env):
    """THE REGRESSION THAT MATTERED MOST, and nothing caught it.

    `provider.py` specifies `halt` as "stop making durable progress" and says
    governance is Andyur's. A provider that implements exactly that -- touching
    none of Andyur's state -- used to leave the workflow `active`: `admit` kept
    admitting runs into it, its tasks and messages kept surfacing, and
    `POST /workflows/{id}/halt` still answered {"state": "halted"}.

    It worked only because the NATIVE provider happened to write the governance
    halt itself, which is precisely the coupling this seam exists to remove. The
    old halt tests all called `coordinator.halt_workflow` directly, so every one
    of them passed while the facade was broken for any second provider.
    """
    class WritesNoGovernance(LocalWorkflowProvider):
        def halt(self, request):
            return orchestration.HaltOutcome(
                workflow_id=request.workflow_id, accepted=True,
                state=orchestration.WorkflowState.HALTED,
                detail="progress stopped; nothing of Andyur's touched")

    f = orchestration.OrchestrationFacade(provider=WritesNoGovernance())
    agent = env.agent("alice")
    run_id, _ = f.request_agent_run(agent, "work")
    workflow = _workflow_of_run(run_id)
    coordinator.finish_run(run_id, "done", None)

    f.halt_workflow(workflow)

    assert coordinator.workflow_state(workflow) == "halted", (
        "the facade left governance to the provider")
    admitted, _ = f.request_agent_run(agent, "after the halt", workflow_id=workflow)
    assert admitted is None, "a run was admitted into a halted workflow"


def test_the_governance_halt_is_written_before_the_provider_is_asked(env):
    """Ordering, and it is the kill switch's.

    A provider that is unreachable must not be able to leave a workflow
    admitting work. Writing governance first means the halt holds even when the
    engine does not answer -- a kill switch that depends on infrastructure being
    healthy is not a control.
    """
    class Unreachable(LocalWorkflowProvider):
        def halt(self, request):
            raise orchestration.ProviderUnavailable("the engine is down")

    f = orchestration.OrchestrationFacade(provider=Unreachable())
    agent = env.agent("alice")
    run_id, _ = f.request_agent_run(agent, "work")
    workflow = _workflow_of_run(run_id)

    with pytest.raises(orchestration.ProviderUnavailable):
        f.halt_workflow(workflow)

    assert coordinator.workflow_state(workflow) == "halted", (
        "an unreachable engine left the workflow admitting work")
    assert is_free(agent)


def test_halting_through_the_facade_is_visible_to_describe(env):
    """The platform-level property the conformance suite deliberately does not
    assert: once Andyur has halted a workflow, asking the provider about it
    reports halted, because the provider reads the record Andyur wrote."""
    f = orchestration.facade()
    agent = env.agent("alice")
    run_id, _ = f.request_agent_run(agent, "work")
    workflow = _workflow_of_run(run_id)

    f.halt_workflow(workflow)

    assert f.describe(workflow).state is orchestration.WorkflowState.HALTED


def test_describe_names_the_workflows_live_runs_to_the_provider(env, monkeypatch):
    """A provider that runs one execution per run has no execution named after
    the workflow. `describe` passed the workflow id alone, so under Temporal it
    could only ever answer "not found"; it now passes Andyur's live runs, as a
    halt does."""
    f = orchestration.facade()
    agent = env.agent("alice")
    run_id, _ = f.request_agent_run(agent, "work")
    workflow = _workflow_of_run(run_id)
    seen = {}
    real = f._provider.describe

    def recording(workflow_id, run_ids=()):
        seen["run_ids"] = run_ids
        return real(workflow_id, run_ids=run_ids)

    monkeypatch.setattr(f._provider, "describe", recording)
    f.describe(workflow)

    assert seen.get("run_ids") == (run_id,), (
        f"describe told the provider {seen.get('run_ids')!r}; the workflow's live "
        f"run is {run_id}")


# --- D9: what the engine's schedule API is, and is not, wired to -------------

SCHEDULE_OPS = {"create_schedule", "update_schedule", "delete_schedule"}


def test_only_the_schedule_service_reaches_the_engines_schedule_api():
    """ADR-014 D9 as amended by D11, pinned as a fact rather than prose.

    Under Architecture A nothing called the engine's schedule API: every
    schedule was a row the native poller fired. Under B+ a provider that
    dispatches runs also FIRES schedules, so `server/schedules.py` creates and
    deletes the engine's Schedule for exactly those rows -- and nothing else in
    the platform may, or a schedule could exist in the engine that Andyur's own
    table does not show.

    Matched on the METHOD NAME, whatever the receiver: the first version only
    matched `orchestration.facade().create_schedule(...)`, so binding the
    facade to a name first walked straight past it.
    """
    offenders = []
    for path in SOURCE.rglob("*.py"):
        rel = str(path.relative_to(ROOT))
        if rel.startswith("andyur/orchestration/") or rel == "andyur/server/schedules.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in SCHEDULE_OPS
                    # the schedule SERVICE's own functions share the names;
                    # calling the service is how everything else should do it
                    and getattr(node.func.value, "id", None) != "schedules"):
                offenders.append(f"{rel}:{node.lineno} -> {node.func.attr}")

    assert offenders == [], (
        f"{offenders} -- something other than the schedule service reaches the "
        "engine's schedule API; ADR-014 D9/D11 say only it does")


def test_positive_control_the_schedule_service_does_reach_it():
    """The scan above must be able to see a call, or it proves nothing."""
    tree = ast.parse((SOURCE / "server" / "schedules.py").read_text())
    ops = {node.func.attr for node in ast.walk(tree)
           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
           and node.func.attr in SCHEDULE_OPS}
    assert {"create_schedule", "delete_schedule"} <= ops


def test_the_engine_workflows_nothing_reaches_are_still_registered():
    """The other half of D9: `ScheduledAgentRun` and `DurableApproval` are
    registered with the worker and exercised by the provider's own tests.

    Asserted so that removing them is a decision someone makes rather than a
    tidy-up nobody notices.
    """
    temporalio = pytest.importorskip(
        "temporalio", reason="the Temporal SDK is an extra")
    from andyur.orchestration.temporal.workflows import ALL_WORKFLOWS

    names = {w.__name__ for w in ALL_WORKFLOWS}
    assert {"ScheduledAgentRun", "DurableApproval"} <= names, (
        "an unreachable-but-working workflow was removed; D9 says that is a "
        "decision, not a cleanup")
