"""The workflow record: what Andyur decided, kept apart from what an engine is doing.

The split these tests defend:

    governance   what the platform DECIDED     authoritative, audited
    mechanics    what an engine is DOING       a belief, and it can be wrong

It is easy to lose by accident. The moment a governance decision reads a cached
provider state, revoking something depends on an engine's retention policy, and
an audit answers a different question than the one it was asked.
"""

import ast
import pathlib

import pytest

from andyur import db, orchestration
from andyur.orchestration import governance
from andyur.orchestration.local import LocalWorkflowProvider
from andyur.server import coordinator

from orchestration_contract.conftest import is_free

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _workflow_of(run_id):
    with db.connect() as c:
        return c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()["workflow_id"]


# --- the binding -------------------------------------------------------------

def test_a_workflow_records_which_engine_is_running_it(env):
    agent = env.agent("alice")

    run_id, _ = orchestration.facade().request_agent_run(agent, "work")

    record = governance.governance_of(_workflow_of(run_id))
    assert record.provider == "local"
    assert record.is_bound
    assert record.updated_at is not None


def test_the_binding_is_idempotent_across_a_workflows_many_runs(env):
    """A workflow gains runs as it delegates. The first binds it and the rest
    agree -- they do not fight over it, and they do not rewrite it."""
    alice, bob = env.agent("alice"), env.agent("bob")
    root, _ = orchestration.facade().request_agent_run(alice, "root")
    workflow = _workflow_of(root)
    first = governance.governance_of(workflow)

    orchestration.facade().request_agent_run(bob, "child", parent_run_id=root)

    after = governance.governance_of(workflow)
    assert after.provider == first.provider
    # AND THE BINDING ITSELF IS UNCHANGED. The shortcut also compared
    # `provider_ref`, which on the native provider is the root run id and so
    # differs per run -- every joining run fell through and rewrote the
    # binding, leaving it naming whichever run joined last. "The first run
    # binds it and the rest agree" was not what the code did.
    assert after.provider_ref == first.provider_ref, (
        "a joining run rewrote the workflow's binding")
    assert after.provider_workflow_id == first.provider_workflow_id


def test_a_workflow_cannot_be_moved_to_another_engine(env):
    """THE PROPERTY THAT MAKES THE BINDING WORTH STORING. Providers do not offer
    the same guarantees, so continuing work under a different one silently
    changes what was promised when it was admitted -- a durable approval
    admitted on an engine that can wait for days, resumed on one that cannot,
    is an approval that will quietly never arrive."""
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    workflow = _workflow_of(run_id)

    with pytest.raises(governance.ProviderMismatch, match="do not offer the same"):
        governance.bind_provider(workflow, "some-other-engine")

    assert governance.provider_of(workflow) == "local"


def test_a_run_for_a_workflow_on_another_engine_is_refused_and_frees_its_agent(env):
    """Refused BEFORE the provider is told, so a durable engine never creates
    an execution on the wrong one -- and the admitted run does not hold its
    agent afterwards."""
    agent = env.agent("alice")
    root, _ = orchestration.facade().request_agent_run(agent, "root")
    workflow = _workflow_of(root)
    coordinator.finish_run(root, "done", None)

    with db.connect() as c:                      # as if it had started elsewhere
        c.execute("UPDATE workflows SET provider = 'elsewhere' WHERE id = ?", (workflow,))

    with pytest.raises(governance.ProviderMismatch):
        orchestration.facade().request_agent_run(
            agent, "more", workflow_id=workflow)

    assert is_free(agent), "a refused workflow still left a run holding the agent"


def test_configuration_does_not_re_home_a_running_workflow(env, monkeypatch):
    """An operator switching providers is choosing where NEW work runs. Reading
    the engine from the environment at read time would silently move work that
    is already running, which is the bug this column exists to prevent.

    THE CONFIGURATION NOW ACTUALLY CHANGES. The comment below said "the
    configured provider changes; the record does not", and nothing changed it:
    the environment was unset, so the configured name was "local" too, and a
    `provider_of` that read the environment instead of the column passed.
    """
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    workflow = _workflow_of(run_id)
    assert governance.provider_of(workflow) == "local"

    # the configured provider changes...
    monkeypatch.setenv("ANDYUR_WORKFLOW_PROVIDER", "temporal")
    orchestration.reset_facade()
    try:
        # ...and the record does not
        assert governance.provider_of(workflow) == "local", (
            "the running workflow's engine followed the configuration -- work "
            "admitted on one engine would be continued by another")
        assert governance.governance_of(workflow).provider_workflow_id == workflow
    finally:
        monkeypatch.delenv("ANDYUR_WORKFLOW_PROVIDER", raising=False)
        orchestration.reset_facade()


def test_a_run_belonging_to_no_workflow_binds_nothing(env):
    """A workflow-less run has no row to bind, and creating one here would
    invent a workflow the platform deliberately did not create."""
    env.agent("boss")
    agent = env.agent("alice")
    with db.connect() as c:
        c.execute("INSERT INTO runs (id, agent, state, created_at) "
                  "VALUES ('run-boss', 'boss', 'running', ?)", (db.utcnow(),))

    run_id, _ = orchestration.facade().request_agent_run(
        agent, "child", parent_run_id="run-boss")

    assert run_id is not None
    assert _workflow_of(run_id) is None
    assert governance.governance_of(run_id) is None, "a workflow was invented"


def test_binding_an_unknown_workflow_does_nothing(env):
    governance.bind_provider("wf-never-existed", "local")

    assert governance.governance_of("wf-never-existed") is None


# --- governance and mechanics stay apart -------------------------------------

def test_halt_state_is_andyurs_and_provider_state_is_a_cache(env):
    """Two fields, on purpose, so no reader can confuse them. `state` is what
    the platform decided; `provider_state` is what an engine last said."""
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    workflow = _workflow_of(run_id)

    orchestration.facade().halt_workflow(workflow)

    record = governance.governance_of(workflow)
    assert record.state == "halted", "Andyur's own state is authoritative"
    assert record.is_halted
    assert record.provider_state == "halted"      # the cache agrees, today


def test_a_stale_cache_does_not_change_what_governance_decides(env):
    """THE POINT OF KEEPING THEM SEPARATE. The cache is stale the moment it is
    written. If anything decided from it, a workflow could be treated as
    running because an engine last said so, while the platform had halted it."""
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    workflow = _workflow_of(run_id)
    orchestration.facade().halt_workflow(workflow)

    governance.record_provider_state(workflow, "running")    # a lying cache

    assert governance.governance_of(workflow).is_halted
    with db.connect() as conn:
        assert coordinator.is_halted(conn, workflow) is True, (
            "the halt stopped holding because a cache said otherwise")
    assert orchestration.facade().request_agent_run(
        env.agent("bob"), "work", workflow_id=workflow)[0] is None


def test_nothing_decides_anything_from_the_cached_provider_state():
    """An architecture test, because the failure is invisible in review: a
    single `if record.provider_state == ...` would make an engine's opinion
    load-bearing, and everything would still pass."""
    offenders = []
    for path in (ROOT / "andyur").rglob("*.py"):
        if path.name == "governance.py":
            continue                     # it owns the column
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "provider_state":
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            if (isinstance(node, ast.Constant) and node.value == "provider_state"
                    and path.name not in ("db.py",)):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} (literal)")

    assert offenders == [], (
        f"{offenders} -- provider_state is a cache for reads; governance reads "
        "workflows.state, which is Andyur's")


def test_the_record_carries_its_schema_version(env):
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")

    assert governance.governance_of(
        _workflow_of(run_id)).schema_version == governance.SCHEMA_VERSION


def test_a_provider_ref_is_stored_but_never_interpreted(env):
    """Opaque by contract: kept so an operator can correlate with an engine's
    own console, never parsed and never compared for meaning."""
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")

    record = governance.governance_of(_workflow_of(run_id))
    assert record.provider_ref == run_id          # what the native provider hands back


def test_a_mismatch_is_refused_before_the_engine_is_told(env):
    """OBSERVABLE, because on the native provider it is not.

    `start` is a no-op locally, so moving the mismatch check after it would
    change nothing here and everything under a durable engine -- which would
    have created an execution on the wrong one before anybody objected. This
    watches whether `start` was called at all.
    """
    started = []

    class Watched(LocalWorkflowProvider):
        def start(self, request):
            started.append(request.workflow_id)
            return super().start(request)

    f = orchestration.OrchestrationFacade(provider=Watched())
    agent = env.agent("alice")
    root, _ = f.request_agent_run(agent, "root")
    workflow = _workflow_of(root)
    coordinator.finish_run(root, "done", None)
    with db.connect() as c:
        c.execute("UPDATE workflows SET provider = 'elsewhere' WHERE id = ?", (workflow,))
    started.clear()

    with pytest.raises(governance.ProviderMismatch):
        f.request_agent_run(agent, "more", workflow_id=workflow)

    assert started == [], "the engine was told to start work it must not run"


def test_a_race_to_bind_one_workflow_to_two_engines_is_refused(env, monkeypatch):
    """THE WRITE WAS UNCONDITIONAL, and the facade said it was checked.

    `bind_provider` read the binding, then wrote it with no condition, on a
    separate connection. Two control planes configured for different providers
    could each read "unbound", each start an execution, and each write -- the
    binding ended as whichever wrote last, and nothing raised.

    Reproduced exactly: another control plane has already bound this workflow to
    `local`, and this call read BEFORE that landed, so it saw it unbound.
    """
    import types

    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    wf = _workflow_of(run_id)

    with db.connect() as c:                      # the other control plane won
        c.execute("UPDATE workflows SET provider = 'local' WHERE id = ?", (wf,))

    real = governance.governance_of
    seen = {"n": 0}

    def stale_first_read(workflow_id):
        seen["n"] += 1
        record = real(workflow_id)
        if seen["n"] == 1:                       # read before the winner landed
            return types.SimpleNamespace(provider=None, is_bound=False,
                                         updated_at=record.updated_at)
        return record

    monkeypatch.setattr(governance, "governance_of", stale_first_read)

    with pytest.raises(governance.ProviderMismatch):
        governance.bind_provider(wf, "temporal")

    monkeypatch.setattr(governance, "governance_of", real)
    assert real(wf).provider == "local", (
        "the loser's write replaced the winner's binding -- the workflow now "
        "claims an engine that is not the one running it")


def test_positive_control_an_uncontested_bind_still_succeeds(env):
    """Without this, a bind that refuses everything passes the race test."""
    agent = env.agent("alice")
    run_id, _ = orchestration.facade().request_agent_run(agent, "work")
    wf = _workflow_of(run_id)
    with db.connect() as c:
        c.execute("UPDATE workflows SET provider = NULL WHERE id = ?", (wf,))

    governance.bind_provider(wf, "temporal")

    assert governance.governance_of(wf).provider == "temporal"
