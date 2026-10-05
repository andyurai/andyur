"""The orchestration seam: that it is implementable, and that it stays neutral.

Stage 3 adds definitions and nothing else -- no behaviour changes, nothing
imports the package yet. So these tests police the two things that can silently
go wrong with a seam nobody is using: it stops being implementable without the
engine it was designed alongside, and it starts carrying things it must not.

The Stage 2 spike's findings are encoded here too, as assertions rather than
prose. A finding that only lives in a document is a finding that gets undone by
the next person who reaches for the obvious API.
"""

import ast
import inspect
import pathlib
from dataclasses import dataclass, is_dataclass

import pytest

from andyur import orchestration as orch
from andyur.orchestration import capabilities, errors, models, provider

from orchestration_contract.fakes import FakeProvider

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "andyur" / "orchestration"


# --- a second provider must be possible without the first one ---------------

def test_a_provider_with_no_engine_satisfies_the_interface():
    assert isinstance(FakeProvider(), orch.WorkflowProvider)


def test_starting_the_same_workflow_twice_yields_one_execution():
    """The SPI's idempotency contract, exercised rather than asserted in prose.

    The Stage 2 spike measured what its absence costs: a step whose effect
    landed before its acknowledgement was lost ran three times under a
    three-attempt retry, which for a launch is three containers for one run.
    """
    p = FakeProvider()
    req = models.WorkflowStart(
        workflow_id="wf-1", root_run_id="r1", workflow_kind="single_agent")

    first = p.start(req)
    second = p.start(req)

    assert first == second


def test_halting_is_idempotent_and_reports_state():
    p = FakeProvider()
    p.start(models.WorkflowStart(
        workflow_id="wf-1", root_run_id="r1", workflow_kind="single_agent"))
    req = models.HaltRequest(workflow_id="wf-1", reason="operator")

    assert (p.halt(req)).accepted is True
    assert (p.halt(req)).accepted is True
    assert (p.describe("wf-1")).state is models.WorkflowState.HALTED


# --- the Stage 2 findings, encoded ------------------------------------------

def test_the_spi_offers_no_cancel_and_no_terminate():
    """MEASURED, NOT ASSUMED. Plan section 19 specified halt as
    provider.cancel() plus runtime.terminate(). The spike ran that against
    Temporal: cancelling a workflow cancels its own execution, so the
    containment step was never scheduled -- the history went straight from
    ACTIVITY_TASK_CANCEL_REQUESTED to WORKFLOW_EXECUTION_CANCELED.

    If someone adds `cancel` back because it is the obvious verb, this fails
    and points at why.
    """
    surface = {m for m in dir(orch.WorkflowProvider) if not m.startswith("_")}

    assert "cancel" not in surface, (
        "provider cancellation cannot run Andyur's containment step; halt is a "
        "signal-shaped operation and containment does not go through the provider")
    assert "terminate" not in surface
    assert "destroy" not in surface
    assert "halt" in surface


def test_halt_documents_that_it_is_not_containment():
    """The dangerous misreading is that a successful halt means the agent
    stopped. It does not, and the docstring has to keep saying so."""
    doc = inspect.getdoc(provider.WorkflowProvider.halt) or ""

    assert "DOES NOT DESTROY" in doc.upper()
    assert "containment" in doc.lower()


def test_containment_is_not_a_provider_capability():
    """Containment must not become something a provider can decline to offer.
    Modelling it as optional would make a legal configuration in which the kill
    switch is advisory."""
    assert not any("contain" in c or "destroy" in c or "kill" in c
                   for c in capabilities.ALL_CAPABILITIES)


# --- nothing provider-specific may leak -------------------------------------

ENGINE_WORDS = ("temporal", "temporalio", "cadence", "restate", "dbos",
                "taskqueue", "task_queue", "searchattribute", "search_attribute",
                "continueasnew", "continue_as_new", "activity", "workflowexecution")


def _neutral_modules():
    return [p for p in PACKAGE.rglob("*.py")
            if not p.is_relative_to(PACKAGE / "local")
            and not p.is_relative_to(PACKAGE / "temporal")]


def test_the_neutral_package_imports_no_engine_sdk():
    """A provider's SDK may only be imported inside that provider's directory."""
    offenders = []
    for path in _neutral_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                if n.split(".")[0] in {"temporalio", "cadence", "restate", "dbos"}:
                    offenders.append(f"{path.name}:{node.lineno} imports {n}")
    assert offenders == [], offenders


def test_public_type_names_carry_no_engine_vocabulary():
    """`TaskQueue` or `ActivityOptions` on a public type means the SPI has
    started describing one engine rather than the semantics."""
    offenders = []
    for name in orch.__all__:
        obj = getattr(orch, name)
        if any(w in name.lower() for w in ("temporal", "taskqueue", "activity")):
            offenders.append(f"exported name {name}")
        if is_dataclass(obj):
            for f in obj.__dataclass_fields__.values():
                if any(w in f.name.lower() for w in ENGINE_WORDS):
                    offenders.append(f"{name}.{f.name}")
    assert offenders == [], offenders


def test_no_code_in_the_neutral_package_branches_on_a_provider_identity():
    """Temporal may be NAMED in prose -- the spike's findings are why several
    decisions here are what they are, and a reader needs that. What must not
    exist is code that ASKS which provider it has.

    Expressed against the syntax tree rather than by reading lines, because the
    line-based version of this test flagged its own explanatory docstring: the
    sentence warning against `if provider == "temporal"` contains the very thing
    it warns about. A heuristic that cannot tell prose from code will either
    miss the real case or cry wolf on the documentation, and crying wolf is how
    a test gets deleted.
    """
    engine_names = {"temporal", "temporalio", "cadence", "restate", "dbos"}
    offenders = []

    for path in _neutral_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            for side in [node.left, *node.comparators]:
                if (isinstance(side, ast.Constant) and isinstance(side.value, str)
                        and side.value.strip().lower() in engine_names):
                    offenders.append(
                        f"{path.name}:{node.lineno} compares against '{side.value}'")

    assert offenders == [], (
        f"{offenders} -- the seam exists so callers do not know which provider "
        "they have; a comparison against one has reintroduced the coupling")


def test_an_unknown_provider_name_is_refused_rather_than_defaulted():
    """NO SILENT FALLBACK. Found by mutation: making the registry fall back to
    the default on an unknown name broke nothing, because nothing asserted the
    refusal.

    It matters because providers do not offer the same guarantees. Work admitted
    under a durable provider and silently continued by a single-node one has
    lost the durability it was accepted on the strength of, and the first
    anyone learns of it is an approval that never returns after a restart.
    """
    from andyur.orchestration import registry

    with pytest.raises(registry.UnknownProvider, match="not a known workflow provider"):
        registry.build_workflow_provider("temporel")

    with pytest.raises(registry.UnknownProvider, match="not a known"):
        registry.build_workflow_provider("cadence")    # a real engine, not built here


def test_the_configured_provider_is_what_gets_built(monkeypatch):
    from andyur.orchestration import registry

    monkeypatch.setenv(registry.ENV_VAR, "local")
    assert registry.build_workflow_provider().name == "local"

    monkeypatch.setenv(registry.ENV_VAR, "  LOCAL  ")
    assert registry.build_workflow_provider().name == "local"

    monkeypatch.delenv(registry.ENV_VAR, raising=False)
    assert registry.build_workflow_provider().name == registry.DEFAULT


def test_the_registry_is_the_only_place_that_names_a_provider():
    """Provider names are data in one dict, not literals scattered through the
    package. Adding a provider should be one edit in one place, and knowing the
    complete set should be one file to read."""
    from andyur.orchestration import registry

    assert set(registry.BUILDERS) == {"local", "temporal"}
    assert registry.DEFAULT in registry.BUILDERS


# --- payloads carry identifiers, never authority ----------------------------

@pytest.mark.parametrize("planted", [
    "subject_token", "run_token", "acting_user", "scope", "scopes",
    "user_asserted_by", "api_key", "private_key", "bearer", "credential",
    "subject_context", "password",
])
def test_a_boundary_type_naming_authority_is_refused(planted):
    """THE POSITIVE CONTROL for the guard in models.py. After narrowing any
    refusal pattern, plant a matching value and confirm it still refuses."""
    with pytest.raises(TypeError, match="names authority"):
        models._guard(dataclass(frozen=True)(type(
            "Planted", (), {"__annotations__": {"workflow_id": str, planted: str}})))


def test_an_innocent_boundary_type_is_not_refused():
    """The negative control: a guard that refuses everything is not a guard."""
    models._guard(dataclass(frozen=True)(type(
        "Fine", (), {"__annotations__": {"workflow_id": str, "attempt": int}})))


def test_a_signal_payload_carrying_authority_is_refused():
    """Fields are checked at import; payload KEYS have to be checked at
    construction, because that is where they are chosen."""
    with pytest.raises(TypeError, match="names authority"):
        models.WorkflowSignal(name="approve", payload={"subject_token": "eyJ"})


def test_a_signal_payload_of_identifiers_is_accepted():
    sig = models.WorkflowSignal(
        name="approve", payload={"action_request_id": "ar-1", "run_id": "r1"})
    assert sig.payload["action_request_id"] == "ar-1"


def test_every_exported_dataclass_is_guarded():
    """A new boundary type added without the guard is the failure this
    catches -- the guard only works on types that carry it."""
    unguarded = []
    for name in orch.__all__:
        obj = getattr(orch, name)
        if is_dataclass(obj) and obj.__module__.endswith("models"):
            try:
                models.assert_carries_no_authority(
                    name, [f.name for f in obj.__dataclass_fields__.values()])
            except TypeError:
                unguarded.append(name)
    assert unguarded == [], unguarded


# --- capabilities fail closed -----------------------------------------------

def test_a_workflow_needing_more_than_the_provider_offers_is_refused():
    local = capabilities.ProviderCapabilities(
        provider="local", schedules=True, durable_timers=True)

    with pytest.raises(errors.ProviderCapabilityMissing) as caught:
        capabilities.check("durable_approval", local)

    assert "durable_signals" in caught.value.missing
    assert caught.value.provider == "local"


def test_the_quickstart_path_runs_on_a_provider_with_no_durability():
    """The 10-minute path must never require durable execution, or the local
    provider stops being a real option and becomes a demo."""
    local = capabilities.ProviderCapabilities(provider="local", schedules=True)

    for kind in ("single_agent", "scheduled_agent", "deferred_work"):
        capabilities.check(kind, local)


def test_an_unknown_workflow_kind_is_refused_rather_than_defaulted():
    """A kind with no declared requirements would be admitted by every
    provider, which is the permissive failure."""
    with pytest.raises(ValueError, match="unknown workflow kind"):
        capabilities.requirements_for("something_new")


def test_mandatory_capabilities_cannot_be_declined():
    """Every provider offers them regardless of what it passes to the
    constructor: they are a precondition of being a provider, and are proven by
    the contract suite rather than by advertising them."""
    bare = capabilities.ProviderCapabilities(provider="bare")

    assert capabilities.MANDATORY <= bare.offered()
    assert "halt" in bare.offered()


def test_no_capability_describes_andyurs_own_semantics():
    """Approval, scope and authority are Andyur's decisions. A capability
    covering one of them would let provider choice change what the platform
    permits."""
    forbidden = ("approval", "authoriz", "scope", "identity", "credential",
                 "policy", "admission")
    leaked = [c for c in capabilities.ALL_CAPABILITIES
              if any(f in c for f in forbidden)]
    assert leaked == [], leaked


# --- errors -----------------------------------------------------------------

def test_a_refusal_is_not_an_availability_problem():
    """Collapsing the two is how a refusal becomes a retry loop."""
    assert not issubclass(errors.WorkflowRejected, errors.ProviderUnavailable)
    assert not issubclass(errors.ProviderCapabilityMissing, errors.ProviderUnavailable)


def test_an_unacknowledged_halt_is_its_own_error():
    """The operator needs to distinguish 'the kill switch was not accepted'
    from 'the engine is unreachable'."""
    assert not issubclass(errors.HaltNotAcknowledged, errors.ProviderUnavailable)
    assert issubclass(errors.HaltNotAcknowledged, errors.OrchestrationError)


def test_every_orchestration_error_shares_one_base():
    for name in dir(errors):
        obj = getattr(errors, name)
        if isinstance(obj, type) and issubclass(obj, Exception) and obj is not Exception:
            assert issubclass(obj, errors.OrchestrationError), name


# --- state normalization ----------------------------------------------------

def test_provider_state_is_not_andyurs_run_state():
    """They may legitimately disagree, and Andyur's record wins. Reusing one
    enum for both would make the disagreement unrepresentable and invite code
    that treats a provider's belief as the truth."""
    from andyur.server import coordinator

    provider_states = {s.value for s in models.WorkflowState}
    assert set(coordinator.TERMINAL_RUN_STATES) != provider_states


def test_terminal_states_are_exactly_the_ones_that_stop():
    terminal = {s for s in models.WorkflowState if s.is_terminal()}
    assert terminal == {
        models.WorkflowState.SUCCEEDED, models.WorkflowState.FAILED,
        models.WorkflowState.CANCELLED, models.WorkflowState.HALTED}
    assert not models.WorkflowState.HALTING.is_terminal(), (
        "HALTING means a halt was accepted and progress is stopping -- the "
        "workflow has not stopped yet, and treating it as terminal would free "
        "the agent while something may still be running")
