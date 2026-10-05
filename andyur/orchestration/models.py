"""Provider-neutral orchestration types.

Everything crossing the provider boundary is defined here, and the rule is the
same in both directions: **identifiers travel, authority does not.**

A provider is durable storage that Andyur does not control the retention of. On
a durable-execution engine, anything handed to a workflow is written into an
event history that may outlive the run, the deployment, and the credential
itself. So a payload carries `run_id` and the provider's activities fetch what
they need through Andyur's own trusted paths, where the answer is CURRENT. That
is not only a secrets-at-rest argument: authority that was frozen into a payload
is authority as it stood when the work was created, and the entire point of
revocation is that the answer changes. See `AUTHORITY_BEARING_FIELDS` below,
which turns the rule into something that fails at construction rather than in
review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


# --- the credential guard ---------------------------------------------------

# Field names that must never appear on a type crossing the provider boundary.
# Checked by name because that is what a future edit will actually do: someone
# adds `scope` to a payload because it was convenient, and no review catches it.
# A name-based guard is imperfect -- `detail` could hold a token -- so it is a
# floor, not a ceiling; tests/test_orchestration_spi.py backs it with an
# architecture test over the module, and the real defence is that activities
# fetch rather than receive.
AUTHORITY_BEARING_FIELDS = frozenset({
    "token", "subject_token", "run_token", "bearer", "credential", "secret",
    "password", "api_key", "private_key", "key", "scope", "scopes",
    "acting_user", "user", "subject", "subject_context", "pin",
    "user_asserted_by", "asserted_by", "authorization", "auth",
})

_WORD = re.compile(r"[a-z0-9]+")


def assert_carries_no_authority(cls_name: str, field_names) -> None:
    """Refuse a boundary type that names an authority-bearing field.

    Raises at import time, which is the point: a payload that would have put a
    scope into an event history fails the build rather than the audit.
    """
    for name in field_names:
        parts = set(_WORD.findall(name.lower()))
        hit = parts & AUTHORITY_BEARING_FIELDS
        if hit or name.lower() in AUTHORITY_BEARING_FIELDS:
            raise TypeError(
                f"{cls_name}.{name} names authority ({', '.join(sorted(hit)) or name}). "
                "Payloads crossing the provider boundary carry identifiers only; "
                "the provider's activities fetch authority from Andyur at the "
                "effect boundary, where it is current and revocation still works.")


def _guard(cls):
    """Class decorator: apply the credential guard to a dataclass."""
    assert_carries_no_authority(cls.__name__, [f.name for f in cls.__dataclass_fields__.values()])
    return cls


# --- what a run looks like from outside -------------------------------------

class WorkflowState(str, Enum):
    """The projected state of a workflow, normalized across providers.

    Deliberately NOT Andyur's run states. A run's state is governance -- it is
    what the platform recorded and what an audit reads. This is only what the
    engine believes about execution progress, and the two can legitimately
    disagree: a halted run whose pod has been destroyed is terminal to Andyur
    while the provider may still be winding down.

    When they disagree, ANDYUR'S RECORD WINS. The provider is authoritative for
    what is still executing, never for what happened.
    """

    REQUESTED = "requested"      # accepted by the provider, not yet dispatched
    QUEUED = "queued"            # waiting for capacity
    RUNNING = "running"          # an executor is working on it
    WAITING = "waiting"          # blocked on a timer, a signal or an approval
    HALTING = "halting"          # a halt was accepted, progress is stopping
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    HALTED = "halted"

    def is_terminal(self) -> bool:
        return self in _TERMINAL


_TERMINAL = frozenset({
    WorkflowState.SUCCEEDED, WorkflowState.FAILED,
    WorkflowState.CANCELLED, WorkflowState.HALTED,
})


# --- starting work ----------------------------------------------------------

@_guard
@dataclass(frozen=True)
class WorkflowStart:
    """The request to begin one workflow.

    `workflow_id` is ANDYUR'S workflow, and `root_run_id` the run being started
    in it. Starting the same RUN twice yields the same logical execution, which
    is what makes an at-least-once caller safe.

    HOW A PROVIDER MAPS THESE TO EXECUTIONS IS ITS BUSINESS, and the id it
    returns on the handle is the one that addresses what it started -- pass
    THAT to `describe` and `signal`, not this `workflow_id`. They coincide for
    a provider with one execution per workflow. The durable provider runs one
    per RUN, because a workflow holds many runs and keying by the workflow left
    every run after the first unobserved; for it they differ, and a caller that
    assumed otherwise described an execution that does not exist.

    `required_capabilities` is carried on the request rather than looked up from
    `workflow_kind` at the provider, so that the check happens once, in the
    facade, against a provider that has already been chosen -- and so that a new
    workflow kind cannot reach a provider that has never heard of it and be
    silently accepted.
    """

    workflow_id: str
    root_run_id: str
    workflow_kind: str
    required_capabilities: frozenset[str] = frozenset()
    schema_version: int = 1

    def __post_init__(self):
        if not self.workflow_id:
            raise ValueError("workflow_id is the idempotency key and cannot be empty")
        if not self.root_run_id:
            raise ValueError("root_run_id is required: a workflow orchestrates a run")


@_guard
@dataclass(frozen=True)
class WorkflowHandle:
    """A reference to a started workflow.

    Two ids, never conflated. `workflow_id` is Andyur's and is stable across
    providers and across a migration. `provider_ref` is whatever the engine
    calls this execution -- a Temporal run id, a row id, nothing at all -- and
    is opaque: it is stored for diagnostics and correlation and is never parsed,
    compared for meaning, or used to address anything.
    """

    workflow_id: str
    provider: str
    provider_ref: str | None = None


@_guard
@dataclass(frozen=True)
class WorkflowSignal:
    """A named message delivered to a running workflow.

    `payload` is a small JSON-able dict and is subject to the same rule as
    everything else here: identifiers, never authority. An approval signal
    carries the action_request_id; the provider's activity then asks Andyur
    whether that action is still permitted, because between the request and the
    approval the answer may have changed.
    """

    name: str
    payload: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            raise ValueError("a signal needs a name")
        assert_carries_no_authority(f"{type(self).__name__}(payload)", self.payload.keys())


@_guard
@dataclass(frozen=True)
class ProviderWorkflowState:
    """What the provider believes about one workflow.

    `detail` is BOUNDED diagnostics -- the provider's own state name, an error
    summary -- and is for humans reading a console. Nothing may branch on it:
    branching on a provider's raw state is how provider vocabulary leaks into
    Andyur's logic one `if` at a time.
    """

    workflow_id: str
    state: WorkflowState
    provider: str
    provider_ref: str | None = None
    detail: str | None = None


# --- halting ----------------------------------------------------------------

@_guard
@dataclass(frozen=True)
class HaltRequest:
    """Ask a provider to stop making durable progress on a workflow.

    READ provider.py's `halt` before assuming this destroys anything. It does
    not. Containment is Andyur's own path and does not run through the provider.
    """

    workflow_id: str
    reason: str
    # THE LIVE RUNS, AS ANDYUR'S RECORD NAMES THEM. A provider that runs one
    # execution per run signals each; one that does not ignores this. Supplied
    # by the facade rather than discovered by the provider, because discovery
    # would read the engine's visibility store, which is eventually consistent,
    # and a kill switch must not miss the run that started a moment ago.
    run_ids: tuple[str, ...] = ()


@_guard
@dataclass(frozen=True)
class HaltOutcome:
    """Whether the provider has accepted that it must stop.

    `accepted` means the provider has the request durably and will make no
    further progress. It does NOT mean the execution is gone, and no caller may
    read it that way.
    """

    workflow_id: str
    accepted: bool
    state: WorkflowState
    detail: str | None = None


# --- schedules --------------------------------------------------------------

@_guard
@dataclass(frozen=True)
class ScheduleSpec:
    """A recurring trigger.

    `on_overlap` is the whole reason this type exists rather than a cron string.
    Andyur's answer is SKIP_AND_RETRY_SOON: an agent that is busy when its
    schedule fires must not queue a backlog, and must not lose the tick either.
    An engine whose native scheduler only offers buffer-or-skip cannot express
    that, and must say so through `schedules` rather than pick the nearest one.
    """

    schedule_id: str
    agent: str
    cron: str
    reason: str
    on_overlap: str = "skip_and_retry_soon"
    paused: bool = False


@_guard
@dataclass(frozen=True)
class ScheduleHandle:
    schedule_id: str
    provider: str
    provider_ref: str | None = None


# --- health -----------------------------------------------------------------

@_guard
@dataclass(frozen=True)
class ProviderHealth:
    """Whether the provider can currently accept work.

    `reachable` is about the engine, not about Andyur. A provider that is down
    must report it rather than raising on the next start, so the control plane
    can refuse new durable work while continuing to serve reads -- Andyur's own
    record of existing runs stays readable regardless of the engine's health.
    """

    provider: str
    reachable: bool
    detail: str | None = None
