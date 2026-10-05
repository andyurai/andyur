"""The workflow record: what Andyur knows about a workflow, independent of any
engine.

The split this file exists to make is easy to state and easy to lose:

    governance   what the platform DECIDED        authoritative, durable, audited
    mechanics    what an engine is DOING          a belief, and it can be wrong

Halt state, workflow identity, the run-to-workflow binding, delegation limits
and work caps are governance. They are Andyur's, they are what an audit reads,
and no engine may be the source of truth for them. **Provider execution history
is not the Andyur governance database**, and the day it becomes one, revoking
something means asking an engine's retention policy for permission.

What this module adds is the other half of the record: which engine is running a
workflow, and what that engine calls it. That binding is governance too -- it is
a decision about where work runs, not an observation of it -- which is why it
lives here rather than being inferred from configuration at read time.

## A workflow does not move between providers

`bind_provider` refuses to rebind a workflow to a different engine. Providers do
not offer the same guarantees, so continuing work under a different one silently
changes what was promised when that work was admitted: a durable approval
admitted under an engine that can wait for days, resumed on one that cannot, is
an approval that will quietly never arrive.

Configuration is the thing that changes. An operator switching
`ANDYUR_WORKFLOW_PROVIDER` is choosing where NEW work runs, and must not thereby
re-home work that is already running -- so the binding is read from the row, not
recomputed from the environment.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import db
from .errors import OrchestrationError

SCHEMA_VERSION = 1


class ProviderMismatch(OrchestrationError):
    """This workflow is already running on a different engine.

    Its own error rather than a generic refusal, because the operator response
    is specific and nothing else produces it: either the configured provider is
    wrong for this deployment, or work outlived a provider change. Retrying
    will not help, and neither will restarting.
    """


@dataclass(frozen=True)
class WorkflowGovernance:
    """Andyur's record of one workflow.

    `state` is the platform's and is authoritative -- 'active' or 'halted'.
    `provider_state` is the engine's last known opinion and is a CACHE: stale
    the moment it is written, never a basis for a decision. The two are kept in
    separate fields precisely so that no reader can confuse them.
    """

    workflow_id: str
    state: str
    provider: str | None
    provider_workflow_id: str | None
    provider_ref: str | None
    provider_state: str | None
    schema_version: int
    created_at: str | None
    updated_at: str | None

    @property
    def is_halted(self) -> bool:
        return self.state == "halted"

    @property
    def is_bound(self) -> bool:
        return self.provider is not None


def governance_of(workflow_id: str) -> WorkflowGovernance | None:
    """The whole record, or None when there is no such workflow.

    None is a real answer here, not an error: a run may belong to no workflow
    at all (`resolve_workflow` inherits the parent's, so a run parented to one
    without a workflow has none either), and the platform tolerates that
    deliberately.
    """
    with db.connect() as conn:
        row = conn.execute(
            "SELECT id, state, provider, provider_workflow_id, provider_ref, "
            "provider_state, schema_version, created_at, updated_at "
            "FROM workflows WHERE id = ?", (workflow_id,)).fetchone()
    if row is None:
        return None
    return WorkflowGovernance(
        workflow_id=row["id"], state=row["state"], provider=row["provider"],
        provider_workflow_id=row["provider_workflow_id"],
        provider_ref=row["provider_ref"], provider_state=row["provider_state"],
        schema_version=row["schema_version"] or SCHEMA_VERSION,
        created_at=row["created_at"], updated_at=row["updated_at"])


def provider_of(workflow_id: str) -> str | None:
    """Which engine owns this workflow, or None if it is unbound or unknown."""
    record = governance_of(workflow_id)
    return record.provider if record else None


def bind_provider(workflow_id: str, provider: str,
                  provider_workflow_id: str | None = None,
                  provider_ref: str | None = None) -> None:
    """Record which engine is running this workflow.

    Idempotent for the SAME provider, so a workflow gaining a second, third and
    hundredth run does not fight over its own binding -- the first run binds it
    and the rest agree. Re-binding to a DIFFERENT provider raises
    `ProviderMismatch`; see the module docstring for why that is refused rather
    than migrated.

    Binds nothing when there is no such workflow. A workflow-less run has no
    row to bind, and creating one here would invent a workflow the platform
    deliberately did not create.
    """
    existing = governance_of(workflow_id)
    if existing is None:
        return
    if existing.provider is not None and existing.provider != provider:
        raise ProviderMismatch(
            f"workflow '{workflow_id}' is running on '{existing.provider}' and "
            f"cannot be moved to '{provider}': the two do not offer the same "
            "guarantees, so work admitted under one must not be continued by "
            "the other")
    if existing.provider == provider:
        # THE FIRST RUN BINDS IT AND THE REST AGREE. This also compared
        # `provider_ref`, which differs per run on the native provider (it is
        # the root run id), so every run joining a workflow rewrote the binding
        # and `provider_ref` ended up naming whichever run joined last --
        # contradicting the sentence above it.
        return

    # A COMPARE-AND-SET, and it was a plain write. The read above and this
    # UPDATE were separate statements on separate connections, and the UPDATE
    # had no condition -- so two control planes configured for different
    # providers could each read "unbound", each start an execution, and each
    # write, with the binding ending up as whichever wrote LAST. The facade
    # comment claimed this function "checks again under the write"; it did not.
    #
    # Now the write only succeeds if the row is still unbound or already bound
    # to THIS provider, and zero rows means someone else won the race to bind
    # it elsewhere. That is the same guarded-UPDATE idea every other claim in
    # the platform uses, and it needs no lock.
    with db.connect() as conn:
        cur = conn.execute(
            "UPDATE workflows SET provider = ?, provider_workflow_id = ?, "
            "provider_ref = ?, schema_version = ?, updated_at = ? "
            "WHERE id = ? AND (provider IS NULL OR provider = ?)",
            (provider, provider_workflow_id or workflow_id, provider_ref,
             SCHEMA_VERSION, db.utcnow(), workflow_id, provider))
        won = cur.rowcount == 1
    if not won:
        now = governance_of(workflow_id)
        if now is not None and now.provider not in (None, provider):
            raise ProviderMismatch(
                f"workflow '{workflow_id}' was bound to '{now.provider}' while "
                f"this was binding it to '{provider}': the two do not offer the "
                "same guarantees, so work admitted under one must not be "
                "continued by the other")


def record_provider_state(workflow_id: str, state: str) -> None:
    """Cache the engine's last known opinion of this workflow.

    A CONVENIENCE FOR READS, never an input to a decision. Governance reads
    `state`; this is for a console that wants to show progress without a call
    per row. It is stale immediately and `describe()` is the live answer.
    """
    with db.connect() as conn:
        conn.execute(
            "UPDATE workflows SET provider_state = ?, updated_at = ? WHERE id = ?",
            (state, db.utcnow(), workflow_id))
