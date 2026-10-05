"""Run-bound asserted-workload publication; authoritative producers come later."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from .models import RunEvent
from .store import _PendingRunEvent, _StoreWriter, RunEventStore
from .taxonomy import (
    DataClassification, Durability, EVENT_RULES, EventType, EventVisibility,
    TrustClass, validate_workload_assertion,
)


@dataclass(frozen=True)
class RunContextSnapshot:
    """Previously verified context bound once when the trusted adapter is built."""

    tenant_id: str
    run_id: str
    agent_id: str
    workflow_id: str | None = None
    registry_digest: str | None = None
    authority_revision: str | None = None


@dataclass(frozen=True)
class EventDraft:
    """Workload content only; contains no tenant/source/trust/order authority."""

    type: EventType
    durability: Durability
    classification: DataClassification
    visibility: EventVisibility
    summary: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    occurred_at: datetime | None = None
    trace_id: str | None = None
    span_id: str | None = None
    parent_event_id: str | None = None


class ProducerNotAuthorized(PermissionError):
    pass


class WorkloadRunEventPublisher:
    """Publisher bound to one sealed run and the asserted sidecar trust class."""

    def __init__(self, store: RunEventStore, context: RunContextSnapshot,
                 *, source: str = "runner-sidecar"):
        self._context = context
        self._source = source
        self._append = store._new_writer().append

    def publish(self, draft: EventDraft) -> RunEvent:
        try:
            validate_workload_assertion(draft.type)
        except (KeyError, ValueError) as exc:
            raise ProducerNotAuthorized(
                f"workload cannot emit {getattr(draft.type, 'value', draft.type)}"
            ) from exc
        rule = EVENT_RULES[draft.type]
        pending = _PendingRunEvent(
            tenant_id=self._context.tenant_id,
            workflow_id=self._context.workflow_id,
            run_id=self._context.run_id,
            agent_id=self._context.agent_id,
            occurred_at=draft.occurred_at,
            category=rule.category,
            type=draft.type,
            source=self._source,
            trust_class=TrustClass.ASSERTED,
            durability=draft.durability,
            classification=draft.classification,
            visibility=draft.visibility,
            summary=draft.summary,
            payload=draft.payload,
            trace_id=draft.trace_id,
            span_id=draft.span_id,
            parent_event_id=draft.parent_event_id,
            registry_digest=self._context.registry_digest,
            authority_revision=self._context.authority_revision,
        )
        return self._append(pending)
