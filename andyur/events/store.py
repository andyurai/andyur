"""Durable RunEvent storage boundary; stores own identity and ordering fields."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol, runtime_checkable

from .models import RunEvent
from .taxonomy import (
    DataClassification, Durability, EventCategory, EventType, EventVisibility,
    TrustClass,
)


@dataclass(frozen=True)
class _PendingRunEvent:
    """Publisher-derived event awaiting store-owned identity/order fields."""

    tenant_id: str
    workflow_id: str | None
    run_id: str
    agent_id: str
    occurred_at: datetime | None
    category: EventCategory
    type: EventType
    source: str
    trust_class: TrustClass
    durability: Durability
    classification: DataClassification
    visibility: EventVisibility
    summary: str | None
    payload: Mapping[str, Any]
    trace_id: str | None
    span_id: str | None
    parent_event_id: str | None
    registry_digest: str | None
    authority_revision: str | None


class TerminalRunError(RuntimeError):
    """The durable stream already contains a terminal run event."""


@runtime_checkable
class RunEventStore(Protocol):
    def _new_writer(self) -> "_StoreWriter":
        """Internal composition seam; never expose this capability to workloads."""

    def read_after(self, tenant_id: str, run_id: str, sequence: int,
                   limit: int = 200) -> list[RunEvent]:
        """Read an ordered, tenant-scoped replay page after a cursor."""

    def high_watermark(self, tenant_id: str, run_id: str) -> int:
        """Return the last durable sequence, or zero when no events exist."""


class _StoreWriter:
    __slots__ = ("_append",)

    def __init__(self, append):
        self._append = append

    def append(self, pending: _PendingRunEvent) -> RunEvent:
        return self._append(pending)
