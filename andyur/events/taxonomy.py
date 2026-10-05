"""Closed semantic taxonomy for the canonical Andyur run event contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EventCategory(StrEnum):
    RUN = "run"
    AGENT = "agent"
    MODEL = "model"
    OPERATION = "operation"
    POLICY = "policy"
    AUTHORITY = "authority"
    CREDENTIAL = "credential"
    DELEGATION = "delegation"
    RUNTIME = "runtime"
    AUDIT = "audit"


class TrustClass(StrEnum):
    ASSERTED = "asserted"
    OBSERVED = "observed"
    AUTHORITATIVE = "authoritative"


class Durability(StrEnum):
    EPHEMERAL = "ephemeral"
    DURABLE = "durable"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class EventVisibility(StrEnum):
    USER = "user"
    DEVELOPER = "developer"
    OPERATOR = "operator"
    SECURITY = "security"


class EventType(StrEnum):
    RUN_CREATED = "run.created"
    RUN_STARTING = "run.starting"
    RUN_STARTED = "run.started"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    RUN_CANCELLED = "run.cancelled"
    RUN_TIMEOUT = "run.timeout"
    AGENT_STARTED = "agent.started"
    AGENT_OUTPUT = "agent.output"
    AGENT_PROGRESS = "agent.progress"
    AGENT_WARNING = "agent.warning"
    AGENT_ERROR = "agent.error"
    MODEL_REQUESTED = "model.requested"
    MODEL_STARTED = "model.started"
    MODEL_DELTA = "model.delta"
    MODEL_COMPLETED = "model.completed"
    MODEL_FAILED = "model.failed"
    OPERATION_REQUESTED = "operation.requested"
    OPERATION_STARTED = "operation.started"
    OPERATION_COMPLETED = "operation.completed"
    OPERATION_FAILED = "operation.failed"
    POLICY_ALLOWED = "policy.allowed"
    POLICY_DENIED = "policy.denied"
    AUTHORITY_RESOLVED = "authority.resolved"
    AUTHORITY_NARROWED = "authority.narrowed"
    AUTHORITY_DENIED = "authority.denied"
    CREDENTIAL_REQUESTED = "credential.requested"
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_REVOKED = "credential.revoked"
    DELEGATION_REQUESTED = "delegation.requested"
    DELEGATION_GRANTED = "delegation.granted"
    DELEGATION_DENIED = "delegation.denied"
    RUNTIME_SCHEDULED = "runtime.scheduled"
    RUNTIME_LAUNCHED = "runtime.launched"
    RUNTIME_DEGRADED = "runtime.degraded"
    RUNTIME_TERMINATED = "runtime.terminated"
    AUDIT_CHECKPOINT = "audit.checkpoint"
    AUDIT_EVIDENCE_PERSISTED = "audit.evidence.persisted"


@dataclass(frozen=True)
class EventRule:
    category: EventCategory
    trust_classes: frozenset[TrustClass]
    durability: frozenset[Durability]


def _rule(category: EventCategory, trust: TrustClass | tuple[TrustClass, ...],
          *durability: Durability) -> EventRule:
    trusts = trust if isinstance(trust, tuple) else (trust,)
    return EventRule(category, frozenset(trusts), frozenset(durability))


_DURABLE = (Durability.DURABLE,)
_MIXED = (Durability.EPHEMERAL, Durability.DURABLE)

EVENT_RULES: dict[EventType, EventRule] = {
    **{event: _rule(EventCategory.RUN, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.RUN_CREATED, EventType.RUN_STARTING, EventType.RUN_STARTED,
        EventType.RUN_COMPLETED, EventType.RUN_FAILED, EventType.RUN_CANCELLED,
        EventType.RUN_TIMEOUT,
    )},
    **{event: _rule(EventCategory.AGENT,
                    (TrustClass.ASSERTED, TrustClass.OBSERVED), *_MIXED) for event in (
        EventType.AGENT_STARTED, EventType.AGENT_OUTPUT, EventType.AGENT_PROGRESS,
        EventType.AGENT_WARNING, EventType.AGENT_ERROR,
    )},
    **{event: _rule(EventCategory.MODEL, TrustClass.OBSERVED, *_DURABLE) for event in (
        EventType.MODEL_REQUESTED, EventType.MODEL_STARTED,
        EventType.MODEL_COMPLETED, EventType.MODEL_FAILED,
    )},
    EventType.MODEL_DELTA: _rule(EventCategory.MODEL, TrustClass.OBSERVED, Durability.EPHEMERAL),
    **{event: _rule(EventCategory.OPERATION,
                    (TrustClass.OBSERVED, TrustClass.AUTHORITATIVE), *_DURABLE) for event in (
        EventType.OPERATION_REQUESTED, EventType.OPERATION_STARTED,
        EventType.OPERATION_COMPLETED, EventType.OPERATION_FAILED,
    )},
    **{event: _rule(EventCategory.POLICY, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.POLICY_ALLOWED, EventType.POLICY_DENIED,
    )},
    **{event: _rule(EventCategory.AUTHORITY, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.AUTHORITY_RESOLVED, EventType.AUTHORITY_NARROWED, EventType.AUTHORITY_DENIED,
    )},
    **{event: _rule(EventCategory.CREDENTIAL, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.CREDENTIAL_REQUESTED, EventType.CREDENTIAL_ISSUED, EventType.CREDENTIAL_REVOKED,
    )},
    **{event: _rule(EventCategory.DELEGATION, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.DELEGATION_REQUESTED, EventType.DELEGATION_GRANTED, EventType.DELEGATION_DENIED,
    )},
    **{event: _rule(EventCategory.RUNTIME, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.RUNTIME_SCHEDULED, EventType.RUNTIME_LAUNCHED,
        EventType.RUNTIME_DEGRADED, EventType.RUNTIME_TERMINATED,
    )},
    **{event: _rule(EventCategory.AUDIT, TrustClass.AUTHORITATIVE, *_DURABLE) for event in (
        EventType.AUDIT_CHECKPOINT, EventType.AUDIT_EVIDENCE_PERSISTED,
    )},
}


if set(EVENT_RULES) != set(EventType):
    raise RuntimeError("every RunEvent type must have exactly one taxonomy rule")


def validate_taxonomy(event_type: EventType, category: EventCategory,
                      trust_class: TrustClass, durability: Durability) -> None:
    """Reject semantic combinations not assigned by the closed taxonomy."""
    rule = EVENT_RULES[event_type]
    if (category != rule.category or trust_class not in rule.trust_classes
            or durability not in rule.durability):
        raise ValueError(
            f"invalid taxonomy for {event_type}: category={category}, "
            f"trust_class={trust_class}, durability={durability}"
        )


def validate_workload_assertion(event_type: EventType) -> None:
    """Enforce the workload boundary before an asserted event is translated."""
    if TrustClass.ASSERTED not in EVENT_RULES[event_type].trust_classes:
        raise ValueError(f"workload cannot assert {event_type}")
