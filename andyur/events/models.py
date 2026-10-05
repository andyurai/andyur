"""Immutable, versioned values for the canonical run event plane."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
from types import MappingProxyType
from typing import Any, Mapping

from .taxonomy import (
    DataClassification, Durability, EventCategory, EventType, EventVisibility,
    TrustClass, validate_taxonomy,
)

SCHEMA_VERSION = 1
MAX_SUMMARY_CHARS = 4096
MAX_PAYLOAD_DEPTH = 16
MAX_PAYLOAD_NODES = 4096
MAX_PAYLOAD_PROPERTIES = 256
MAX_PAYLOAD_ITEMS = 1024
MAX_PAYLOAD_STRING_CHARS = 65_536
MAX_PAYLOAD_KEY_CHARS = 512
MAX_IDENTIFIER_CHARS = 512
MAX_PAYLOAD_INTEGER = 9_223_372_036_854_775_807
MAX_SEQUENCE = MAX_PAYLOAD_INTEGER

# Structural guardrails, not a generic secret scanner. Payload-specific schemas
# will make allowed keys closed as event producers are added.
PROHIBITED_SECRET_KEYS = frozenset({
    "access_token", "refresh_token", "api_key", "private_key", "client_secret",
    "authorization", "cookie", "password", "raw_svid", "credential_value",
})
_PROHIBITED_SECRET_KEY_FORMS = frozenset(
    re.sub(r"[^a-z0-9]", "", key.lower()) for key in PROHIBITED_SECRET_KEYS
)


def is_prohibited_secret_key(key: str) -> bool:
    return re.sub(r"[^a-z0-9]", "", key.lower()) in _PROHIBITED_SECRET_KEY_FORMS


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > MAX_IDENTIFIER_CHARS:
        raise ValueError(f"{name} exceeds {MAX_IDENTIFIER_CHARS} characters")


def _optional_text(name: str, value: str | None) -> None:
    if value is not None:
        _require_text(name, value)


def _validate_time(name: str, value: datetime | None, *, optional: bool = False) -> None:
    if value is None:
        if optional:
            return
        raise ValueError(f"{name} must be a timezone-aware datetime")
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _freeze_json(value: Any, path: str = "payload", *, depth: int = 0,
                 budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [MAX_PAYLOAD_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError(f"payload exceeds {MAX_PAYLOAD_NODES} values")
    if depth > MAX_PAYLOAD_DEPTH:
        raise ValueError(f"{path} exceeds maximum depth {MAX_PAYLOAD_DEPTH}")
    if isinstance(value, str) and len(value) > MAX_PAYLOAD_STRING_CHARS:
        raise ValueError(f"{path} string exceeds {MAX_PAYLOAD_STRING_CHARS} characters")
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_PAYLOAD_INTEGER:
            raise ValueError(f"{path} integer is outside signed 64-bit range")
        return value
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        if abs(value) > MAX_PAYLOAD_INTEGER:
            raise ValueError(f"{path} number is outside signed 64-bit magnitude")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_PAYLOAD_PROPERTIES:
            raise ValueError(f"{path} exceeds {MAX_PAYLOAD_PROPERTIES} properties")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            if not key.isascii() or not key.isprintable():
                raise ValueError(f"{path} keys must contain printable ASCII only")
            if len(key) > MAX_PAYLOAD_KEY_CHARS:
                raise ValueError(f"{path} key exceeds {MAX_PAYLOAD_KEY_CHARS} characters")
            if is_prohibited_secret_key(key):
                raise ValueError(f"{path}.{key} is a prohibited secret-bearing field")
            frozen[key] = _freeze_json(item, f"{path}.{key}", depth=depth + 1,
                                       budget=budget)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_PAYLOAD_ITEMS:
            raise ValueError(f"{path} exceeds {MAX_PAYLOAD_ITEMS} items")
        return tuple(_freeze_json(item, f"{path}[]", depth=depth + 1,
                                  budget=budget) for item in value)
    raise ValueError(f"{path} must contain JSON-compatible values")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class RunEvent:
    """An already-recorded event; producers must use the trusted publisher."""

    event_id: str
    tenant_id: str
    run_id: str
    agent_id: str
    sequence: int
    recorded_at: datetime
    category: EventCategory
    type: EventType
    source: str
    trust_class: TrustClass
    durability: Durability
    classification: DataClassification
    visibility: EventVisibility
    workflow_id: str | None = None
    occurred_at: datetime | None = None
    summary: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    trace_id: str | None = None
    span_id: str | None = None
    parent_event_id: str | None = None
    registry_digest: str | None = None
    authority_revision: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("event_id", "tenant_id", "run_id", "agent_id", "source"):
            _require_text(name, getattr(self, name))
        for name in ("workflow_id", "trace_id", "span_id", "parent_event_id",
                     "registry_digest", "authority_revision"):
            _optional_text(name, getattr(self, name))
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version: {self.schema_version}")
        if (not isinstance(self.sequence, int) or isinstance(self.sequence, bool)
                or not 1 <= self.sequence <= MAX_SEQUENCE):
            raise ValueError(f"sequence must be an integer from 1 to {MAX_SEQUENCE}")
        _validate_time("recorded_at", self.recorded_at)
        _validate_time("occurred_at", self.occurred_at, optional=True)
        enum_fields = {
            "category": EventCategory, "type": EventType, "trust_class": TrustClass,
            "durability": Durability, "classification": DataClassification,
            "visibility": EventVisibility,
        }
        for name, enum_type in enum_fields.items():
            if not isinstance(getattr(self, name), enum_type):
                raise ValueError(f"{name} must be a {enum_type.__name__}")
        if self.summary is not None:
            if not isinstance(self.summary, str):
                raise ValueError("summary must be a string or None")
            if len(self.summary) > MAX_SUMMARY_CHARS:
                raise ValueError(f"summary exceeds {MAX_SUMMARY_CHARS} characters")
        validate_taxonomy(self.type, self.category, self.trust_class, self.durability)
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be an object")
        object.__setattr__(self, "payload", _freeze_json(self.payload))

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON representation used by stores and APIs."""
        result = {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "sequence": self.sequence,
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat()
            if self.occurred_at else None,
            "recorded_at": self.recorded_at.astimezone(timezone.utc).isoformat(),
            "category": self.category.value,
            "type": self.type.value,
            "source": self.source,
            "trust_class": self.trust_class.value,
            "durability": self.durability.value,
            "classification": self.classification.value,
            "visibility": self.visibility.value,
            "summary": self.summary,
            "payload": _thaw_json(self.payload),
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_event_id": self.parent_event_id,
            "registry_digest": self.registry_digest,
            "authority_revision": self.authority_revision,
        }
        return result
