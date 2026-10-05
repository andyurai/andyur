"""Deterministic JSON Schema generation from the canonical Python contract."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .models import (
    MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_ITEMS, MAX_PAYLOAD_PROPERTIES,
    MAX_PAYLOAD_INTEGER, MAX_PAYLOAD_KEY_CHARS, MAX_PAYLOAD_STRING_CHARS,
    MAX_SEQUENCE, MAX_SUMMARY_CHARS, MAX_IDENTIFIER_CHARS,
    PROHIBITED_SECRET_KEYS, SCHEMA_VERSION,
)
from .taxonomy import (
    DataClassification, Durability, EVENT_RULES, EventCategory, EventType,
    EventVisibility, TrustClass,
)

WIRE_FIELDS = frozenset({
    "schema_version", "event_id", "tenant_id", "workflow_id", "run_id",
    "agent_id", "sequence", "occurred_at", "recorded_at", "category", "type",
    "source", "trust_class", "durability", "classification", "visibility",
    "summary", "payload", "trace_id", "span_id", "parent_event_id",
    "registry_digest", "authority_revision",
})

_UTC_TIMESTAMP = (
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|\+00:00)$"
)


def _secret_key_pattern() -> str:
    def ascii_fold(text: str) -> str:
        folded = [f"[{char.lower()}{char.upper()}]" for char in text if char.isalnum()]
        separators = r"[^A-Za-z0-9]*"
        return separators + separators.join(folded) + separators

    alternatives = "|".join(
        ascii_fold(key)
        for key in sorted(PROHIBITED_SECRET_KEYS)
    )
    return rf"^(?:{alternatives})$"


def _payload_defs() -> dict[str, Any]:
    scalar = [
        {"type": ["null", "boolean"]},
        {"type": "integer", "minimum": -MAX_PAYLOAD_INTEGER,
         "maximum": MAX_PAYLOAD_INTEGER},
        {"type": "number", "minimum": -MAX_PAYLOAD_INTEGER,
         "maximum": MAX_PAYLOAD_INTEGER},
        {"type": "string", "maxLength": MAX_PAYLOAD_STRING_CHARS},
    ]
    definitions: dict[str, Any] = {}
    for depth in range(MAX_PAYLOAD_DEPTH, 0, -1):
        variants = list(scalar)
        if depth < MAX_PAYLOAD_DEPTH:
            child = {"$ref": f"#/$defs/payloadValue{depth + 1}"}
            variants.extend([
                {"type": "array", "maxItems": MAX_PAYLOAD_ITEMS, "items": child},
                {
                    "type": "object", "maxProperties": MAX_PAYLOAD_PROPERTIES,
                    "propertyNames": {"maxLength": MAX_PAYLOAD_KEY_CHARS,
                                      "pattern": r"^[ -~]+$",
                                      "not": {"pattern": _secret_key_pattern()}},
                    "additionalProperties": child,
                },
            ])
        definitions[f"payloadValue{depth}"] = {"anyOf": variants}
    return definitions


def build_schema() -> dict[str, Any]:
    """Build the public schema from the same enums/rules used by RunEvent."""
    properties: dict[str, Any] = {
        "schema_version": {"const": SCHEMA_VERSION},
        "event_id": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "tenant_id": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "workflow_id": {"type": ["string", "null"], "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "run_id": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "agent_id": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "sequence": {"type": "integer", "minimum": 1, "maximum": MAX_SEQUENCE},
        "occurred_at": {"type": ["string", "null"], "format": "date-time",
                        "pattern": _UTC_TIMESTAMP},
        "recorded_at": {"type": "string", "format": "date-time",
                        "pattern": _UTC_TIMESTAMP},
        "category": {"enum": [item.value for item in EventCategory]},
        "type": {"enum": [item.value for item in EventType]},
        "source": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "trust_class": {"enum": [item.value for item in TrustClass]},
        "durability": {"enum": [item.value for item in Durability]},
        "classification": {"enum": [item.value for item in DataClassification]},
        "visibility": {"enum": [item.value for item in EventVisibility]},
        "summary": {"type": ["string", "null"], "maxLength": MAX_SUMMARY_CHARS},
        "payload": {
            "type": "object", "maxProperties": MAX_PAYLOAD_PROPERTIES,
            "propertyNames": {"maxLength": MAX_PAYLOAD_KEY_CHARS,
                              "pattern": r"^[ -~]+$",
                              "not": {"pattern": _secret_key_pattern()}},
            "additionalProperties": {"$ref": "#/$defs/payloadValue1"},
        },
        "trace_id": {"type": ["string", "null"], "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "span_id": {"type": ["string", "null"], "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "parent_event_id": {"type": ["string", "null"], "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "registry_digest": {"type": ["string", "null"], "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
        "authority_revision": {"type": ["string", "null"], "minLength": 1, "maxLength": MAX_IDENTIFIER_CHARS, "pattern": r".*\S.*"},
    }
    rules = []
    for event_type, rule in EVENT_RULES.items():
        rules.append({
            "if": {"properties": {"type": {"const": event_type.value}}},
            "then": {"properties": {
                "category": {"const": rule.category.value},
                "trust_class": {"enum": sorted(item.value for item in rule.trust_classes)},
                "durability": {"enum": sorted(item.value for item in rule.durability)},
            }},
        })
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://andyur.ai/schemas/run-event-v1.schema.json",
        "title": "Andyur RunEvent v1", "type": "object",
        "additionalProperties": False, "$defs": _payload_defs(),
        "required": sorted(WIRE_FIELDS), "properties": properties, "allOf": rules,
    }


def write_schema(path: str | Path) -> None:
    Path(path).write_text(json.dumps(build_schema(), indent=2) + "\n")


def strict_json_loads(document: str | bytes | bytearray) -> Any:
    """Parse standards-conforming JSON; Python otherwise accepts NaN/Infinity."""
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON numeric constant: {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed) or abs(parsed) > MAX_PAYLOAD_INTEGER:
            raise ValueError(f"JSON number is outside the canonical magnitude: {value}")
        return parsed

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object member: {key}")
            result[key] = value
        return result

    return json.loads(document, parse_constant=reject_constant,
                      parse_float=parse_finite_float, object_pairs_hook=unique_object)
