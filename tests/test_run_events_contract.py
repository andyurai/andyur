from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from andyur.events import (
    DataClassification, Durability, EventCategory, EventType, EventVisibility,
    RunEvent, TrustClass, validate_workload_assertion,
)
from andyur.events.taxonomy import EVENT_RULES
from andyur.events.models import (
    MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_ITEMS, MAX_PAYLOAD_NODES,
    MAX_PAYLOAD_INTEGER, MAX_PAYLOAD_KEY_CHARS, MAX_PAYLOAD_PROPERTIES,
    MAX_PAYLOAD_STRING_CHARS, MAX_SEQUENCE, PROHIBITED_SECRET_KEYS,
)
from andyur.events.schema import WIRE_FIELDS, build_schema, strict_json_loads


SCHEMA_PATH = Path(__file__).parents[1] / "andyur/events/run-event-v1.schema.json"


def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text()),
                                format_checker=FormatChecker())


def event(**overrides) -> RunEvent:
    values = {
        "event_id": "evt-1",
        "tenant_id": "tenant-1",
        "workflow_id": "workflow-1",
        "run_id": "run-1",
        "agent_id": "agent-1",
        "sequence": 1,
        "occurred_at": datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc),
        "recorded_at": datetime(2026, 8, 15, 11, 0, 1, tzinfo=timezone.utc),
        "category": EventCategory.AGENT,
        "type": EventType.AGENT_OUTPUT,
        "source": "runner-sidecar",
        "trust_class": TrustClass.ASSERTED,
        "durability": Durability.DURABLE,
        "classification": DataClassification.CONFIDENTIAL,
        "visibility": EventVisibility.DEVELOPER,
        "summary": "Agent produced output",
        "payload": {"text": "safe", "items": [1, {"ok": True}]},
        "registry_digest": "sha256:abc",
    }
    values.update(overrides)
    return RunEvent(**values)


def test_every_event_type_has_a_closed_taxonomy_rule():
    assert set(EVENT_RULES) == set(EventType)


def test_valid_event_is_immutable_and_has_stable_wire_shape():
    recorded = event()
    with pytest.raises(FrozenInstanceError):
        recorded.sequence = 2
    with pytest.raises(TypeError):
        recorded.payload["text"] = "changed"
    with pytest.raises(TypeError):
        recorded.payload["items"][1]["ok"] = False

    wire = recorded.to_dict()
    assert wire["schema_version"] == 1
    assert wire["type"] == "agent.output"
    assert wire["payload"] == {"text": "safe", "items": [1, {"ok": True}]}
    json.dumps(wire)


def test_agent_and_operation_trust_classes_match_the_design_contract():
    event(trust_class=TrustClass.OBSERVED)
    for trust_class in (TrustClass.OBSERVED, TrustClass.AUTHORITATIVE):
        event(type=EventType.OPERATION_COMPLETED,
              category=EventCategory.OPERATION, trust_class=trust_class)


@pytest.mark.parametrize("overrides", [
    {"category": EventCategory.POLICY},
    {"trust_class": TrustClass.AUTHORITATIVE},
    {"type": EventType.POLICY_ALLOWED},
    {"durability": Durability.EPHEMERAL, "type": EventType.POLICY_DENIED,
     "category": EventCategory.POLICY, "trust_class": TrustClass.AUTHORITATIVE},
])
def test_taxonomy_mismatches_are_rejected(overrides):
    with pytest.raises(ValueError, match="invalid taxonomy"):
        event(**overrides)


def test_workload_can_assert_agent_content_but_not_platform_facts():
    validate_workload_assertion(EventType.AGENT_OUTPUT)
    for authoritative in (
        EventType.POLICY_ALLOWED,
        EventType.AUTHORITY_RESOLVED,
        EventType.CREDENTIAL_ISSUED,
        EventType.RUNTIME_LAUNCHED,
        EventType.AUDIT_CHECKPOINT,
    ):
        with pytest.raises(ValueError, match="workload cannot assert"):
            validate_workload_assertion(authoritative)


@pytest.mark.parametrize("payload", [
    {"access_token": "secret"},
    {"nested": {"private_key": "secret"}},
    {"items": [{"authorization": "Bearer secret"}]},
])
def test_secret_bearing_payload_fields_are_structurally_prohibited(payload):
    with pytest.raises(ValueError):
        event(payload=payload)


@pytest.mark.parametrize("key", sorted(PROHIBITED_SECRET_KEYS))
@pytest.mark.parametrize("variant", [
    str.upper, str.title, lambda value: value.replace("_", "-"),
    lambda value: value.replace("_", "--"),
    lambda value: value.replace("_", "."),
    lambda value: " ".join(value.replace("_", "")),
    lambda value: "🔥".join(value.replace("_", "")),
    lambda value: "--" + value,
    lambda value: value + "--",
    lambda value: "*$" + value + "~|",
])
def test_secret_key_variants_are_rejected_by_model_and_schema(key, variant):
    candidate = variant(key)
    payload = {"nested": [{candidate: "secret"}]}
    with pytest.raises(ValueError):
        event(payload=payload)
    wire = event().to_dict()
    wire["payload"] = payload
    with pytest.raises(ValidationError):
        validator().validate(wire)


def test_unicode_confusable_payload_keys_are_rejected_by_both_contracts():
    payload = {"access_toKen": "secret"}
    with pytest.raises(ValueError, match="printable ASCII"):
        event(payload=payload)
    wire = event().to_dict()
    wire["payload"] = payload
    with pytest.raises(ValidationError):
        validator().validate(wire)


@pytest.mark.parametrize("overrides, message", [
    ({"sequence": 0}, "integer from 1"),
    ({"recorded_at": None}, "timezone-aware datetime"),
    ({"recorded_at": datetime(2026, 8, 15)}, "timezone-aware"),
    ({"type": "agent.output"}, "type must be a EventType"),
    ({"payload": {"score": float("nan")}}, "non-finite number"),
    ({"summary": "x" * 4097}, "summary exceeds"),
    ({"schema_version": 2}, "unsupported schema_version"),
])
def test_envelope_bounds_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        event(**overrides)


def test_both_timestamps_are_normalized_to_utc():
    offset = timezone(timedelta(hours=5, minutes=30))
    wire = event(
        occurred_at=datetime(2026, 8, 15, 16, 30, tzinfo=offset),
        recorded_at=datetime(2026, 8, 15, 16, 30, 1, tzinfo=offset),
    ).to_dict()
    assert wire["occurred_at"] == "2026-08-15T11:00:00+00:00"
    assert wire["recorded_at"] == "2026-08-15T11:00:01+00:00"
    validator().validate(wire)


@pytest.mark.parametrize("field", ["recorded_at", "occurred_at"])
@pytest.mark.parametrize("bad_value", ["not-a-date", "2026-02-31T00:00:00+00:00",
                                        "2026-08-15T11:00:00+05:30"])
def test_schema_rejects_malformed_timestamps(field, bad_value):
    wire = event().to_dict()
    wire[field] = bad_value
    with pytest.raises(ValidationError):
        validator().validate(wire)


def test_packaged_schema_is_closed_and_matches_the_python_enums():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema == build_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]["type"]["enum"]) == {item.value for item in EventType}
    assert set(schema["properties"]["category"]["enum"]) == {item.value for item in EventCategory}
    assert schema["properties"]["schema_version"] == {"const": 1}
    assert len(schema["allOf"]) == len(EventType)
    assert schema["properties"]["payload"]["additionalProperties"] == {
        "$ref": "#/$defs/payloadValue1"
    }
    assert set(schema["required"]) == set(schema["properties"]) == WIRE_FIELDS


def test_packaged_schema_accepts_every_canonical_taxonomy_rule():
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    schema_validator = validator()
    for event_type, rule in EVENT_RULES.items():
        for trust_class in rule.trust_classes:
            for durability in rule.durability:
                wire = event(
                    type=event_type,
                    category=rule.category,
                    trust_class=trust_class,
                    durability=durability,
                ).to_dict()
                schema_validator.validate(wire)


def test_python_and_schema_agree_on_every_taxonomy_combination():
    schema_validator = validator()
    baseline = event().to_dict()
    for event_type, rule in EVENT_RULES.items():
        for category in EventCategory:
            for trust_class in TrustClass:
                for durability in Durability:
                    allowed = (category == rule.category
                               and trust_class in rule.trust_classes
                               and durability in rule.durability)
                    wire = baseline | {
                        "type": event_type.value, "category": category.value,
                        "trust_class": trust_class.value,
                        "durability": durability.value,
                    }
                    assert (not bool(list(schema_validator.iter_errors(wire)))) == allowed
                    try:
                        event(type=event_type, category=category,
                              trust_class=trust_class, durability=durability)
                        model_allowed = True
                    except ValueError:
                        model_allowed = False
                    assert model_allowed == allowed


def test_every_wire_field_is_required():
    schema_validator = validator()
    wire = event().to_dict()
    assert set(wire) == WIRE_FIELDS
    for field in WIRE_FIELDS:
        missing = dict(wire)
        del missing[field]
        with pytest.raises(ValidationError):
            schema_validator.validate(missing)


@pytest.mark.parametrize("mutation", [
    {"type": "policy.allowed"},
    {"payload": {"nested": {"access_token": "secret"}}},
    {"unexpected": True},
])
def test_packaged_schema_rejects_taxonomy_secret_and_shape_mutations(mutation):
    wire = event().to_dict() | mutation
    with pytest.raises(ValidationError):
        validator().validate(wire)


def _nested_payload(levels: int):
    value = "leaf"
    for _ in range(levels):
        value = {"child": value}
    return value


def test_payload_depth_and_local_size_bounds_match_the_schema():
    schema_validator = validator()
    accepted = event(payload=_nested_payload(MAX_PAYLOAD_DEPTH)).to_dict()
    schema_validator.validate(accepted)
    too_deep = event().to_dict()
    too_deep["payload"] = _nested_payload(MAX_PAYLOAD_DEPTH + 1)
    with pytest.raises(ValueError, match="maximum depth"):
        event(payload=too_deep["payload"])
    with pytest.raises(ValidationError):
        schema_validator.validate(too_deep)

    for accepted_payload, rejected_payload, message in (
        ({str(index): index for index in range(MAX_PAYLOAD_PROPERTIES)},
         {str(index): index for index in range(MAX_PAYLOAD_PROPERTIES + 1)}, "properties"),
        ({"items": list(range(MAX_PAYLOAD_ITEMS))},
         {"items": list(range(MAX_PAYLOAD_ITEMS + 1))}, "items"),
        ({"text": "x" * MAX_PAYLOAD_STRING_CHARS},
         {"text": "x" * (MAX_PAYLOAD_STRING_CHARS + 1)}, "string"),
        ({"x" * MAX_PAYLOAD_KEY_CHARS: "value"},
         {"x" * (MAX_PAYLOAD_KEY_CHARS + 1): "value"}, "key"),
    ):
        schema_validator.validate(event(payload=accepted_payload).to_dict())
        with pytest.raises(ValueError, match=message):
            event(payload=rejected_payload)
        wire = event().to_dict()
        wire["payload"] = rejected_payload
        with pytest.raises(ValidationError):
            schema_validator.validate(wire)


def test_python_ingress_has_an_additional_total_node_budget():
    payload = {str(index): list(range(16)) for index in range(256)}
    with pytest.raises(ValueError, match=f"exceeds {MAX_PAYLOAD_NODES} values"):
        event(payload=payload)


@pytest.mark.parametrize("value", [MAX_PAYLOAD_INTEGER + 1,
                                    -(MAX_PAYLOAD_INTEGER + 1),
                                    float("inf"), float("-inf"), float("nan")])
def test_payload_numeric_bounds_reject_non_json_or_oversized_numbers(value):
    with pytest.raises(ValueError):
        event(payload={"value": value})
    wire = event().to_dict()
    wire["payload"] = {"value": value}
    if isinstance(value, int) or value in (float("inf"), float("-inf")):
        with pytest.raises(ValidationError):
            validator().validate(wire)
    if not isinstance(value, int):
        with pytest.raises(ValueError):
            json.dumps(wire, allow_nan=False)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_strict_json_parser_rejects_nonstandard_numeric_constants(constant):
    with pytest.raises(ValueError, match="non-standard JSON numeric constant"):
        strict_json_loads('{"value": ' + constant + "}")


@pytest.mark.parametrize("document", [
    '{"trust_class":"asserted","trust_class":"authoritative"}',
    '{"payload":{"value":1,"value":2}}',
])
def test_strict_json_parser_rejects_duplicate_members_at_every_depth(document):
    with pytest.raises(ValueError, match="duplicate JSON object member"):
        strict_json_loads(document)


@pytest.mark.parametrize("number", ["1e9999", "-1e9999"])
def test_strict_json_parser_rejects_exponent_overflow(number):
    with pytest.raises(ValueError, match="outside the canonical magnitude"):
        strict_json_loads('{"value": ' + number + "}")


def test_strict_json_parser_positive_control():
    assert strict_json_loads('{"payload":{"value":1.5}}') == {
        "payload": {"value": 1.5}
    }


@pytest.mark.parametrize("sequence", [0, -1, MAX_SEQUENCE + 1, True, 1.5])
def test_sequence_signed_64_bit_contract(sequence):
    with pytest.raises(ValueError, match="sequence must be"):
        event(sequence=sequence)
    wire = event().to_dict()
    wire["sequence"] = sequence
    with pytest.raises(ValidationError):
        validator().validate(wire)
