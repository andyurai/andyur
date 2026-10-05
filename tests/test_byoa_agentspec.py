"""AgentManifest v1 parsing and the narrowing compiler, each rule shown able
to fail.

Same philosophy as test_manifest_registry.py: the value is not that a good
manifest compiles, but that a bad one is refused with the right exception and
that NOTHING a manifest says can widen authority. Every negative starts from
the known-good document and breaks exactly one thing.

The docs-truth section pins three artifacts to each other: the parser, the
published JSON Schema (andyur/agentspec/agent-manifest-v1.schema.json), and
the YAML example inside docs/agent-runtime-protocol-v1.md. Any one drifting
alone is a red test, which is the mechanism that keeps the public spec TRUE.
"""

import copy
import json
import re
from pathlib import Path

import pytest
import yaml

from andyur.agentspec import (
    InvalidManifest,
    ManifestDenied,
    PlatformPolicy,
    compile_resolution,
    load_manifest,
    manifest_digest,
    parse_manifest,
)
from andyur.agentspec.models import InconsistentPolicy
from andyur.agentspec import parser as agentspec_parser
from andyur.registry.manifest_registry import (
    _AGENT_ID_RE,
    _MCP_TOOL_NAME_RE,
    _NAME_RE,
)
from andyur.registry.models import AuthorityCeiling, McpToolGrant, ToolBinding

PLATFORM_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PLATFORM_ROOT / "andyur" / "agentspec" / "agent-manifest-v1.schema.json"
SPEC_DOC = PLATFORM_ROOT / "docs" / "agent-runtime-protocol-v1.md"

GOOD = {
    "apiVersion": "andyur.ai/v1",
    "kind": "Agent",
    "metadata": {"id": "agt_fraud", "name": "fraud-investigator",
                 "version": "1.4.2"},
    "runtime": {
        "type": "container",
        "image": {"ref": "ghcr.io/acme/fraud-agent",
                  "digest": "sha256:" + "ab" * 32},
        "command": ["/app/agent"],
        "interface": {"protocol": "andyur-agent-runtime/v1"},
        "resources": {"cpu": "2", "memory": "4Gi"},
    },
    "instructions": "Investigate the ticket and report a root cause.",
    "model": {"requested": "claude-sonnet", "access": "proxy"},
    "capabilities": {"tools": [
        {"server": "tickets", "tools": ["read_ticket", "comment_ticket"]},
    ]},
    "input": {"schema": "schemas/input.schema.json"},
    "output": {"schema": "schemas/output.schema.json"},
}

CATALOG = {
    "tickets": ToolBinding(
        name="tickets",
        reach_url="https://tickets.internal:8443/mcp",
        resource_id="urn:andyur:tool:tickets",
        authority="managed",
        mcp_tools=(
            McpToolGrant(name="read_ticket", requires="tickets.read"),
            McpToolGrant(name="comment_ticket", requires="tickets.write"),
            McpToolGrant(name="close_ticket", requires="tickets.admin"),
        ),
    ),
    "telemetry": ToolBinding(
        name="telemetry",
        reach_url="https://telemetry.internal:8443/mcp",
        resource_id="urn:andyur:tool:telemetry",
        authority="managed",
        mcp_tools=(McpToolGrant(name="get_metrics", requires="telemetry.read"),),
    ),
    "legacy": ToolBinding(
        name="legacy",
        reach_url="https://legacy.internal:8443/mcp",
        resource_id="urn:andyur:tool:legacy",
        authority="managed",
        mcp_tools=None,           # audience-level entry, not enumerated
    ),
    "scratch": ToolBinding(
        name="scratch",
        reach_url="http://localhost:9999/mcp",
        resource_id="urn:andyur:tool:scratch",
        authority="passthrough",
    ),
}

POLICY = PlatformPolicy(
    tool_catalog=CATALOG,
    ceiling=AuthorityCeiling(
        actions=("tickets.read", "tickets.write", "tickets.admin",
                 "telemetry.read"),
        resources=("urn:andyur:tool:tickets", "urn:andyur:tool:telemetry"),
    ),
    approved_models=("claude-sonnet", "claude-haiku"),
    revision="rev-42",
)


def _broken(path: list, value):
    """A deep copy of GOOD with one field replaced (BREAK sentinel deletes)."""
    doc = copy.deepcopy(GOOD)
    obj = doc
    for key in path[:-1]:
        obj = obj[key]
    if value is _DELETE:
        del obj[path[-1]]
    else:
        obj[path[-1]] = value
    return doc


_DELETE = object()


# ---------------------------------------------------------------- parsing --

def test_good_manifest_parses_completely():
    m = parse_manifest(GOOD)
    assert m.metadata.id == "agt_fraud"
    assert m.metadata.version == "1.4.2"
    assert m.runtime.type == "container"
    assert m.runtime.image.digest == "sha256:" + "ab" * 32
    assert m.runtime.command == ("/app/agent",)
    assert m.runtime.interface_protocol == "andyur-agent-runtime/v1"
    assert m.runtime.resources.memory == "4Gi"
    assert m.model_requested == "claude-sonnet"
    assert m.tool_requests[0].server == "tickets"
    assert m.tool_requests[0].tools == ("read_ticket", "comment_ticket")
    assert m.input_schema == "schemas/input.schema.json"


def test_builtin_manifest_parses_with_no_packaging():
    doc = copy.deepcopy(GOOD)
    doc["runtime"] = {"type": "builtin-claude"}
    m = parse_manifest(doc)
    assert m.runtime.type == "builtin-claude"
    assert m.runtime.image is None
    assert m.runtime.interface_protocol is None


@pytest.mark.parametrize("path,value", [
    (["apiVersion"], "andyur.ai/v2"),
    (["kind"], "Deployment"),
    (["metadata", "id"], "fraud"),                       # not agt_*
    (["metadata", "name"], "Fraud Investigator"),        # bad chars
    (["metadata", "version"], "latest"),                 # not numeric
    (["instructions"], ""),
    (["instructions"], _DELETE),
    (["runtime", "type"], "vm"),
    (["runtime", "image", "digest"], "sha256:short"),
    (["runtime", "image", "ref"], "ghcr.io/acme/agent@sha256:" + "ab" * 32),
    (["runtime", "interface", "protocol"], "andyur-agent-runtime/v9"),
    (["runtime", "resources", "memory"], "lots"),
    (["model", "access"], "direct"),
    (["model", "requested"], "claude\r\nx-inject: evil"),   # CRLF injection
    (["model", "requested"], "has space"),
    (["capabilities", "tools"], [{"server": "tickets", "tools": []}]),
    (["input", "schema"], "../../../etc/passwd"),
])
def test_each_bad_field_is_refused(path, value):
    with pytest.raises(InvalidManifest):
        parse_manifest(_broken(path, value))


@pytest.mark.parametrize("where,extra", [
    ([], {"privileged": True}),
    (["metadata"], {"owner": "me"}),
    (["runtime"], {"host_network": True}),
    (["runtime", "image"], {"pull_policy": "Always"}),
    (["capabilities"], {"filesystem": "rw"}),
])
def test_unknown_fields_fail_closed(where, extra):
    doc = copy.deepcopy(GOOD)
    obj = doc
    for key in where:
        obj = obj[key]
    obj.update(extra)
    with pytest.raises(InvalidManifest, match="unknown field"):
        parse_manifest(doc)


def test_governed_requires_image_digest_and_ungoverned_does_not():
    doc = _broken(["runtime", "image", "digest"], _DELETE)
    with pytest.raises(InvalidManifest, match="immutable image digest"):
        parse_manifest(doc, governed=True)
    m = parse_manifest(doc, governed=False)
    assert m.runtime.image.digest is None


def test_container_requires_explicit_governed_command_in_every_mode():
    doc = _broken(["runtime", "command"], _DELETE)

    for governed in (False, True):
        with pytest.raises(InvalidManifest, match="explicit command"):
            parse_manifest(doc, governed=governed)


def test_builtin_refuses_container_packaging_fields():
    for key, value in [("image", {"ref": "x"}), ("command", ["/x"]),
                       ("interface", {"protocol": "andyur-agent-runtime/v1"}),
                       ("resources", {"cpu": "1"})]:
        doc = copy.deepcopy(GOOD)
        doc["runtime"] = {"type": "builtin-claude", key: value}
        with pytest.raises(InvalidManifest, match="builtin-claude"):
            parse_manifest(doc)


@pytest.mark.parametrize("field,value", [
    ("command", ["/app/agent", "--api-key=sk-abc123"]),
    ("command", ["/bin/sh", "-c", "TOKEN: hunter2 ./run"]),
])
def test_credential_shaped_command_is_refused(field, value):
    doc = _broken(["runtime", field], value)
    with pytest.raises(InvalidManifest, match="credential"):
        parse_manifest(doc)


def test_credential_shaped_instructions_are_refused():
    doc = _broken(["instructions"], "Use api_key=sk-live-1234 to call the API")
    with pytest.raises(InvalidManifest, match="credential"):
        parse_manifest(doc)


def test_duplicate_and_oversized_tool_requests_are_refused():
    dup = _broken(["capabilities", "tools"], [
        {"server": "tickets", "tools": ["read_ticket"]},
        {"server": "tickets", "tools": ["comment_ticket"]},
    ])
    with pytest.raises(InvalidManifest, match="duplicate"):
        parse_manifest(dup)
    too_many = _broken(["capabilities", "tools"], [
        {"server": f"srv-{i}", "tools": ["t"]} for i in range(33)])
    with pytest.raises(InvalidManifest, match="limit"):
        parse_manifest(too_many)


def test_load_manifest_round_trips_and_rejects_bad_json(tmp_path):
    p = tmp_path / "agent.json"
    p.write_text(json.dumps(GOOD))
    assert load_manifest(p).metadata.id == "agt_fraud"
    p.write_text("{not json")
    with pytest.raises(InvalidManifest, match="not valid JSON"):
        load_manifest(p)


def test_manifest_digest_is_canonical_and_content_sensitive():
    a = parse_manifest(GOOD)
    reordered = json.loads(json.dumps(GOOD))  # same content
    reordered["metadata"] = dict(reversed(list(GOOD["metadata"].items())))
    b = parse_manifest(reordered)
    assert manifest_digest(a) == manifest_digest(b)
    c = parse_manifest(_broken(["metadata", "version"], "1.4.3"))
    assert manifest_digest(a) != manifest_digest(c)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest(a))


# -------------------------------------------------------------- compiling --

def test_compile_grants_exactly_the_requested_intersection():
    compiled = compile_resolution(parse_manifest(GOOD), POLICY)
    (tool,) = compiled.resolution.tools
    assert tool.name == "tickets"
    # facts come from POLICY, not the manifest
    assert tool.reach_url == "https://tickets.internal:8443/mcp"
    assert tool.resource_id == "urn:andyur:tool:tickets"
    # granted = requested ∩ approved, with policy's own action mapping
    assert [(g.name, g.requires) for g in tool.mcp_tools] == [
        ("read_ticket", "tickets.read"), ("comment_ticket", "tickets.write")]
    # close_ticket was approved but NOT requested: not granted
    assert "close_ticket" not in {g.name for g in tool.mcp_tools}
    assert compiled.resolution.model == "claude-sonnet"
    assert compiled.resolution.instructions == GOOD["instructions"]


def test_compile_narrows_ceiling_resources_to_granted_tools():
    compiled = compile_resolution(parse_manifest(GOOD), POLICY)
    # telemetry was in the policy ceiling but no granted tool declares it
    assert compiled.resolution.ceiling.resources == ("urn:andyur:tool:tickets",)
    assert compiled.resolution.ceiling.actions == POLICY.ceiling.actions


def test_compile_preserves_ceiling_tristate():
    manifest = parse_manifest(GOOD)
    open_policy = PlatformPolicy(tool_catalog=CATALOG,
                                 ceiling=AuthorityCeiling(actions=None,
                                                          resources=None))
    compiled = compile_resolution(manifest, open_policy)
    assert compiled.resolution.ceiling.actions is None
    assert compiled.resolution.ceiling.resources is None


def test_requested_tool_above_approval_is_denied_by_name():
    doc = _broken(["capabilities", "tools"],
                  [{"server": "tickets", "tools": ["read_ticket", "drop_db"]}])
    with pytest.raises(ManifestDenied, match="drop_db"):
        compile_resolution(parse_manifest(doc), POLICY)


def test_unknown_server_is_denied():
    doc = _broken(["capabilities", "tools"],
                  [{"server": "payments", "tools": ["refund"]}])
    with pytest.raises(ManifestDenied, match="payments"):
        compile_resolution(parse_manifest(doc), POLICY)


def test_audience_level_catalog_entry_cannot_grant_per_tool():
    doc = _broken(["capabilities", "tools"],
                  [{"server": "legacy", "tools": ["anything"]}])
    with pytest.raises(ManifestDenied, match="enumerate"):
        compile_resolution(parse_manifest(doc), POLICY)


def test_passthrough_server_is_denied():
    doc = _broken(["capabilities", "tools"],
                  [{"server": "scratch", "tools": ["write_note"]}])
    with pytest.raises(ManifestDenied, match="passthrough"):
        compile_resolution(parse_manifest(doc), POLICY)


def test_unapproved_model_is_denied_and_absent_model_passes():
    doc = _broken(["model"], {"requested": "gpt-99"})
    with pytest.raises(ManifestDenied, match="gpt-99"):
        compile_resolution(parse_manifest(doc), POLICY)
    no_model = _broken(["model"], _DELETE)
    compiled = compile_resolution(parse_manifest(no_model), POLICY)
    assert compiled.resolution.model is None


def test_inconsistent_policy_is_loud_not_granted():
    # A catalog grant whose required action the ceiling can never yield: the
    # locked registry validator refuses the composed resolution, and the
    # compiler must surface that as a platform fault, not a grant.
    bad_policy = PlatformPolicy(
        tool_catalog=CATALOG,
        ceiling=AuthorityCeiling(actions=("telemetry.read",),
                                 resources=("urn:andyur:tool:tickets",)),
    )
    with pytest.raises(InconsistentPolicy):
        compile_resolution(parse_manifest(GOOD), bad_policy)


def test_nothing_requested_grants_nothing():
    doc = _broken(["capabilities"], _DELETE)
    compiled = compile_resolution(parse_manifest(doc), POLICY)
    assert compiled.resolution.tools == ()
    assert compiled.resolution.ceiling.resources == ()


def test_widening_is_impossible_across_request_shapes():
    """Property sweep: for every subset of requestable tools, the grant is a
    subset of BOTH the request and the approval, and the ceiling never gains
    a resource policy did not already hold."""
    approved = {g.name for g in CATALOG["tickets"].mcp_tools}
    from itertools import combinations
    names = sorted(approved)
    for r in range(1, len(names) + 1):
        for req in combinations(names, r):
            doc = _broken(["capabilities", "tools"],
                          [{"server": "tickets", "tools": list(req)}])
            compiled = compile_resolution(parse_manifest(doc), POLICY)
            granted = {g.name for t in compiled.resolution.tools
                       for g in t.mcp_tools}
            assert granted == set(req)          # never more than requested
            assert granted <= approved          # never more than approved
            assert set(compiled.resolution.ceiling.resources) <= set(
                POLICY.ceiling.resources)


def test_runtime_resolution_carries_provenance():
    compiled = compile_resolution(parse_manifest(GOOD), POLICY)
    rt = compiled.runtime
    assert rt.runtime_type == "container"
    assert rt.image_ref == "ghcr.io/acme/fraud-agent"
    assert rt.image_digest == "sha256:" + "ab" * 32
    assert rt.interface_version == "andyur-agent-runtime/v1"
    assert rt.manifest_digest == manifest_digest(parse_manifest(GOOD))
    assert rt.policy_revision == "rev-42"


# ------------------------------------------------------------- docs truth --

def _schema():
    return json.loads(SCHEMA_PATH.read_text())


def _container_runtime(schema):
    """The container variant of the runtime oneOf (the richer of the two)."""
    variants = schema["properties"]["runtime"]["oneOf"]
    return max(variants, key=lambda v: len(v["properties"]))


def test_schema_and_parser_agree_on_every_field_set():
    schema = _schema()
    assert set(schema["properties"]) == agentspec_parser._TOP_KEYS
    assert set(schema["properties"]["metadata"]["properties"]) == \
        agentspec_parser._METADATA_KEYS
    runtime_variants = schema["properties"]["runtime"]["oneOf"]
    builtin, container = sorted(runtime_variants,
                                key=lambda v: len(v["properties"]))
    assert set(builtin["properties"]) == {"type"}
    assert set(container["properties"]) == agentspec_parser._RUNTIME_KEYS
    assert set(container["properties"]["image"]["properties"]) == \
        agentspec_parser._IMAGE_KEYS
    assert set(container["properties"]["interface"]["properties"]) == \
        agentspec_parser._INTERFACE_KEYS
    assert set(container["properties"]["resources"]["properties"]) == \
        agentspec_parser._RESOURCES_KEYS
    assert set(schema["properties"]["model"]["properties"]) == \
        agentspec_parser._MODEL_KEYS
    caps = schema["properties"]["capabilities"]
    assert set(caps["properties"]) == agentspec_parser._CAPABILITIES_KEYS
    entry = caps["properties"]["tools"]["items"]
    assert set(entry["properties"]) == agentspec_parser._TOOL_REQUEST_KEYS
    for io_key in ("input", "output"):
        assert set(schema["properties"][io_key]["properties"]) == \
            agentspec_parser._IO_KEYS


def test_schema_patterns_match_the_single_source_regexes():
    schema = _schema()
    rt = _container_runtime(schema)
    # identifier patterns shared with the registry (single source)
    assert schema["properties"]["metadata"]["properties"]["id"]["pattern"] == \
        _AGENT_ID_RE.pattern
    assert schema["properties"]["metadata"]["properties"]["name"]["pattern"] == \
        _NAME_RE.pattern
    entry = schema["properties"]["capabilities"]["properties"]["tools"]["items"]
    assert entry["properties"]["tools"]["items"]["pattern"] == \
        _MCP_TOOL_NAME_RE.pattern
    assert entry["properties"]["server"]["pattern"] == _NAME_RE.pattern
    # parser-local patterns: every anchored shape the schema restates must be
    # the SAME string as the parser's regex, or the two can diverge silently.
    assert schema["properties"]["metadata"]["properties"]["version"]["pattern"] \
        == agentspec_parser._VERSION_RE.pattern
    assert rt["properties"]["image"]["properties"]["digest"]["pattern"] == \
        agentspec_parser._DIGEST_RE.pattern
    assert rt["properties"]["image"]["properties"]["ref"]["pattern"] == \
        agentspec_parser._IMAGE_REF_RE.pattern
    for dim in ("cpu", "memory"):
        assert rt["properties"]["resources"]["properties"][dim]["pattern"] == \
            agentspec_parser._QUANTITY_RE.pattern
    for io_key in ("input", "output"):
        assert schema["properties"][io_key]["properties"]["schema"]["pattern"] \
            == agentspec_parser._SCHEMA_REF_RE.pattern


def test_schema_caps_match_the_single_source_limits():
    """The numeric caps the docs-truth sentence promises cannot drift: each
    schema bound is pinned to the parser/registry constant it mirrors."""
    from andyur.registry.manifest_registry import MAX_MCP_TOOLS
    from andyur.registry.models import MAX_TOOL_BINDINGS as REG_MAX_BINDINGS
    schema = _schema()
    rt = _container_runtime(schema)
    assert rt["properties"]["command"]["maxItems"] == \
        agentspec_parser.MAX_COMMAND_ARGS
    assert rt["properties"]["command"]["items"]["maxLength"] == \
        agentspec_parser.MAX_COMMAND_ARG_LEN
    assert schema["properties"]["instructions"]["maxLength"] == \
        agentspec_parser.MAX_INSTRUCTIONS_LEN
    caps = schema["properties"]["capabilities"]["properties"]["tools"]
    assert caps["maxItems"] == REG_MAX_BINDINGS
    assert caps["items"]["properties"]["tools"]["maxItems"] == MAX_MCP_TOOLS


def test_schema_required_fields_match_the_parser():
    """Required-ness is part of the contract the docs claim is pinned."""
    schema = _schema()
    assert set(schema["required"]) == {"apiVersion", "kind", "metadata",
                                       "runtime", "instructions"}
    assert set(schema["properties"]["metadata"]["required"]) == \
        agentspec_parser._METADATA_KEYS
    rt = _container_runtime(schema)
    assert set(rt["required"]) == {"type", "image", "command", "interface"}
    assert set(rt["properties"]["image"]["required"]) == {"ref"}
    assert set(rt["properties"]["interface"]["required"]) == {"protocol"}
    assert schema["properties"]["model"]["required"] == ["requested"]


def test_spec_documents_yaml_example_is_a_valid_governed_manifest():
    text = SPEC_DOC.read_text()
    blocks = re.findall(r"```yaml\n(.*?)```", text, flags=re.DOTALL)
    assert len(blocks) == 1, "the spec should carry exactly one YAML example"
    doc = yaml.safe_load(blocks[0])
    manifest = parse_manifest(doc, source="docs example", governed=True)
    assert manifest.metadata.id == "agt_fraud"
    assert manifest.runtime.interface_protocol == "andyur-agent-runtime/v1"


def test_schema_accepts_the_good_document_shape():
    """The schema is documentation; jsonschema is not a dependency. This
    guards the cheap half anyway: every GOOD field name must appear in the
    schema, so a field added to GOOD (and the parser) without a schema update
    is a red test."""
    schema = _schema()

    def walk(doc_obj, schema_obj, where):
        assert isinstance(schema_obj, dict), where
        props = schema_obj.get("properties")
        if props is None and "oneOf" in schema_obj:
            merged = {}
            for variant in schema_obj["oneOf"]:
                merged.update(variant.get("properties", {}))
            props = merged
        if not isinstance(doc_obj, dict):
            return
        for key, val in doc_obj.items():
            assert key in props, f"{where}.{key} missing from schema"
            walk(val, props[key], f"{where}.{key}")

    walk(GOOD, schema, "$")
