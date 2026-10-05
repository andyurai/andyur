"""The ManifestAgentRegistry read contract, and every validation rule that
guards it, each shown able to fail.

The locked contract (`docs/reviews/spire-registry-v2-review-notes.md` section 7)
is a security seam: the harness trusts whatever resolve() returns as the agent's
authority. So the value of these tests is not that a good manifest resolves, but
that a BAD one is refused at construction rather than reaching a run. Every
negative starts from the known-good manifest and breaks exactly one thing.
"""

import copy
import dataclasses
import json

import pytest

from andyur.registry import (
    AgentNotFound,
    AgentResolution,
    InvalidAgentManifest,
    ManifestAgentRegistry,
    ToolBinding,
)

GOOD = {
    "schema_version": "andyur.agent-resolution/v1",
    "agent_id": "agt_classifier",
    "name": "classifier",
    "instructions": "Classify the supplied content without modifying it.",
    "model": None,
    "tools": [
        {
            "name": "filesystem",
            "reach_url": "http://authority-tool:8080/mcp",
            "resource_id": "resource:filesystem",
            "authority": "managed",
        }
    ],
    "ceiling": {
        "actions": ["files:read"],
        "resources": ["resource:filesystem"],
    },
}


def _write(tmp_path, manifest, name="a.json"):
    p = tmp_path / name
    p.write_text(json.dumps(manifest))
    return p


def _registry(tmp_path, manifest):
    return ManifestAgentRegistry(_write(tmp_path, manifest))


# --- the positive control: a good manifest resolves to the exact shape --------

def test_a_valid_manifest_resolves_to_an_immutable_resolution(tmp_path):
    reg = _registry(tmp_path, GOOD)
    r = reg.resolve("agt_classifier")
    assert isinstance(r, AgentResolution)
    assert (r.agent_id, r.name, r.model) == ("agt_classifier", "classifier", None)
    assert r.instructions.startswith("Classify")
    assert r.tools == (
        ToolBinding("filesystem", "http://authority-tool:8080/mcp",
                    "resource:filesystem", "managed"),
    )
    assert r.ceiling.actions == ("files:read",)
    assert r.ceiling.resources == ("resource:filesystem",)


def test_the_resolution_cannot_be_mutated(tmp_path):
    r = _registry(tmp_path, GOOD).resolve("agt_classifier")
    # frozen dataclass + tuples: the harness cannot alter registry policy.
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.agent_id = "agt_other"          # type: ignore[misc]
    assert isinstance(r.tools, tuple)


def test_reach_url_is_never_the_resource_id(tmp_path):
    """The contract's core correction: routing and audience are distinct. A
    manifest can and does declare a resource_id that is not its URL."""
    r = _registry(tmp_path, GOOD).resolve("agt_classifier")
    tool = r.tools[0]
    assert tool.reach_url != tool.resource_id
    assert tool.resource_id == "resource:filesystem"


# --- resolve() lookups --------------------------------------------------------

def test_resolve_unknown_agent_raises(tmp_path):
    with pytest.raises(AgentNotFound):
        _registry(tmp_path, GOOD).resolve("agt_nope")


def test_a_directory_indexes_every_manifest(tmp_path):
    _write(tmp_path, GOOD, "one.json")
    second = copy.deepcopy(GOOD)
    second["agent_id"] = "agt_second"
    second["name"] = "second"
    _write(tmp_path, second, "two.json")
    reg = ManifestAgentRegistry(tmp_path)
    assert {a.agent_id for a in reg.list_agents()} == {"agt_classifier", "agt_second"}
    assert reg.resolve("agt_second").name == "second"


# --- the ceiling tri-state must survive parsing -------------------------------

@pytest.mark.parametrize("value, expected", [
    (None, None),          # no ceiling in that dimension
    ([], ()),              # explicitly deny everything
    (["a", "b"], ("a", "b")),  # permit at most these
])
def test_ceiling_dimension_tristate_is_preserved(tmp_path, value, expected):
    m = copy.deepcopy(GOOD)
    m["ceiling"]["actions"] = value
    r = _registry(tmp_path, m).resolve("agt_classifier")
    assert r.ceiling.actions == expected


def test_empty_and_null_ceiling_are_not_the_same(tmp_path):
    """[] denies everything; null means no ceiling. Flattening them would turn a
    deny-all into an allow -- the exact bug the tri-state exists to prevent."""
    deny = copy.deepcopy(GOOD); deny["ceiling"]["actions"] = []
    none = copy.deepcopy(GOOD); none["ceiling"]["actions"] = None
    assert _registry(tmp_path, deny).resolve("agt_classifier").ceiling.actions == ()
    assert _registry(tmp_path, none).resolve("agt_classifier").ceiling.actions is None


def test_model_absent_defaults_to_none(tmp_path):
    m = copy.deepcopy(GOOD); del m["model"]
    assert _registry(tmp_path, m).resolve("agt_classifier").model is None


def test_model_when_set_is_carried(tmp_path):
    m = copy.deepcopy(GOOD); m["model"] = "claude-fable-5"
    assert _registry(tmp_path, m).resolve("agt_classifier").model == "claude-fable-5"


# --- every validation rule, each proven able to fail --------------------------

def test_unknown_top_level_field_is_rejected(tmp_path):
    m = copy.deepcopy(GOOD); m["surprise"] = 1
    with pytest.raises(InvalidAgentManifest, match="unknown field"):
        _registry(tmp_path, m)


def test_unknown_tool_field_is_rejected(tmp_path):
    m = copy.deepcopy(GOOD); m["tools"][0]["extra"] = "x"
    with pytest.raises(InvalidAgentManifest, match="unknown field"):
        _registry(tmp_path, m)


def test_unknown_ceiling_field_is_rejected(tmp_path):
    m = copy.deepcopy(GOOD); m["ceiling"]["scopes"] = []
    with pytest.raises(InvalidAgentManifest, match="unknown field"):
        _registry(tmp_path, m)


def test_wrong_schema_version_is_rejected(tmp_path):
    m = copy.deepcopy(GOOD); m["schema_version"] = "andyur.agent-resolution/v2"
    with pytest.raises(InvalidAgentManifest, match="schema_version"):
        _registry(tmp_path, m)


@pytest.mark.parametrize("field", ["schema_version", "agent_id", "name",
                                   "instructions", "tools", "ceiling"])
def test_missing_required_field_is_rejected(tmp_path, field):
    m = copy.deepcopy(GOOD); del m[field]
    with pytest.raises(InvalidAgentManifest):
        _registry(tmp_path, m)


def test_duplicate_tool_name_is_rejected(tmp_path):
    m = copy.deepcopy(GOOD)
    m["tools"].append(copy.deepcopy(m["tools"][0]))
    with pytest.raises(InvalidAgentManifest, match="duplicate tool name"):
        _registry(tmp_path, m)


def test_bad_authority_mode_is_rejected(tmp_path):
    m = copy.deepcopy(GOOD); m["tools"][0]["authority"] = "trusted"
    with pytest.raises(InvalidAgentManifest, match="authority"):
        _registry(tmp_path, m)


def test_managed_tool_needs_a_resource_id(tmp_path):
    m = copy.deepcopy(GOOD); m["tools"][0]["resource_id"] = ""
    with pytest.raises(InvalidAgentManifest):
        _registry(tmp_path, m)


def test_passthrough_tool_still_needs_a_resource_id(tmp_path):
    m = copy.deepcopy(GOOD)
    m["tools"][0]["authority"] = "passthrough"
    del m["tools"][0]["resource_id"]
    with pytest.raises(InvalidAgentManifest):
        _registry(tmp_path, m)


def test_ceiling_dimension_must_be_null_or_list(tmp_path):
    m = copy.deepcopy(GOOD); m["ceiling"]["actions"] = "files:read"
    with pytest.raises(InvalidAgentManifest):
        _registry(tmp_path, m)


def test_invalid_json_is_rejected_at_construction(tmp_path):
    p = tmp_path / "bad.json"; p.write_text("{not json")
    with pytest.raises(InvalidAgentManifest, match="not valid JSON"):
        ManifestAgentRegistry(p)


def test_duplicate_agent_id_across_fixtures_is_rejected(tmp_path):
    _write(tmp_path, GOOD, "one.json")
    _write(tmp_path, GOOD, "two.json")   # same agent_id
    with pytest.raises(InvalidAgentManifest, match="duplicate agent_id"):
        ManifestAgentRegistry(tmp_path)


def test_an_empty_directory_is_an_empty_catalogue_and_a_wrong_path_is_not(tmp_path):
    """This used to reject an empty directory, and that broke uninstall.

    The refusal read as a guard against a misconfigured ANDYUR_AGENT_REGISTRY_DIR.
    What it actually prevented was removing your LAST bundle: the files were
    deleted, the rebuild then refused, and the registry was left empty on disk
    and stale in memory -- a destroyed catalogue that the process could not
    reload. An existing but empty directory is a legal state, and `registry
    list` has always had the copy for it.

    The guard that catches the misconfiguration is the one below: a path that is
    not there at all is still refused, and that is the shape a typo actually
    takes.
    """
    assert ManifestAgentRegistry(tmp_path).list_agents() == []

    with pytest.raises(InvalidAgentManifest, match="not a file or directory"):
        ManifestAgentRegistry(tmp_path / "does-not-exist")


# --- the shipped demo manifest is itself valid --------------------------------

def test_the_sre_demo_manifest_resolves(tmp_path):
    """The fixture the demo will consume must satisfy its own contract."""
    from pathlib import Path
    here = Path(__file__).resolve().parent.parent
    reg = ManifestAgentRegistry(here / "demos" / "agent-registry")
    r = reg.resolve("agt_oncall")
    assert r.model == "claude-haiku-4-5"
    assert {t.name for t in r.tools} == {"obs", "tickets"}
    # resource ids are the canonical audience namespace, distinct from /mcp urls
    assert {t.resource_id for t in r.tools} == {"resource:telemetry", "resource:tickets"}
    assert {t.reach_url for t in r.tools} == {
        "http://host.docker.internal:8797/mcp",
        "http://host.docker.internal:8798/mcp",
    }
    assert r.ceiling.actions == ("obs:read", "tickets:read", "tickets:comment")
    local = reg.resolve("agt_oncall_ollama")
    assert local.model == "muse-glimmer:30b-mlx"
    assert local.ceiling == r.ceiling
    assert local.tools == r.tools


# --- expected_spiffe_id: the tool's own workload identity (authority data) -----

def test_expected_spiffe_id_is_optional_and_defaults_none(tmp_path):
    """A manifest without it resolves exactly as before -- the field is
    additive, so existing manifests are unaffected."""
    tool = _registry(tmp_path, GOOD).resolve("agt_classifier").tools[0]
    assert tool.expected_spiffe_id is None


def test_expected_spiffe_id_is_parsed_and_carried(tmp_path):
    """When declared on a managed tool it is validated and preserved, so the
    data plane can later match it against the tool's certificate URI SAN."""
    m = copy.deepcopy(GOOD)
    m["tools"][0]["expected_spiffe_id"] = "spiffe://andyur.local/tool/filesystem"
    tool = _registry(tmp_path, m).resolve("agt_classifier").tools[0]
    assert tool.expected_spiffe_id == "spiffe://andyur.local/tool/filesystem"


def test_a_malformed_expected_spiffe_id_fails_manifest_validation(tmp_path):
    """A value that is not a well-formed SPIFFE ID would compile to a SAN
    matcher that never matches; reject it at load time, not mid-run."""
    for bad in ("https://andyur.local/tool/fs", "spiffe://andyur.local",
                "spiffe://", "tool/filesystem", ""):
        m = copy.deepcopy(GOOD)
        m["tools"][0]["expected_spiffe_id"] = bad
        with pytest.raises(InvalidAgentManifest, match="SPIFFE ID"):
            _registry(tmp_path, m)


def test_expected_spiffe_id_is_refused_on_a_passthrough_tool(tmp_path):
    """A passthrough leg carries no Andyur-authenticated connection, so pinning
    a peer identity there is a claim nothing can enforce -- refused loudly."""
    m = copy.deepcopy(GOOD)
    m["tools"][0]["authority"] = "passthrough"
    m["tools"][0]["expected_spiffe_id"] = "spiffe://andyur.local/tool/filesystem"
    with pytest.raises(InvalidAgentManifest, match="passthrough"):
        _registry(tmp_path, m)


# --- mcp_tools: the per-tool authority grants (authority data) ----------------

def _with_mcp_tools(entries):
    m = copy.deepcopy(GOOD)
    m["tools"][0]["mcp_tools"] = entries
    return m


def test_mcp_tools_absent_defaults_none(tmp_path):
    """Additive: a manifest that does not enumerate the server's tools resolves
    exactly as before, and the decision stays audience-level."""
    tool = _registry(tmp_path, GOOD).resolve("agt_classifier").tools[0]
    assert tool.mcp_tools is None


def test_mcp_tools_tristate_empty_list_is_deny_all_not_absent(tmp_path):
    """[] must survive as an empty tuple: 'no tool may be invoked' collapsing
    into 'not enumerated' would silently widen to audience-level."""
    tool = _registry(tmp_path, _with_mcp_tools([])) \
        .resolve("agt_classifier").tools[0]
    assert tool.mcp_tools == ()


def test_mcp_tools_are_parsed_and_carried_in_order(tmp_path):
    m = _with_mcp_tools([
        {"name": "read_file", "requires": "files:read"},
        {"name": "stat_file", "requires": "files:read"},
    ])
    tool = _registry(tmp_path, m).resolve("agt_classifier").tools[0]
    assert [(g.name, g.requires) for g in tool.mcp_tools] == [
        ("read_file", "files:read"), ("stat_file", "files:read")]


def test_mcp_tools_duplicate_name_is_rejected(tmp_path):
    m = _with_mcp_tools([
        {"name": "read_file", "requires": "files:read"},
        {"name": "read_file", "requires": "files:read"},
    ])
    with pytest.raises(InvalidAgentManifest, match="duplicate mcp_tools"):
        _registry(tmp_path, m)


def test_mcp_tools_unknown_entry_field_is_rejected(tmp_path):
    m = _with_mcp_tools([
        {"name": "read_file", "requires": "files:read", "extra": 1}])
    with pytest.raises(InvalidAgentManifest, match="unknown field"):
        _registry(tmp_path, m)


def test_mcp_tools_bad_shapes_are_rejected(tmp_path):
    for bad in ("read_file", {"read_file": "files:read"},
                [["read_file", "files:read"]], [{"name": "read_file"}],
                [{"requires": "files:read"}]):
        with pytest.raises(InvalidAgentManifest):
            _registry(tmp_path, _with_mcp_tools(bad))


def test_mcp_tools_unsafe_name_or_requires_is_rejected(tmp_path):
    """The name becomes a comparison key and a filter term; the action is
    compared as a whole string. Values that cannot round-trip those paths
    (spaces, qualifiers, empties) are manifest errors, not runtime surprises."""
    for name in ("", "has space", "a" * 129, "semi;colon"):
        with pytest.raises(InvalidAgentManifest):
            _registry(tmp_path, _with_mcp_tools(
                [{"name": name, "requires": "files:read"}]))
    for req in ("", "files read", "files:read@account=447", "x" * 257):
        with pytest.raises(InvalidAgentManifest):
            _registry(tmp_path, _with_mcp_tools(
                [{"name": "read_file", "requires": req}]))


def test_mcp_tools_refused_on_a_passthrough_tool(tmp_path):
    """Same rule as expected_spiffe_id: a passthrough leg has no enforcement
    point, and an unenforced grant reads as a control."""
    m = copy.deepcopy(GOOD)
    m["tools"][0]["authority"] = "passthrough"
    m["tools"][0]["mcp_tools"] = [
        {"name": "read_file", "requires": "files:read"}]
    with pytest.raises(InvalidAgentManifest, match="passthrough"):
        _registry(tmp_path, m)


def test_mcp_tools_requiring_actions_above_the_ceiling_are_rejected(tmp_path):
    """A grant whose required action the agent's ceiling can never yield is
    dead on arrival: every tools/call would 403 while the reviewer believes the
    grant means something."""
    m = _with_mcp_tools([{"name": "write_file", "requires": "files:write"}])
    with pytest.raises(InvalidAgentManifest, match="above this agent's ceiling"):
        _registry(tmp_path, m)


def test_mcp_tools_ceiling_check_honours_unrestricted_and_qualifiers(tmp_path):
    """None and "*" ceilings restrict nothing; a qualified ceiling entry still
    names its base action, so a grant requiring that base action stands."""
    m = _with_mcp_tools([{"name": "write_file", "requires": "files:write"}])
    m["ceiling"]["actions"] = None
    m["ceiling"]["resources"] = None
    _registry(tmp_path, m)   # must not raise
    m2 = _with_mcp_tools([{"name": "write_file", "requires": "files:write"}])
    m2["ceiling"]["actions"] = ["files:write@account=447"]
    _registry(tmp_path, m2)  # must not raise


def test_mcp_tools_qualified_ceiling_grant_is_exercisable_at_runtime(tmp_path):
    """The manifest ceiling check strips @qualifiers; permitted_tools (the
    runtime gate) must match the same way, or a grant this validation blesses
    would 403 on every call -- the two sources of truth must agree."""
    from andyur.dataplane import extauthz
    m = _with_mcp_tools([{"name": "write_file", "requires": "files:write"}])
    m["ceiling"]["actions"] = ["files:write@account=447"]
    # manifest accepts it ...
    _registry(tmp_path, m)
    # ... and the runtime gate, given a decision carrying the qualified action,
    # actually permits the tool (would be [] under a whole-string compare).
    assert extauthz.permitted_tools(
        {"actions": ["files:write@account=447"]},
        {"write_file": "files:write"}) == ["write_file"]
