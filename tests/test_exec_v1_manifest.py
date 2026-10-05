"""exec/v1 manifest surface: ADR-011 D4 and D5.

The security control here is the CLOSED REFERENCE VOCABULARY. `exec/v1` needs to
put values into a stock workload's environment and config files, which is an
injection surface, and "only safe values are interpolated" is prose rather than
a control. Every reference is enumerated in code and anything else is refused.

The rule the vocabulary encodes: a manifest may name the RUN'S OWN CAPABILITY
MATERIAL, never a DOWNSTREAM CREDENTIAL.
"""

from __future__ import annotations

import copy
import json

import pytest

from andyur.agentspec.compiler import compile_resolution
from andyur.agentspec.models import InvalidManifest, PlatformPolicy
from andyur.agentspec.parser import (
    _CONFIG_REFERENCES,
    MAX_CONFIG_FILES,
    MAX_ENV_VARS,
    PROTOCOL_EXEC_V1,
    PROTOCOL_V1,
    SUPPORTED_PROTOCOLS,
    parse_manifest,
)
from andyur.registry.models import AuthorityCeiling
from andyur.registry.runtime_wire import encode_runtime

DIGEST = "sha256:" + "ab" * 32


def manifest(runtime_over=None, protocol=PROTOCOL_EXEC_V1) -> dict:
    runtime = {
        "type": "container",
        "image": {"ref": "ghcr.io/tracer-cloud/opensre", "digest": DIGEST},
        "command": ["opensre", "investigate", "-i", "-"],
        "interface": {"protocol": protocol},
    }
    if protocol == PROTOCOL_EXEC_V1:
        runtime["process"] = {"input": {"mode": "stdin"}}
    if runtime_over:
        runtime = {**runtime, **copy.deepcopy(runtime_over)}
    doc = {
        "apiVersion": "andyur.ai/v1", "kind": "Agent",
        "metadata": {"id": "agt_stock", "name": "stock-workload",
                     "version": "1.0.0"},
        "runtime": runtime,
        "instructions": "Investigate the assigned incident.",
    }
    if protocol == PROTOCOL_EXEC_V1:
        # a stock process cannot learn its model from a context: exec/v1
        # manifests MUST name one (R MED-1)
        doc["model"] = {"requested": "granted-model", "access": "proxy"}
    return doc


def config(**over) -> dict:
    return {"configuration": over}


# --------------------------------------------------------------------------
# The interface itself
# --------------------------------------------------------------------------

def _by_name(env):
    """Index the configuration's variables by name.

    `env` is a tuple of EnvVar rather than (name, value) pairs: the name lives
    inside the entry so that the wire form is a list of self-describing objects
    like every other collection, instead of one positional two-element list in
    an artifact operators read to answer "what was this run configured with".
    """
    return {var.name: var for var in env}


def test_exec_v1_is_a_served_protocol():
    assert PROTOCOL_EXEC_V1 in SUPPORTED_PROTOCOLS
    assert parse_manifest(manifest()).runtime.interface_protocol == PROTOCOL_EXEC_V1


def test_the_audited_opensre_shape_parses():
    """The configuration that actually ran the stock image in the compatibility
    audit: openai provider, proxy base URL, throwaway key, stdin input."""
    parsed = parse_manifest(manifest(config(env={
        "LLM_PROVIDER": {"literal": "openai"},
        "OPENAI_BASE_URL": {"from": "services.model.openai_base_url"},
        "OPENAI_API_KEY": {"literal": "andyur-placeholder"},
        "HOME": {"from": "workspace.home"},
    })))
    env = _by_name(parsed.runtime.configuration.env)
    assert env["LLM_PROVIDER"].literal == "openai"
    assert env["OPENAI_BASE_URL"].reference == "services.model.openai_base_url"
    assert parsed.runtime.process.input_mode == "stdin"


def test_exec_v1_requires_a_process_block():
    """Nothing about a stock binary tells the platform how to hand it a task.
    Defaulting to stdin would work for most and silently do the wrong thing for
    the rest."""
    doc = manifest()
    del doc["runtime"]["process"]
    with pytest.raises(InvalidManifest, match="requires a 'process' block"):
        parse_manifest(doc)


@pytest.mark.parametrize("key", ["process", "configuration"])
def test_process_and_configuration_are_refused_on_runtime_v1(key):
    """A runtime-v1 agent learns all of this from the context document it
    fetches. Accepting it here would be a second way to say the same thing."""
    doc = manifest(protocol="andyur-agent-runtime/v1")
    doc["runtime"][key] = {"input": {"mode": "stdin"}} if key == "process" else {}
    with pytest.raises(InvalidManifest, match="applies only to"):
        parse_manifest(doc)


# --------------------------------------------------------------------------
# THE CONTROL: a manifest may not name a downstream credential
# --------------------------------------------------------------------------

@pytest.mark.parametrize("reference", [
    "credentials.datadog",
    "vault.secret",
    "secrets.OPENAI_API_KEY",
    "services.model.api_key",
    "services.tools.credential",
    "run.subject_token",
    "../../etc/passwd",
    "services.model.base_url.evil",
    "",
])
def test_a_reference_outside_the_vocabulary_is_refused(reference):
    with pytest.raises(InvalidManifest, match="not a resolvable reference|non-empty"):
        parse_manifest(manifest(config(env={"K": {"from": reference}})))


@pytest.mark.parametrize("reference", [
    "credentials.datadog", "vault.secret", "services.model.api_key",
])
def test_the_same_reference_is_refused_inside_a_file_template(reference):
    """A config file must not become the way to say what the env mapping
    refused. Both surfaces validate against one vocabulary."""
    with pytest.raises(InvalidManifest, match="not a resolvable reference"):
        parse_manifest(manifest(config(files=[
            {"path": "/tmp/c.yaml", "template": "key: ${%s}\n" % reference}])))


def test_a_reference_is_refused_inside_a_file_path_too():
    with pytest.raises(InvalidManifest, match="not a resolvable reference"):
        parse_manifest(manifest(config(files=[
            {"path": "/tmp/${vault.secret}", "template": "x"}])))


@pytest.mark.parametrize("path", [
    "/tmp/andyur/input", "/tmp/andyur/other", "/tmp/andyur/", "/tmp/andyur/sub/x",
    # R M-A: normalised variants that a raw prefix test let through
    "/tmp//andyur/input", "/tmp/./andyur/input", "/tmp/andyur"])
def test_a_config_file_colliding_with_the_input_path_is_refused(path):
    """A file declared at (or under) the run input's directory passes the
    writable-root check but would overwrite, or be overwritten by, the input --
    silently losing 'input lands verbatim'. Refused at parse."""
    doc = manifest(config(files=[{"path": path, "template": "x"}]))
    with pytest.raises(InvalidManifest, match="run input"):
        parse_manifest(doc)
    # a sibling directory under /tmp is fine
    ok = manifest(config(files=[{"path": "/tmp/other/x", "template": "y"}]))
    assert parse_manifest(ok)


@pytest.mark.parametrize("reference", sorted(_CONFIG_REFERENCES))
def test_every_vocabulary_entry_actually_resolves(reference):
    """Positive control over the whole set. A vocabulary with a dead entry
    would refuse something the ADR says is allowed, and the refusal tests above
    would still pass."""
    # run.input_path is defined only under mode 'file'; the fixture's default
    # is the audited stdin shape, so that one entry is proven in its own mode.
    over = ({"process": {"input": {"mode": "file"}}}
            if reference == "run.input_path" else {})
    parsed = parse_manifest(manifest({**over, **config(env={"K": {"from": reference}})}))
    assert _by_name(parsed.runtime.configuration.env)["K"].reference == reference


@pytest.mark.parametrize("mode", ["stdin", "argv", "none"])
@pytest.mark.parametrize("place", ["env", "template"])
def test_input_path_is_refused_under_every_mode_but_file(mode, place):
    """${run.input_path} names a file only mode 'file' writes. Under any other
    mode the workload would open a path nothing wrote, late, in its own words;
    refused at parse, where both facts sit in one document. (A file PATH cannot
    name it at all: paths must start with a writable root, checked earlier.)"""
    if place == "env":
        configuration = config(env={"INPUT": {"from": "run.input_path"}})
    else:
        configuration = config(files=[{"path": "${workspace.tmp}/c",
                                       "template": "in: ${run.input_path}"}])
    doc = manifest({"process": {"input": {"mode": mode}}, **configuration})
    with pytest.raises(InvalidManifest, match="only defined when .* is 'file'"):
        parse_manifest(doc)
    # positive control: the same document under mode 'file' parses
    assert parse_manifest(manifest(
        {"process": {"input": {"mode": "file"}}, **configuration}))


def test_the_per_run_mcp_bearer_resolves_because_the_workload_needs_it():
    """ADR-011 D4's distinction. This is the run's OWN capability material at a
    loopback service, not authority at a third party, and the workload cannot
    call its governed endpoint without it."""
    parsed = parse_manifest(manifest(config(env={
        "SENTRY_MCP_AUTH_TOKEN": {"from": "services.tools.mcp_headers.Authorization"}})))
    assert _by_name(parsed.runtime.configuration.env)["SENTRY_MCP_AUTH_TOKEN"].reference \
        == "services.tools.mcp_headers.Authorization"


def test_a_header_prefix_does_not_admit_arbitrary_depth():
    with pytest.raises(InvalidManifest, match="does not name a valid header"):
        parse_manifest(manifest(config(env={
            "K": {"from": "services.tools.mcp_headers.a/../../secret"}})))


def test_the_platform_namespace_cannot_be_written_by_a_manifest():
    """A manifest that could set ANDYUR_* could impersonate platform
    configuration to the workload."""
    with pytest.raises(InvalidManifest, match="platform's namespace"):
        parse_manifest(manifest(config(env={
            "ANDYUR_RUNTIME_URL": {"literal": "http://attacker"}})))


# --------------------------------------------------------------------------
# Shape and bounds
# --------------------------------------------------------------------------

@pytest.mark.parametrize("spec,expected", [
    ({"literal": "a", "from": "run.id"}, "exactly one"),
    ({}, "exactly one"),
    ({"literal": "a\r\nInjected: y"}, "CR or LF"),
    ({"literal": 5}, "must be a string"),
    ({"unknown": "x"}, "unknown field"),
])
def test_malformed_env_values_are_refused(spec, expected):
    with pytest.raises(InvalidManifest, match=expected):
        parse_manifest(manifest(config(env={"K": spec})))


@pytest.mark.parametrize("name", ["1BAD", "has-dash", "has space", "", "a" * 200])
def test_invalid_environment_variable_names_are_refused(name):
    with pytest.raises(InvalidManifest, match="not a valid environment variable"):
        parse_manifest(manifest(config(env={name: {"literal": "x"}})))


@pytest.mark.parametrize("path", [
    "/etc/passwd", "/app/config.yaml", "relative/path",
    "/tmp/../etc/shadow", "/home/agent/../../etc/x",
])
def test_a_generated_file_must_land_in_the_writable_scratch(path):
    with pytest.raises(InvalidManifest, match="writable scratch|may not traverse"):
        parse_manifest(manifest(config(files=[{"path": path, "template": "x"}])))


@pytest.mark.parametrize("path", [
    "/tmp/c.yaml", "/home/agent/.config/w/config.yaml",
    "${workspace.home}/.config/w/config.yaml", "${workspace.tmp}/c.yaml",
])
def test_writable_scratch_paths_are_accepted(path):
    """Positive control: the refusals above must not be refusing everything."""
    parsed = parse_manifest(manifest(config(files=[
        {"path": path, "template": "x"}])))
    assert parsed.runtime.configuration.files[0].path == path


def test_a_duplicate_generated_path_is_refused():
    with pytest.raises(InvalidManifest, match="declared twice"):
        parse_manifest(manifest(config(files=[
            {"path": "/tmp/c", "template": "a"},
            {"path": "/tmp/c", "template": "b"}])))


def test_env_and_file_counts_are_bounded():
    with pytest.raises(InvalidManifest, match="variable limit"):
        parse_manifest(manifest(config(env={
            f"K{i}": {"literal": "v"} for i in range(MAX_ENV_VARS + 1)})))
    with pytest.raises(InvalidManifest, match="file limit"):
        parse_manifest(manifest(config(files=[
            {"path": f"/tmp/c{i}", "template": "x"}
            for i in range(MAX_CONFIG_FILES + 1)])))


@pytest.mark.parametrize("process,expected", [
    ({"input": {"mode": "telepathy"}}, "mode must be one of"),
    ({"input": {}}, "mode must be one of"),
    ({}, "'input' must be an object"),
    ({"input": {"mode": "stdin", "max_bytes": True}}, "must be an integer"),
    ({"input": {"mode": "stdin", "max_bytes": 0}}, "must be between"),
    ({"input": {"mode": "stdin", "max_bytes": 10 ** 9}}, "must be between"),
    ({"input": {"mode": "none", "max_bytes": 1024}}, "meaningless with mode 'none'"),
    ({"input": {"mode": "stdin"}, "output": {"stdout": "shout"}}, "must be one of"),
    ({"input": {"mode": "stdin"}, "unknown": 1}, "unknown field"),
])
def test_malformed_process_blocks_are_refused(process, expected):
    with pytest.raises(InvalidManifest, match=expected):
        parse_manifest(manifest({"process": process}))


def test_output_defaults_to_captured_and_bounded():
    """ADR-011 D3: captured output is diagnostic. It is still bounded, because
    an unbounded one is a denial of service dressed as a log."""
    p = parse_manifest(manifest()).runtime.process
    assert (p.stdout, p.stderr) == ("capture", "capture")
    assert 0 < p.output_max_bytes <= 16 * 1024 * 1024


# --------------------------------------------------------------------------
# The published schema must not drift from the parser
# --------------------------------------------------------------------------

def test_the_published_schema_serves_both_protocols():
    from pathlib import Path

    import andyur.agentspec as pkg
    schema = json.loads(
        (Path(pkg.__file__).parent / "agent-manifest-v1.schema.json").read_text())
    container = [b for b in schema["properties"]["runtime"]["oneOf"]
                 if b["properties"]["type"].get("const") == "container"][0]
    assert set(container["properties"]["interface"]["properties"]["protocol"]["enum"]) \
        == set(SUPPORTED_PROTOCOLS)
    assert "process" in container["properties"]
    assert "configuration" in container["properties"]


# --------------------------------------------------------------------------
# Review findings: the containment check and the regex bound
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "${services.model.base_url}/cfg.yaml",
    "${services.tools.mcp_url}/x",
    "${run.id}/cfg",
    "${services.tools.mcp_headers.Authorization}/x",
    "${services.model.name}/cfg",
])
def test_only_a_workspace_reference_may_open_a_generated_path(path):
    """The check substituted "/home/agent" for EVERY reference, so any path
    beginning with one satisfied the prefix test regardless of what it
    resolves to. Only two references resolve to a writable directory; the rest
    are identifiers, URLs and header VALUES -- the last of which would have put
    the run's bearer token in a path segment."""
    with pytest.raises(InvalidManifest, match="does not resolve to a writable"):
        parse_manifest(manifest(config(files=[{"path": path, "template": "x"}])))


def test_a_reference_may_not_appear_after_the_first_segment_of_a_path():
    """Containment cannot be established for a reference in the middle: what it
    resolves to is not known here."""
    with pytest.raises(InvalidManifest, match="only as its first segment"):
        parse_manifest(manifest(config(files=[
            {"path": "/tmp/${run.id}/cfg", "template": "x"}])))


def test_an_overlong_reference_is_seen_and_refused():
    """A `{1,128}` bound on the capture made `${` + 129 chars + `}` invisible to
    findall, so it never reached the vocabulary check and survived verbatim into
    the resolved configuration."""
    long_ref = "a" * 200
    with pytest.raises(InvalidManifest, match="not a resolvable reference"):
        parse_manifest(manifest(config(files=[
            {"path": "/tmp/c", "template": "k: ${%s}" % long_ref}])))
    with pytest.raises(InvalidManifest, match="not a resolvable reference"):
        parse_manifest(manifest(config(env={"K": {"from": long_ref}})))


@pytest.mark.parametrize("key", ["process", "configuration"])
def test_builtin_claude_refuses_process_and_configuration(key):
    """_RUNTIME_KEYS was widened to admit both, but the builtin applicability
    loop was not, so a builtin-claude manifest declaring them parsed and had
    them SILENTLY DISCARDED -- exactly what that loop's own comment says it
    exists to prevent: an unread declaration in a reviewed document."""
    doc = manifest()
    doc["runtime"] = {"type": "builtin-claude",
                      key: {"input": {"mode": "stdin"}} if key == "process" else {}}
    with pytest.raises(InvalidManifest, match="not applicable to builtin-claude"):
        parse_manifest(doc)


def test_the_adr_example_actually_loads():
    """ADR-008's acceptance is that a developer can build against the published
    spec ALONE. An earlier draft of ADR-011's D5 example put `process` and
    `configuration` at the TOP LEVEL, where the parser's closed key set refuses
    them -- so a manifest copied from the design document did not load, which is
    a defect in the design document.

    This extracts the example from the ADR and parses it, so the two cannot
    drift again.
    """
    import re
    from pathlib import Path

    import andyur.agentspec as pkg
    adr = (Path(pkg.__file__).parents[2] / "docs" /
           "adr-011-exec-v1-stock-process-contract.md").read_text()
    block = re.search(r"```yaml\n(runtime:.*?)```", adr, re.S)
    assert block, "the D5 example is no longer a yaml block named `runtime:`"
    example = block.group(1)

    # Structural pinning without taking a YAML dependency the package refuses:
    # what broke was WHERE the keys sit, so that is what is asserted.
    assert re.search(r"^  process:", example, re.M), (
        "`process` must sit under `runtime`, not at the top level")
    assert re.search(r"^  configuration:", example, re.M), (
        "`configuration` must sit under `runtime`, not at the top level")
    assert not re.search(r"^process:", example, re.M)
    assert not re.search(r"^configuration:", example, re.M)

    # And every reference the example uses must be resolvable -- asked of the
    # REAL rule rather than a restatement of it here, which is how the previous
    # version of this assertion would have gone on passing a retired scalar.
    from andyur.registry.models import check_reference

    for ref in re.findall(r"from: ([\w.]+)", example):
        check_reference(ref, "adr example", InvalidManifest)
    for ref in re.findall(r"\$\{([^}]+)\}", example):
        check_reference(ref, "adr example", InvalidManifest)


# --------------------------------------------------------------------------
# Downstream of the parser: the surface has to REACH the launch snapshot
#
# ADR-011's status line read "a manifest is fully validated and then DISCARDED
# at compile time", because RuntimeResolution -- the frozen snapshot that is
# signed, sealed on the run row and handed to a worker -- had nowhere to put
# either block. These tests are what make that sentence false, and they are the
# only guard on the compiler's hand-written constructor until the codec's
# import-time check widens to reach it (S-06).
# --------------------------------------------------------------------------

CONFIGURED = config(
    env={
        "LLM_PROVIDER": {"literal": "openai"},
        "OPENAI_BASE_URL": {"from": "services.model.openai_base_url"},
        "HOME": {"from": "workspace.home"},
    },
    files=[{"path": "${workspace.home}/.config/w/config.yaml",
            "template": "mcp_url: ${services.tools.mcp_url}\n"}],
)


def _policy(**kw) -> PlatformPolicy:
    base = dict(tool_catalog={},
                ceiling=AuthorityCeiling(actions=None, resources=None),
                approved_models=None, revision="rev-1")
    base.update(kw)
    return PlatformPolicy(**base)


def _compiled(doc):
    return compile_resolution(parse_manifest(doc), _policy()).resolution.runtime


def test_the_compiler_carries_the_exec_v1_surface():
    """The claim this increment falsifies.

    Before it, both blocks parsed, validated fail-closed, and then reached a
    constructor with no field to put them in -- so a governed launcher received
    a snapshot that could not say how the workload takes its input or what
    configuration it was promised, and nothing anywhere reported a loss.
    """
    runtime = _compiled(manifest(CONFIGURED))

    assert runtime.process is not None, "the process block did not survive compile"
    assert runtime.process.input_mode == "stdin"

    assert runtime.configuration is not None
    env = _by_name(runtime.configuration.env)
    assert env["LLM_PROVIDER"].literal == "openai"
    assert env["OPENAI_BASE_URL"].reference == "services.model.openai_base_url"
    assert len(runtime.configuration.files) == 1
    assert runtime.configuration.files[0].path.startswith("${workspace.home}")


def test_the_snapshot_carries_references_rather_than_resolved_values():
    """The design decision of the increment, pinned so it cannot erode.

    Every reference but the two workspace paths resolves to something that does
    not exist at compile time: the run id, its deadline, the per-run MCP bearer,
    the loopback service URLs. A resolution is signed ONCE and reused by every
    run of that agent, so a snapshot holding resolved values would be a snapshot
    of one run -- and the per-run bearer would be sealed into a signed artifact
    that outlives the run it belongs to.
    """
    document = json.dumps(encode_runtime(_compiled(manifest(CONFIGURED))),
                          sort_keys=True)
    assert "services.model.openai_base_url" in document
    assert "${services.tools.mcp_url}" in document
    # Nothing resolved: no scheme, no host, no bearer.
    assert "http://" not in document and "https://" not in document


def test_a_runtime_v1_agent_carries_no_process_surface():
    """exec/v1 only. A runtime-v1 agent is told what to do by the context
    document, so a process block there would be a second way to say the same
    thing -- and the parser refuses it before the compiler is reached."""
    runtime = _compiled(manifest(protocol=PROTOCOL_V1))
    assert runtime.process is None
    assert runtime.configuration is None


def test_an_exec_v1_manifest_without_a_model_is_refused():
    """R MED-1: a model-less exec/v1 grant compiled to model=None and the
    sidecar's front then pinned the platform DEFAULT -- a model the policy
    never approved. A stock process has no context to learn a model from, so
    the manifest names one or is refused; a runtime-v1 manifest may still omit it."""
    doc = manifest()
    del doc["model"]
    with pytest.raises(InvalidManifest, match="requires a 'model' block"):
        parse_manifest(doc)
    v1 = manifest(protocol=PROTOCOL_V1)
    v1.pop("model", None)
    assert parse_manifest(v1).model_requested is None

