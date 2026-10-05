"""The codec that ended a defect class, and the properties that keep it ended.

RuntimeResolution used to be restated by hand at four wire crossings. Adding
`lifecycle` meant editing four places, three were edited, and the worker's
envelope validator refused the name nobody had told it about -- so every
lifecycle-granted agent was unlaunchable on the only governed BYOA launcher,
silently, while ninety-five BYOA tests stayed green on hand-built fixtures.

These tests guard the three things a single codec has to get right:

  1. It must not MOVE THE BYTES. The overlay goes into a signed snapshot and
     the assignment is compared byte for byte against the run row sealed at
     admission. The goldens below were captured before any of this landed from
     the TWO hand-written encoders -- publisher._runtime_document and
     coordinator._runtime_assignment -- which agreed with each other on every
     shape. The other two crossings were decoders, and the nearest thing the
     worker produced (its hand-written return dict) CONTRADICTS the two
     lifecycle goldens rather than corroborating them, because dropping
     lifecycle was the defect.
  2. It must cover every field, structurally rather than by promise.
  3. It must keep the two boundaries' POLICIES apart while sharing the parser.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import subprocess
import sys
import pathlib
import textwrap

import pytest

from andyur import config
from andyur.daemon.governed_kubernetes import (
    LAUNCHABLE_PROTOCOLS,
    validate_runtime_envelope,
)
from andyur.registry.models import (
    RUNTIME_PROTOCOL_EXEC_V1,
    RUNTIME_PROTOCOL_V1,
    ConfigFile,
    ConfigurationSpec,
    EnvVar,
    InvalidAgentManifest,
    LifecycleSpec,
    ProcessSpec,
    ResourceSpec,
    RuntimeResolution,
)
from andyur.registry.runtime_overlay import SUPPORTED_PROTOCOLS, _parse_runtime
from andyur.registry import runtime_wire
from andyur.registry.runtime_wire import (
    _WIRE,
    CONTAINER_ONLY_FIELDS,
    decode_runtime,
    encode_runtime,
)

def _refusals():
    """The two boundaries' refusal types, resolved AT CALL TIME.

    Naming them beats a bare Exception: a TypeError or AttributeError escaping
    the parser would otherwise satisfy a test meant to prove a controlled
    refusal. But they cannot be captured at import. `test_profile.py` and
    `test_console_client.py` both `importlib.reload(config)`, which rebinds
    `InsecureProfile` to a NEW class object, while governed_kubernetes reads
    `config.InsecureProfile` per call and therefore raises the new one. A tuple
    frozen at collection time holds the pre-reload class, so these tests pass
    alone and fail in the full suite -- which is exactly how this was found.
    """
    return (InvalidAgentManifest, config.InsecureProfile)

DIGEST = "sha256:" + "ab" * 32


def _runtime(**over) -> RuntimeResolution:
    base = dict(
        runtime_type="container",
        interface_version=RUNTIME_PROTOCOL_V1,
        manifest_digest=DIGEST,
        image_ref="ghcr.io/x/y",
        image_digest=DIGEST,
        command=("/app/agent",),
    )
    base.update(over)
    return RuntimeResolution(**base)


# THE REAL REGISTRY ENTRY POINT, not decode_runtime with arguments this file
# chose. The first version of this helper called decode_runtime directly and
# handed it SUPPORTED_PROTOCOLS itself, which made every "the registry admits
# exec/v1" assertion circular: narrowing the registry's own protocol set in
# runtime_overlay.py survived the entire suite, and that narrowing IS the
# historical bug -- exec/v1 unpackageable while parsing and compiling cleanly.
_overlay = functools.partial(_parse_runtime, "agt_x")


def _canonical(runtime) -> str:
    return json.dumps(encode_runtime(runtime), sort_keys=True,
                      separators=(",", ":"))


# ---------------------------------------------------------------------------
# 1. The bytes. Captured from the four hand-written encoders BEFORE the codec
#    existed, so this is a record of what production already sealed, not a
#    restatement of what the codec happens to do now.
# ---------------------------------------------------------------------------

_C = '"command":["/app/agent"]'
_I = f'"image_digest":"{DIGEST}","image_ref":"ghcr.io/x/y"'
_M = f'"manifest_digest":"{DIGEST}"'

GOLDEN = {
    "no lifecycle": (
        _runtime(),
        '{' + _C + ',' + _I + f',"interface_version":"{RUNTIME_PROTOCOL_V1}",'
        + _M + ',"policy_revision":null,"resources":null,'
        '"runtime_type":"container"}',
    ),
    "task lifecycle": (
        _runtime(lifecycle=LifecycleSpec(mode="task", max_seconds=3600)),
        '{' + _C + ',' + _I + f',"interface_version":"{RUNTIME_PROTOCOL_V1}",'
        '"lifecycle":{"idle_seconds":null,"max_seconds":3600,"mode":"task",'
        '"on_exit":"fail"},' + _M + ',"policy_revision":null,'
        '"resources":null,"runtime_type":"container"}',
    ),
    "service lifecycle and resources": (
        _runtime(resources=ResourceSpec(cpu="2", memory="2Gi"),
                 policy_revision="rev-9",
                 lifecycle=LifecycleSpec(mode="service", max_seconds=7200,
                                         idle_seconds=600, on_exit="restart")),
        '{' + _C + ',' + _I + f',"interface_version":"{RUNTIME_PROTOCOL_V1}",'
        '"lifecycle":{"idle_seconds":600,"max_seconds":7200,"mode":"service",'
        '"on_exit":"restart"},' + _M + ',"policy_revision":"rev-9",'
        '"resources":{"cpu":"2","memory":"2Gi"},"runtime_type":"container"}',
    ),
    "builtin-claude": (
        RuntimeResolution(runtime_type="builtin-claude",
                          interface_version=None, manifest_digest=DIGEST),
        '{"command":null,"image_digest":null,"image_ref":null,'
        '"interface_version":null,' + _M + ',"policy_revision":null,'
        '"resources":null,"runtime_type":"builtin-claude"}',
    ),
}


@pytest.mark.parametrize("case", sorted(GOLDEN))
def test_the_codec_did_not_move_the_bytes(case):
    """The single most expensive thing this refactor could have broken.

    runs.runtime_resolution is compared BYTE FOR BYTE on every later
    assignment. Change these bytes and every row sealed before the deploy
    mismatches forever, reported as "no longer matches its admitted
    provenance" -- which reads to an operator as tampering, not as a refactor.
    """
    runtime, expected = GOLDEN[case]
    assert _canonical(runtime) == expected


def test_an_unset_additive_field_leaves_no_trace_in_the_bytes():
    """Why `lifecycle` is declared additive rather than merely optional.

    An agent that declared no lifetime has to produce the bytes it produced
    before the field existed. A key whose value is always null would be
    harmless in any other codec and is not harmless here.
    """
    assert "lifecycle" not in _canonical(_runtime())
    assert _WIRE["lifecycle"].additive is True
    assert "lifecycle" in _canonical(
        _runtime(lifecycle=LifecycleSpec(mode="task", max_seconds=3600)))


# ---------------------------------------------------------------------------
# 2. Coverage, structurally. This is what replaced the two anti-drift tests
#    that compared hand-maintained key sets.
# ---------------------------------------------------------------------------

def test_the_codec_covers_every_field_or_refuses_to_import():
    declared = {field.name for field in dataclasses.fields(RuntimeResolution)}
    assert set(_WIRE) == declared


def test_a_wire_rule_cannot_be_written_without_both_decisions():
    """Why _FieldWire carries no defaults.

    Both flags default to the PERMISSIVE answer if allowed to default: an
    unmarked field is emitted as null (moving bytes sealed on existing run
    rows) and admitted on a builtin-claude runtime. A field whose author
    forgot to decide would then be silently granted the wrong answer to both.
    Requiring them makes forgetting a TypeError at the table, not a fail-open
    in production.
    """
    with pytest.raises(TypeError):
        runtime_wire._FieldWire(parse=lambda v, w, e: v)
    with pytest.raises(TypeError):
        runtime_wire._FieldWire(parse=lambda v, w, e: v, additive=True)
    # Positive control: stating both is accepted, so the refusals above are
    # about the missing decisions and not about the constructor generally.
    assert runtime_wire._FieldWire(
        parse=lambda v, w, e: v, additive=True, container_only=True) is not None


@pytest.mark.parametrize("spec,attr", [
    ("RuntimeResolution", None),
    ("ResourceSpec", "resources"),
    ("LifecycleSpec", "lifecycle"),
])
def test_the_import_guard_actually_fires_rather_than_merely_existing(spec, attr):
    """The test above asserts the INVARIANT; this asserts the MECHANISM.

    Deleting the import-time raise left the whole suite green, because nothing
    exercised it -- a test named "or refuses to import" that never imported
    anything. So smuggle a field into each spec BEFORE runtime_wire is first
    imported and require the module to refuse, naming the field.

    All three specs, because the nested two are where this failed twice: their
    key sets were derived while their constructors were hand-written, so a new
    field was admitted, dropped, and re-encoded as null.
    """
    probe = textwrap.dedent(f"""
        import dataclasses
        from andyur.registry import models
        target = getattr(models, {spec!r})
        smuggled = dataclasses.field(default=None)
        smuggled.name = "smuggled_field"
        smuggled.type = "str | None"
        smuggled._field_type = dataclasses._FIELD
        target.__dataclass_fields__["smuggled_field"] = smuggled
        try:
            import andyur.registry.runtime_wire  # noqa: F401
        except RuntimeError as exc:
            print("REFUSED" if "smuggled_field" in str(exc) else "WRONG_MESSAGE")
        else:
            print("IMPORTED_ANYWAY")
    """)
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                            text=True, cwd=str(pathlib.Path(__file__).parent.parent))
    assert result.stdout.strip() == "REFUSED", (
        f"runtime_wire imported with an unmapped {spec} field: "
        f"{result.stdout.strip()} {result.stderr[-400:]}")


@pytest.mark.parametrize("case", sorted(GOLDEN))
def test_every_field_survives_a_round_trip_through_both_boundaries(case):
    """A field can be admitted and then dropped, which is the quieter half of
    the same bug: the worker's validator accepted `lifecycle` into its key set
    and then returned a hand-written dict that did not carry it."""
    runtime, _ = GOLDEN[case]
    wire = json.loads(_canonical(runtime))
    assert _overlay(wire) == runtime
    if runtime.runtime_type == "container":
        assert validate_runtime_envelope(wire) == runtime


def test_container_only_fields_are_derived_from_the_same_declaration():
    """A second hand-maintained list of field names -- one per decoder -- and
    the one that failed OPEN: a field forgotten there is a field a
    builtin-claude may carry."""
    assert set(CONTAINER_ONLY_FIELDS) == {
        "interface_version", "image_ref", "image_digest", "command",
        "resources", "lifecycle",
        # exec/v1: a builtin-claude has no stock process to configure, so
        # carrying either of these is a resolution that cannot mean anything.
        "process", "configuration",
    }
    for name in CONTAINER_ONLY_FIELDS:
        assert _WIRE[name].container_only is True


@pytest.mark.parametrize("field,value", [
    ("interface_version", RUNTIME_PROTOCOL_V1),
    ("image_ref", "ghcr.io/x/y"),
    ("image_digest", DIGEST),
    ("command", ["/app/agent"]),
    ("resources", {"cpu": "1", "memory": "1Gi"}),
    ("lifecycle", {"mode": "task", "max_seconds": 3600}),
])
def test_builtin_claude_may_carry_no_container_field(field, value):
    """`lifecycle` is the case that motivated deriving this list: the worker's
    copy omitted it, so a builtin-claude carrying a lifetime was refused by the
    registry and accepted by the launcher."""
    doc = {"runtime_type": "builtin-claude", "manifest_digest": DIGEST,
           field: value}
    with pytest.raises(InvalidAgentManifest, match="may not declare container"):
        _overlay(doc)


def test_a_builtin_claude_carrying_nothing_is_still_accepted():
    """Positive control. Without it the six refusals above would pass against
    a decoder that refused every builtin-claude."""
    assert _overlay({"runtime_type": "builtin-claude",
                     "manifest_digest": DIGEST}).runtime_type == "builtin-claude"


# ---------------------------------------------------------------------------
# 3. One parser, two policies. The decoders were merged; the boundaries were
#    not, and these are the differences that had to survive the merge.
# ---------------------------------------------------------------------------

def test_each_boundary_raises_its_own_trust_failure():
    """A bad registry snapshot and a bad HTTP envelope are different events.
    Collapsing them to one exception type would tell an operator that a signed
    artifact was malformed when a worker was handed junk, or the reverse."""
    with pytest.raises(InvalidAgentManifest):
        _parse_runtime("agt_x", {"runtime_type": "nonsense"})
    with pytest.raises(config.InsecureProfile):
        validate_runtime_envelope({"runtime_type": "nonsense"})


def test_the_worker_serves_the_protocols_the_registry_publishes_and_no_other():
    """exec/v1 was packageable before it was launchable, and `protocols` being
    an argument is what let the two boundaries say so separately. Since the
    flip (gated on M1, see governed_kubernetes.LAUNCHABLE_PROTOCOLS) both
    admit the same two, and BOTH still refuse a protocol neither knows: a
    launcher that admitted more than the registry would run a contract nobody
    published.
    """
    assert RUNTIME_PROTOCOL_EXEC_V1 in SUPPORTED_PROTOCOLS
    assert RUNTIME_PROTOCOL_EXEC_V1 in LAUNCHABLE_PROTOCOLS
    assert LAUNCHABLE_PROTOCOLS <= SUPPORTED_PROTOCOLS

    # A VALID exec/v1: it must carry a process block (the parser and now the
    # codec require it -- see the C2 tests below), so this is the packageable
    # shape, not the bare one the codec used to admit.
    exec_v1 = encode_runtime(_runtime(
        interface_version=RUNTIME_PROTOCOL_EXEC_V1,
        process=ProcessSpec(input_mode="stdin", input_max_bytes=1024)))
    assert _overlay(exec_v1).interface_version == RUNTIME_PROTOCOL_EXEC_V1
    assert validate_runtime_envelope(exec_v1).interface_version == RUNTIME_PROTOCOL_EXEC_V1
    # and a protocol NEITHER boundary knows is refused at the launcher by name
    with pytest.raises(config.InsecureProfile, match="is not served here"):
        validate_runtime_envelope({**exec_v1, "interface_version": "exec/v99"})


def test_only_the_worker_demands_an_explicit_command():
    """Falling back to the platform entrypoint would make a third-party image
    execute `python -m andyur.agent`, which it never approved. That is a launch
    concern, so the registry stays silent about it and the launcher does not.
    """
    no_command = encode_runtime(_runtime(command=None))
    assert _overlay(no_command).command is None
    with pytest.raises(config.InsecureProfile, match="requires an explicit command"):
        validate_runtime_envelope(no_command)


def test_a_command_carrying_an_inline_credential_is_refused_at_both():
    """Shared parsing is the point: one rule, enforced identically wherever the
    object arrives from."""
    doc = encode_runtime(_runtime())
    doc["command"] = ["/app/agent", "--token=hunter2"]
    for boundary in (_overlay, validate_runtime_envelope):
        with pytest.raises(_refusals(), match="no inline credential"):
            boundary(doc)


def test_an_unknown_field_is_refused_rather_than_ignored():
    """If either reader ignored unknown keys, an older platform handed a newer
    snapshot would silently run a 24-hour service as a 900-second task."""
    doc = encode_runtime(_runtime())
    doc["something_newer"] = 1
    for boundary in (_overlay, validate_runtime_envelope):
        with pytest.raises(_refusals(), match="unknown fields"):
            boundary(doc)


def test_a_stand_in_shaped_like_a_resource_spec_is_refused_by_name():
    """The stale-fixture trap, closed at the encoder.

    A duck-typed stand-in used to serialize fine, because the old encoders read
    attributes. That is how a fake goes stale without saying so, and it is why
    ninety-five tests passed against an unlaunchable platform. The refusal
    names the field so the failure is the fake, not a TypeError from inside
    json.dumps.
    """
    from types import SimpleNamespace

    with pytest.raises(TypeError, match="resources holds SimpleNamespace"):
        encode_runtime(_runtime(resources=SimpleNamespace(cpu="2", memory="2Gi")))


# ---------------------------------------------------------------------------
# 4. The bounds, pinned at BOTH boundaries.
#
# This closes the one real cost of merging the two parsers, and it was found by
# mutation rather than argued: before the merge a bound had to be deleted from
# two separate parsers to disappear, so a single careless edit left one of them
# standing. Now one edit removes it everywhere. Four mutations survived the
# whole suite for exactly this reason -- and survived at HEAD too, so the gap
# is older than this change; the merge is what makes closing it urgent.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,value,expected", [
    ("image_ref", "ghcr.io/" + "a" * 1017, "at most 1024 characters"),
    ("policy_revision", "", "non-empty string"),
    ("interface_version", "v" * 513, "at most 512 characters"),
    ("image_digest", "sha256:" + "a" * 65, "at most 71 characters"),
])
def test_each_string_bound_holds_at_both_boundaries(field, value, expected):
    doc = encode_runtime(_runtime())
    doc[field] = value
    for boundary in (_overlay, validate_runtime_envelope):
        with pytest.raises(_refusals(), match=expected):
            boundary(doc)


def test_the_command_argument_length_bound_holds_at_both_boundaries():
    doc = encode_runtime(_runtime())
    doc["command"] = ["/app/agent", "x" * 4097]
    for boundary in (_overlay, validate_runtime_envelope):
        with pytest.raises(_refusals(), match="non-empty strings"):
            boundary(doc)
    # Positive control: one byte under the limit is accepted, so the refusal
    # above is the bound and not a blanket rejection of long arguments.
    doc["command"] = ["/app/agent", "x" * 4096]
    assert len(_overlay(doc).command) == 2


def test_an_unknown_resources_key_is_refused_at_both_boundaries():
    doc = encode_runtime(_runtime(resources=ResourceSpec(cpu="1", memory="1Gi")))
    doc["resources"] = {"cpu": "1", "memory": "1Gi", "cores": "9"}
    for boundary in (_overlay, validate_runtime_envelope):
        with pytest.raises(_refusals(), match=r"unknown fields \['cores'\]"):
            boundary(doc)


def test_a_resource_quantity_must_be_bounded_at_both_boundaries():
    doc = encode_runtime(_runtime())
    doc["resources"] = {"cpu": "all-of-it", "memory": None}
    for boundary in (_overlay, validate_runtime_envelope):
        with pytest.raises(_refusals(), match="not a bounded resource quantity"):
            boundary(doc)


# ---------------------------------------------------------------------------
# 4. exec/v1 crosses the wire (ADR-011 D5)
#
# The goldens in section 1 were captured from the hand-written encoders BEFORE
# the codec existed, so they record what production had already sealed. The one
# below cannot be, and saying so matters: exec/v1 is a NEW shape that no
# deployed encoder ever produced, so this pins a decision rather than preserving
# a fact. What preserves the facts is that section 1 still passes unchanged --
# every agent that declares neither block produces the same bytes it always did,
# which is what `additive` buys and why both fields are declared that way.
# ---------------------------------------------------------------------------

EXEC_PROCESS = ProcessSpec(input_mode="stdin", input_max_bytes=262144)
EXEC_CONFIGURATION = ConfigurationSpec(
    env=(EnvVar(name="LLM_PROVIDER", literal="openai"),
         EnvVar(name="OPENAI_BASE_URL",
                reference="services.model.openai_base_url")),
    files=(ConfigFile(path="${workspace.home}/c.yaml",
                      template="mcp_url: ${services.tools.mcp_url}"),))


def _exec_runtime(**over) -> RuntimeResolution:
    base = dict(interface_version=RUNTIME_PROTOCOL_EXEC_V1,
                process=EXEC_PROCESS, configuration=EXEC_CONFIGURATION)
    base.update(over)
    return _runtime(**base)


def test_the_exec_v1_surface_round_trips_through_the_registry():
    """Through the REAL overlay entry point, not decode_runtime with arguments
    this file chose -- the same circularity that once made every "the registry
    admits exec/v1" assertion prove nothing."""
    decoded = _overlay(encode_runtime(_exec_runtime()))
    assert decoded == _exec_runtime()
    assert decoded.process.input_mode == "stdin"
    assert decoded.configuration.env[1].reference == "services.model.openai_base_url"


def test_an_unset_exec_surface_leaves_no_trace_in_the_bytes():
    """The same rule `lifecycle` established, for two more fields.

    A key whose value is always null would be harmless in most codecs. Here the
    assignment string is compared byte for byte against the value sealed on the
    run row at admission, so a new always-present key invalidates every row
    sealed before the deploy -- surfacing as "no longer matches its admitted
    provenance", which reads to an operator as tampering rather than a deploy.
    """
    document = encode_runtime(_runtime())
    assert "process" not in document
    assert "configuration" not in document


def test_a_signed_snapshot_may_not_smuggle_an_unknown_reference():
    """Why the vocabulary moved out of the manifest parser.

    A decoder that admits a reference the parser would have refused hands the
    launcher something to resolve, and ADR-011 D7 is explicit that nothing
    refuses on the workload's behalf: a stock binary starts under whatever it is
    given and fails in its own way, later, having perhaps already acted. Bytes
    are not trusted just because they are signed.
    """
    document = encode_runtime(_exec_runtime())
    document["configuration"]["env"][1]["reference"] = "services.model.api_key"
    with pytest.raises(_refusals()) as caught:
        _overlay(document)
    # The refusal names the closed set rather than hinting at it.
    assert "not a resolvable reference" in str(caught.value)


def test_a_generated_file_may_not_escape_the_writable_scratch_on_the_wire():
    """The containment rule is the parser's, run again at the trust boundary --
    one implementation in registry/models.py, called by both."""
    document = encode_runtime(_exec_runtime())
    document["configuration"]["files"][0]["path"] = "/etc/passwd"
    with pytest.raises(_refusals()):
        _overlay(document)


def test_a_duplicate_variable_is_refused_on_the_wire():
    """Unreachable from a manifest, whose env is an object and cannot repeat a
    key. Reachable HERE, where env is a list -- and a duplicate there is a
    launcher picking between two values by iteration order."""
    document = encode_runtime(_exec_runtime())
    document["configuration"]["env"].append(
        {"name": "LLM_PROVIDER", "literal": "anthropic", "reference": None})
    with pytest.raises(_refusals()):
        _overlay(document)


def test_a_builtin_claude_may_not_carry_the_exec_v1_surface():
    """Container-only, enforced at both boundaries from one declaration. A
    builtin-claude has no stock process to configure, so a resolution carrying
    either block cannot mean anything."""
    document = encode_runtime(
        RuntimeResolution(runtime_type="builtin-claude", interface_version=None,
                          manifest_digest=DIGEST, process=EXEC_PROCESS))
    with pytest.raises(_refusals()):
        _overlay(document)


def test_the_parser_and_the_decoder_share_one_vocabulary_object():
    """Not "the two sets are equal" -- equal sets drift. The manifest parser's
    name is a BINDING to the registry's, so there is one object and nothing to
    keep in step."""
    from andyur.agentspec import parser as manifest_parser
    from andyur.registry import models as registry_models

    assert manifest_parser._CONFIG_REFERENCES is registry_models.CONFIG_REFERENCES
    assert manifest_parser._TEMPLATE_REF_RE is registry_models.TEMPLATE_REF_RE


# ---------------------------------------------------------------------------
# C2 (R PR#17): the codec mirrors the parser's interface<->process/configuration
# COMBINATION rule, at BOTH decode boundaries. Without it a signed snapshot
# could carry process/configuration on a runtime-v1 container, or exec/v1 with
# no process, that the manifest parser refuses -- and the worker would build an
# init container + bearer secretKeyRef for it and the run would die at init.
# ---------------------------------------------------------------------------
import pytest as _pytest
from andyur.registry.models import (RUNTIME_PROTOCOL_EXEC_V1, ProcessSpec,
                                    ConfigurationSpec, EnvVar, InvalidAgentManifest)
from andyur.registry.runtime_overlay import _parse_runtime as _registry_decode
from andyur.daemon.governed_kubernetes import validate_runtime_envelope as _worker_decode
from andyur import config as _config

_EXEC_PROC = ProcessSpec(input_mode="stdin", input_max_bytes=1024)
_EXEC_CFG = ConfigurationSpec(env=(EnvVar(name="HOME", reference="workspace.home"),), files=())


def _wire(**over):
    return encode_runtime(_runtime(**over))


def test_codec_refuses_process_or_configuration_on_a_runtime_v1_container():
    """Mutant 11: keyed on interface_version, not merely on being a container.
    A runtime-v1 CONTAINER carrying either is refused by name (the interface),
    at the registry boundary."""
    for field, value in (("process", _EXEC_PROC), ("configuration", _EXEC_CFG)):
        with _pytest.raises(InvalidAgentManifest, match=r"applies only to 'exec/v1'"):
            _registry_decode("agt", _wire(**{field: value}))


def test_codec_refuses_exec_v1_without_a_process_block():
    """The exec/v1-without-process combo the parser refuses, at the registry
    boundary (which serves exec/v1)."""
    with _pytest.raises(InvalidAgentManifest, match=r"requires a process block"):
        _registry_decode("agt", _wire(interface_version=RUNTIME_PROTOCOL_EXEC_V1))


def test_codec_accepts_the_adr_d5_exec_v1_shape_and_a_plain_runtime_v1():
    """Mutant 10 (rule inverted): the positive control. exec/v1 WITH a process
    (the ADR-011 D5 shape) decodes, and a plain runtime-v1 decodes, at BOTH
    boundaries."""
    good_exec = _wire(interface_version=RUNTIME_PROTOCOL_EXEC_V1,
                      process=_EXEC_PROC, configuration=_EXEC_CFG)
    assert _registry_decode("agt", good_exec).process == _EXEC_PROC
    # since the M1 flip the worker serves exec/v1 too: the same D5 shape decodes
    # at the worker boundary with its process block intact (positive control for
    # the combination rule, which the next test proves still refuses).
    assert _worker_decode(good_exec).process == _EXEC_PROC
    plain = _wire()
    assert _registry_decode("agt", plain).interface_version == RUNTIME_PROTOCOL_V1
    assert _worker_decode(plain).interface_version == RUNTIME_PROTOCOL_V1


def test_codec_combination_rule_is_enforced_at_the_worker_boundary_too():
    """Mutant 9: the rule holds at BOTH decode sites. The worker serves v1, so
    a v1 container carrying configuration is refused here as well -- proving the
    rule is not registry-only."""
    with _pytest.raises(_config.InsecureProfile, match=r"applies only to 'exec/v1'"):
        _worker_decode(_wire(configuration=_EXEC_CFG))
    with _pytest.raises(_config.InsecureProfile, match=r"applies only to 'exec/v1'"):
        _worker_decode(_wire(process=_EXEC_PROC))
