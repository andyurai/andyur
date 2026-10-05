"""Fail-closed parser for AgentManifest v1 (`andyur.ai/v1`, kind Agent).

Same posture as `registry/manifest_registry.py`, which is the house idiom this
deliberately mirrors: unknown fields are rejected everywhere, formats are
anchored, collections are capped, and a manifest that parses is a manifest
whose every field means something. The published JSON Schema
(`agent-manifest-v1.schema.json`, shipped beside this module) documents the
same shape; `tests/test_byoa_agentspec.py` pins parser, schema, and the spec
document to each other so none can drift alone.

`load_manifest` reads JSON. YAML is an equivalent serialization of the same
schema (the spec says so and the schema is serialization-agnostic), but this
package takes no YAML dependency; the packaging CLI grows YAML loading when
it lands (ADR-008 C2) with the dependency declared, not borrowed.

Identifier formats are imported from the registry parser rather than
restated: an agent id or MCP tool name that is valid in a request but invalid
in a resolution (or vice versa) would be a seam bug, so there is exactly one
definition of each. They are private names there; the pinning test fails
loudly if they move.
"""

from __future__ import annotations

import hashlib
import json
import dataclasses
import re
from typing import get_args
from dataclasses import asdict
from pathlib import Path

from ..registry.manifest_registry import (
    MAX_MCP_TOOLS,
    _AGENT_ID_RE,
    _MCP_TOOL_NAME_RE,
    _NAME_RE,
)
from ..registry.models import (
    COMMAND_CREDENTIAL_RE,
    MAX_COMMAND_ARGS,
    MAX_COMMAND_ARG_LEN,
    LIFETIME_CEILING_SECONDS,
    LIFETIME_FLOOR_SECONDS,
    MAX_TOOL_BINDINGS,
    OCI_IMAGE_REF_RE,
    RESOURCE_QUANTITY_RE,
    RUNTIME_PROTOCOL_EXEC_V1,
    SUPPORTED_PROTOCOLS,
    LifecycleMode,
    LifecycleSpec,
    OnExit,
    RuntimeType,
    RUNTIME_PROTOCOL_V1,
    SHA256_DIGEST_RE,
    CONFIG_REFERENCES,
    CONFIG_REFERENCE_PREFIXES,
    ENV_NAME_RE,
    MAX_CONFIG_FILES as _MAX_CONFIG_FILES,
    MAX_ENV_VARS as _MAX_ENV_VARS,
    MAX_INPUT_BYTES,
    MAX_LITERAL_LEN as _MAX_LITERAL_LEN,
    MAX_OUTPUT_BYTES,
    MAX_TEMPLATE_BYTES as _MAX_TEMPLATE_BYTES,
    MIN_INPUT_BYTES,
    MIN_OUTPUT_BYTES,
    DEFAULT_INPUT_MAX_BYTES,
    DEFAULT_OUTPUT_MAX_BYTES,
    TEMPLATE_REF_RE,
    WRITABLE_REFERENCES,
    check_reference,
    validate_config_file,
    validate_configuration,
    validate_process,
)
from .models import (
    AgentManifest,
    ConfigFile,
    ConfigurationSpec,
    EnvVar,
    ImageRef,
    InvalidManifest,
    LifecycleRequest,
    ProcessSpec,
    ManifestMetadata,
    ResourceSpec,
    RuntimeSpec,
    ToolRequest,
)

API_VERSION = "andyur.ai/v1"
KIND = "Agent"
PROTOCOL_V1 = RUNTIME_PROTOCOL_V1
PROTOCOL_EXEC_V1 = RUNTIME_PROTOCOL_EXEC_V1


_TOP_KEYS = {"apiVersion", "kind", "metadata", "runtime", "instructions",
             "model", "capabilities", "input", "output"}
_METADATA_KEYS = {"id", "name", "version"}
_RUNTIME_KEYS = {"type", "image", "command", "interface", "resources",
                 "lifecycle", "process", "configuration"}
_PROCESS_KEYS = {"input", "output"}
_PROCESS_INPUT_KEYS = {"mode", "max_bytes"}
_PROCESS_OUTPUT_KEYS = {"stdout", "stderr", "max_bytes"}
_INPUT_MODES = frozenset({"stdin", "argv", "file", "none"})
_CAPTURE_MODES = frozenset({"capture", "discard"})
_CONFIGURATION_KEYS = {"env", "files"}
_ENV_VALUE_KEYS = {"literal", "from"}
_CONFIG_FILE_KEYS = {"path", "template"}

# THE CLOSED REFERENCE VOCABULARY (ADR-011 D4). Every value a manifest may ask
# the platform to resolve, enumerated here and nowhere else.
#
# The rule it encodes: a manifest may name THE RUN'S OWN CAPABILITY MATERIAL,
# never a DOWNSTREAM CREDENTIAL. The per-run MCP bearer is in the list because
# the workload cannot call its own governed endpoint without it and holding it
# grants nothing beyond what the run already has. A vendor API key is authority
# at a third party that outlives the run, which is the thing Andyur exists to
# keep out of the workload -- so no reference resolves to one, and "put the
# Datadog key in the config file" is not expressible however it is written.
#
# A prefix entry (trailing ".") admits exactly one further bounded segment.
# BOUND to the registry's definitions, not restated. These names stay here
# because they are part of this module's surface (tests parametrize over the
# vocabulary), but they are the same objects: an alias cannot drift from what it
# aliases, and a second frozenset that agrees today can.
_CONFIG_REFERENCES = CONFIG_REFERENCES
_CONFIG_REFERENCE_PREFIXES = CONFIG_REFERENCE_PREFIXES
_TEMPLATE_REF_RE = TEMPLATE_REF_RE
_ENV_NAME_RE = ENV_NAME_RE
MAX_ENV_VARS = _MAX_ENV_VARS
MAX_CONFIG_FILES = _MAX_CONFIG_FILES
MAX_TEMPLATE_BYTES = _MAX_TEMPLATE_BYTES
MAX_LITERAL_LEN = _MAX_LITERAL_LEN
_WRITABLE_REFERENCES = WRITABLE_REFERENCES
_LIFECYCLE_KEYS = {field.name for field in dataclasses.fields(LifecycleSpec)}
# DERIVED from the same Literals the registry validates against. The manifest
# surface and the wire surface are different vocabularies of KEY NAMES, but
# these three are the same closed sets of VALUES, and a manifest that accepts a
# mode the registry refuses is a manifest that reviews clean and cannot ship.
_LIFECYCLE_MODES = frozenset(get_args(LifecycleMode))
_ON_EXIT = frozenset(get_args(OnExit))
_IMAGE_KEYS = {"ref", "digest"}
_INTERFACE_KEYS = {"protocol"}
_RESOURCES_KEYS = {"cpu", "memory"}
_MODEL_KEYS = {"requested", "access"}
_CAPABILITIES_KEYS = {"tools"}
_TOOL_REQUEST_KEYS = {"server", "tools"}
_IO_KEYS = {"schema"}

_RUNTIME_TYPES = frozenset(get_args(RuntimeType))

_VERSION_RE = re.compile(r"^\d{1,9}(\.\d{1,9}){0,2}([-+][A-Za-z0-9.-]{1,32})?$")
_DIGEST_RE = SHA256_DIGEST_RE
# Conservative OCI reference subset: lowercase repository path, optional
# registry host, optional tag. '@' is refused because the digest has its own
# field and a second place to state it would be a second source of truth;
# whitespace and uppercase are refused because no real reference needs them.
_IMAGE_REF_RE = OCI_IMAGE_REF_RE
# Kubernetes-style quantities ("2", "500m", "4Gi"). Anchored so a resource
# request can be embedded in generated launch configuration verbatim, and the
# digit runs are length-bounded so every manifest string carries an explicit
# cap (a bare `\d+` would validate a 100 MB all-digit value).
_QUANTITY_RE = RESOURCE_QUANTITY_RE
# A schema reference is a relative path or URI, one line, no traversal.
_SCHEMA_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]{0,511}$")
# A model name flows into resolution.model, which the runtime enforces and the
# C2 model proxy will place in an outbound request. Anchored to the same
# conservative shape real provider/model ids use, so a value carrying CR/LF or
# other control characters -- a header-injection latent -- fails at manifest
# validation rather than reaching the proxy. Every other string field the
# parser accepts is anchored; model was the one gap.
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,127}$")
# The manifest is a public, reviewable document; these shapes in a command
# line are how credentials leak into ones. A footgun guard, not the security
# control -- the platform never supplies a secret for a manifest to hold.
_CREDENTIAL_SHAPE_RE = COMMAND_CREDENTIAL_RE

MAX_INSTRUCTIONS_LEN = 32_768


def _reject_unknown(where: str, got: dict, allowed: set[str]) -> None:
    extra = set(got) - allowed
    if extra:
        raise InvalidManifest(
            f"{where}: unknown field(s) {sorted(extra)}; allowed {sorted(allowed)}")


def _require_obj(where: str, raw: dict, key: str) -> dict:
    val = raw.get(key)
    if not isinstance(val, dict):
        raise InvalidManifest(f"{where}: {key!r} must be an object")
    return val


def _require_str(where: str, obj: dict, key: str) -> str:
    if key not in obj:
        raise InvalidManifest(f"{where}: missing required field {key!r}")
    val = obj[key]
    if not isinstance(val, str) or not val:
        raise InvalidManifest(f"{where}: {key!r} must be a non-empty string")
    return val


def _parse_metadata(raw: dict) -> ManifestMetadata:
    md = _require_obj("manifest", raw, "metadata")
    _reject_unknown("metadata", md, _METADATA_KEYS)
    agent_id = _require_str("metadata", md, "id")
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise InvalidManifest("metadata: id must be an immutable agt_* identifier")
    name = _require_str("metadata", md, "name")
    if not _NAME_RE.fullmatch(name):
        raise InvalidManifest(f"metadata: {name!r} is not a valid agent name")
    version = _require_str("metadata", md, "version")
    if not _VERSION_RE.fullmatch(version):
        raise InvalidManifest(
            f"metadata: version {version!r} must be a dotted numeric version")
    return ManifestMetadata(id=agent_id, name=name, version=version)


def _parse_image(where: str, raw, governed: bool) -> ImageRef:
    if not isinstance(raw, dict):
        raise InvalidManifest(f"{where}: image must be an object")
    _reject_unknown(where, raw, _IMAGE_KEYS)
    ref = _require_str(where, raw, "ref")
    # _IMAGE_REF_RE's charset already excludes '@', so a digest pinned into the
    # ref ("repo@sha256:...") fails this match -- the digest field is the one
    # place an immutable pin belongs.
    if not _IMAGE_REF_RE.fullmatch(ref):
        raise InvalidManifest(
            f"{where}: {ref!r} is not a plain OCI reference (digest goes in "
            "the digest field, never in the ref)")
    digest = raw.get("digest")
    if digest is not None and (
            not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest)):
        raise InvalidManifest(f"{where}: digest must match sha256:<64 hex>")
    if governed and digest is None:
        # The whole supply-chain story hangs on this refusal: a tag is a
        # mutable pointer, and governed mode admits only immutable identity.
        raise InvalidManifest(
            f"{where}: governed mode requires an immutable image digest")
    return ImageRef(ref=ref, digest=digest)


def _parse_command(where: str, raw) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise InvalidManifest(f"{where}: command must be a non-empty list of strings")
    if len(raw) > MAX_COMMAND_ARGS:
        raise InvalidManifest(
            f"{where}: command exceeds the {MAX_COMMAND_ARGS}-argument limit")
    args: list[str] = []
    for i, arg in enumerate(raw):
        if not isinstance(arg, str) or not arg or len(arg) > MAX_COMMAND_ARG_LEN:
            raise InvalidManifest(
                f"{where}: command[{i}] must be a non-empty string of at most "
                f"{MAX_COMMAND_ARG_LEN} chars")
        if _CREDENTIAL_SHAPE_RE.search(arg):
            raise InvalidManifest(
                f"{where}: command[{i}] looks like it embeds a credential; "
                "a manifest is a public document and no secret is a legal "
                "value in one")
        args.append(arg)
    return tuple(args)


def _lifetime_int(where: str, value) -> int:
    # bool is an int subclass, so `true` would otherwise be accepted as 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidManifest(f"{where} must be an integer number of seconds")
    if not LIFETIME_FLOOR_SECONDS <= value <= LIFETIME_CEILING_SECONDS:
        raise InvalidManifest(
            f"{where} must be between {LIFETIME_FLOOR_SECONDS} and "
            f"{LIFETIME_CEILING_SECONDS} seconds")
    return value


def _parse_lifecycle(raw) -> LifecycleRequest:
    """Parse a requested lifetime. Refuses combinations that cannot mean
    anything, so a reviewer never approves a manifest whose text and behaviour
    disagree. What policy does with the request is the compiler's business."""
    if not isinstance(raw, dict):
        raise InvalidManifest("runtime.lifecycle must be an object")
    _reject_unknown("runtime.lifecycle", raw, _LIFECYCLE_KEYS)

    mode = raw.get("mode")
    if mode not in _LIFECYCLE_MODES:
        raise InvalidManifest(
            f"runtime.lifecycle: mode must be one of {sorted(_LIFECYCLE_MODES)}, "
            f"got {mode!r}")
    if mode == "service":
        # The vocabulary carries 'service' because the registry and the overlay
        # must be able to READ one the day it exists. Nothing may REQUEST one
        # yet: the runtime still delivers exactly one invocation per run, with a
        # per-run event-stream budget and a pod that never restarts. Granting
        # the word would produce a long task wearing the name of a service, and
        # a manifest is a document a reviewer is entitled to believe.
        raise InvalidManifest(
            "runtime.lifecycle: mode 'service' is not implemented. The runtime "
            "serves one invocation per run (protocol v1), bounds the event "
            "stream per run, and never restarts an agent pod. Use 'task' with "
            "the max_seconds you need; a resident agent needs turn polling, "
            "stream windows and supervised restart first.")
    if "max_seconds" not in raw:
        raise InvalidManifest(
            "runtime.lifecycle: max_seconds is required; a lifecycle block that "
            "declares no bound is the same as declaring none at all")
    max_seconds = _lifetime_int("runtime.lifecycle.max_seconds", raw["max_seconds"])

    on_exit = raw.get("on_exit", "fail")
    if on_exit not in _ON_EXIT:
        raise InvalidManifest(
            f"runtime.lifecycle: on_exit must be one of {sorted(_ON_EXIT)}, "
            f"got {on_exit!r}")

    idle_seconds = None
    if raw.get("idle_seconds") is not None:
        idle_seconds = _lifetime_int("runtime.lifecycle.idle_seconds",
                                     raw["idle_seconds"])

    if mode == "task":
        if idle_seconds is not None:
            raise InvalidManifest(
                "runtime.lifecycle: idle_seconds is meaningless for a task, "
                "which has exactly one unit of work")
        if on_exit != "fail":
            raise InvalidManifest(
                f"runtime.lifecycle: on_exit={on_exit!r} is refused for a task; "
                "restarting a task would silently re-run its work")
    elif idle_seconds is not None and idle_seconds > max_seconds:
        raise InvalidManifest(
            "runtime.lifecycle: idle_seconds exceeds max_seconds, so it could "
            "never fire")

    return LifecycleRequest(mode=mode, max_seconds=max_seconds,
                            idle_seconds=idle_seconds, on_exit=on_exit)


def _check_reference(where: str, ref) -> str:
    """One reference, against the closed vocabulary.

    The rule itself lives in registry/models.py because the wire decoder needs
    the identical answer; this keeps the manifest-shaped call site and supplies
    the manifest's exception.
    """
    return check_reference(ref, where, InvalidManifest)


def _parse_process(raw) -> ProcessSpec:
    if not isinstance(raw, dict):
        raise InvalidManifest("runtime.process must be an object")
    _reject_unknown("runtime.process", raw, _PROCESS_KEYS)

    inp = raw.get("input")
    if not isinstance(inp, dict):
        raise InvalidManifest(
            "runtime.process: 'input' must be an object; a stock process has to "
            "be told how its task arrives")
    _reject_unknown("runtime.process.input", inp, _PROCESS_INPUT_KEYS)
    mode = inp.get("mode")
    if mode not in _INPUT_MODES:
        raise InvalidManifest(
            f"runtime.process.input: mode must be one of {sorted(_INPUT_MODES)}, "
            f"got {mode!r}")
    input_max = _bounded("runtime.process.input.max_bytes",
                         inp.get("max_bytes", DEFAULT_INPUT_MAX_BYTES),
                         MIN_INPUT_BYTES, MAX_INPUT_BYTES)
    if mode == "none" and "max_bytes" in inp:
        raise InvalidManifest(
            "runtime.process.input: max_bytes is meaningless with mode 'none'")

    out = raw.get("output")
    stdout, stderr = "capture", "capture"
    output_max = DEFAULT_OUTPUT_MAX_BYTES
    if out is not None:
        if not isinstance(out, dict):
            raise InvalidManifest("runtime.process.output must be an object")
        _reject_unknown("runtime.process.output", out, _PROCESS_OUTPUT_KEYS)
        for key in ("stdout", "stderr"):
            value = out.get(key, "capture")
            if value not in _CAPTURE_MODES:
                raise InvalidManifest(
                    f"runtime.process.output.{key} must be one of "
                    f"{sorted(_CAPTURE_MODES)}, got {value!r}")
        stdout = out.get("stdout", "capture")
        stderr = out.get("stderr", "capture")
        output_max = _bounded("runtime.process.output.max_bytes",
                              out.get("max_bytes", DEFAULT_OUTPUT_MAX_BYTES),
                              MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)

    spec = ProcessSpec(input_mode=mode, input_max_bytes=input_max,
                       stdout=stdout, stderr=stderr, output_max_bytes=output_max)
    # The same check the wire decoder runs. The syntax rules above are about the
    # DOCUMENT -- which keys may appear, what an omitted one means; this is about
    # the built spec, and it is what a caller constructing one in code meets.
    validate_process(spec, "runtime.process", InvalidManifest)
    return spec


def _bounded(where: str, value, low: int, high: int) -> int:
    # bool is an int subclass; `true` would otherwise pass as 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidManifest(f"{where} must be an integer")
    if not low <= value <= high:
        raise InvalidManifest(f"{where} must be between {low} and {high}")
    return value


def _check_input_path_reference(process, configuration) -> None:
    """``${run.input_path}`` names a file that exists only under mode 'file'.

    A manifest that maps it into a config under mode 'stdin' would pass every
    other check, and the workload would open a path nothing wrote -- late, in
    its own words. Refused here because both facts are in one document."""
    if process.input_mode == "file":
        return
    refs = [(f"runtime.configuration.env[{var.name!r}].from", var.reference)
            for var in configuration.env if var.reference]
    for i, config_file in enumerate(configuration.files):
        for field in ("path", "template"):
            refs.extend((f"runtime.configuration.files[{i}].{field}", ref)
                        for ref in TEMPLATE_REF_RE.findall(getattr(config_file, field)))
    for where, ref in refs:
        if ref == "run.input_path":
            raise InvalidManifest(
                f"{where}: ${{run.input_path}} is only defined when "
                f"runtime.process.input.mode is 'file' (declared: "
                f"{process.input_mode!r}); no such file exists in that mode")


def _parse_configuration(raw) -> ConfigurationSpec:
    if not isinstance(raw, dict):
        raise InvalidManifest("runtime.configuration must be an object")
    _reject_unknown("runtime.configuration", raw, _CONFIGURATION_KEYS)

    env: list[EnvVar] = []
    raw_env = raw.get("env")
    if raw_env is not None:
        if not isinstance(raw_env, dict):
            raise InvalidManifest("runtime.configuration.env must be an object")
        if len(raw_env) > MAX_ENV_VARS:
            raise InvalidManifest(
                f"runtime.configuration.env exceeds the {MAX_ENV_VARS}-variable limit")
        for name, spec in raw_env.items():
            at = f"runtime.configuration.env[{name!r}]"
            if not isinstance(name, str) or not _ENV_NAME_RE.fullmatch(name):
                raise InvalidManifest(f"{at}: not a valid environment variable name")
            if name.startswith("ANDYUR_"):
                # The platform's own bootstrap namespace. A manifest that could
                # write into it could impersonate platform configuration.
                raise InvalidManifest(
                    f"{at}: ANDYUR_* is the platform's namespace and cannot be set "
                    "by a manifest")
            if not isinstance(spec, dict):
                raise InvalidManifest(f"{at}: must be an object")
            _reject_unknown(at, spec, _ENV_VALUE_KEYS)
            has_literal, has_from = "literal" in spec, "from" in spec
            if has_literal == has_from:
                raise InvalidManifest(
                    f"{at}: exactly one of 'literal' or 'from' is required")
            if has_literal:
                literal = spec["literal"]
                if not isinstance(literal, str) or len(literal) > MAX_LITERAL_LEN:
                    raise InvalidManifest(
                        f"{at}.literal must be a string of at most "
                        f"{MAX_LITERAL_LEN} characters")
                if "\r" in literal or "\n" in literal:
                    raise InvalidManifest(
                        f"{at}.literal must not contain CR or LF")
                env.append(EnvVar(name=name, literal=literal))
            else:
                env.append(EnvVar(
                    name=name,
                    reference=_check_reference(f"{at}.from", spec["from"])))

    files: list[ConfigFile] = []
    raw_files = raw.get("files")
    if raw_files is not None:
        if not isinstance(raw_files, list):
            raise InvalidManifest("runtime.configuration.files must be a list")
        if len(raw_files) > MAX_CONFIG_FILES:
            raise InvalidManifest(
                f"runtime.configuration.files exceeds the {MAX_CONFIG_FILES}-file limit")
        seen: set[str] = set()
        for i, entry in enumerate(raw_files):
            at = f"runtime.configuration.files[{i}]"
            if not isinstance(entry, dict):
                raise InvalidManifest(f"{at}: must be an object")
            _reject_unknown(at, entry, _CONFIG_FILE_KEYS)
            config_file = ConfigFile(
                path=_require_str(at, entry, "path"),
                template=_require_str(at, entry, "template"))
            # Containment, traversal, the leading-reference rule, and every
            # reference in the path and the template: one implementation, in
            # registry/models.py, run identically by the wire decoder.
            validate_config_file(config_file, at, InvalidManifest)
            path = config_file.path
            if path in seen:
                raise InvalidManifest(f"{at}.path is declared twice")
            seen.add(path)
            files.append(config_file)

    spec = ConfigurationSpec(env=tuple(env), files=tuple(files))
    validate_configuration(spec, "runtime.configuration", InvalidManifest)
    return spec


def _parse_runtime(raw: dict, governed: bool) -> RuntimeSpec:
    rt = _require_obj("manifest", raw, "runtime")
    _reject_unknown("runtime", rt, _RUNTIME_KEYS)
    rtype = rt.get("type")
    if rtype not in _RUNTIME_TYPES:
        raise InvalidManifest(
            f"runtime: type must be one of {sorted(_RUNTIME_TYPES)}, got {rtype!r}")

    if rtype == "builtin-claude":
        # The platform owns the builtin executable, its launch, and its
        # (internal) channel; every one of these fields would be a
        # declaration nothing reads, and an unread declaration in a reviewed
        # document is worse than a refusal.
        for key in ("image", "command", "interface", "resources", "lifecycle",
                    "process", "configuration"):
            if key in rt:
                raise InvalidManifest(
                    f"runtime: {key!r} is not applicable to builtin-claude; "
                    "the platform owns the builtin runtime's packaging")
        return RuntimeSpec(type="builtin-claude")

    image = _parse_image("runtime.image", rt.get("image"), governed)
    interface = rt.get("interface")
    if not isinstance(interface, dict):
        raise InvalidManifest(
            "runtime: container runtimes must declare interface.protocol")
    _reject_unknown("runtime.interface", interface, _INTERFACE_KEYS)
    protocol = _require_str("runtime.interface", interface, "protocol")
    if protocol not in SUPPORTED_PROTOCOLS:
        raise InvalidManifest(
            f"runtime.interface: protocol {protocol!r} is not served; "
            f"supported: {sorted(SUPPORTED_PROTOCOLS)}")

    if "command" not in rt:
        raise InvalidManifest(
            "runtime: container runtimes must declare an explicit command; "
            "image entrypoint metadata is not governed executable identity")
    command = _parse_command("runtime", rt["command"])

    resources = None
    if "resources" in rt:
        res = rt["resources"]
        if not isinstance(res, dict):
            raise InvalidManifest("runtime: resources must be an object")
        _reject_unknown("runtime.resources", res, _RESOURCES_KEYS)
        parsed: dict[str, str | None] = {}
        for key in ("cpu", "memory"):
            val = res.get(key)
            if val is not None and (
                    not isinstance(val, str) or not _QUANTITY_RE.fullmatch(val)):
                raise InvalidManifest(
                    f"runtime.resources: {key} must be a quantity like '2', "
                    f"'500m', or '4Gi', got {val!r}")
            parsed[key] = val
        resources = ResourceSpec(cpu=parsed["cpu"], memory=parsed["memory"])

    lifecycle = None
    if "lifecycle" in rt:
        lifecycle = _parse_lifecycle(rt["lifecycle"])

    # `process` and `configuration` describe a STOCK PROCESS: how its task
    # arrives, how its output is treated, what is placed in its environment. A
    # runtime-v1 agent learns all of that from the context document it fetches,
    # so accepting them there would be a second way to say the same thing, and
    # the two would eventually disagree.
    exec_v1 = protocol == PROTOCOL_EXEC_V1
    for key in ("process", "configuration"):
        if key in rt and not exec_v1:
            raise InvalidManifest(
                f"runtime: {key!r} applies only to {PROTOCOL_EXEC_V1!r}; a "
                f"{protocol!r} agent takes its input and configuration from the "
                "context document it fetches")

    process = None
    configuration = None
    if exec_v1:
        if "process" not in rt:
            # Nothing about a stock binary tells the platform how to hand it a
            # task. Defaulting to stdin would work for most and silently do the
            # wrong thing for the rest, which is worse than refusing.
            raise InvalidManifest(
                f"runtime: {PROTOCOL_EXEC_V1!r} requires a 'process' block "
                "declaring how the task is delivered")
        process = _parse_process(rt["process"])
        if "configuration" in rt:
            configuration = _parse_configuration(rt["configuration"])
            _check_input_path_reference(process, configuration)

    return RuntimeSpec(type="container", image=image, command=command,
                       interface_protocol=protocol, resources=resources,
                       lifecycle=lifecycle, process=process,
                       configuration=configuration)


def _parse_model(raw: dict) -> str | None:
    if "model" not in raw:
        return None
    model = raw["model"]
    if not isinstance(model, dict):
        raise InvalidManifest("manifest: model must be an object")
    _reject_unknown("model", model, _MODEL_KEYS)
    requested = _require_str("model", model, "requested")
    if not _MODEL_RE.fullmatch(requested):
        raise InvalidManifest(
            f"model: requested {requested!r} is not a valid model identifier "
            "(letters, digits, and . _ / : @ - only)")
    access = model.get("access", "proxy")
    if access != "proxy":
        # v1 has exactly one access mode: the platform's credential-holding
        # proxy. A manifest asking for direct access is asking for a
        # credential, which no manifest may hold.
        raise InvalidManifest(
            f"model: access must be 'proxy' in v1, got {access!r}")
    return requested


def _parse_tool_requests(raw: dict) -> tuple[ToolRequest, ...]:
    if "capabilities" not in raw:
        return ()
    caps = raw["capabilities"]
    if not isinstance(caps, dict):
        raise InvalidManifest("manifest: capabilities must be an object")
    _reject_unknown("capabilities", caps, _CAPABILITIES_KEYS)
    tools = caps.get("tools", [])
    if not isinstance(tools, list):
        raise InvalidManifest("capabilities: tools must be a list")
    if len(tools) > MAX_TOOL_BINDINGS:
        raise InvalidManifest(
            f"capabilities: tools exceeds the {MAX_TOOL_BINDINGS}-server limit")
    requests: list[ToolRequest] = []
    seen_servers: set[str] = set()
    for i, entry in enumerate(tools):
        at = f"capabilities.tools[{i}]"
        if not isinstance(entry, dict):
            raise InvalidManifest(f"{at}: each entry must be an object")
        _reject_unknown(at, entry, _TOOL_REQUEST_KEYS)
        server = _require_str(at, entry, "server")
        if not _NAME_RE.fullmatch(server):
            raise InvalidManifest(f"{at}: {server!r} is not a valid server name")
        if server in seen_servers:
            raise InvalidManifest(
                f"capabilities: duplicate request for server {server!r}")
        seen_servers.add(server)
        names = entry.get("tools")
        if not isinstance(names, list) or not names:
            # An empty request is a request for nothing; write no entry
            # instead. Requiring the list non-empty keeps "requested the
            # server with no tools" from reading as "requested every tool".
            raise InvalidManifest(
                f"{at}: tools must be a non-empty list of tool names")
        if len(names) > MAX_MCP_TOOLS:
            raise InvalidManifest(
                f"{at}: tools exceeds the {MAX_MCP_TOOLS}-entry limit")
        parsed_names: list[str] = []
        seen_names: set[str] = set()
        for j, name in enumerate(names):
            if not isinstance(name, str) or not _MCP_TOOL_NAME_RE.fullmatch(name):
                raise InvalidManifest(
                    f"{at}: tools[{j}] is not a safe MCP tool name")
            if name in seen_names:
                raise InvalidManifest(f"{at}: duplicate tool name {name!r}")
            seen_names.add(name)
            parsed_names.append(name)
        requests.append(ToolRequest(server=server, tools=tuple(parsed_names)))
    return tuple(requests)


def _parse_io_schema(raw: dict, key: str) -> str | None:
    if key not in raw:
        return None
    obj = raw[key]
    if not isinstance(obj, dict):
        raise InvalidManifest(f"manifest: {key} must be an object")
    _reject_unknown(key, obj, _IO_KEYS)
    ref = _require_str(key, obj, "schema")
    if not _SCHEMA_REF_RE.fullmatch(ref) or ".." in ref:
        raise InvalidManifest(
            f"{key}: schema must be a plain relative path or URI reference")
    return ref


def parse_manifest(raw: dict, *, source: str = "manifest",
                   governed: bool = True) -> AgentManifest:
    """Parse one decoded manifest document, fail-closed.

    `governed` gates the immutable-digest requirement; it defaults on because
    the ungoverned path is the development convenience, never the assumption.
    """
    if not isinstance(raw, dict):
        raise InvalidManifest(f"{source}: manifest must be a JSON object")
    _reject_unknown(source, raw, _TOP_KEYS)
    if raw.get("apiVersion") != API_VERSION:
        raise InvalidManifest(
            f"{source}: apiVersion must be {API_VERSION!r}, "
            f"got {raw.get('apiVersion')!r}")
    if raw.get("kind") != KIND:
        raise InvalidManifest(
            f"{source}: kind must be {KIND!r}, got {raw.get('kind')!r}")

    metadata = _parse_metadata(raw)
    runtime = _parse_runtime(raw, governed)
    instructions = _require_str(source, raw, "instructions")
    if len(instructions) > MAX_INSTRUCTIONS_LEN:
        raise InvalidManifest(
            f"{source}: instructions exceed {MAX_INSTRUCTIONS_LEN} chars")
    if _CREDENTIAL_SHAPE_RE.search(instructions):
        raise InvalidManifest(
            f"{source}: instructions look like they embed a credential; a "
            "manifest is a public document and no secret is a legal value in one")

    model_requested = _parse_model(raw)
    if runtime.interface_protocol == PROTOCOL_EXEC_V1 and model_requested is None:
        # A runtime-v1 agent learns its model from the run's context; a stock
        # process has no context to fetch, and a model-less grant used to pin
        # the platform default at the front -- a model the policy never
        # approved (R MED-1). The manifest names its model, or it is refused.
        raise InvalidManifest(
            f"{source}: runtime.interface {PROTOCOL_EXEC_V1!r} requires a 'model' "
            "block; a stock process cannot learn its model from a context document")
    return AgentManifest(
        metadata=metadata,
        runtime=runtime,
        instructions=instructions,
        model_requested=model_requested,
        tool_requests=_parse_tool_requests(raw),
        input_schema=_parse_io_schema(raw, "input"),
        output_schema=_parse_io_schema(raw, "output"),
    )


def load_manifest(path: str | Path, *, governed: bool = True) -> AgentManifest:
    """Read and parse one manifest file (JSON)."""
    p = Path(path)
    try:
        raw = json.loads(p.read_text())
    except OSError as exc:
        raise InvalidManifest(f"{p}: cannot read manifest: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InvalidManifest(f"{p}: not valid JSON: {exc}") from exc
    return parse_manifest(raw, source=str(p), governed=governed)


def manifest_digest(manifest: AgentManifest) -> str:
    """The canonical digest of a parsed manifest: sha256 over the sorted-key
    JSON of its parsed content. Computed from the PARSED document, not the
    input bytes, so JSON and YAML serializations of one manifest -- and any
    key order -- share one digest, and the digest names what was validated
    rather than what was typed."""
    canonical = json.dumps(asdict(manifest), sort_keys=True,
                           separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
