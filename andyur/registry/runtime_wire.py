"""The one translation between RuntimeResolution and its wire form.

A RuntimeResolution crosses three boundaries where only bytes can travel: the
cosign-signed snapshot on disk, the ``runs.runtime_resolution`` column, and the
HTTP assignment handed to a worker. Three boundaries, four crossings, because
the middle one is crossed twice.

Each of those four crossings used to spell the field names out by hand. Adding
``lifecycle`` therefore meant editing four places; three were edited, and the
fourth -- the worker's envelope validator -- refused the name it had never been
told about. Every lifecycle-granted agent became unlaunchable on the only
governed BYOA launcher, and silently: the launch failed, the run stayed
pending, and the reaper failed it later as "never started". Ninety-five BYOA
tests stayed green because their fixtures were hand-built from the same stale
list.

So there is now exactly one list, ``_WIRE``, and it cannot be incomplete: this
module refuses to import unless it covers every field of RuntimeResolution,
and the same check covers the two nested specs. A field added without a wire
rule reddens the whole suite at collection time instead of one launch path in
production. That is the difference between a promise to remember and a thing
that cannot be forgotten.

The guarantee is exactly this and no wider: it binds the four WIRE crossings.
The compiler that BUILDS a RuntimeResolution (``agentspec/compiler.py``) and
``models.lifecycle_from_assignment``, which reads the lifetime back off the run
row, still enumerate fields by hand; a new field lands there as its default
without complaint. Widening the check to them is the next deletion boundary,
not a claim this module gets to make.

Three invariants live here, all load-bearing.

**Additive fields are omitted when None, never emitted as null.** The overlay
document is dumped into a signed snapshot and the assignment string is compared
byte for byte against the value sealed on the run row at admission. A key whose
value is always null changes the bytes for every agent that declared nothing,
which invalidates every row sealed before the deploy and surfaces as "no longer
matches its admitted provenance" -- a message that reads as tampering.

**The decoders differ by policy, not by parsing.** The registry overlay serves
both protocols the platform publishes; the worker serves only the one it can
actually launch, demands an explicit command, and raises at a different trust
boundary. Those are arguments to ``decode_runtime``, not duplicated parser
bodies, so the difference is stated once where it is decided. The PARSING is
the same at both, and it mirrors the manifest parser -- including the
combination rules that pair the interface with process/configuration (exec/v1
requires a process; a runtime-v1 container carries neither) -- so a signed
snapshot cannot decode into a shape the manifest surface would have refused.

**Which fields are container-only is authority, so it is declared here too.**
It was a second hand-maintained list of field names -- one in each decoder --
and it fails OPEN: a field added to the dataclass and forgotten there is a
field a builtin-claude runtime may silently carry.

The nested specs (ResourceSpec, LifecycleSpec) are encoded whole, every field
emitted, because neither has an additive field and both are written and read as
one unit. Adding a field to either changes the wire bytes for every agent that
carries one, which is what ``test_runtime_wire``'s frozen goldens exist to
catch.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, get_args

from .models import (
    COMMAND_CREDENTIAL_RE,
    RUNTIME_PROTOCOL_EXEC_V1,
    LIFETIME_CEILING_SECONDS,
    LIFETIME_FLOOR_SECONDS,
    MAX_COMMAND_ARGS,
    MAX_COMMAND_ARG_LEN,
    MAX_CONFIG_FILES,
    MAX_CONFIG_PATH_LEN,
    MAX_ENV_VARS,
    MAX_LITERAL_LEN,
    MAX_TEMPLATE_BYTES,
    OCI_IMAGE_REF_RE,
    RESOURCE_QUANTITY_RE,
    SHA256_DIGEST_RE,
    CaptureMode,
    ConfigFile,
    ConfigurationSpec,
    EnvVar,
    InputMode,
    LifecycleMode,
    LifecycleSpec,
    OnExit,
    ProcessSpec,
    ResourceSpec,
    RuntimeResolution,
    RuntimeType,
    validate_config_file,
    validate_configuration,
    validate_env_var,
    validate_process,
)

# Derived from the annotations rather than restated. Each of these closed
# vocabularies was previously a literal set in three places -- both decoders
# and the manifest parser -- with `lifecycle_from_assignment` inlining two of
# them a fourth time. All of those now read these, so a value added to a
# Literal cannot be honoured by one reader and coerced away by another.
RUNTIME_TYPES = get_args(RuntimeType)
LIFECYCLE_MODES = get_args(LifecycleMode)
ON_EXIT_VALUES = get_args(OnExit)
INPUT_MODES = get_args(InputMode)
CAPTURE_MODES = get_args(CaptureMode)


# A parser takes the raw value, the dotted path to report it under, and the
# exception class of the boundary that is refusing. The boundary supplies the
# exception because a registry snapshot and an HTTP envelope are different
# trust failures and an operator has to be able to tell them apart.
Parser = Callable[[object, str, "type[Exception]"], object]

# Sentinel: distinguishes "this key may be omitted, and omission means X"
# from "omission is a refusal". None cannot do that job here, because
# None is itself a legal value for most of these fields.
_REQUIRED = object()


@dataclasses.dataclass(frozen=True)
class _FieldWire:
    """Everything the wire needs to know about one RuntimeResolution field."""

    parse: Parser
    # NO DEFAULTS on either flag, deliberately. A default is a decision made on
    # behalf of whoever forgets to make it, and both of these default to the
    # PERMISSIVE answer: an un-marked field would be emitted as null (moving
    # the sealed bytes) and admitted on a builtin-claude runtime. Requiring
    # both keeps "I forgot" and "I decided" distinguishable.
    additive: bool
    container_only: bool


def _optional_string(max_len: int) -> Parser:
    def parse(value, where, error):
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > max_len:
            raise error(
                f"{where} must be null or a non-empty string at most "
                f"{max_len} characters")
        return value

    return parse


def _one_of(values: tuple[str, ...], *, absent=_REQUIRED) -> Parser:
    """One closed vocabulary. `absent` is the value an omitted key means, and
    defaults to "omission is an error" so a vocabulary field cannot quietly
    acquire a meaning nobody chose."""
    def parse(value, where, error):
        if value is None and absent is not _REQUIRED:
            return absent
        if value not in values:
            raise error(f"{where} is invalid; expected one of {sorted(values)}")
        return value

    return parse


def _parse_manifest_digest(value, where, error):
    """Required, unlike every other string here: it names the reviewed manifest
    this executable identity was approved under, and a resolution that cannot
    say which manifest approved it is not a resolution."""
    digest = _optional_string(71)(value, where, error)
    if digest is None or not SHA256_DIGEST_RE.fullmatch(digest):
        raise error(f"{where} must be sha256:<64 hex>")
    return digest


def _parse_command(value, where, error):
    if value is None:
        return None
    # A tuple is accepted alongside a list because in-process callers construct
    # one; json.loads only ever yields a list, so this widens nothing on the
    # wire itself.
    if (not isinstance(value, (list, tuple)) or not value or
            len(value) > MAX_COMMAND_ARGS or
            not all(isinstance(part, str) and part and
                    len(part) <= MAX_COMMAND_ARG_LEN and
                    not COMMAND_CREDENTIAL_RE.search(part)
                    for part in value)):
        raise error(
            f"{where} must be null or 1..{MAX_COMMAND_ARGS} non-empty strings "
            "carrying no inline credential")
    return tuple(value)


@dataclasses.dataclass(frozen=True)
class _NestedWire:
    """A nested frozen spec, its per-field parsers, and its cross-field rule.

    RuntimeResolution's own coverage check does not reach in here, and the
    first version of this module proved that matters: the key sets for these
    two specs were DERIVED while their constructors were still hand-written
    kwargs, so a field added to ResourceSpec was admitted by the unknown-key
    check and then dropped on the floor by the constructor -- and re-encoded
    as null, so a signed overlay declaring it would decode, lose it, and launch
    without it. That is the same asymmetry, one level down, inside the module
    written to end it. `parsers` is checked against the dataclass at import for
    exactly the same reason `_WIRE` is.
    """

    spec: type
    parsers: dict[str, Parser]
    # Combinations that parse field-by-field and still cannot mean anything.
    check: object = None


def _parse_nested(nested: _NestedWire, value, where, error):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise error(f"{where} must be null or an object")
    unknown = set(value) - set(nested.parsers)
    if unknown:
        raise error(f"{where} has unknown fields {sorted(unknown)}")
    built = nested.spec(**{
        name: parse(value.get(name), f"{where}.{name}", error)
        for name, parse in nested.parsers.items()
    })
    if nested.check is not None:
        nested.check(built, where, error)
    return built


def _resource_quantity(max_len: int) -> Parser:
    def parse(value, where, error):
        quantity = _optional_string(max_len)(value, where, error)
        if quantity is not None and not RESOURCE_QUANTITY_RE.fullmatch(quantity):
            raise error(f"{where} is not a bounded resource quantity")
        return quantity

    return parse


def _bounded_seconds(value, where, error):
    # bool is an int subclass in Python, and True would otherwise pass as 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise error(f"{where} must be an integer")
    if not LIFETIME_FLOOR_SECONDS <= value <= LIFETIME_CEILING_SECONDS:
        raise error(
            f"{where} must be between {LIFETIME_FLOOR_SECONDS} and "
            f"{LIFETIME_CEILING_SECONDS} seconds")
    return value


def _optional_seconds(value, where, error):
    return None if value is None else _bounded_seconds(value, where, error)


def _lifecycle_combination(spec, where, error):
    """A task has exactly one unit of work, so it has no idle window and is
    never restarted. Accepting those keys on a task would let a reviewer
    approve a manifest whose text says one thing and whose behaviour is
    another."""
    if spec.mode == "task":
        if spec.idle_seconds is not None:
            raise error(
                f"{where}: idle_seconds is meaningless for a task, which has "
                "exactly one unit of work")
        if spec.on_exit != "fail":
            raise error(
                f"{where}: on_exit={spec.on_exit!r} is refused for a task; "
                "restarting a task would silently re-run its work")
    elif spec.idle_seconds is not None and spec.idle_seconds > spec.max_seconds:
        raise error(
            f"{where}: idle_seconds exceeds max_seconds, so it could never fire")


_RESOURCES = _NestedWire(spec=ResourceSpec, parsers={
    "cpu": _resource_quantity(32),
    "memory": _resource_quantity(32),
})

_LIFECYCLE = _NestedWire(spec=LifecycleSpec, check=_lifecycle_combination, parsers={
    "mode": _one_of(LIFECYCLE_MODES),
    "max_seconds": _bounded_seconds,
    "idle_seconds": _optional_seconds,
    # Absent means "fail": the conservative half, and the value the publisher
    # has always written, so making it explicit moves no bytes.
    "on_exit": _one_of(ON_EXIT_VALUES, absent="fail"),
})


def _parse_resources(value, where, error):
    return _parse_nested(_RESOURCES, value, where, error)


def _parse_lifecycle(value, where, error):
    return _parse_nested(_LIFECYCLE, value, where, error)


def _passthrough(value, where, error):
    """Carry the raw value to the nested spec's `check`, which owns its rules.

    Used where the bounds live in models.py beside the dataclass and are shared
    with the manifest parser. A second copy of "between 1 and 8 MiB" here is a
    second thing to keep in step, and this module exists because that pattern
    already cost a production outage once.
    """
    return value


def _required_string(max_len: int) -> Parser:
    def parse(value, where, error):
        if not isinstance(value, str) or not value or len(value) > max_len:
            raise error(
                f"{where} must be a non-empty string at most {max_len} "
                "characters")
        return value

    return parse


def _nested_list(nested: _NestedWire, limit: int) -> Parser:
    """A list of nested frozen specs, each parsed by the same rules as one.

    Absence means EMPTY, stated rather than assumed: the encoder always emits
    both collection keys, so an omitted one comes from a hand-built or older
    document, and "the workload was given no variables" is the conservative
    reading of silence. The per-entry `check` runs here; collection-level rules
    (limits, duplicates) belong to the parent's `check`, which can see them all.
    """
    def parse(value, where, error):
        if value is None:
            return ()
        if not isinstance(value, (list, tuple)):
            raise error(f"{where} must be a list")
        if len(value) > limit:
            raise error(f"{where} holds more than {limit} entries")
        return tuple(
            _parse_nested(nested, item, f"{where}[{index}]", error)
            for index, item in enumerate(value))

    return parse


def _process_combination(spec, where, error):
    validate_process(spec, where, error)


def _configuration_combination(spec, where, error):
    validate_configuration(spec, where, error)


def _env_var_combination(spec, where, error):
    validate_env_var(spec, where, error)


def _config_file_combination(spec, where, error):
    validate_config_file(spec, where, error)


_PROCESS = _NestedWire(spec=ProcessSpec, check=_process_combination, parsers={
    "input_mode": _one_of(INPUT_MODES),
    "input_max_bytes": _passthrough,
    # Absent means "capture", the value the publisher has always written, so
    # making it explicit moves no bytes.
    "stdout": _one_of(CAPTURE_MODES, absent="capture"),
    "stderr": _one_of(CAPTURE_MODES, absent="capture"),
    "output_max_bytes": _passthrough,
})

_ENV_VAR = _NestedWire(spec=EnvVar, check=_env_var_combination, parsers={
    "name": _required_string(128),
    "literal": _optional_string(MAX_LITERAL_LEN),
    "reference": _optional_string(512),
})

_CONFIG_FILE = _NestedWire(
    spec=ConfigFile, check=_config_file_combination, parsers={
        "path": _required_string(MAX_CONFIG_PATH_LEN),
        "template": _required_string(MAX_TEMPLATE_BYTES),
    })

_CONFIGURATION = _NestedWire(
    spec=ConfigurationSpec, check=_configuration_combination, parsers={
        "env": _nested_list(_ENV_VAR, MAX_ENV_VARS),
        "files": _nested_list(_CONFIG_FILE, MAX_CONFIG_FILES),
    })


def _parse_process(value, where, error):
    return _parse_nested(_PROCESS, value, where, error)


def _parse_configuration(value, where, error):
    return _parse_nested(_CONFIGURATION, value, where, error)


# THE ONE LIST. Every field of RuntimeResolution appears here exactly once, and
# the check below makes that structural rather than aspirational.
_WIRE: dict[str, _FieldWire] = {
    "runtime_type": _FieldWire(
        parse=_one_of(RUNTIME_TYPES), additive=False, container_only=False),
    "interface_version": _FieldWire(
        parse=_optional_string(512), additive=False, container_only=True),
    "manifest_digest": _FieldWire(
        parse=_parse_manifest_digest, additive=False, container_only=False),
    "image_ref": _FieldWire(
        parse=_optional_string(1024), additive=False, container_only=True),
    "image_digest": _FieldWire(
        parse=_optional_string(71), additive=False, container_only=True),
    "command": _FieldWire(
        parse=_parse_command, additive=False, container_only=True),
    "resources": _FieldWire(
        parse=_parse_resources, additive=False, container_only=True),
    "policy_revision": _FieldWire(
        parse=_optional_string(256), additive=False, container_only=False),
    "lifecycle": _FieldWire(
        parse=_parse_lifecycle, additive=True, container_only=True),
    # exec/v1. Additive for the same reason lifecycle is -- every agent sealed
    # before this deploy declared neither, and emitting them as null would move
    # the bytes of every one of those rows. Container-only because a
    # builtin-claude has no stock process to configure.
    "process": _FieldWire(
        parse=_parse_process, additive=True, container_only=True),
    "configuration": _FieldWire(
        parse=_parse_configuration, additive=True, container_only=True),
}


def _covers(table, spec, what: str) -> None:
    """Refuse at IMPORT when a wire table and its dataclass disagree.

    Import-time, deliberately, and extracted so a test can exercise the raise
    itself rather than only its consequences. A field cannot reach one of these
    specs without reaching the code that carries it across the wire, because
    the omission stops the process instead of one path inside it.
    """
    declared = {field.name for field in dataclasses.fields(spec)}
    missing, extra = declared - set(table), set(table) - declared
    if missing or extra:
        raise RuntimeError(
            f"{what} is out of step with {spec.__name__}: "
            f"missing wire rules for {sorted(missing)}, "
            f"rules for fields that do not exist {sorted(extra)}. "
            "Every field needs a wire rule and, at the top level, an explicit "
            "additive and container-only decision -- because forgetting one of "
            "them is how lifecycle-granted agents became unlaunchable, and how "
            "a nested field was later admitted and then silently dropped.")


_DECLARED = tuple(field.name for field in dataclasses.fields(RuntimeResolution))
_covers(_WIRE, RuntimeResolution, "runtime_wire._WIRE")
# The nested specs get the same treatment. Deriving their KEY SETS while
# hand-writing their CONSTRUCTORS is exactly the asymmetry that caused the
# original outage, and it was reproduced here before this check existed.
for _nested in (_RESOURCES, _LIFECYCLE, _PROCESS, _CONFIGURATION,
                _ENV_VAR, _CONFIG_FILE):
    _covers(_nested.parsers, _nested.spec, f"runtime_wire {_nested.spec.__name__}")

CONTAINER_ONLY_FIELDS = tuple(
    name for name in _DECLARED if _WIRE[name].container_only)


# What may appear in a JSON document, plus the two structural forms that carry
# it. Anything else is refused HERE rather than passed through to json.dumps,
# which reports it as "Object of type X is not JSON serializable" from inside
# the encoder with no idea which field it came from.
_SCALARS = (str, int, float, bool)


def _to_wire(value, where: str):
    if value is None or isinstance(value, _SCALARS):
        return value
    if isinstance(value, (tuple, list)):
        return [_to_wire(item, f"{where}[{index}]")
                for index, item in enumerate(value)]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _to_wire(getattr(value, field.name), f"{where}.{field.name}")
                for field in dataclasses.fields(value)}
    # A duck-typed stand-in used to serialize fine here, because this walked
    # attributes rather than checking the type. That is precisely how a fixture
    # goes stale without saying so: it keeps working while it silently lacks
    # whatever was added to the real spec.
    raise TypeError(
        f"{where} holds {type(value).__name__}, which has no wire form; "
        "executable identity is carried by the frozen registry dataclasses, "
        "not by anything shaped like them")


def encode_runtime(runtime: RuntimeResolution) -> dict:
    """The frozen executable identity as the object that crosses every boundary.

    Field order follows the dataclass, which is irrelevant to the bytes: both
    consumers dump this with ``sort_keys=True``. What is NOT irrelevant is the
    set of keys present, which is why additive fields drop out when unset.
    """
    document = {}
    for name in _DECLARED:
        value = getattr(runtime, name)
        if value is None and _WIRE[name].additive:
            continue
        document[name] = _to_wire(value, name)
    return document


def decode_runtime(raw, *, where: str, error: type[Exception],
                   protocols: frozenset[str] | set[str],
                   require_command: bool) -> RuntimeResolution:
    """Parse and validate one runtime object arriving from outside.

    ``protocols`` is the set of interface versions THIS boundary can honour,
    and ``require_command`` says whether a container may leave its entrypoint
    to the image. Both are policy, they genuinely differ between the registry
    snapshot and the worker envelope, and stating them at the call site is what
    lets one parser serve both without either boundary drifting into the
    other's rules.
    """
    if not isinstance(raw, dict):
        raise error(f"{where} must be an object")
    unknown = set(raw) - set(_WIRE)
    if unknown:
        raise error(f"{where} has unknown fields {sorted(unknown)}")

    runtime = RuntimeResolution(**{
        name: wire.parse(raw.get(name), f"{where}.{name}", error)
        for name, wire in _WIRE.items()
    })

    if runtime.runtime_type == "container":
        if runtime.interface_version not in protocols:
            # Echo what arrived. A boundary may legitimately serve fewer
            # protocols than the platform publishes -- the launcher refuses
            # exec/v1 that the registry deliberately packages -- and an
            # operator holding a correctly signed snapshot needs to see that
            # this is a scope difference, not a corrupt artifact.
            raise error(
                f"{where}: interface_version {runtime.interface_version!r} is "
                f"not served here; this boundary launches only "
                f"{sorted(protocols)}")
        if (runtime.image_ref is None or runtime.image_digest is None or
                not SHA256_DIGEST_RE.fullmatch(runtime.image_digest)):
            raise error(
                f"{where}: governed container runtime needs image_ref and "
                "sha256 image_digest")
        if not OCI_IMAGE_REF_RE.fullmatch(runtime.image_ref):
            raise error(
                f"{where}.image_ref must be an unpinned OCI repository/name; "
                "digest is separate")
        if require_command and runtime.command is None:
            raise error(
                f"{where}: governed container runtime requires an explicit "
                "command")
        # The process/configuration COMBINATION rule, mirroring the parser
        # (agentspec/parser.py). validate_process/validate_configuration cover
        # the per-entry and collection rules, but NOT the pairing with the
        # interface -- so without this the codec ADMITTED what the parser
        # refuses: process/configuration on a runtime-v1 container (which learns
        # both from its context document), and exec/v1 WITHOUT a process block.
        # A signed snapshot could then carry either, the worker would build an
        # init container and a bearer secretKeyRef for it, and the run would die
        # silently at init. Keyed on interface_version, NOT merely on being a
        # container. Enforced at both decode boundaries because decode_runtime
        # is the one both call.
        is_exec = runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
        if is_exec and runtime.process is None:
            raise error(
                f"{where}: {RUNTIME_PROTOCOL_EXEC_V1!r} requires a process block "
                "declaring how the task is delivered")
        if not is_exec:
            for field in ("process", "configuration"):
                if getattr(runtime, field) is not None:
                    raise error(
                        f"{where}: {field!r} applies only to "
                        f"{RUNTIME_PROTOCOL_EXEC_V1!r}; a "
                        f"{runtime.interface_version!r} container takes its "
                        "input and configuration from the context document")
    else:
        # Enforced at BOTH boundaries, on purpose. The worker's copy of this
        # check used to omit `lifecycle`, so a builtin-claude carrying a
        # lifetime was refused by the registry and accepted by the launcher.
        # "The registry refuses it upstream" is not the reason to keep this
        # here -- that argument would justify deleting the worker's validator
        # entirely, and the validator exists precisely because an HTTP
        # assignment is untrusted input to the worker. Two independent
        # boundaries, one rule, derived from one declaration.
        carried = [name for name in CONTAINER_ONLY_FIELDS
                   if getattr(runtime, name) is not None]
        if carried:
            raise error(
                f"{where}: builtin-claude may not declare container execution "
                f"fields {carried}")

    return runtime
