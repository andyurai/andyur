"""The locked read contract between the agent registry and the run harness.

Frozen dataclasses and tuples are intentional: a resolution is a snapshot
consumed by one launch. C2 extends the locked read contract additively with the
runtime identity that selects the executable bytes; existing authority-only
resolution artifacts remain valid and expose ``runtime=None``.
"""

from __future__ import annotations

from dataclasses import dataclass
import posixpath
import re
from typing import Literal, Protocol, get_args, runtime_checkable

AuthorityMode = Literal["managed", "brokered", "passthrough"]
RuntimeType = Literal["container", "builtin-claude"]
LifecycleMode = Literal["task", "service"]
OnExit = Literal["fail", "restart"]
MAX_TOOL_BINDINGS = 32

# Absolute bounds on a declared lifetime. These are the schema's outer edge, not
# the grant: PlatformPolicy caps below them and the resolution carries whatever
# survives that intersection. The floor exists because a lifetime shorter than a
# model round trip cannot complete any run and would only ever be a typo; the
# ceiling exists because an unbounded declaration is indistinguishable from a
# missing one, and "forever" is not a lifetime a reviewer can reason about.
LIFETIME_FLOOR_SECONDS = 60
LIFETIME_CEILING_SECONDS = 7 * 24 * 3600
RUNTIME_PROTOCOL_V1 = "andyur-agent-runtime/v1"
RUNTIME_PROTOCOL_EXEC_V1 = "exec/v1"
# Every protocol the platform PUBLISHES, defined once at the layer both the
# manifest parser and the registry overlay import. They held identical copies,
# and runtime_overlay's own comment records what divergence cost: exec/v1 was
# unpackageable while parsing and compiling cleanly. Which protocols a given
# boundary can LAUNCH is a narrower, separate question -- see
# governed_kubernetes.LAUNCHABLE_PROTOCOLS (both admit exec/v1 since the M1 flip).
SUPPORTED_PROTOCOLS = frozenset({RUNTIME_PROTOCOL_V1, RUNTIME_PROTOCOL_EXEC_V1})
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_IMAGE_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/:-]{0,254}$")
RESOURCE_QUANTITY_RE = re.compile(
    r"^\d{1,20}(\.\d{1,6})?(m|k|M|G|T|Ki|Mi|Gi|Ti)?$")
COMMAND_CREDENTIAL_RE = re.compile(
    r"(?i)\b(secret|token|passw(or)?d|api[_-]?key|private[_-]?key)\b\s*[=:]")
MAX_COMMAND_ARGS = 64
MAX_COMMAND_ARG_LEN = 4096


@dataclass(frozen=True)
class McpToolGrant:
    """One MCP tool this server may expose and the action it requires."""

    name: str
    requires: str


@dataclass(frozen=True)
class ToolBinding:
    """One reviewed tool binding in the immutable authority snapshot."""

    name: str
    reach_url: str
    resource_id: str
    authority: AuthorityMode
    expected_spiffe_id: str | None = None
    credential_ref: str | None = None
    mcp_tools: tuple[McpToolGrant, ...] | None = None
    # Which request headers this binding's brokered credential may set. WHICH
    # headers a vendor authenticates with is a fact about that vendor, so it is
    # authority data reviewed with the binding rather than a platform constant.
    # It replaced a hardcoded {authorization, x-api-key} literal that lived in
    # two files and could not express Datadog, which needs DD-API-KEY and
    # DD-APPLICATION-KEY together. `None` means the binding brokers no
    # credential headers, and the sidecar then injects none.
    credential_headers: tuple[str, ...] | None = None


@dataclass(frozen=True)
class AuthorityCeiling:
    """What the agent may ever hold, preserving the None/()/values tri-state."""

    actions: tuple[str, ...] | None
    resources: tuple[str, ...] | None


@dataclass(frozen=True)
class ResourceSpec:
    """Runtime resource limits copied from an approved AgentManifest."""

    cpu: str | None = None
    memory: str | None = None


@dataclass(frozen=True)
class LifecycleSpec:
    """How long an approved agent may run, and what happens when it stops.

    This is the granted lifetime, already intersected with policy. It exists so
    that a run's wall-clock bound is a property of the agent the registry
    approved rather than a platform-global constant. Before it, one environment
    variable governed every agent on the platform and was read independently by
    four modules, which is four sources of truth for one fact.

    ``idle_seconds`` and ``on_exit='restart'`` are meaningful only for a service:
    a task has no idle window because it has exactly one unit of work, and
    restarting a task would silently re-run it.
    """

    mode: LifecycleMode
    max_seconds: int
    idle_seconds: int | None = None
    on_exit: OnExit = "fail"


InputMode = Literal["stdin", "argv", "file", "none"]
CaptureMode = Literal["capture", "discard"]

# ---------------------------------------------------------------------------
# ADR-011 exec/v1: the stock-process surface, its closed reference vocabulary,
# and the rules that bound it.
#
# This lives HERE rather than in the manifest parser that first wrote it,
# because `configuration` now crosses the wire into the signed launch snapshot.
# A decoder that admits a reference the parser would have refused hands the
# launcher something to resolve, and D7 is explicit that nothing refuses on the
# workload's behalf. registry/ cannot import agentspec/ -- the dependency runs
# the other way -- so the vocabulary moved down rather than being restated. A
# second frozenset that agrees today is the exact shape of the drift the module
# next door was written to end.
#
# The rule that the vocabulary encodes (D4): a manifest may name the run's own
# capability material; it may never name a downstream credential.
CONFIG_REFERENCES = frozenset({
    "services.model.base_url",
    "services.model.openai_base_url",
    "services.model.name",
    "services.tools.mcp_url",
    "run.id",
    "run.deadline_epoch",
    # Where the run's input lands under process.input.mode 'file': a fixed
    # path inside the writable scratch (execconfig.INPUT_PATH). Naming it under
    # any other mode is refused by the parser, and resolves to nothing at
    # launch, because the file does not exist there.
    "run.input_path",
    "workspace.home",
    "workspace.tmp",
})
# A prefix entry admits exactly one further bounded segment.
CONFIG_REFERENCE_PREFIXES = ("services.tools.mcp_headers.",)
# `services.tools.mcp_url` is SINGULAR on purpose, and it is not an
# exec/v1 invention: it is the same endpoint runtime-v1 publishes to its agents
# as `services.mcp_url`. The runner starts one ToolService per run
# (runner/toolservice.py) and hands the workload its base URL; per-server
# passthrough configurations are a separate concept (`extra_mcp_servers`) that
# exec/v1 does not surface yet.
#
# The server name pattern lives here rather than in manifest_registry so a
# single charset serves both. manifest_registry binds to this object.
SERVER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
# The only references that resolve to a directory a workload may write.
WRITABLE_REFERENCES = frozenset({"workspace.home", "workspace.tmp"})
# Generated files may only land in the two writable, ephemeral paths the runtime
# actually provides. Anywhere else is either read-only (the write fails at run
# time, far from the manifest that caused it) or outside the workload's reach.
WRITABLE_ROOTS = ("/tmp/", "/home/")
# Where a run's input lands under process.input.mode 'file' (execconfig writes
# it here, the ${run.input_path} reference resolves to it). Defined HERE, the
# one place the writable-path rules live, so validate_config_file can refuse a
# declared file that would collide with it -- a config file at this path (or
# under its directory) passes the writable-root check but is then overwritten by
# the input, or overwrites the input, silently breaking "input lands verbatim".
INPUT_PATH = "/tmp/andyur/input"
INPUT_DIR = "/tmp/andyur/"
# Deliberately narrow: no nesting, no expressions, no defaults. No upper bound on
# the captured name, either -- a `{1,128}` bound once made `${` + 129 chars + `}`
# INVISIBLE to findall, so it never reached the reference check and survived
# verbatim into the resolved configuration. Length is bounded by the vocabulary
# check itself, which refuses anything outside the closed set.
TEMPLATE_REF_RE = re.compile(r"\$\{([^{}]+)\}")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
HEADER_SEGMENT_RE = re.compile(r"^[A-Za-z0-9!#$%&\'*+.^_`|~-]{1,64}$")
MAX_ENV_VARS = 64
MAX_CONFIG_FILES = 8
MAX_TEMPLATE_BYTES = 64 * 1024
MAX_LITERAL_LEN = 4096
MAX_CONFIG_PATH_LEN = 4096
# Input and output capture bounds. The floor is 1 rather than 0 because a
# zero-byte bound is indistinguishable from "no capture", which is what
# `discard` says explicitly.
MIN_INPUT_BYTES, MAX_INPUT_BYTES = 1, 8 * 1024 * 1024
MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES = 1, 16 * 1024 * 1024
DEFAULT_INPUT_MAX_BYTES = 256 * 1024
DEFAULT_OUTPUT_MAX_BYTES = 1 << 20


@dataclass(frozen=True)
class ProcessSpec:
    """How a stock process receives its task and how its output is treated.

    Only meaningful under `exec/v1`. A runtime-v1 agent takes its input from the
    context document and reports through the event stream, so declaring process
    I/O there would be a second way to say the same thing.

    `stdout`/`stderr` are DIAGNOSTIC (ADR-011 D3). Output is captured, stored and
    shown to an operator; nothing authorizes on it, and no evidence record may
    treat it as proof that work happened. The bound exists so that "captured"
    cannot mean "unbounded".
    """

    input_mode: InputMode
    input_max_bytes: int
    stdout: CaptureMode = "capture"
    stderr: CaptureMode = "capture"
    output_max_bytes: int = DEFAULT_OUTPUT_MAX_BYTES


@dataclass(frozen=True)
class EnvVar:
    """One environment variable: a constant, or a reference the platform
    resolves at launch. Exactly one of the two, never both.

    The NAME is carried in the dataclass rather than as the first half of a
    (name, value) pair. On the wire that pair would be a positional two-element
    list -- one bespoke shape for env beside the self-describing objects used
    for everything else, in an artifact an operator reads to answer "what was
    this run configured with".
    """

    name: str
    literal: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class ConfigFile:
    """A file generated into the workload's writable scratch before it starts.

    `template` may interpolate `${reference}` from the closed vocabulary and
    nothing else, so a config file cannot become the way to say what the
    environment mapping refused.
    """

    path: str
    template: str


@dataclass(frozen=True)
class ConfigurationSpec:
    """The declarative surface that adapts a stock binary without an adapter.

    UNRESOLVED, and that is the design decision rather than an omission. Every
    reference but the two workspace paths resolves to something that does not
    exist at compile time -- the run id, its deadline, the per-run MCP bearer,
    the loopback service URLs. A snapshot of resolved values would be a snapshot
    of ONE run, and this one is signed and reused across every run of the agent.
    So references cross the wire intact and the launcher substitutes per run:
    compile time keeps the vocabulary check, launch time does the substitution.
    """

    env: tuple[EnvVar, ...] = ()
    files: tuple[ConfigFile, ...] = ()


def check_reference(ref, where: str, error: type[Exception]) -> str:
    """One reference, against the closed vocabulary.

    Refusals name the whole set: an author guessing at what is allowed is an
    author who will eventually guess a credential.

    `error` is the caller's boundary exception, the same convention
    `runtime_wire.Parser` uses -- a manifest refusing at parse time and a
    decoder refusing a signed snapshot are different trust failures, and an
    operator has to be able to tell them apart.
    """
    if not isinstance(ref, str) or not ref:
        raise error(f"{where}: reference must be a non-empty string")
    if ref in CONFIG_REFERENCES:
        return ref
    for prefix in CONFIG_REFERENCE_PREFIXES:
        if ref.startswith(prefix):
            segment = ref[len(prefix):]
            if not HEADER_SEGMENT_RE.fullmatch(segment):
                raise error(f"{where}: {ref!r} does not name a valid header")
            return ref
    raise error(
        f"{where}: {ref!r} is not a resolvable reference. Allowed: "
        f"{sorted(CONFIG_REFERENCES)} or "
        f"{[p + '<header>' for p in CONFIG_REFERENCE_PREFIXES]}")


def validate_env_var(var: EnvVar, where: str, error: type[Exception]) -> None:
    """Bounds and vocabulary for one variable, after it is built."""
    if not isinstance(var.name, str) or not ENV_NAME_RE.fullmatch(var.name):
        raise error(f"{where}: not a valid environment variable name")
    if var.name.startswith("ANDYUR_"):
        # The platform's own bootstrap namespace. A manifest that could write
        # into it could impersonate platform configuration.
        raise error(
            f"{where}: ANDYUR_* is the platform's namespace and cannot be set "
            "by a manifest")
    if (var.literal is None) == (var.reference is None):
        raise error(f"{where}: exactly one of 'literal' or 'from' is required")
    if var.literal is not None:
        if not isinstance(var.literal, str) or len(var.literal) > MAX_LITERAL_LEN:
            raise error(
                f"{where}.literal must be a string of at most "
                f"{MAX_LITERAL_LEN} characters")
        if "\r" in var.literal or "\n" in var.literal:
            raise error(f"{where}.literal must not contain CR or LF")
    else:
        check_reference(var.reference, f"{where}.from", error)


def validate_config_file(spec: ConfigFile, where: str,
                         error: type[Exception]) -> None:
    """Containment and vocabulary for one generated file."""
    if (not isinstance(spec.path, str) or not spec.path or
            len(spec.path) > MAX_CONFIG_PATH_LEN):
        raise error(f"{where}.path must be a bounded non-empty string")
    if not isinstance(spec.template, str):
        raise error(f"{where}.template must be a string")
    if len(spec.template.encode()) > MAX_TEMPLATE_BYTES:
        raise error(f"{where}.template exceeds {MAX_TEMPLATE_BYTES} bytes")
    # Every reference in the path AND the template, or a config file becomes the
    # way to say what the env mapping refused.
    for ref in TEMPLATE_REF_RE.findall(spec.path):
        check_reference(ref, f"{where}.path", error)
    for ref in TEMPLATE_REF_RE.findall(spec.template):
        check_reference(ref, f"{where}.template", error)
    # ONLY the workspace references resolve to a writable root. An earlier check
    # substituted "/home/agent" for EVERY ${ref}, so a path beginning with any
    # reference satisfied the prefix test -- including
    # ${services.tools.mcp_headers.Authorization}/x, which would have put the
    # run's bearer token in a path segment.
    leading = TEMPLATE_REF_RE.match(spec.path)
    if leading is not None:
        if leading.group(1) not in WRITABLE_REFERENCES:
            raise error(
                f"{where}.path may begin only with {sorted(WRITABLE_REFERENCES)}; "
                f"{leading.group(1)!r} does not resolve to a writable directory")
        remainder = spec.path[leading.end():]
    else:
        if not spec.path.startswith(WRITABLE_ROOTS):
            raise error(
                f"{where}.path must be inside the writable scratch "
                f"({', '.join(WRITABLE_ROOTS)})")
        remainder = spec.path
    if ".." in spec.path:
        raise error(f"{where}.path may not traverse")
    # The input's own path is off limits: a file declared at INPUT_PATH (or
    # under its directory) passes the writable-root check but would overwrite,
    # or be overwritten by, the run's input -- silently breaking "input lands
    # verbatim". Refused for a literal path here; the resolved form is refused
    # again in execconfig.render_files, since a leading ${workspace.tmp} could
    # resolve under it.
    # Compare the NORMALISED path: `/tmp//andyur/input`, `/tmp/./andyur/input`
    # and the bare `/tmp/andyur` all normalise onto the input's path/dir and
    # must be refused too (a raw prefix test let them through -- R M-A).
    if leading is None:
        normalised = posixpath.normpath(spec.path)
        if (normalised == INPUT_PATH
                or normalised == INPUT_DIR.rstrip("/")
                or normalised.startswith(INPUT_DIR)):
            raise error(
                f"{where}.path {spec.path!r} is the run input's directory "
                f"({INPUT_DIR}), which the platform owns; choose another path")
    # A reference anywhere but the front cannot be checked for containment,
    # because what it resolves to is not known here.
    if TEMPLATE_REF_RE.search(remainder):
        raise error(
            f"{where}.path may interpolate a reference only as its first "
            "segment, where containment can be established")


def validate_configuration(spec: ConfigurationSpec, where: str,
                           error: type[Exception]) -> None:
    """The whole surface: per-entry rules plus the collection-level ones.

    Called by BOTH the manifest parser and the wire decoder. The two build a
    ConfigurationSpec from different syntaxes -- an object keyed by variable
    name, and a list of self-describing entries -- and then submit the result to
    one rule set for the per-entry and collection rules. The COMBINATION rule
    (configuration/process belong only to exec/v1, and exec/v1 must carry a
    process) lives beside each caller -- the parser and decode_runtime -- because
    it needs the interface, which this function is not given; both enforce it,
    so a signed snapshot cannot carry a combination the manifest surface refuses.
    """
    if len(spec.env) > MAX_ENV_VARS:
        raise error(f"{where}.env exceeds the {MAX_ENV_VARS}-variable limit")
    seen_names: set[str] = set()
    for var in spec.env:
        at = f"{where}.env[{var.name!r}]"
        validate_env_var(var, at, error)
        if var.name in seen_names:
            # Unreachable from a manifest, whose env is an object and cannot
            # repeat a key. Reachable from the wire, where env is a list -- and
            # a duplicate there is a launcher choosing between two values by
            # iteration order.
            raise error(f"{at}: declared twice")
        seen_names.add(var.name)
    if len(spec.files) > MAX_CONFIG_FILES:
        raise error(f"{where}.files exceeds the {MAX_CONFIG_FILES}-file limit")
    seen_paths: set[str] = set()
    for index, config_file in enumerate(spec.files):
        at = f"{where}.files[{index}]"
        validate_config_file(config_file, at, error)
        if config_file.path in seen_paths:
            raise error(f"{at}.path is declared twice")
        seen_paths.add(config_file.path)


def validate_process(spec: ProcessSpec, where: str,
                     error: type[Exception]) -> None:
    """Vocabulary and bounds for the process block, after it is built."""
    if spec.input_mode not in get_args(InputMode):
        raise error(
            f"{where}.input.mode must be one of {sorted(get_args(InputMode))}")
    for field_name, value, low, high in (
            ("input.max_bytes", spec.input_max_bytes,
             MIN_INPUT_BYTES, MAX_INPUT_BYTES),
            ("output.max_bytes", spec.output_max_bytes,
             MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)):
        # bool is an int subclass in Python, and True would otherwise pass as 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise error(f"{where}.{field_name} must be an integer")
        if not low <= value <= high:
            raise error(f"{where}.{field_name} must be between {low} and {high}")
    for stream in ("stdout", "stderr"):
        if getattr(spec, stream) not in get_args(CaptureMode):
            raise error(
                f"{where}.output.{stream} must be one of "
                f"{sorted(get_args(CaptureMode))}")
    # On the supported launch envelope a container's stdout and stderr are ONE
    # combined stream (the kubelet does not split them), captured under the
    # stdout bound. So "discard stdout but capture stderr" is not something the
    # platform can honour -- it would silently capture everything or nothing.
    # Refuse it at parse rather than let a manifest believe it got stderr-only.
    if spec.stdout == "discard" and spec.stderr == "capture":
        raise error(
            f"{where}.output cannot discard stdout while capturing stderr: the "
            "container's streams are one combined log on the supported envelope, "
            "captured under the stdout setting (see ADR-011 D3)")


@dataclass(frozen=True)
class RuntimeResolution:
    """Immutable executable identity approved for an agent.

    ``image_digest`` is the byte identity for a container runtime; ``image_ref``
    is only the human-readable repository/name used to form ``ref@digest``.
    The command and protocol are carried in the same frozen snapshot so no
    scheduler or worker has to rediscover them from mutable configuration.

    ``lifecycle``, ``process`` and ``configuration`` are additive in the same way
    ``runtime`` itself was: an older overlay parses with ``None``, and every
    consumer falls back to the platform default for an agent that declared
    nothing. ``process`` and ``configuration`` are meaningful only under
    ``exec/v1``; a runtime-v1 agent is told what to do by the context document.
    """

    runtime_type: RuntimeType
    interface_version: str | None
    manifest_digest: str
    image_ref: str | None = None
    image_digest: str | None = None
    command: tuple[str, ...] | None = None
    resources: ResourceSpec | None = None
    policy_revision: str | None = None
    lifecycle: LifecycleSpec | None = None
    # exec/v1 (ADR-011 D5). Additive in the same way ``lifecycle`` was, and
    # carried UNRESOLVED: see ConfigurationSpec. Before these two fields a
    # manifest's process and configuration were fully validated by the parser
    # and then discarded at compile time, because the snapshot they had to
    # travel in could not hold them.
    process: ProcessSpec | None = None
    configuration: ConfigurationSpec | None = None


@dataclass(frozen=True)
class AgentCard:
    """What an agent is FOR, in the words of somebody choosing one.

    The registry is a catalogue, and a catalogue nobody can read is a list of
    identifiers. `registry list` could only ever print an id and a name, so an
    operator handed a bundle of six agents had no way to learn what any of them
    did, what it needed, or which would sit idle for want of a backend.

    DESCRIPTION ONLY, and that is a security property rather than a scoping
    accident. Nothing on this card is consulted when a run is authorised -- the
    ceiling and the tool bindings decide that, alone. A card that could widen
    either would be a way to talk past review, which is exactly the move a
    catalogue entry must not be able to make.
    """

    summary: str
    category: str | None = None
    # Prerequisites in prose: "a reachable Wazuh deployment", "an OSV MCP server
    # on the run network". A bundle DECLARES what it needs and never starts it.
    # A file that could start processes would be a code-execution vector aimed
    # at the one component whose entire job is deciding what may run, so the
    # platform reads this to tell a human what to provision -- nothing more.
    # Tri-state like the ceiling: None is "unstated", () is "needs nothing".
    requires: tuple[str, ...] | None = None


@dataclass(frozen=True)
class AgentResolution:
    """One validated, launchable agent snapshot.

    ``registry_digest`` names the immutable, signature-verified registry
    artifact. ``runtime`` is additive for C2: older authority-only resolution
    artifacts parse with ``None``; governed BYOA launchers require a populated
    runtime and fail closed rather than substituting a worker-global image.
    """

    agent_id: str
    name: str
    instructions: str
    model: str | None
    tools: tuple[ToolBinding, ...]
    ceiling: AuthorityCeiling
    registry_digest: str | None = None
    runtime: RuntimeResolution | None = None
    # What this agent is FOR, and which bundle shipped it. Both are catalogue
    # data: see AgentCard on why nothing here may reach an authority decision.
    card: AgentCard | None = None
    bundle: str | None = None


def granted_lifetime_seconds(lifecycle: LifecycleSpec | None, default: int) -> int:
    """The ONE place a run's wall-clock bound is decided.

    Every consumer -- the runner arming its deadline, the SPIRE registrar
    sizing an entry, the server reaping runs that never reported -- reads this.
    They previously each read ANDYUR_RUN_TTL_SECONDS themselves, which is four
    readers of one fact and therefore four things to keep in step. `default` is
    that same platform setting, now demoted to what it always should have been:
    the answer for an agent that declared nothing.
    """
    # The platform default is bounded by the same ceiling as a declared grant.
    # It is an operator setting with no other limit, and the engine's execution
    # bound is derived from this ceiling: a default above it would outlive the
    # execution that watches it.
    if lifecycle is None:
        return min(default, LIFETIME_CEILING_SECONDS)
    return lifecycle.max_seconds


class MalformedLifecycle(ValueError):
    """A run's persisted lifecycle is PRESENT but unreadable.

    Distinct from absent on purpose. Absent means the agent declared no
    lifetime and the platform default is the right answer. Present-but-invalid
    means a grant existed and we cannot read it, and treating that as absent
    WIDENS a run granted 120s to the 900s default -- "not immortal" is not the
    same as fail-closed. Consumers reap conservatively instead.
    """


def lifecycle_from_assignment(raw) -> LifecycleSpec | None:
    """Rebuild a granted lifetime from the durable per-run runtime assignment.

    The server persists the resolved runtime on the run row at creation, so the
    reaper reads the lifetime the registry actually granted rather than
    re-resolving a snapshot that may have moved on.

    Returns None when NO lifecycle was recorded (the agent declared none).
    Raises MalformedLifecycle when one was recorded and cannot be read, so a
    caller can tell "no grant" from "a grant we lost" and refuse to widen.
    """
    if not isinstance(raw, dict):
        raise MalformedLifecycle("runtime assignment is not an object")
    if "lifecycle" not in raw or raw["lifecycle"] is None:
        return None                      # genuinely absent: no grant was made
    spec = raw["lifecycle"]
    if not isinstance(spec, dict):
        raise MalformedLifecycle("lifecycle is present but not an object")
    mode, seconds = spec.get("mode"), spec.get("max_seconds")
    if mode not in get_args(LifecycleMode):
        raise MalformedLifecycle(f"lifecycle.mode {mode!r} is unreadable")
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise MalformedLifecycle("lifecycle.max_seconds is not an integer")
    if not LIFETIME_FLOOR_SECONDS <= seconds <= LIFETIME_CEILING_SECONDS:
        raise MalformedLifecycle(
            f"lifecycle.max_seconds {seconds} is outside the permitted bounds")
    idle = spec.get("idle_seconds")
    if isinstance(idle, bool) or not isinstance(idle, int):
        idle = None
    # DERIVED, not restated. This reader is deliberately more forgiving than
    # the registry's -- the reaper must act on a grant it only partly
    # understands rather than crash -- but "forgiving" must not mean "reading a
    # different vocabulary". A value added to OnExit and missed here would be
    # silently coerced to "fail": a run honouring a grant nobody wrote, with
    # nothing said about it.
    on_exit = spec.get("on_exit")
    return LifecycleSpec(
        mode=mode, max_seconds=seconds, idle_seconds=idle,
        on_exit=on_exit if on_exit in get_args(OnExit) else "fail",
    )


@runtime_checkable
class AgentRegistry(Protocol):
    """The one operation the run harness needs from the registry."""

    def resolve(self, agent_id: str) -> AgentResolution:
        """Return one validated, launchable agent or raise AgentNotFound."""
        ...


@runtime_checkable
class AgentCatalog(AgentRegistry, Protocol):
    """Administrative read surface used by the HTTP listing endpoint."""

    def list_agents(self) -> list[AgentResolution]:
        """Return the validated resolutions visible to this catalog."""
        ...


class AgentNotFound(LookupError):
    """resolve() was asked for an agent id the registry does not hold."""


class InvalidAgentManifest(ValueError):
    """A registry resolution failed validation."""


class RegistryUnavailable(RuntimeError):
    """The configured registry backend could not provide a validated snapshot."""
