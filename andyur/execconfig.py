"""Resolution of the exec/v1 configuration surface into concrete values.

ADR-011 D4 gives a manifest a closed vocabulary of references it may name. The
parser refuses everything outside that vocabulary and the wire decoder refuses
it again, so by the time a resolution reaches a launcher the only question left
is what each reference RESOLVES TO for this one run.

That question has exactly one owner, here, for the same reason mcpwire.py owns
the permitted-tool calculation: the alternative is one substitution table per
launcher, and the tables disagree the moment a reference is added. Launcher
parity is then a property of having one implementation rather than a promise to
keep several in step.

WHAT IS SECRET AND WHAT IS NOT, because the split decides where values travel.
Every reference but one resolves to a URL, a path, an identifier or a deadline:
public facts about this run that are already visible in its own Pod spec. The
exception is ``services.tools.mcp_headers.*``, which resolves to the run's
MCP bearer as a complete ``Authorization`` header value (``Bearer <token>``).
That value must never enter a Pod spec, a log line, a label
or an annotation, so it reaches this module from the environment (populated
from a Secret by a secretKeyRef) and never from a caller that built it into a
manifest document.

RENDERING RUNS TWICE, IN TWO PLACES, ON PURPOSE:

  * the launcher calls ``plan_environment`` while BUILDING the Pod, to decide
    which variables are literals and which must be secretKeyRef entries. It
    never needs the bearer's value to do that.
  * ``render_files`` runs INSIDE the init container, at run time, with the
    bearer in its own environment. A file rendered launcher-side would have to
    travel to the workload as bytes, and bytes containing a credential need a
    Secret object to carry them -- so rendering late is what keeps the rendered
    credential out of the cluster's storage entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import pathlib
import sys

from .registry.models import (
    CONFIG_REFERENCE_PREFIXES,
    CONFIG_REFERENCES,
    ConfigurationSpec,
    TEMPLATE_REF_RE,
    WRITABLE_ROOTS,
    check_reference,
)

# The one reference family that resolves to a credential. Everything else is a
# public fact about the run. Derived from the vocabulary's prefix list rather
# than restated, so a second prefix cannot be added there and silently treated
# as public here.
SECRET_REFERENCE_PREFIXES = CONFIG_REFERENCE_PREFIXES

# How the launcher hands this module the run's public facts and its bearer.
# The published contract fixes these (agent-runtime-protocol-v1: "exactly two
# writable, empty, ephemeral directories at fixed paths"), so they are constants
# rather than per-run facts -- and they live here, beside the code that
# validates containment against them.
# The MCP endpoint path, defined here rather than in runner/toolservice.py so
# the daemon can read it without importing uvicorn, starlette and the MCP server
# stack for one string. toolservice binds to this object.
MCP_PATH = "/mcp"
WORKSPACE_HOME = "/home/agent"
WORKSPACE_TMP = "/tmp"
FACTS_ENV = "ANDYUR_EXEC_FACTS"
BEARER_ENV = "ANDYUR_EXEC_MCP_BEARER"
# Where the run's input lands under process.input.mode 'file'. Fixed, like the
# two scratch roots, so a manifest's command can name it as a literal
# (`-i /tmp/andyur/input`) and conformance evidence binds a command that does
# not change per run. Inside WORKSPACE_TMP because that is the scratch the
# platform promises is writable, and the init container that writes it runs
# as the workload's uid.
# The input path is defined in registry/models.py, beside the writable-root
# rules, so validate_config_file can refuse a file that collides with it.
from .registry.models import INPUT_PATH  # noqa: E402  (re-exported here)
# How the controller tells the init container to persist an input: the path,
# and the manifest's bound so a stream longer than declared is refused inside
# the Pod as well as at the door and the launcher.
INPUT_PATH_ENV = "ANDYUR_EXEC_INPUT_PATH"
INPUT_MAX_ENV = "ANDYUR_EXEC_INPUT_MAX_BYTES"
# The EXACT byte count the controller will attach. Known at build time
# (len(exec_input)), so the init container can refuse a stream that arrives
# short -- the mid-write-fault-under-stdinOnce case -- instead of writing a
# silently truncated task.
INPUT_LEN_ENV = "ANDYUR_EXEC_INPUT_LEN"


class UnresolvedReference(ValueError):
    """A reference survived substitution, or resolved to nothing.

    Its own class because the failure is not the manifest's: the manifest was
    validated twice before it got here. This means the LAUNCHER was asked for a
    fact it did not supply, and shipping the literal ``${...}`` into a stock
    workload would be worse than refusing -- the workload would read it as a
    URL, connect nowhere, and report something unrelated.
    """


@dataclass(frozen=True)
class RunFacts:
    """What the closed vocabulary resolves to for one run.

    Every field is a public fact about this run except ``mcp_bearer``, which is
    absent (None) in every launcher-side use. A launcher that never sets it
    cannot leak it, which is why it is optional rather than required.
    """

    run_id: str
    deadline_epoch: int
    model_base_url: str
    model_openai_base_url: str
    model_name: str
    # The run's governed MCP endpoint -- ONE url, the same one runtime-v1
    # publishes to its agents as services.mcp_url. Per-server passthrough
    # configurations are a separate concept this surface does not carry.
    mcp_url: str
    workspace_home: str
    workspace_tmp: str
    # Empty unless the process declared mode 'file'; then INPUT_PATH. An empty
    # value fails closed at resolve(), which is the launcher-side backstop for
    # the parser's refusal of ${run.input_path} under any other mode.
    input_path: str = ""
    # The COMPLETE Authorization header value (`Bearer <token>`), never the bare
    # token: the reference family that resolves to it names HEADERS
    # (`services.tools.mcp_headers.<Name>`), exactly as runtime-v1 publishes
    # `services.mcp_headers.Authorization`, and a stock tool sends what it is
    # given verbatim. Arrives in BEARER_ENV from the runtime Secret's
    # `mcp-authorization` key; the proxy's ToolService compares the token inside.
    mcp_bearer: str | None = None

    def public(self) -> dict[str, str]:
        """The subset that may be written into a Pod spec, as a JSON-able map."""
        return {
            "run.id": self.run_id,
            "run.deadline_epoch": str(self.deadline_epoch),
            "services.model.base_url": self.model_base_url,
            "services.model.openai_base_url": self.model_openai_base_url,
            "services.model.name": self.model_name,
            "services.tools.mcp_url": self.mcp_url,
            "run.input_path": self.input_path,
            "workspace.home": self.workspace_home,
            "workspace.tmp": self.workspace_tmp,
        }


def is_secret_reference(ref: str) -> bool:
    return any(ref.startswith(prefix) for prefix in SECRET_REFERENCE_PREFIXES)


def resolve(ref: str, facts: RunFacts, *, where: str) -> str:
    """One reference to one value, refusing anything the vocabulary does not name.

    The vocabulary check runs AGAIN here even though the parser and the wire
    decoder both ran it. This is a third boundary with a third input: a launcher
    can construct a ConfigurationSpec in code, and "the registry already
    refused it upstream" is the argument that would justify deleting every
    validator in the codebase.
    """
    check_reference(ref, where, UnresolvedReference)
    if is_secret_reference(ref):
        if facts.mcp_bearer is None:
            raise UnresolvedReference(
                f"{where}: {ref!r} resolves to this run's MCP bearer, which was "
                f"not supplied; it must arrive in ${{{BEARER_ENV}}} from a "
                "Secret, never from a caller")
        return facts.mcp_bearer
    public = facts.public()
    if ref not in public:
        # Reachable only if the vocabulary gained an entry and this map did not.
        raise UnresolvedReference(
            f"{where}: {ref!r} is in the vocabulary but this launcher supplied "
            "no value for it")
    value = public[ref]
    if not value:
        # Fail closed on an empty value for the same reason as a missing bearer:
        # an empty model name or base URL is not a smaller configuration, it is
        # a broken one that the workload will report as its own fault.
        raise UnresolvedReference(
            f"{where}: {ref!r} resolved to an empty value")
    return value


def substitute(text: str, facts: RunFacts, *, where: str) -> str:
    """Every ${reference} in one string, with nothing left over.

    The leftover check is the point. A partially substituted template is the
    failure mode that looks like success: the file is written, the workload
    starts, and it reads a literal ``${services.tools.mcp_url}`` as a hostname.
    """
    rendered = TEMPLATE_REF_RE.sub(
        lambda match: resolve(match.group(1), facts, where=where), text)
    leftover = TEMPLATE_REF_RE.search(rendered)
    if leftover is not None:
        raise UnresolvedReference(
            f"{where}: {leftover.group(0)!r} survived substitution")
    return rendered


def plan_environment(
    configuration: ConfigurationSpec | None, facts: RunFacts,
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Split the declared environment into literals and secret-backed names.

    Returns ``(plain, secret_names)``. ``plain`` is (name, value) ready for a
    Pod spec. ``secret_names`` are the variables whose value is the run's MCP
    bearer, which the caller must wire to a secretKeyRef -- this module will not
    return that value, so a launcher cannot accidentally inline it.
    """
    if configuration is None:
        return (), ()
    plain: list[tuple[str, str]] = []
    secret: list[str] = []
    for var in configuration.env:
        where = f"configuration.env[{var.name!r}]"
        if var.literal is not None:
            plain.append((var.name, var.literal))
        elif is_secret_reference(var.reference):
            check_reference(var.reference, where, UnresolvedReference)
            secret.append(var.name)
        else:
            plain.append((var.name, resolve(var.reference, facts, where=where)))
    return tuple(plain), tuple(secret)


def render_files(
    configuration: ConfigurationSpec | None, facts: RunFacts,
) -> tuple[tuple[str, str], ...]:
    """Every declared file as (absolute path, content), fully resolved.

    Runs inside the init container. Containment is re-established on the
    RESOLVED path: the parser could only check the unresolved form, where
    ``${workspace.home}/x`` is a promise about a value it could not see.
    """
    if configuration is None:
        return ()
    roots = (facts.workspace_home, facts.workspace_tmp)
    rendered: list[tuple[str, str]] = []
    for index, config_file in enumerate(configuration.files):
        where = f"configuration.files[{index}]"
        path = substitute(config_file.path, facts, where=f"{where}.path")
        resolved = pathlib.PurePosixPath(path)
        if not resolved.is_absolute() or ".." in resolved.parts:
            raise UnresolvedReference(
                f"{where}.path resolved to {path!r}, which is not an absolute "
                "path inside the scratch")
        # TWO checks, against two different authorities, and the order matters.
        #
        # WRITABLE_ROOTS is the platform's own constant -- the published
        # contract fixes the writable paths at /tmp and /home/agent -- so it is
        # checked FIRST and cannot be influenced by anything passed in. The
        # per-run roots are checked second, and narrow it to THIS run's scratch.
        #
        # Checking only the per-run roots is what the first version of this did,
        # and it was circular: a facts object claiming workspace.home is /etc
        # validated /etc/passwd against itself and passed. The value being
        # validated cannot also be the thing that decides what is valid.
        if not path.startswith(WRITABLE_ROOTS):
            raise UnresolvedReference(
                f"{where}.path resolved to {path!r}, which is outside the "
                f"platform's writable roots {list(WRITABLE_ROOTS)}")
        from .registry.models import INPUT_DIR
        normalised = str(resolved)   # PurePosixPath already normalised // and /./
        if (normalised == INPUT_PATH or normalised == INPUT_DIR.rstrip("/")
                or normalised.startswith(INPUT_DIR)):
            raise UnresolvedReference(
                f"{where}.path resolved to {path!r}, inside the run input's "
                f"directory {INPUT_DIR}, which the platform owns")
        if not any(resolved.is_relative_to(root) for root in roots):
            raise UnresolvedReference(
                f"{where}.path resolved to {path!r}, outside this run's "
                f"scratch {list(roots)}")
        rendered.append(
            (path, substitute(config_file.template, facts,
                              where=f"{where}.template")))
    return tuple(rendered)


def facts_from_environment() -> RunFacts:
    """Rebuild the facts inside the init container.

    Public facts arrive as one JSON object because a per-reference variable
    naming scheme would have to encode header names, and the header vocabulary
    permits characters no environment variable may hold.
    """
    raw = os.environ.get(FACTS_ENV, "").strip()
    if not raw:
        raise UnresolvedReference(f"{FACTS_ENV} is empty; nothing to resolve")
    public = json.loads(raw)
    return RunFacts(
        run_id=public["run.id"],
        deadline_epoch=int(public["run.deadline_epoch"]),
        model_base_url=public["services.model.base_url"],
        model_openai_base_url=public["services.model.openai_base_url"],
        model_name=public["services.model.name"],
        mcp_url=public["services.tools.mcp_url"],
        workspace_home=public["workspace.home"],
        workspace_tmp=public["workspace.tmp"],
        input_path=public.get("run.input_path", ""),
        # Absent is legal: a configuration that names no header needs no bearer,
        # and an init container that is not given one cannot leak one.
        mcp_bearer=os.environ.get(BEARER_ENV) or None,
    )


def materialize(files: tuple[tuple[str, str], ...]) -> list[str]:
    """Write rendered files into the scratch, creating parents.

    Mode 0600 on the file and 0700 on directories this creates: the scratch is
    private to one workload running as one uid, and a rendered file may hold the
    run's bearer. The emptyDir itself arrives world-writable from kubelet, which
    is what lets a non-root workload use it at all -- that is the mount's
    permission, not a reason to widen the file's.
    """
    written = []
    for path, content in files:
        target = pathlib.Path(path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(content)
        target.chmod(0o600)
        written.append(path)
    return written


# Where the launcher mounts the declared templates for the init container. They
# are non-secret manifest data already carried in the signed resolution, so a
# ConfigMap is the right home -- the same place the broker's Envoy bootstrap
# lives. What must NOT travel this way is the rendered result, which is why
# rendering happens here rather than launcher-side.
TEMPLATES_MOUNT = "/etc/andyur-exec"
TEMPLATES_FILE = "files.json"


def persist_input(path: str, max_bytes: int, source=None,
                  expect_len: int | None = None) -> str:
    """Write the run's input, read from stdin, to `path`. VERBATIM.

    The bytes are the caller's data and are written exactly as received: they
    never pass through substitute(), so an input containing
    ``${services.tools.mcp_headers.Authorization}`` lands as those characters
    and not as this run's bearer, which is in this process's environment when
    any declared file needs it. That separation is the whole reason input and
    templates are different code paths rather than one "render everything".

    Bounded read: at most max_bytes + 1, and the extra byte means refuse. The
    same bound was checked at the door and at the launcher; this is the copy
    that runs inside the Pod, where the stream actually arrives.

    ``expect_len`` is the EXACT count the controller is attaching. When given, a
    stream that arrives SHORT is refused rather than written: a mid-write attach
    fault under ``stdinOnce`` can close the workload's-side stream after a
    partial frame, and a short task written verbatim would start the workload on
    a truncated input it cannot tell from a complete one.
    """
    if not path.startswith(WRITABLE_ROOTS):
        raise UnresolvedReference(
            f"input path {path!r} is outside the platform's writable roots "
            f"{list(WRITABLE_ROOTS)}")
    stream = sys.stdin.buffer if source is None else source
    data = stream.read(max_bytes + 1)
    from .runinput import InputRefused
    if len(data) > max_bytes:
        raise InputRefused(
            f"input exceeds the manifest's process.input.max_bytes bound of "
            f"{max_bytes}; refusing to write a truncated task")
    if expect_len is not None and len(data) != expect_len:
        raise InputRefused(
            f"input arrived as {len(data)} bytes but {expect_len} were "
            "attached; refusing to write a truncated task")
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_bytes(data)
    target.chmod(0o600)
    return path


def main() -> int:
    """The init container: persist the run's input and render the declared
    files into the workload's scratch.

    Runs before the workload starts, in the same Pod, sharing its scratch
    volumes. It exits non-zero on any unresolved reference or oversized
    input, and a failed init container means the workload never starts --
    which is the correct outcome. A stock binary handed a half-written config
    would not refuse it; it would start, misbehave in its own way, and report
    something unrelated.

    Input first, because the controller is attached to this container's stdin
    waiting to write it, and nothing here should hold that attach open longer
    than the read itself. Each half is conditional on the controller having
    asked for it: an env-only manifest under mode 'file' gets the input and no
    templates mount; a templated one under mode 'stdin' gets templates and no
    input.
    """
    from .registry.models import ConfigFile, ConfigurationSpec

    written: list[str] = []
    input_path = os.environ.get(INPUT_PATH_ENV, "")
    if input_path:
        expect = os.environ.get(INPUT_LEN_ENV)
        written.append(persist_input(
            input_path, int(os.environ[INPUT_MAX_ENV]),
            expect_len=int(expect) if expect is not None else None))
    templates = pathlib.Path(TEMPLATES_MOUNT) / TEMPLATES_FILE
    if templates.exists():
        facts = facts_from_environment()
        declared = json.loads(templates.read_text())
        configuration = ConfigurationSpec(files=tuple(
            ConfigFile(path=entry["path"], template=entry["template"])
            for entry in declared))
        written.extend(materialize(render_files(configuration, facts)))
    # Paths and sizes only. The rendered content may hold this run's bearer, and
    # a log line is the one place it would outlive the scratch it was written
    # into.
    for path in written:
        print(f"materialized {path} ({pathlib.Path(path).stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
