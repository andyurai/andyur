"""Atomic publisher for one governed BYOA registry snapshot.

The existing AgentManifest compiler is the authority decision. This module is
only its transaction/serialization boundary: both registry documents and the
runtime overlay are emitted from the same frozen ``CompiledAgent`` objects and
then read back through the production parsers before one directory rename.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from ..registry.manifest_registry import _parse_manifest
from .. import otel
from ..registry.models import AgentResolution, InvalidAgentManifest
from ..registry.models import RUNTIME_PROTOCOL_EXEC_V1
from ..registry.runtime_overlay import RUNTIME_OVERLAY, load_runtime_overlay
from ..registry.runtime_wire import encode_runtime
from .compiler import compile_resolution
from .models import InvalidManifest, PlatformPolicy
from .parser import load_manifest

MAX_PUBLISH_INPUT_BYTES = 1024 * 1024
MAX_GATE_SOURCE_BYTES = 1024 * 1024
# A Sigstore bundle, not a bare signature: cosign v3 emits the signature, the
# public key and any transparency-log proof together, and its offline path
# (no tlog upload) REQUIRES this format. Attestation needs cosign v3 or newer.
EVIDENCE_SIGNATURE_SUFFIX = ".sigstore.json"
PUBLISH_TOOL_TIMEOUT_SECONDS = 180

# The live conformance gate is the only producer of publication evidence. Its
# source files are hashed into every artifact it writes, and publication
# recomputes those hashes from the gate sources so evidence produced by an
# older, newer, or edited gate can never sign a snapshot. One location, shared
# with the CLI that launches the gate, so the two cannot drift apart.
#
# The gate lives in infra/, which is NOT part of the installed package: it is a
# disposable live gate, not a library. So publication -- like running the gate
# itself -- needs the source tree, or an explicit gate directory pointing at
# the sources that produced the evidence. Publishing evidence nobody can check
# against a gate would be the property this exists to provide, given away.
CONFORMANCE_GATE_DIR = Path(__file__).resolve().parents[2] / "infra" / "byoa-spike"
CONFORMANCE_GATE_SCRIPT = "byoa_gate.py"
CONFORMANCE_GATE_SOURCES = {"gate_sha256": CONFORMANCE_GATE_SCRIPT,
                            "harness_sha256": "runtime_v1.py"}
# The exec/v1 gate (ADR-011 D8) is a sibling script with the same evidence
# contract. Each artifact names the gate that produced it (`gate`), and
# publication checks it against THAT gate's sources: the two gates evolve
# independently, and editing one must not silently stale the other's evidence.
EXEC_CONFORMANCE_GATE_SCRIPT = "exec_v1_gate.py"
EXEC_CONFORMANCE_GATE_SOURCES = {"exec_gate_sha256": EXEC_CONFORMANCE_GATE_SCRIPT}
CONFORMANCE_GATES = {
    "byoa-runtime-v1": CONFORMANCE_GATE_SOURCES,
    "exec-v1-conformance": EXEC_CONFORMANCE_GATE_SOURCES,
}


def _destination_refusal(target: Path) -> str:
    """Why this destination is refused, distinguishing the two cases.

    An EMPTY directory is this publisher's own reservation left behind by a run
    that was killed mid-flight, not evidence. Saying so is the difference
    between a path an operator can reclaim and one that looks permanently
    taken. It is never reclaimed automatically: a concurrent publisher's live
    reservation is indistinguishable, and two publishers writing one
    destination is exactly what the reservation prevents.
    """
    try:
        occupied = any(target.iterdir())
    except OSError:
        occupied = True
    if occupied:
        return "destination already exists"
    return ("an empty directory is here, left by an interrupted publish; "
            "remove it to retry")


def _read_bounded(path: Path, cap: int = MAX_PUBLISH_INPUT_BYTES) -> bytes:
    """Read a REGULAR file of at most `cap` bytes, never following a symlink.

    Every input here is an operator-supplied path. Sizing with `stat()` and
    then reading is both a TOCTOU and a lie for anything that is not a regular
    file: a character device reports zero bytes and returns them forever, so
    `--conformance-evidence /dev/zero` grew to 30 GiB of RSS and never
    terminated, and a FIFO simply hangs. One descriptor, checked, bounded.
    """
    try:
        # O_NONBLOCK matters as much as the S_ISREG check below: opening a
        # FIFO read-only BLOCKS until someone writes to it, so without this the
        # refusal never runs and the publisher simply hangs.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise InvalidManifest(f"{path}: cannot read: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InvalidManifest(f"{path}: not a regular file")
        data = os.read(fd, cap + 1)
        if len(data) > cap:
            raise InvalidManifest(f"{path}: input exceeds {cap} bytes")
        return data
    except OSError as exc:
        raise InvalidManifest(f"{path}: cannot read: {exc}") from exc
    finally:
        os.close(fd)


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(_read_bounded(path).decode())
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidManifest(f"{path}: cannot read validated JSON: {exc}") from exc
    except RecursionError as exc:  # deeply nested JSON is input, not a crash
        raise InvalidManifest(f"{path}: document nests too deeply") from exc
    if not isinstance(value, dict):
        raise InvalidManifest(f"{path}: document must be an object")
    return value


def conformance_source_digests(gate_dir: str | Path = CONFORMANCE_GATE_DIR,
                               gate: str = "byoa-runtime-v1") -> dict:
    """sha256 of each of ONE gate's source files as they exist right now."""
    try:
        sources = CONFORMANCE_GATES[gate]
    except KeyError:
        raise InvalidManifest(
            f"unknown conformance gate {gate!r}; known: {sorted(CONFORMANCE_GATES)}") from None
    digests = {}
    for key, name in sources.items():
        source = Path(gate_dir) / name
        try:
            digests[key] = hashlib.sha256(
                _read_bounded(source, MAX_GATE_SOURCE_BYTES)).hexdigest()
        except InvalidManifest as exc:
            raise InvalidManifest(
                f"conformance gate source {source} not usable ({exc}). Publication "
                "checks evidence against the gate that produced it, and the gate "
                "ships only in the source tree, not the installed package: run "
                "this from a checkout, or pass the gate directory explicitly "
                "(--conformance-gate-dir)") from exc
    return digests


@dataclass(frozen=True)
class ProvenWorkload:
    """What one green artifact proved, as the publisher binds it: the image and
    command always; interface, input mode and granted model when the producing
    gate records them (the exec/v1 gate does; the runtime-v1 gate's contract
    predates them and implies runtime-v1)."""
    image: str
    command: tuple[str, ...]
    gate: str
    interface: str | None = None
    input_mode: str | None = None
    model: str | None = None


_SERVICE = "andyur-publisher"


def _evidence_span(path: Path):
    """`publisher.evidence`: one artifact's acceptance or refusal BY NAME
    (observability-exit-criteria.md 1). The refusal code is the InvalidManifest
    class of the decision; the message rides as a bounded detail."""
    return otel.setup_tracing(_SERVICE).start_as_current_span(
        "publisher.evidence", attributes={"andyur.evidence": otel.safe_attribute(path.name)})


def _refused(span, code: str, message: str) -> InvalidManifest:
    try:
        span.set_attribute("andyur.outcome", "refused")
        span.set_attribute("andyur.refusal", code)
        span.set_attribute("andyur.detail", otel.safe_attribute(message))
    except Exception:
        pass
    return InvalidManifest(message)


def load_conformance_evidence(path: str | Path, *,
                              gate_dir: str | Path = CONFORMANCE_GATE_DIR
                              ) -> ProvenWorkload:
    with _evidence_span(Path(path)) as span:
        proven = _load_conformance_evidence(Path(path), span, gate_dir=gate_dir)
        try:
            span.set_attribute("andyur.outcome", "accepted")
            span.set_attribute("andyur.gate", proven.gate)
            span.set_attribute("andyur.image", otel.safe_attribute(proven.image))
        except Exception:
            pass
        return proven


def _load_conformance_evidence(path: Path, span, *, gate_dir) -> ProvenWorkload:
    """Validate one gate artifact; return what it proved (ProvenWorkload).

    Evidence is only meaningful for the exact workload production will launch:
    the digest-pinned image AND the manifest command that overrides its
    entrypoint. It must be completely green and produced by the gate source
    installed here: a single trusted operator can still write an artifact by
    hand (the expected digests are just sha256 of two readable files), but
    evidence from an older, newer, or edited gate can no longer pass as a
    description of the gate that exists now.
    """
    source = path
    evidence = _read_json(source)
    inputs = evidence.get("inputs")
    if not isinstance(inputs, dict):
        raise _refused(span, "evidence_no_inputs", f"{source}: conformance evidence records no inputs")
    checks = evidence.get("checks")
    if (evidence.get("ok") is not True or not isinstance(checks, list) or
            not checks or not all(isinstance(item, dict) and item.get("ok") is True
                                  for item in checks)):
        raise _refused(span, "evidence_not_green",
            f"{source}: conformance evidence is not completely green")
    selected = inputs.get("selected_image")
    command = inputs.get("selected_command")
    if (not isinstance(selected, str) or not selected or
            not isinstance(command, list) or not command or
            not all(isinstance(part, str) and part for part in command)):
        raise _refused(span, "evidence_unbound_workload",
            f"{source}: conformance evidence does not name the selected image and command")
    # An artifact that names no gate is the runtime-v1 gate's (it predates the
    # field); one that names an unknown gate is refused, never assumed.
    gate = evidence.get("gate", "byoa-runtime-v1")
    if gate not in CONFORMANCE_GATES:
        raise _refused(span, "evidence_unknown_gate",
            f"{source}: conformance evidence names an unknown gate {gate!r}")
    expected = conformance_source_digests(gate_dir, gate=gate)
    for key, digest in expected.items():
        if inputs.get(key) != digest:
            raise _refused(span, "evidence_stale_source",
                f"{source}: conformance evidence {key} does not match the installed "
                f"gate source; rerun `andyur agents conformance`")
    if gate == "exec-v1-conformance":
        # The exec/v1 gate records what it launched beyond image+command; an
        # artifact missing any of them is not this gate's (R MED-3).
        for key in ("interface", "input_mode", "granted_model"):
            if not isinstance(inputs.get(key), str) or not inputs[key]:
                raise _refused(span, "evidence_missing_binding",
                    f"{source}: exec/v1 conformance evidence records no {key}")
        return ProvenWorkload(selected, tuple(command), gate, inputs["interface"],
                              inputs["input_mode"], inputs["granted_model"])
    return ProvenWorkload(selected, tuple(command), gate, "andyur-agent-runtime/v1")


def sign_evidence(evidence: str | Path, signing_key: str | Path, *,
                  disable_transparency_log: bool = False,
                  runner=subprocess.run) -> Path:
    """Detach-sign one conformance artifact with cosign; return the .sig path.

    Optional, and off unless an operator asks for it. Content binding proves an
    artifact describes the gate it names; it cannot prove a gate ever ran,
    because the digests it compares are of files anyone can read. A signature
    is the part that carries WHO produced the evidence, which is what a
    publisher other than the operator would have to be judged on. cosign is the
    signing component here exactly as it is for the snapshot itself.
    """
    source = Path(evidence)
    _read_bounded(source)  # refuse anything we would not accept as evidence
    key = Path(signing_key)
    if not key.is_file():
        raise InvalidManifest(f"cosign signing key not found at {key}")
    signature = source.with_name(source.name + EVIDENCE_SIGNATURE_SUFFIX)
    if signature.exists():
        raise InvalidManifest(f"{signature}: signature already exists")
    argv = ["cosign", "sign-blob", "--key", str(key), "--yes"]
    if disable_transparency_log:
        # Both flags, together: v3 refuses --tlog-upload=false while a signing
        # config is in play. Same pair the snapshot signing path uses.
        argv.extend(["--tlog-upload=false", "--use-signing-config=false"])
    argv.extend(["--new-bundle-format", "--bundle", signature.name])
    _tool([*argv, source.name], cwd=source.parent, runner=runner)
    if not signature.is_file():
        raise InvalidManifest("cosign sign-blob wrote no bundle")
    return signature


def verify_evidence_signature(evidence: str | Path, public_key: str | Path, *,
                              runner=subprocess.run) -> None:
    """Refuse an artifact that is not signed by the expected key."""
    source = Path(evidence)
    signature = source.with_name(source.name + EVIDENCE_SIGNATURE_SUFFIX)
    if not signature.is_file():
        raise InvalidManifest(
            f"{source}: no {EVIDENCE_SIGNATURE_SUFFIX} beside it, and a "
            "conformance key was required for this publication")
    key = Path(public_key)
    if not key.is_file():
        raise InvalidManifest(f"conformance public key not found at {key}")
    # The KEY signature is the property being relied on here. Transparency-log
    # verification is skipped deliberately: evidence signed offline carries no
    # log entry by design, and requiring one would make the offline path
    # unverifiable rather than more secure.
    _tool(["cosign", "verify-blob", "--key", str(key),
           "--bundle", signature.name,
           "--insecure-ignore-tlog=true", source.name],
          cwd=source.parent, runner=runner)


def load_policy_resolution(path: str | Path) -> AgentResolution:
    """Load the platform-owned authority document used as compiler policy.

    Reusing the production registry parser avoids a publisher-only policy
    grammar. Its agent identity/instructions are labels; tools and ceiling are
    the approved catalog. Approved models remain an explicit CLI/API input so
    an omitted model list cannot be confused with the document's one model.
    """
    source = Path(path)
    try:
        return _parse_manifest(str(source), _read_json(source))
    except InvalidAgentManifest as exc:
        raise InvalidManifest(f"{source}: invalid policy resolution: {exc}") from exc


def _authority_document(resolution: AgentResolution) -> dict:
    return {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": resolution.agent_id,
        "name": resolution.name,
        "instructions": resolution.instructions,
        "model": resolution.model,
        "tools": [
            {
                "name": tool.name,
                "reach_url": tool.reach_url,
                "resource_id": tool.resource_id,
                "authority": tool.authority,
                "expected_spiffe_id": tool.expected_spiffe_id,
                "credential_ref": tool.credential_ref,
                "credential_headers": (None if tool.credential_headers is None
                                       else list(tool.credential_headers)),
                "mcp_tools": (None if tool.mcp_tools is None else [
                    {"name": grant.name, "requires": grant.requires}
                    for grant in tool.mcp_tools
                ]),
            }
            for tool in resolution.tools
        ],
        "ceiling": {
            "actions": (None if resolution.ceiling.actions is None
                        else list(resolution.ceiling.actions)),
            "resources": (None if resolution.ceiling.resources is None
                          else list(resolution.ceiling.resources)),
        },
    }


def _runtime_document(resolution: AgentResolution) -> dict:
    runtime = resolution.runtime
    if runtime is None:  # compile_resolution promises this; defend the boundary.
        raise InvalidManifest(f"{resolution.agent_id}: compiler omitted runtime")
    # One codec, shared with the per-run assignment and both decoders. The
    # omit-when-unset rule that keeps these bytes stable across an added field
    # lives there, declared per field, rather than in each site's own dict.
    return encode_runtime(runtime)


def package_agents(manifest_paths: list[str | Path], policy_path: str | Path,
                   destination: str | Path, *,
                   approved_models: tuple[str, ...] | None,
                   policy_revision: str | None,
                   max_lifetime_seconds: int | None = None) -> Path:
    """Compile and atomically publish a new, validated snapshot directory.

    Existing destinations are refused: immutable evidence is never overwritten.
    Signing/pushing the completed directory remains the OCI tooling's job.
    """
    if not manifest_paths:
        raise InvalidManifest("package requires at least one manifest")
    target = Path(destination)
    if target.exists():
        raise InvalidManifest(f"{target}: {_destination_refusal(target)}")
    target.parent.mkdir(parents=True, exist_ok=True)

    approved = load_policy_resolution(policy_path)
    policy = PlatformPolicy(
        tool_catalog={tool.name: tool for tool in approved.tools},
        ceiling=approved.ceiling,
        approved_models=approved_models,
        revision=policy_revision,
        max_lifetime_seconds=max_lifetime_seconds,
    )
    compiled = [compile_resolution(load_manifest(path), policy)
                for path in manifest_paths]
    ids = [item.resolution.agent_id for item in compiled]
    if len(set(ids)) != len(ids):
        raise InvalidManifest("package contains duplicate agent ids")

    # Exclusive mkdir is the atomic "does not exist yet" check; the early
    # exists() above only spares a doomed compile. A concurrent publisher loses
    # the race here, before either snapshot becomes visible, and the empty
    # reservation is what the final rename replaces.
    try:
        os.mkdir(target)
    except FileExistsError as exc:
        raise InvalidManifest(f"{target}: {_destination_refusal(target)}") from exc
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))
        overlay = {}
        for item in compiled:
            resolution = item.resolution
            _write_durable(staging / f"{resolution.agent_id}.json",
                           _authority_document(resolution))
            overlay[resolution.agent_id] = _runtime_document(resolution)
        _write_durable(staging / RUNTIME_OVERLAY, overlay)

        # Enforcement-point readback: the exact production consumers must join
        # every emitted authority/runtime pair before the directory is visible.
        runtimes = load_runtime_overlay(staging)
        parsed_authority = {
            agent_id: _parse_manifest(
                str(staging / f"{agent_id}.json"),
                _read_json(staging / f"{agent_id}.json"),
            )
            for agent_id in ids
        }
        if set(parsed_authority) != set(runtimes) or set(parsed_authority) != set(ids):
            raise InvalidManifest("published authority/runtime agent sets differ")
        for item in compiled:
            expected = item.resolution
            agent_id = expected.agent_id
            if parsed_authority[agent_id] != dataclasses.replace(
                    expected, runtime=None):
                raise InvalidManifest(
                    f"{agent_id}: serialized authority differs from compiler output")
            if runtimes[agent_id] != expected.runtime:
                raise InvalidManifest(
                    f"{agent_id}: serialized runtime differs from compiler output")
        _fsync_dir(staging)
    except Exception as exc:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        try:
            os.rmdir(target)  # only ever the empty reservation; a snapshot is non-empty
        except OSError:
            pass
        # A filesystem failure while staging is still a refused publication,
        # and the CLI reports refusals -- an escaping OSError would reach the
        # operator as a traceback instead.
        if isinstance(exc, OSError):
            raise InvalidManifest(
                f"{target}: could not stage the snapshot: {exc}") from exc
        raise

    # The rename is the commit. Past it the snapshot is visible and complete,
    # so nothing here may report a refusal: a caller told "refused" while a
    # signed-publishable snapshot sits at --output is the worst outcome of all.
    # The parent fsync only makes that rename survive a crash, and a failure to
    # persist it costs a republish, not correctness.
    try:
        os.replace(staging, target)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        try:
            os.rmdir(target)
        except OSError:
            pass
        raise InvalidManifest(f"{target}: could not publish the snapshot: {exc}") from exc
    try:
        _fsync_dir(target.parent)
    except OSError:
        pass
    return target


def _write_durable(path: Path, document: dict) -> None:
    """Write canonical JSON and fsync it: the snapshot is evidence, and a rename
    that outlives a crash while its contents do not is a corrupt snapshot."""
    data = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    with open(path, "x") as handle:  # exclusive: never overwrite inside staging
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _tool(argv: list[str], *, cwd: Path,
          runner=subprocess.run) -> subprocess.CompletedProcess:
    try:
        result = runner(
            argv, cwd=cwd, capture_output=True, text=True,
            timeout=PUBLISH_TOOL_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise InvalidManifest(f"publisher needs {argv[0]!r} on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise InvalidManifest(
            f"{argv[0]} exceeded {PUBLISH_TOOL_TIMEOUT_SECONDS}s") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-500:]
        raise InvalidManifest(f"{argv[0]} failed (rc={result.returncode}): {detail}")
    return result


def publish_snapshot(snapshot: str | Path, tagged_ref: str, signing_key: str | Path,
                     *, allow_http_registry: bool = False,
                     disable_transparency_log: bool = False,
                     conformance_evidence: tuple[str | Path, ...] = (),
                     conformance_key: str | Path | None = None,
                     gate_dir: str | Path = CONFORMANCE_GATE_DIR,
                     runner=subprocess.run) -> str:
    """Push a completed snapshot, sign its returned digest, return pinned ref.

    ORAS and cosign remain the mature transport/enforcement components. The tag
    is only a publication rendezvous; success is reported exclusively as the
    immutable digest reference that ORAS says it stored and cosign signed.
    """
    source = Path(snapshot)
    files = sorted(source.glob("*.json")) if source.is_dir() else []
    if not files:
        raise InvalidManifest(f"{source}: snapshot has no JSON artifacts")
    # Copy into a private directory and do EVERYTHING against that copy:
    # validate it, and hand ORAS that directory. Validating one set of bytes
    # and then giving ORAS filenames to re-open is not a small race, it is a
    # different set of bytes -- ORAS reads the mutable original long after the
    # checks passed, so a concurrent writer could get attacker content signed.
    # There is no window to shrink here; there is a path to remove.
    sealed = Path(tempfile.mkdtemp(prefix=".publish."))
    # `publisher.publish`: the publication as one span -- the tag it was asked
    # for, the digest ORAS stored and cosign signed, or the refusal by name.
    with otel.setup_tracing(_SERVICE).start_as_current_span(
            "publisher.publish", attributes={
                "andyur.tagged_ref": otel.safe_attribute(tagged_ref),
                "andyur.evidence_count": len(conformance_evidence)}) as span:
        try:
            for item in files:
                (sealed / item.name).write_bytes(_read_bounded(item))
            pinned = _publish_sealed(sealed, files, tagged_ref, key_path=signing_key,
                                     allow_http_registry=allow_http_registry,
                                     disable_transparency_log=disable_transparency_log,
                                     conformance_evidence=conformance_evidence,
                                     conformance_key=conformance_key,
                                     gate_dir=gate_dir, runner=runner)
            span.set_attribute("andyur.outcome", "published")
            span.set_attribute("andyur.snapshot_ref", otel.safe_attribute(pinned))
            return pinned
        except InvalidManifest as exc:
            span.set_attribute("andyur.outcome", "refused")
            span.set_attribute("andyur.detail", otel.safe_attribute(str(exc)))
            raise
        finally:
            shutil.rmtree(sealed, ignore_errors=True)


def _publish_sealed(source: Path, files: list, tagged_ref: str, *, key_path,
                    allow_http_registry: bool, disable_transparency_log: bool,
                    conformance_evidence, conformance_key, gate_dir,
                    runner) -> str:
    """Validate and push one immutable copy of a snapshot."""
    signing_key = key_path
    runtimes = load_runtime_overlay(source)
    # Everything being pushed must parse, not merely exist: otherwise "the
    # validated snapshot" names only the overlay, and the authority documents
    # ride along unread.
    authority = {}
    for item in files:
        if item.name == RUNTIME_OVERLAY:
            continue
        try:
            parsed = _parse_manifest(str(source / item.name),
                                     _read_json(source / item.name))
        except InvalidAgentManifest as exc:
            raise InvalidManifest(
                f"{item.name}: not a publishable authority document: {exc}") from exc
        authority[parsed.agent_id] = parsed
    if set(authority) != set(runtimes):
        raise InvalidManifest(
            f"{source}: authority and runtime documents describe different agents")
    # Evidence is keyed on the whole launched workload, image AND command:
    # production overrides the image entrypoint with the manifest command, so
    # an image proven under a different command was never actually tested.
    containers = {agent_id: runtime for agent_id, runtime in runtimes.items()
                  if runtime.runtime_type == "container"}
    # The overlay grammar tolerates a commandless container; conformance cannot.
    # Refuse it by name here rather than formatting an unsatisfiable
    # requirement no evidence could ever match.
    commandless = sorted(agent_id for agent_id, runtime in containers.items()
                         if not runtime.command)
    if commandless:
        raise InvalidManifest(
            "container runtimes without a command cannot be conformance-tested: "
            + ", ".join(commandless))
    if conformance_key is not None:
        # Before the content is trusted enough to be read as evidence.
        for path in conformance_evidence:
            verify_evidence_signature(path, conformance_key, runner=runner)
    proven = {}
    for path in conformance_evidence:
        item = load_conformance_evidence(path, gate_dir=gate_dir)
        proven[(item.image, tuple(item.command))] = item
    # Evidence is bound to the WHOLE workload the snapshot seals, not only to
    # image+command: the interface the gate exercised, the input mode it
    # delivered, and the model it granted must be the ones being published,
    # and an exec/v1 runtime is proven only by the exec/v1 gate (R MED-3).
    problems = []
    for agent_id, runtime in sorted(containers.items()):
        key = (f"{runtime.image_ref}@{runtime.image_digest}", tuple(runtime.command))
        item = proven.get(key)
        if item is None:
            problems.append(f"{key[0]} {list(key[1])}: no green conformance evidence")
            continue
        exec_v1 = runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
        if exec_v1 and item.gate != "exec-v1-conformance":
            problems.append(f"{agent_id}: an exec/v1 runtime needs exec/v1 conformance "
                            f"evidence, not the {item.gate!r} gate's")
            continue
        if item.interface is not None and item.interface != runtime.interface_version:
            problems.append(f"{agent_id}: evidence proved interface {item.interface!r}, "
                            f"the runtime declares {runtime.interface_version!r}")
        want_mode = runtime.process.input_mode if runtime.process else None
        if item.input_mode is not None and item.input_mode != want_mode:
            problems.append(f"{agent_id}: evidence delivered input by {item.input_mode!r}, "
                            f"the runtime declares {want_mode!r}")
        granted = authority[agent_id].model
        if item.model is not None and item.model != granted:
            problems.append(f"{agent_id}: evidence ran with model {item.model!r}, "
                            f"the snapshot grants {granted!r}")
    if problems:
        raise InvalidManifest("publication lacks matching conformance evidence: "
                              + "; ".join(problems))
    if (not tagged_ref or "@" in tagged_ref or any(c.isspace() for c in tagged_ref)
            or tagged_ref.startswith("-") or ":" not in tagged_ref.rsplit("/", 1)[-1]):
        raise InvalidManifest(
            "publication reference must be a non-digest OCI reference with an explicit tag")
    key = Path(signing_key)
    if not key.is_file():
        raise InvalidManifest(f"cosign signing key not found at {key}")

    push = ["oras", "push", "--format", "json"]
    if allow_http_registry:
        push.append("--plain-http")
    push.extend([tagged_ref, *sorted(item.name for item in files)])
    result = _tool(push, cwd=source, runner=runner)
    try:
        reference = json.loads(result.stdout)["reference"]
        digest = reference.rsplit("@", 1)[1]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        raise InvalidManifest("oras push did not return an immutable reference") from exc
    from ..registry.models import SHA256_DIGEST_RE
    if not SHA256_DIGEST_RE.fullmatch(digest):
        raise InvalidManifest(f"oras push returned invalid digest {digest!r}")
    pinned = tagged_ref.rsplit(":", 1)[0] + "@" + digest

    sign = ["cosign", "sign", "--key", str(key), "--yes"]
    if allow_http_registry:
        sign.append("--allow-http-registry")
    if disable_transparency_log:
        sign.append("--tlog-upload=false")
    # cosign v3 requires this when intentionally disabling the tlog; v2 does
    # not know it. Retry only that compatibility form, never a different ref.
    primary = sign.copy()
    if disable_transparency_log:
        primary.append("--use-signing-config=false")
    try:
        _tool([*primary, pinned], cwd=source, runner=runner)
    except InvalidManifest:
        if not disable_transparency_log:
            raise
        _tool([*sign, pinned], cwd=source, runner=runner)
    return pinned
