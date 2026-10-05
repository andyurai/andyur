"""Atomic publisher: one compiler transaction produces both governed halves."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from andyur.agentspec import InvalidManifest
from andyur.agentspec.publisher import package_agents, publish_snapshot
from andyur.agentspec import publisher
from andyur.cli import build_parser, cmd_agents_init
from andyur import cli
from andyur.registry.governed import GovernedAgentRegistry
from andyur.registry.runtime_overlay import load_runtime_overlay


DIGEST = "sha256:" + "ab" * 32


def _manifest(agent_id="agt_customer", model="model-approved"):
    return {
        "apiVersion": "andyur.ai/v1", "kind": "Agent",
        "metadata": {"id": agent_id, "name": agent_id.removeprefix("agt_"),
                     "version": "1.0.0"},
        "runtime": {"type": "container",
                    "image": {"ref": "registry.example/customer", "digest": DIGEST},
                    "command": ["/app/agent", "serve"],
                    "interface": {"protocol": "andyur-agent-runtime/v1"}},
        "instructions": "Serve governed work.",
        "model": {"requested": model, "access": "proxy"},
    }


def _policy():
    return {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": "agt_publisher_policy", "name": "publisher-policy",
        "instructions": "Platform-owned publisher policy input.",
        "model": None, "tools": [],
        "ceiling": {"actions": [], "resources": []},
    }


def _write(path: Path, value):
    path.write_text(json.dumps(value))
    return path


def _gate_dir(tmp_path: Path) -> Path:
    """A stand-in installed gate whose source hashes the tests control."""
    gate = tmp_path / "gate"
    gate.mkdir(exist_ok=True)
    (gate / "byoa_gate.py").write_text("# simulated gate source\n")
    (gate / "runtime_v1.py").write_text("# simulated harness source\n")
    return gate


def _expected_digests(gate_dir: Path) -> dict:
    """Recomputed here rather than through the code under test: a test that
    asks the implementation what to expect agrees with its bugs."""
    return {
        "gate_sha256": hashlib.sha256(
            (gate_dir / "byoa_gate.py").read_bytes()).hexdigest(),
        "harness_sha256": hashlib.sha256(
            (gate_dir / "runtime_v1.py").read_bytes()).hexdigest(),
    }


def _green_evidence(gate_dir: Path, image: str, command: list[str]) -> dict:
    return {
        "ok": True,
        "inputs": {"selected_image": image, "selected_command": command,
                   **_expected_digests(gate_dir)},
        "checks": [{"check": "G1", "ok": True}],
    }


def test_package_emits_one_joinable_authority_and_runtime_snapshot(tmp_path):
    manifest = _write(tmp_path / "agent.json", _manifest())
    policy = _write(tmp_path / "policy.json", _policy())
    output = package_agents([manifest], policy, tmp_path / "snapshot",
                            approved_models=("model-approved",),
                            policy_revision="review-17")

    key = _write(tmp_path / "cosign.pub", {"test": "public-key-placeholder"})
    registry = GovernedAgentRegistry(
        "registry.example/snapshot@sha256:" + "cd" * 32, str(key),
        verify=lambda ref, key_path: None,
        pull=lambda ref, destination: [
            shutil.copy(item, destination)
            for item in output.iterdir()
        ],
    )
    authority = registry.resolve("agt_customer")
    runtime = authority.runtime
    assert authority.agent_id == "agt_customer"
    assert runtime.image_digest == DIGEST
    assert runtime.policy_revision == "review-17"
    assert runtime.manifest_digest.startswith("sha256:")
    assert set(p.name for p in output.iterdir()) == {
        "agt_customer.json", "runtime-resolutions.json",
    }


def test_policy_denial_leaves_no_partial_destination(tmp_path):
    manifest = _write(tmp_path / "agent.json", _manifest(model="model-denied"))
    policy = _write(tmp_path / "policy.json", _policy())
    output = tmp_path / "snapshot"
    with pytest.raises(PermissionError, match="model-denied"):
        package_agents([manifest], policy, output,
                       approved_models=("model-approved",), policy_revision="r1")
    assert not output.exists()
    assert list(tmp_path.glob(".snapshot.*")) == []


def test_existing_evidence_directory_is_never_overwritten(tmp_path):
    manifest = _write(tmp_path / "agent.json", _manifest())
    policy = _write(tmp_path / "policy.json", _policy())
    output = tmp_path / "snapshot"
    output.mkdir()
    marker = _write(output / "evidence.json", {"keep": True})
    with pytest.raises(InvalidManifest, match="already exists"):
        package_agents([manifest], policy, output,
                       approved_models=("model-approved",), policy_revision="r1")
    assert json.loads(marker.read_text()) == {"keep": True}


def test_duplicate_agent_id_is_refused_before_publication(tmp_path):
    first = _write(tmp_path / "one.json", _manifest())
    second = _write(tmp_path / "two.json", _manifest())
    policy = _write(tmp_path / "policy.json", _policy())
    with pytest.raises(InvalidManifest, match="duplicate agent ids"):
        package_agents([first, second], policy, tmp_path / "snapshot",
                       approved_models=("model-approved",), policy_revision="r1")
    assert not (tmp_path / "snapshot").exists()


def test_valid_but_drifted_runtime_serialization_is_refused(tmp_path, monkeypatch):
    """Mutate the exact split-artifact seam: valid JSON, wrong executable."""
    manifest = _write(tmp_path / "agent.json", _manifest())
    policy = _write(tmp_path / "policy.json", _policy())
    original = publisher._runtime_document

    def drifted(resolution):
        document = original(resolution)
        document["image_digest"] = "sha256:" + "ef" * 32
        return document

    monkeypatch.setattr(publisher, "_runtime_document", drifted)
    with pytest.raises(InvalidManifest, match="runtime differs"):
        package_agents([manifest], policy, tmp_path / "snapshot",
                       approved_models=("model-approved",), policy_revision="r1")
    assert not (tmp_path / "snapshot").exists()
    assert list(tmp_path.glob(".snapshot.*")) == []


def test_cli_package_is_wired_with_secure_model_default():
    args = build_parser().parse_args([
        "agents", "package", "agent.json",
        "--policy-resolution", "policy.json",
        "--policy-revision", "review-17", "--output", "snapshot",
    ])
    assert args.func.__name__ == "cmd_agents_package"
    assert args.approved_model == []


def test_cli_validate_is_wired_for_multiple_manifests():
    args = build_parser().parse_args([
        "agents", "validate", "one.json", "two.json",
    ])
    assert args.func.__name__ == "cmd_agents_validate"
    assert args.manifests == ["one.json", "two.json"]


def test_cli_conformance_is_wired_to_one_governed_manifest():
    args = build_parser().parse_args([
        "agents", "conformance", "agent.json", "--evidence", "evidence.json",
    ])
    assert args.func.__name__ == "cmd_agents_conformance"
    assert args.manifest == "agent.json"
    assert args.evidence == "evidence.json"


def _conformance_run(tmp_path, monkeypatch, recorded_inputs_mutation=None):
    """Drive `agents conformance` with a simulated gate process; return the env
    the gate saw. The simulated gate writes evidence exactly as instructed,
    then a mutation callback corrupts one recorded input (None = honest gate).
    """
    manifest = _write(tmp_path / "agent.json", _manifest())
    gate = _gate_dir(tmp_path)
    monkeypatch.setattr(publisher, "CONFORMANCE_GATE_DIR", gate)
    evidence = tmp_path / "evidence.json"
    seen_env = {}
    seen_argv = []

    def fake_gate(argv, **kwargs):
        env = kwargs["env"]
        seen_argv.extend(argv)
        seen_env.update({k: v for k, v in env.items()
                         if k.startswith("ANDYUR_CONFORMANCE_")})
        recorded = {
            "ok": True,
            "inputs": {
                "selected_image": env["ANDYUR_CONFORMANCE_IMAGE"],
                "selected_command": json.loads(env["ANDYUR_CONFORMANCE_COMMAND"]),
                **_expected_digests(gate),
            },
            "checks": [{"check": "G1", "ok": True}],
        }
        if recorded_inputs_mutation is not None:
            recorded_inputs_mutation(recorded["inputs"])
        Path(env["ANDYUR_CONFORMANCE_EVIDENCE"]).write_text(json.dumps(recorded))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(cli.subprocess, "run", fake_gate)
    args = build_parser().parse_args([
        "agents", "conformance", str(manifest), "--evidence", str(evidence),
    ])
    cli.cmd_agents_conformance(args)
    return seen_env, seen_argv


def test_conformance_runs_the_manifest_workload_and_accepts_honest_evidence(
        tmp_path, monkeypatch):
    """Positive control + H2 wiring: the gate is launched with the manifest's
    exact image AND command, and honest evidence for that workload passes."""
    env, argv = _conformance_run(tmp_path, monkeypatch)
    assert env["ANDYUR_CONFORMANCE_IMAGE"] == "registry.example/customer@" + DIGEST
    assert json.loads(env["ANDYUR_CONFORMANCE_COMMAND"]) == ["/app/agent", "serve"]
    # ...and it launched the gate it validated, not some other process
    assert argv == [sys.executable,
                    str(publisher.CONFORMANCE_GATE_DIR / "byoa_gate.py")]


@pytest.mark.parametrize("mutation, expected", [
    (lambda inputs: inputs.update(
        selected_image="registry.example/default@sha256:" + "cd" * 32),
     "not bound to the selected image and command"),
    (lambda inputs: inputs.update(selected_command=["/bin/other"]),
     "not bound to the selected image and command"),
    (lambda inputs: inputs.update(gate_sha256="ab" * 32),
     "gate_sha256 does not match"),
    (lambda inputs: inputs.update(harness_sha256="ab" * 32),
     "harness_sha256 does not match"),
], ids=["different-image", "different-command", "different-gate-source",
        "different-harness-source"])
def test_conformance_refuses_evidence_for_a_different_workload_or_gate(
        tmp_path, monkeypatch, capsys, mutation, expected):
    """Exact mutations: evidence drifting from the selected image, the selected
    command, or the gate source must all be refused.

    The exit STATUS is the assertion that matters as much as the exception: a
    refusal that exits 0 is a pass to every shell pipeline and CI step, and
    `pytest.raises(SystemExit)` alone cannot tell those apart.
    """
    with pytest.raises(SystemExit) as refusal:
        _conformance_run(tmp_path, monkeypatch, mutation)
    assert refusal.value.code == 1
    assert expected in capsys.readouterr().err


def test_cli_init_writes_a_valid_governed_skeleton_without_overwrite(tmp_path):
    output = tmp_path / "agent.json"
    args = build_parser().parse_args([
        "agents", "init", "--id", "agt_customer", "--name", "customer",
        "--image-ref", "registry.example/customer",
        "--image-digest", DIGEST,
        "--output", str(output),
    ])
    cmd_agents_init(args)
    assert json.loads(output.read_text())["metadata"]["id"] == "agt_customer"
    from andyur.agentspec import load_manifest
    assert load_manifest(output).metadata.name == "customer"
    with pytest.raises(SystemExit):
        cmd_agents_init(args)


def test_publish_signs_exact_digest_returned_by_oras(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write(snapshot / "agt_customer.json", _authority())
    _write(snapshot / "runtime-resolutions.json", {"agt_customer": {
        "runtime_type": "builtin-claude", "interface_version": None,
        "manifest_digest": "sha256:" + "cd" * 32, "image_ref": None,
        "image_digest": None, "command": None, "resources": None,
        "policy_revision": "r1"}})
    key = _write(tmp_path / "cosign.key", {"private": "placeholder"})
    calls = []
    digest = "sha256:" + "cd" * 32

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "oras":
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"reference": f"localhost:5001/a@{digest}"}), "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    pinned = publish_snapshot(
        snapshot, "localhost:5001/a:review-17", key,
        allow_http_registry=True, disable_transparency_log=True, runner=runner,
    )
    assert pinned == f"localhost:5001/a@{digest}"
    assert calls[0][:4] == ["oras", "push", "--format", "json"]
    assert "localhost:5001/a:review-17" in calls[0]
    assert {"agt_customer.json", "runtime-resolutions.json"} <= set(calls[0])
    assert calls[1][-1] == pinned
    assert "--allow-http-registry" in calls[1]
    assert "--tlog-upload=false" in calls[1]


@pytest.mark.parametrize("reference", [
    "registry.example/a", "registry.example/a@sha256:" + "ab" * 32,
    "-registry.example/a:tag", "registry.example/a:tag with-space",
])
def test_publish_refuses_ambiguous_or_mutable_success_references(
        tmp_path, reference):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write(snapshot / "agt_customer.json", _authority())
    _write(snapshot / "runtime-resolutions.json", {"agt_customer": {
        "runtime_type": "builtin-claude", "interface_version": None,
        "manifest_digest": "sha256:" + "cd" * 32, "image_ref": None,
        "image_digest": None, "command": None, "resources": None,
        "policy_revision": "r1"}})
    key = _write(tmp_path / "cosign.key", {})
    with pytest.raises(InvalidManifest, match="explicit tag"):
        publish_snapshot(snapshot, reference, key, runner=pytest.fail)


def test_publish_refuses_oras_output_without_digest_and_never_signs(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write(snapshot / "agt_customer.json", _authority())
    _write(snapshot / "runtime-resolutions.json", {"agt_customer": {
        "runtime_type": "builtin-claude", "interface_version": None,
        "manifest_digest": "sha256:" + "cd" * 32, "image_ref": None,
        "image_digest": None, "command": None, "resources": None,
        "policy_revision": "r1"}})
    key = _write(tmp_path / "cosign.key", {})
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"reference": "registry.example/a:tag"}), "")

    with pytest.raises(InvalidManifest, match="immutable reference"):
        publish_snapshot(snapshot, "registry.example/a:tag", key, runner=runner)
    assert len(calls) == 1 and calls[0][0] == "oras"


def _authority(agent_id="agt_customer"):
    """A real authority document: publication parses everything it pushes."""
    return {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": agent_id, "name": agent_id.removeprefix("agt_"),
        "instructions": "Serve governed work.", "model": "model-approved",
        "tools": [], "ceiling": {"actions": [], "resources": []},
    }


def _container_snapshot(tmp_path: Path, command=("/app/agent", "serve")):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write(snapshot / "agt_customer.json", _authority())
    _write(snapshot / "runtime-resolutions.json", {"agt_customer": {
        "runtime_type": "container",
        "interface_version": "andyur-agent-runtime/v1",
        "manifest_digest": "sha256:" + "cd" * 32,
        "image_ref": "registry.example/customer",
        "image_digest": DIGEST,
        "command": list(command),
        "resources": None,
        "policy_revision": "r1",
    }})
    return snapshot, "registry.example/customer@" + DIGEST


def test_container_publication_requires_exact_green_conformance_evidence(tmp_path):
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    key = _write(tmp_path / "cosign.key", {})
    with pytest.raises(InvalidManifest, match="lacks matching conformance"):
        publish_snapshot(snapshot, "registry.example/a:tag", key,
                         gate_dir=gate, runner=pytest.fail)

    wrong = _write(tmp_path / "wrong.json", _green_evidence(
        gate, image + "-wrong", ["/app/agent", "serve"]))
    with pytest.raises(InvalidManifest, match="lacks matching conformance"):
        publish_snapshot(snapshot, "registry.example/a:tag", key, gate_dir=gate,
                         conformance_evidence=(wrong,), runner=pytest.fail)

    green = _write(tmp_path / "green.json", _green_evidence(
        gate, image, ["/app/agent", "serve"]))
    calls = []
    pushed = "sha256:" + "ef" * 32

    def runner(argv, **kwargs):
        calls.append(argv)
        stdout = (json.dumps({"reference": f"registry.example/a@{pushed}"})
                  if argv[0] == "oras" else "")
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    assert publish_snapshot(
        snapshot, "registry.example/a:tag", key, gate_dir=gate,
        conformance_evidence=(green,), runner=runner,
    ) == f"registry.example/a@{pushed}"
    assert [call[0] for call in calls] == ["oras", "cosign"]


def test_publication_refuses_evidence_from_a_different_gate_source(tmp_path):
    """H1 regression: green evidence whose recorded gate/harness hashes do not
    match the installed gate source must never publish. Without source binding
    a stale artifact from an older (weaker) gate keeps signing forever."""
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    key = _write(tmp_path / "cosign.key", {})
    evidence = _green_evidence(gate, image, ["/app/agent", "serve"])
    stale = _write(tmp_path / "stale.json", evidence)
    (gate / "byoa_gate.py").write_text("# the gate has since changed\n")
    with pytest.raises(InvalidManifest, match="gate_sha256 does not match"):
        publish_snapshot(snapshot, "registry.example/a:tag", key, gate_dir=gate,
                         conformance_evidence=(stale,), runner=pytest.fail)

    # The HARNESS is half the gate -- runtime_v1.py implements the protocol
    # under test, including G3's liveness check -- so its digest must bind too.
    (gate / "byoa_gate.py").write_text("# simulated gate source\n")  # restore
    (gate / "runtime_v1.py").write_text("# the harness has since changed\n")
    with pytest.raises(InvalidManifest, match="harness_sha256 does not match"):
        publish_snapshot(snapshot, "registry.example/a:tag", key, gate_dir=gate,
                         conformance_evidence=(stale,), runner=pytest.fail)
    (gate / "runtime_v1.py").write_text("# simulated harness source\n")
    # positive control: evidence regenerated against the current source passes
    fresh = _write(tmp_path / "fresh.json",
                   _green_evidence(gate, image, ["/app/agent", "serve"]))
    with pytest.raises(InvalidManifest, match="cosign signing key"):
        publish_snapshot(snapshot, "registry.example/a:tag",
                         tmp_path / "missing.key", gate_dir=gate,
                         conformance_evidence=(fresh,), runner=pytest.fail)


def test_publication_refuses_evidence_for_a_different_command(tmp_path):
    """H2 regression: production launches image+manifest command; evidence for
    the same image under another command (or none) proves the wrong workload."""
    snapshot, image = _container_snapshot(tmp_path, command=("/app/agent", "serve"))
    gate = _gate_dir(tmp_path)
    key = _write(tmp_path / "cosign.key", {})
    other = _write(tmp_path / "other.json", _green_evidence(
        gate, image, ["/bin/sh", "-c", "true"]))
    with pytest.raises(InvalidManifest, match="lacks matching conformance"):
        publish_snapshot(snapshot, "registry.example/a:tag", key, gate_dir=gate,
                         conformance_evidence=(other,), runner=pytest.fail)
    commandless = _green_evidence(gate, image, ["x"])
    commandless["inputs"]["selected_command"] = None
    bare = _write(tmp_path / "bare.json", commandless)
    with pytest.raises(InvalidManifest, match="selected image and command"):
        publish_snapshot(snapshot, "registry.example/a:tag", key, gate_dir=gate,
                         conformance_evidence=(bare,), runner=pytest.fail)


def test_failed_package_removes_its_reservation_and_never_a_snapshot(
        tmp_path, monkeypatch):
    """A failure AFTER the exclusive target reservation (readback refusal, the
    latest possible one) must reap both staging and the reservation so a retry
    works, while an existing real snapshot stays refused and untouched."""
    policy = _write(tmp_path / "policy.json", _policy())
    good = _write(tmp_path / "good.json", _manifest())
    target = tmp_path / "snap"
    original = publisher._runtime_document

    def drifted(resolution):
        document = original(resolution)
        document["command"] = ["/tampered"]
        return document

    monkeypatch.setattr(publisher, "_runtime_document", drifted)
    with pytest.raises(InvalidManifest, match="serialized runtime differs"):
        package_agents([good], policy, target,
                       approved_models=("model-approved",), policy_revision="r1")
    assert not target.exists()  # reservation reaped; retry is possible
    monkeypatch.setattr(publisher, "_runtime_document", original)
    out = package_agents([good], policy, target,
                         approved_models=("model-approved",),
                         policy_revision="r1")
    assert out == target
    before = sorted(item.name for item in target.iterdir())
    with pytest.raises(InvalidManifest, match="already exists"):
        package_agents([good], policy, target,
                       approved_models=("model-approved",),
                       policy_revision="r1")
    assert sorted(item.name for item in target.iterdir()) == before


def test_live_conformance_evidence_is_current():
    """The committed BYOA conformance artifact must stay bound to the gate
    source that produced it, exactly like the sibling Kubernetes evidence.

    This is the test that keeps the ledger honest: edit byoa_gate.py or
    runtime_v1.py and this goes red until the live gate is rerun, so a
    recorded 11/11 can never silently describe a gate that no longer exists.
    It is also the property publication enforces, asserted here where CI runs
    it rather than only at publish time.
    """
    artifacts = sorted(
        item for item in publisher.CONFORMANCE_GATE_DIR.glob("result-conformance-*.json")
        if not item.name.endswith(publisher.EVIDENCE_SIGNATURE_SUFFIX))
    assert len(artifacts) == 1, (
        "exactly one conformance artifact is the current one; superseded "
        f"evidence is removed, not accumulated: {[a.name for a in artifacts]}")
    artifact = artifacts[0]
    proven = publisher.load_conformance_evidence(artifact)
    recorded = json.loads(artifact.read_text())
    assert recorded["ok"] is True
    assert len(recorded["checks"]) == 11
    assert all(check["ok"] is True for check in recorded["checks"])
    # Identities, not just a count: a gate that dropped G3 and duplicated a
    # trivial G1 would still record 11 green checks with matching hashes.
    assert {check["check"].split()[0] for check in recorded["checks"]} == {
        "G1", "G2", "G3", "G4", "G5", "G6"}
    assert (proven.image, proven.command, proven.gate, proven.interface) == (
        "localhost:5003/andyur/conformance@sha256:"
        "ab1eb4ffc1e5ff931d4b94ecfc516a4b3a2453dd0d18235a19e8a3c793f647dd",
        ("python", "/app/agent.py"), "byoa-runtime-v1", "andyur-agent-runtime/v1",
    )


def test_package_never_reports_refusal_after_the_snapshot_is_visible(
        tmp_path, monkeypatch):
    """The rename is the commit. A failure past it (the durability fsync of the
    parent directory) must not tell the operator the package was refused while
    a complete, signed-publishable snapshot sits at --output."""
    policy = _write(tmp_path / "policy.json", _policy())
    manifest = _write(tmp_path / "agent.json", _manifest())
    target = tmp_path / "snap"
    real_fsync = publisher._fsync_dir
    calls = []

    def failing_parent_fsync(path):
        calls.append(Path(path))
        if len(calls) > 1:  # the post-rename parent fsync, not the staging one
            raise OSError(5, "simulated EIO")
        return real_fsync(path)

    monkeypatch.setattr(publisher, "_fsync_dir", failing_parent_fsync)
    out = package_agents([manifest], policy, target,
                         approved_models=("model-approved",),
                         policy_revision="r1")
    assert out == target
    assert sorted(item.name for item in target.iterdir()) == [
        "agt_customer.json", "runtime-resolutions.json"]
    assert len(calls) == 2  # the failing call really happened


def test_staging_io_failure_is_reported_as_a_refusal_not_a_traceback(
        tmp_path, monkeypatch):
    """`andyur agents package` reports refusals; a filesystem error while
    staging must arrive as one, not as a raw OSError traceback."""
    policy = _write(tmp_path / "policy.json", _policy())
    manifest = _write(tmp_path / "agent.json", _manifest())

    def failing_write(path, document):
        raise OSError(28, "simulated ENOSPC")

    monkeypatch.setattr(publisher, "_write_durable", failing_write)
    with pytest.raises(InvalidManifest, match="could not stage the snapshot"):
        package_agents([manifest], policy, tmp_path / "snap",
                       approved_models=("model-approved",),
                       policy_revision="r1")
    assert not (tmp_path / "snap").exists()


def test_interrupted_reservation_is_named_as_such_not_as_a_snapshot(tmp_path):
    """An empty directory at the destination is this publisher's reservation
    left by an interrupted run. Refuse, but say which case it is: otherwise the
    path is refused forever with a message that sounds like real evidence."""
    policy = _write(tmp_path / "policy.json", _policy())
    manifest = _write(tmp_path / "agent.json", _manifest())
    abandoned = tmp_path / "snap"
    abandoned.mkdir()
    with pytest.raises(InvalidManifest, match="interrupted publish"):
        package_agents([manifest], policy, abandoned,
                       approved_models=("model-approved",),
                       policy_revision="r1")
    (abandoned / "agt_customer.json").write_text("{}")
    with pytest.raises(InvalidManifest, match="destination already exists"):
        package_agents([manifest], policy, abandoned,
                       approved_models=("model-approved",),
                       policy_revision="r1")


def test_commandless_container_is_refused_by_name(tmp_path):
    """The overlay grammar tolerates a container with no command; conformance
    cannot test one. Refuse it by agent id instead of demanding evidence that
    could never exist."""
    snapshot, _ = _container_snapshot(tmp_path)
    overlay = json.loads((snapshot / "runtime-resolutions.json").read_text())
    overlay["agt_customer"]["command"] = None
    _write(snapshot / "runtime-resolutions.json", overlay)
    with pytest.raises(InvalidManifest, match="agt_customer"):
        publish_snapshot(snapshot, "registry.example/a:tag",
                         _write(tmp_path / "cosign.key", {}),
                         gate_dir=_gate_dir(tmp_path), runner=pytest.fail)


def test_publication_pushes_the_bytes_it_validated_not_the_directory(tmp_path):
    """ORAS re-opens its inputs, so the bytes pushed must not be reachable
    through the mutable snapshot directory at all.

    The earlier version of this guard re-hashed the files just before invoking
    ORAS. That could only ever see a rewrite landing between two adjacent
    statements -- never the window an attacker actually has, which stays open
    until ORAS itself opens the files. This test therefore rewrites the
    directory AFTER validation and asserts on the bytes the pushing tool
    actually reads, which is the only thing that distinguishes the two designs.
    """
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    key = _write(tmp_path / "cosign.key", {})
    green = _write(tmp_path / "green.json", _green_evidence(
        gate, image, ["/app/agent", "serve"]))
    original = publisher.load_runtime_overlay
    pushed = {}

    def overlay_then_rewrite(directory):
        result = original(directory)
        # a concurrent writer, the instant validation of the overlay completes
        _write(snapshot / "agt_customer.json", {**_authority(),
                                                "instructions": "ATTACKER"})
        return result

    def runner(argv, **kwargs):
        if argv[0] == "oras":
            # read the inputs off disk exactly as the real ORAS does
            for name in argv[argv.index("--format") + 2:][1:]:
                pushed[name] = (Path(kwargs["cwd"]) / name).read_text()
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(
                    {"reference": "registry.example/a@sha256:" + "ef" * 32}), "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(publisher, "load_runtime_overlay", overlay_then_rewrite)
    try:
        publish_snapshot(snapshot, "registry.example/a:tag", key, gate_dir=gate,
                         conformance_evidence=(green,), runner=runner)
    finally:
        monkeypatch.undo()
    assert "ATTACKER" not in pushed["agt_customer.json"], (
        "ORAS pushed bytes rewritten after validation")
    assert json.loads(snapshot.joinpath("agt_customer.json").read_text())[
        "instructions"] == "ATTACKER"  # the rewrite really happened


def test_absent_gate_sources_say_how_to_publish_anyway(tmp_path):
    """The gate ships only in the source tree. Publishing from an installed
    package must name that constraint and its remedy, not just a missing path:
    this is the one new way an existing working install can stop publishing."""
    snapshot, image = _container_snapshot(tmp_path)
    key = _write(tmp_path / "cosign.key", {})
    green = _write(tmp_path / "green.json", _green_evidence(
        _gate_dir(tmp_path), image, ["/app/agent", "serve"]))
    with pytest.raises(InvalidManifest, match="conformance-gate-dir"):
        publish_snapshot(snapshot, "registry.example/a:tag", key,
                         gate_dir=tmp_path / "site-packages" / "infra",
                         conformance_evidence=(green,), runner=pytest.fail)


@pytest.mark.parametrize("wreck, expected", [
    (lambda e: e.update(ok=False), "not completely green"),
    (lambda e: e["checks"].append({"check": "G4", "ok": False}),
     "not completely green"),
    (lambda e: e.update(checks=[]), "not completely green"),
    (lambda e: e.update(checks="G1 passed"), "not completely green"),
], ids=["ok-false", "one-red-check", "no-checks", "checks-not-a-list"])
def test_publication_requires_evidence_that_is_actually_green(
        tmp_path, wreck, expected):
    """"Green" is the whole premise: a failed run, or one that recorded no
    checks at all, must not sign a snapshot. The image/command tests hold the
    other dimensions fixed, so nothing else asserts this one."""
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    evidence = _green_evidence(gate, image, ["/app/agent", "serve"])
    wreck(evidence)
    with pytest.raises(InvalidManifest, match=expected):
        publish_snapshot(snapshot, "registry.example/a:tag",
                         _write(tmp_path / "cosign.key", {}), gate_dir=gate,
                         conformance_evidence=(_write(tmp_path / "e.json", evidence),),
                         runner=pytest.fail)


def test_a_real_snapshot_survives_the_reservation_reaper(tmp_path, monkeypatch):
    """The failure path reaps its own empty reservation with rmdir precisely so
    it can never remove a populated directory. Single-threaded that case is
    unreachable, which is why it needs asserting: a concurrent publisher is the
    only way to reach it, and rmtree here would delete their snapshot."""
    policy = _write(tmp_path / "policy.json", _policy())
    manifest = _write(tmp_path / "agent.json", _manifest())
    target = tmp_path / "snap"
    original = publisher._write_durable

    def populate_target_then_fail(path, document):
        original(path, document)
        (target / "someone-elses-snapshot.json").write_text('{"theirs": true}')
        raise InvalidManifest("simulated staging failure")

    monkeypatch.setattr(publisher, "_write_durable", populate_target_then_fail)
    with pytest.raises(InvalidManifest, match="simulated staging failure"):
        package_agents([manifest], policy, target,
                       approved_models=("model-approved",),
                       policy_revision="r1")
    assert (target / "someone-elses-snapshot.json").read_text() == '{"theirs": true}'


# The gate is exercised out-of-process on purpose: importing it assigns the
# channel budgets it tests into os.environ, which would leak into every test
# that runs after it in the same session.
def _gate_subprocess(code: str, _argv=(), **env) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code, *_argv], capture_output=True, text=True,
        timeout=120, cwd=publisher.CONFORMANCE_GATE_DIR.parents[1],
        env={**os.environ, **env})


@pytest.mark.parametrize("value, expected", [
    (None, "requires ANDYUR_CONFORMANCE_COMMAND"),
    ("not json", "is not JSON"),
    ('"a string"', "JSON list of non-empty strings"),
    ("[]", "JSON list of non-empty strings"),
    ('["ok", ""]', "JSON list of non-empty strings"),
], ids=["absent", "not-json", "not-a-list", "empty", "empty-element"])
def test_gate_refuses_a_governed_image_it_cannot_run_faithfully(value, expected):
    """A governed image with no usable command must refuse BEFORE doing
    anything, with exit 2 -- distinct from 1, which means the gate ran and
    something was RED. Conformance of the image's own entrypoint would attest a
    workload production never launches."""
    env = {"ANDYUR_CONFORMANCE_IMAGE": "registry.example/x@sha256:" + "ab" * 32}
    if value is not None:
        env["ANDYUR_CONFORMANCE_COMMAND"] = value
    done = _gate_subprocess(
        "import sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import asyncio, byoa_gate; sys.exit(asyncio.run(byoa_gate.main()))",
        **env)
    assert done.returncode == 2, done.stderr
    assert expected in done.stderr
    assert "Traceback" not in done.stderr


def test_gate_runs_the_manifest_command_the_way_a_pod_does():
    """The command REPLACES the entrypoint and its tail becomes container args
    -- never docker flags. This is the mapping the whole H2 fix rests on, and
    nothing else in CI executes it."""
    done = _gate_subprocess(
        "import json, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "byoa_gate.sh = lambda *argv, **kw: json.dump(list(argv), sys.stdout);"
        "byoa_gate.run_agent_container('http://0.0.0.0:1/', 'tok',"
        " image='img@sha256:ab', name='c', command=('/app/agent', 'serve', '-v'))")
    assert done.returncode == 0, done.stderr
    argv = json.loads(done.stdout)
    assert argv[:5] == ["docker", "run", "--rm", "--name", "c"]
    # The scratch space the contract promises (spec section 8) and the Pod
    # actually grants. Without it this gate is STRICTER than the cluster and
    # reddens agents that run fine in production.
    # `:exec` because a Kubernetes emptyDir is exec-capable while Docker's
    # tmpfs is noexec by default; without it the gate is stricter than the Pod.
    assert argv[argv.index("--tmpfs") + 1] == "/tmp:exec"
    assert "/home/agent:exec" in argv
    # the entrypoint is replaced, and only the image's own args follow it
    assert argv[argv.index("--entrypoint") + 1] == "/app/agent"
    assert argv[-3:] == ["img@sha256:ab", "serve", "-v"]
    assert argv.index("--entrypoint") < argv.index("img@sha256:ab")


def test_gate_without_a_governed_command_leaves_the_entrypoint_alone():
    """The developer path builds the reference agent and runs its own
    entrypoint: the positive control for the test above."""
    done = _gate_subprocess(
        "import json, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "byoa_gate.sh = lambda *argv, **kw: json.dump(list(argv), sys.stdout);"
        "byoa_gate.run_agent_container('http://0.0.0.0:1/', 'tok',"
        " image='local:gate', name='c')")
    assert done.returncode == 0, done.stderr
    argv = json.loads(done.stdout)
    assert "--entrypoint" not in argv
    assert argv[-1] == "local:gate"


def test_gate_inspects_the_governed_workload_not_the_image_default():
    """G2 creates its inspection container with the governed command too.

    An image built FOR governed launch has no reason to declare an ENTRYPOINT
    or CMD, and `docker create` on one without either fails "no command
    specified" -- so the check meant to prove the launch subtraction would go
    red for exactly the images publication exists to certify.
    """
    done = _gate_subprocess(
        "import json, subprocess, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "calls = [];"
        "byoa_gate.COMMAND = ('/app/agent', 'serve');"
        "byoa_gate.IMAGE_TAG = 'img@sha256:ab';"
        "byoa_gate.sh = lambda *argv, **kw: (calls.append(list(argv)),"
        " subprocess.CompletedProcess(argv, 1, '', 'stub'))[1];"
        "byoa_gate.record = lambda *a, **k: None;"  # keep stdout parseable
        "byoa_gate.g2_launch_configuration();"
        "json.dump(calls[0], sys.stdout)")
    assert done.returncode == 0, done.stderr
    argv = json.loads(done.stdout)
    assert argv[:2] == ["docker", "create"]
    assert argv[argv.index("--entrypoint") + 1] == "/app/agent"
    assert argv[-2:] == ["img@sha256:ab", "serve"]


@pytest.mark.parametrize("kind", ["char-device", "fifo", "symlink", "oversized"])
def test_operator_supplied_paths_are_read_bounded_and_regular(tmp_path, kind):
    """Every path here comes from an operator flag. Sizing with stat() and then
    reading is a lie for anything that is not a regular file: a character
    device reports zero bytes and returns them forever, so
    `--conformance-evidence /dev/zero` read tens of gigabytes and never
    finished, and a FIFO simply hangs. One checked, bounded descriptor.
    """
    if kind == "char-device":
        target = Path("/dev/zero")
    elif kind == "fifo":
        target = tmp_path / "fifo"
        os.mkfifo(target)
    elif kind == "symlink":
        real = _write(tmp_path / "real.json", {"ok": True})
        target = tmp_path / "link.json"
        target.symlink_to(real)
    else:
        target = tmp_path / "big.json"
        target.write_text(" " * (publisher.MAX_PUBLISH_INPUT_BYTES + 1))

    with pytest.raises(InvalidManifest) as refusal:
        publisher.load_conformance_evidence(target, gate_dir=_gate_dir(tmp_path))
    assert any(word in str(refusal.value)
               for word in ("not a regular file", "cannot read", "exceeds"))


def test_gate_sources_are_read_bounded_too(tmp_path):
    """--conformance-gate-dir is an operator flag on the same footing, and the
    digest read had no cap at all: a gate source symlinked to /dev/zero grew
    without bound before this."""
    gate = _gate_dir(tmp_path)
    (gate / "byoa_gate.py").unlink()
    (gate / "byoa_gate.py").symlink_to("/dev/zero")
    with pytest.raises(InvalidManifest, match="not usable"):
        publisher.conformance_source_digests(gate)


def _signed_evidence(tmp_path, gate, image, command=("/app/agent", "serve")):
    evidence = _write(tmp_path / "signed.json",
                      _green_evidence(gate, image, list(command)))
    bundle = evidence.with_name(evidence.name + publisher.EVIDENCE_SIGNATURE_SUFFIX)
    bundle.write_text('{"stub": "bundle"}')
    return evidence


def test_attestation_is_off_unless_a_key_is_supplied(tmp_path):
    """Opt-in, and off by default: requiring cosign to publish would put a
    dependency in front of the getting-started path. Content binding still
    applies -- this only governs WHO the evidence is attributed to."""
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    green = _write(tmp_path / "green.json", _green_evidence(
        gate, image, ["/app/agent", "serve"]))
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv[0])
        stdout = (json.dumps({"reference": "registry.example/a@sha256:" + "ef" * 32})
                  if argv[0] == "oras" else "")
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    publish_snapshot(snapshot, "registry.example/a:tag",
                     _write(tmp_path / "cosign.key", {}), gate_dir=gate,
                     conformance_evidence=(green,), runner=runner)
    assert "cosign" in calls          # the snapshot is still signed
    assert calls.count("cosign") == 1  # but nothing verified the evidence


def test_required_attestation_refuses_unsigned_evidence_before_reading_it(tmp_path):
    """With a key required, an artifact carrying no bundle is refused -- and
    refused BEFORE its content is trusted enough to be parsed as evidence."""
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    unsigned = _write(tmp_path / "unsigned.json", _green_evidence(
        gate, image, ["/app/agent", "serve"]))
    with pytest.raises(InvalidManifest, match="conformance key was required"):
        publish_snapshot(snapshot, "registry.example/a:tag",
                         _write(tmp_path / "cosign.key", {}), gate_dir=gate,
                         conformance_evidence=(unsigned,),
                         conformance_key=_write(tmp_path / "cosign.pub", {}),
                         runner=pytest.fail)


def test_required_attestation_refuses_when_cosign_rejects_the_bundle(tmp_path):
    """A bundle that does not verify must stop publication, and ORAS must never
    run. cosign is the verifier; this asserts the refusal is wired to it."""
    snapshot, image = _container_snapshot(tmp_path)
    gate = _gate_dir(tmp_path)
    evidence = _signed_evidence(tmp_path, gate, image)
    seen = []

    def runner(argv, **kwargs):
        seen.append(argv)
        if argv[0] == "cosign" and argv[1] == "verify-blob":
            return subprocess.CompletedProcess(argv, 1, "", "invalid signature")
        raise AssertionError(f"nothing else may run: {argv}")

    with pytest.raises(InvalidManifest, match="cosign failed"):
        publish_snapshot(snapshot, "registry.example/a:tag",
                         _write(tmp_path / "cosign.key", {}), gate_dir=gate,
                         conformance_evidence=(evidence,),
                         conformance_key=_write(tmp_path / "cosign.pub", {}),
                         runner=runner)
    assert [argv[:2] for argv in seen] == [["cosign", "verify-blob"]]


def test_signing_evidence_uses_the_offline_form_when_the_tlog_is_disabled(tmp_path):
    """--disable-transparency-log must actually keep the artifact's hash off
    the public log. cosign v3 refuses --tlog-upload=false unless the signing
    config is disabled too, so a form that omits either flag either uploads or
    errors -- both of which this asserts against."""
    evidence = _write(tmp_path / "e.json", {"ok": True})
    seen = []

    def runner(argv, **kwargs):
        seen.extend(argv)
        (Path(kwargs["cwd"]) / argv[argv.index("--bundle") + 1]).write_text("{}")
        return subprocess.CompletedProcess(argv, 0, "", "")

    publisher.sign_evidence(evidence, _write(tmp_path / "k", {}),
                            disable_transparency_log=True, runner=runner)
    assert "--tlog-upload=false" in seen and "--use-signing-config=false" in seen
    assert "--new-bundle-format" in seen


def test_g5_fails_when_only_the_commands_interpreter_is_dirty():
    """The property, not the probe order: a venv interpreter the command names
    can import andyur while PATH's python is clean, and the VERDICT must be
    red. Asserting only which interpreters were probed would stay green if the
    extra probe's result were computed and then dropped."""
    name, ok, detail = _g5_verdict(
        "byoa_gate.COMMAND = ('/venv/bin/python', '/app/agent.py');"
        + _stub_docker(
            "(0, '') if 'import json' in argv[-1]"
            " else ((0, '') if argv[argv.index('--entrypoint') + 1]"
            " == '/venv/bin/python' else (1, 'ModuleNotFoundError'))"))
    assert ok is False, detail
    assert "/venv/bin/python: import andyur exit=0 IMPORTABLE" in detail


def test_g5_probes_an_interpreter_wrapped_in_a_shell_command():
    """["/bin/sh","-c","exec /venv/bin/python /app/agent.py"] runs its agent
    under a Python that is a WORD inside the third argument, not argv[0].
    Reading argv[0] alone leaves the verdict to PATH's python -- an evasion
    that is neither compiled nor a binary, so the documented limit did not
    cover it."""
    name, ok, detail = _g5_verdict(
        "byoa_gate.COMMAND = ('/bin/sh', '-c',"
        " 'exec /venv/bin/python /app/agent.py');"
        + _stub_docker(
            "(0, '') if 'import json' in argv[-1]"
            " else ((0, '') if argv[argv.index('--entrypoint') + 1]"
            " == '/venv/bin/python' else (1, 'ModuleNotFoundError'))"))
    assert ok is False, detail
    assert "/venv/bin/python: import andyur exit=0 IMPORTABLE" in detail


def test_g5_does_not_probe_script_paths_that_are_not_interpreters():
    """Only words whose basename looks like a Python are probed. Probing the
    script path would return "not executable", which is inconclusive, and
    would fail every ordinary agent."""
    done = _gate_subprocess(
        "import json, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "json.dump([byoa_gate.command_interpreters(('/bin/sh', '-c',"
        " 'exec /venv/bin/python3.12 /app/agent.py --data /x/python.json')),"
        " byoa_gate.command_interpreters(('/app/agent', 'serve')),"
        " byoa_gate.command_interpreters(None)], sys.stdout)")
    assert done.returncode == 0, done.stderr
    wrapped, compiled, absent = json.loads(done.stdout)
    assert wrapped == ["/venv/bin/python3.12"]   # not /app/agent.py, not /x/python.json
    assert compiled == [] and absent == []


def test_g5_probes_both_path_names_and_the_commands_interpreter():
    """The SET of interpreters asked, not the order they were asked in.

    PATH's `python` and `python3` both matter (distro images ship only the
    second), and so does whatever the governed command names -- that one is
    the interpreter which will actually run the agent.
    """
    done = _gate_subprocess(
        "import json, subprocess, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "probed = [];"
        "byoa_gate.IMAGE_TAG = 'img@sha256:ab';"
        "byoa_gate.COMMAND = ('/venv/bin/python', '/app/agent.py');"
        "byoa_gate.record = lambda *a, **k: None;"
        "byoa_gate.sh = lambda *argv, **kw: (probed.append(argv),"
        " subprocess.CompletedProcess(argv, 0 if 'import json' in argv[-1] else 1,"
        " '', 'ModuleNotFoundError'))[1];"
        "byoa_gate.g5_image_cannot_import_andyur();"
        "json.dump(sorted({a[a.index('--entrypoint') + 1] for a in probed}), sys.stdout)")
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == ["/venv/bin/python", "python", "python3"]


def test_g5_stays_not_applicable_when_no_candidate_is_a_python():
    """A Go or Rust agent has no interpreter, and must not be failed for it --
    that would make every non-Python agent unpublishable."""
    done = _gate_subprocess(
        "import json, subprocess, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "results = [];"
        "byoa_gate.IMAGE_TAG = 'img@sha256:ab';"
        "byoa_gate.COMMAND = ('/app/agent',);"
        "byoa_gate.record = lambda name, ok, detail: results.append((name, ok));"
        # nothing in the image can import the stdlib: no python here at all
        "byoa_gate.sh = lambda *argv, **kw: subprocess.CompletedProcess(argv, 127, '', ''); "
        "byoa_gate.g5_image_cannot_import_andyur();"
        "json.dump(results, sys.stdout)")
    assert done.returncode == 0, done.stderr
    [(name, ok)] = json.loads(done.stdout)
    assert ok is True and "not applicable" in name
def _g5_verdict(driver: str) -> tuple[str, bool, str]:
    """Run G5 out of process against a stubbed docker and return its VERDICT."""
    done = _gate_subprocess(
        "import json, subprocess, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "byoa_gate.IMAGE_TAG = 'img@sha256:ab';"
        "results = [];"
        "byoa_gate.record = lambda name, ok, detail: results.append((name, ok, detail));"
        + driver +
        "byoa_gate.g5_image_cannot_import_andyur();"
        "json.dump(results[0], sys.stdout)")
    assert done.returncode == 0, done.stderr
    name, ok, detail = json.loads(done.stdout)
    return name, ok, detail


def _stub_docker(rules: str) -> str:
    """rules: a python expression over `argv` returning (returncode, stderr)."""
    return ("byoa_gate.sh = lambda *argv, **kw: (lambda rc_err:"
            " subprocess.CompletedProcess(argv, rc_err[0], '', rc_err[1]))"
            f"({rules});")


def test_g5_finds_a_python_that_is_only_called_python3():
    """Debian, Ubuntu and Alpine ship python3 with no `python` alias. Probing
    one name and reading its absence as "no Python here" waved every
    distro-based image through, andyur inside or not."""
    name, ok, detail = _g5_verdict(_stub_docker(
        "(127, 'executable file not found') if '--entrypoint' in argv and"
        " argv[argv.index('--entrypoint') + 1] == 'python'"
        " else ((0, '') if 'import json' in argv[-1] else (0, ''))"))
    # python3 exists AND imports andyur cleanly -> the check must FAIL
    assert ok is False, detail
    assert "IMPORTABLE" in detail


def test_g5_fails_closed_when_no_probe_actually_answered():
    """A non-zero probe is not proof of absence. Exit 126 (not executable) or
    125 (daemon error) means the question was never answered, and an
    unanswered question must not certify the image as andyur-free."""
    name, ok, detail = _g5_verdict(_stub_docker("(126, 'permission denied')"))
    assert ok is False, detail
    assert "inconclusive" in name


def test_g5_is_not_applicable_only_when_python_is_definitively_absent():
    """The positive control for the two tests above: a genuine Go or Rust
    image, where every candidate is reported missing by docker itself, is not
    failed for lacking an interpreter."""
    name, ok, detail = _g5_verdict(_stub_docker(
        "(127, 'executable file not found in $PATH')"))
    assert ok is True, detail
    assert "not applicable" in name


def test_g5_passes_a_clean_python_image(tmp_path):
    """And the ordinary green path still goes green: python present, andyur
    not importable."""
    name, ok, detail = _g5_verdict(_stub_docker(
        "(0, '') if 'import json' in argv[-1] else (1, 'ModuleNotFoundError')"))
    assert ok is True, detail
    assert "clean" in detail


def test_gate_evidence_path_ending_in_tmp_is_not_self_destructive(tmp_path):
    """`--evidence run.tmp` made the gate's own temp path equal the artifact
    path, so a completed run wrote, linked and then deleted its only evidence
    and reported a refusal."""
    done = _gate_subprocess(
        "import json, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "byoa_gate.CHECKS[:] = [{'check': 'G1', 'ok': True}];"
        "byoa_gate.sh = lambda *a, **k: __import__('subprocess')"
        ".CompletedProcess(a, 0, '', '');"
        "out = byoa_gate.write_evidence('img', 0.0, True);"
        "json.dump([str(out), out.exists()], sys.stdout)",
        ANDYUR_CONFORMANCE_EVIDENCE=str(tmp_path / "run.tmp"))
    assert done.returncode == 0, done.stderr
    path, exists = json.loads(done.stdout)
    assert path == str(tmp_path / "run.tmp")
    assert exists, "the completed run's evidence was deleted"
    assert json.loads(Path(path).read_text())["ok"] is True


def test_cli_publish_is_wired_to_the_publisher_evidence_gate(tmp_path, monkeypatch):
    """`agents package --publish-ref` must actually hand the publisher the
    evidence, key and gate directory. Both halves existed and were tested
    separately; nothing asserted the wire between them, so a dropped argument
    would publish with the gate silently disabled."""
    from andyur.agentspec import publisher as pub
    manifest = _write(tmp_path / "agent.json", _manifest())
    policy = _write(tmp_path / "policy.json", _policy())
    seen = {}

    def fake_publish(snapshot, ref, key, **kwargs):
        seen.update(kwargs)
        seen["ref"] = ref
        return "registry.example/a@sha256:" + "ef" * 32

    monkeypatch.setattr(pub, "publish_snapshot", fake_publish)
    args = build_parser().parse_args([
        "agents", "package", str(manifest),
        "--policy-resolution", str(policy), "--output", str(tmp_path / "snap"),
        "--approved-model", "model-approved", "--policy-revision", "r1",
        "--publish-ref", "registry.example/a:tag",
        "--cosign-key", str(_write(tmp_path / "k", {})),
        "--conformance-evidence", "one.json",
        "--conformance-evidence", "two.json",
    ])
    cli.cmd_agents_package(args)
    assert seen["ref"] == "registry.example/a:tag"
    assert seen["conformance_evidence"] == ("one.json", "two.json")
    assert seen["gate_dir"] == pub.CONFORMANCE_GATE_DIR

@pytest.mark.parametrize("command, expected", [
    (["/bin/sh", "-c", "exec '/venv/bin/python' /app/agent.py"],
     ["/venv/bin/python"]),
    (["/bin/sh", "-c", 'exec "/venv/bin/python" /app/agent.py'],
     ["/venv/bin/python"]),
    (["/bin/sh", "-c", "exec '/opt/my python/bin/python' /app/agent.py"],
     ["/opt/my python/bin/python"]),
    (["/bin/sh", "-c", "exec /opt/we\\ird/python3 /app/agent.py"],
     ["/opt/we\\ird/python3", "/opt/weird/python3"]),
    (["/bin/sh", "-c", "exec /venv/bin/python /app/agent.py"],
     ["/venv/bin/python"]),
    (["/venv/bin/python", "/app/agent.py"], ["/venv/bin/python"]),
    (["/bin/sh", "-c", 'exec "/venv/bin/python /app/agent.py'],
     ["\"/venv/bin/python"]),
    (["/app/agent", "serve"], []),
], ids=["single-quoted", "double-quoted", "quoted-with-space",
        "backslash-path", "unquoted-control", "plain-control",
        "unbalanced-quote", "compiled-control"])
def test_g5_sees_a_quoted_interpreter_inside_a_shell_command(command, expected):
    """The command is written by the party this check exists to police, so
    both tokenizers run and their results are unioned.

    Each is blind to exactly what the other sees. Splitting on whitespace
    cannot see through quotes: `exec '/venv/bin/python' agent.py` yields a word
    whose basename is `python'`, matching nothing, so the venv is never probed
    and the verdict falls back to PATH's clean python. Parsing shell words
    instead consumes backslashes: a real interpreter at /opt/we\\ird/python3
    resolves to /opt/weird/python3, which does not exist and probes as absent.
    Swapping one for the other only trades a quoting bypass for an escaping
    one, so the backslash case asserts the LITERAL path survives alongside the
    unescaped one.

    The unquoted, plain and compiled forms are the positive controls: the fix
    must not change what already worked, and must not start matching
    everything. An unbalanced quote is not a parseable word list, so it
    degrades to the naive split rather than raising -- never skipped silently.
    """
    done = _gate_subprocess(
        "import json, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "json.dump(byoa_gate.command_interpreters(json.loads(sys.argv[1])), sys.stdout)",
        _argv=[json.dumps(command)])
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == expected


def test_g5_probe_order_is_identical_between_runs():
    """Probe order reaches the evidence artifact's recorded detail, so it has
    to be a property of the command and not of this process.

    Deduping through a set would make it neither: set iteration order varies
    between processes, so two identical runs of the same gate on the same
    image would write different artifacts and the currency binding would be
    guarding a moving target.
    """
    command = json.dumps(["/bin/sh", "-c",
                          "exec '/venv/bin/python' && /opt/x/python3 && python3.12"])
    runs = set()
    for _ in range(4):
        done = _gate_subprocess(
            "import json, sys; sys.path.insert(0, 'infra/byoa-spike');"
            "import byoa_gate;"
            "json.dump(byoa_gate.command_interpreters(json.loads(sys.argv[1])),"
            " sys.stdout)",
            _argv=[command])
        assert done.returncode == 0, done.stderr
        runs.add(done.stdout)
    assert len(runs) == 1, f"probe order differed between processes: {runs}"
    assert json.loads(runs.pop()) == [
        "/opt/x/python3", "python3.12", "/venv/bin/python"]


def test_g5_does_not_fail_an_image_over_a_directory_named_like_python():
    """A path whose basename is a valid Python name can be a directory, and
    `--entrypoint /usr/lib/python3.11` exits 126 "is a directory". That is a
    definitive answer -- not an interpreter -- rather than an unanswered
    question, and treating it as inconclusive would fail the gate for an image
    that did nothing wrong."""
    done = _gate_subprocess(
        "import json, subprocess, sys; sys.path.insert(0, 'infra/byoa-spike');"
        "import byoa_gate;"
        "byoa_gate.IMAGE_TAG = 'img@sha256:ab';"
        "byoa_gate.sh = lambda *argv, **kw: subprocess.CompletedProcess("
        " argv, 126, '', 'exec: \"/usr/lib/python3.11\": is a directory:"
        " unknown: permission denied');"
        "json.dump(list(byoa_gate.interpreter_state('/usr/lib/python3.11')),"
        " sys.stdout)")
    assert done.returncode == 0, done.stderr
    state, detail = json.loads(done.stdout)
    assert state == "absent", detail
    assert "directory" in detail


# --- the exec/v1 gate's evidence is bound to ITS gate, per artifact ------------

def _exec_gate_dir(tmp_path: Path) -> Path:
    gate = _gate_dir(tmp_path)
    (gate / "exec_v1_gate.py").write_text("# simulated exec/v1 gate source\n")
    return gate


def _green_exec_evidence(gate_dir: Path, image: str, command: list[str]) -> dict:
    return {
        "gate": "exec-v1-conformance", "ok": True,
        "inputs": {"selected_image": image, "selected_command": command,
                   "interface": "exec/v1", "input_mode": "stdin",
                   "granted_model": "qwen3-andyur:latest",
                   "exec_gate_sha256": hashlib.sha256(
                       (gate_dir / "exec_v1_gate.py").read_bytes()).hexdigest()},
        "checks": [{"check": "E1", "ok": True}],
    }


def test_exec_v1_evidence_is_checked_against_the_exec_gate_source(tmp_path):
    gate = _exec_gate_dir(tmp_path)
    image = "ghcr.io/tracer-cloud/opensre@sha256:" + "80" * 32
    evidence = _write(tmp_path / "exec.json",
                      _green_exec_evidence(gate, image, ["opensre", "investigate", "-i", "-"]))
    proven = publisher.load_conformance_evidence(evidence, gate_dir=gate)
    assert (proven.image, proven.command) == (image, ("opensre", "investigate", "-i", "-"))
    assert (proven.interface, proven.input_mode, proven.model) == ("exec/v1", "stdin", "qwen3-andyur:latest")
    # the exec/v1 artifact is NOT held to the runtime-v1 gate's hashes: editing
    # byoa_gate.py must not stale it ...
    (gate / "byoa_gate.py").write_text("# edited runtime-v1 gate\n")
    assert publisher.load_conformance_evidence(evidence, gate_dir=gate).image == image
    # ... but editing the exec gate does
    (gate / "exec_v1_gate.py").write_text("# edited exec/v1 gate\n")
    with pytest.raises(InvalidManifest, match="exec_gate_sha256"):
        publisher.load_conformance_evidence(evidence, gate_dir=gate)


def test_runtime_v1_evidence_is_not_staled_by_the_exec_gate(tmp_path):
    gate = _exec_gate_dir(tmp_path)
    image = "registry.example/customer@" + DIGEST
    evidence = _write(tmp_path / "v1.json", _green_evidence(gate, image, ["/app/agent", "serve"]))
    (gate / "exec_v1_gate.py").write_text("# edited exec/v1 gate\n")
    assert publisher.load_conformance_evidence(evidence, gate_dir=gate).image == image


def test_evidence_naming_an_unknown_gate_is_refused_not_assumed(tmp_path):
    gate = _exec_gate_dir(tmp_path)
    doc = _green_exec_evidence(gate, "registry.example/x@" + DIGEST, ["x"])
    doc["gate"] = "some-other-gate"
    evidence = _write(tmp_path / "unknown.json", doc)
    with pytest.raises(InvalidManifest, match="unknown gate"):
        publisher.load_conformance_evidence(evidence, gate_dir=gate)


def test_cli_conformance_dispatches_an_exec_v1_manifest_to_the_exec_gate(tmp_path, monkeypatch):
    """The manifest's declared interface selects the gate script and passes the
    manifest path (the gate resolves process/configuration through the real
    parser). A runtime-v1 manifest keeps the runtime-v1 gate."""
    import subprocess
    import types
    from andyur import cli
    seen = []

    def fake_run(argv, cwd=None, env=None):
        seen.append((argv, env))
        return types.SimpleNamespace(returncode=1)          # stop after dispatch

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    manifest = Path(__file__).resolve().parents[1] / "demos" / "opensre" / "agent.json"
    alert = _write(tmp_path / "alert.json", {"alert_name": "x"})
    args = types.SimpleNamespace(manifest=str(manifest), evidence=str(tmp_path / "e.json"),
                                 input=str(alert), sign_evidence=None,
                                 disable_transparency_log=False)
    with pytest.raises(SystemExit):
        cli.cmd_agents_conformance(args)
    argv, env = seen[0]
    assert argv[1].endswith("exec_v1_gate.py")
    assert env["ANDYUR_CONFORMANCE_MANIFEST"] == str(manifest)
    assert env["ANDYUR_CONFORMANCE_INPUT"] == str(alert)
    assert env["ANDYUR_CONFORMANCE_COMMAND"] == json.dumps(["opensre", "investigate", "-i", "-"])
    assert env["ANDYUR_CONFORMANCE_IMAGE"].startswith("ghcr.io/tracer-cloud/opensre@sha256:")


def _exec_snapshot(tmp_path, model="qwen3-andyur:latest"):
    """A packaged exec/v1 snapshot (the OpenSRE demo manifest) to publish."""
    from andyur.agentspec.publisher import package_agents
    root = Path(__file__).resolve().parents[1]
    policy = _write(tmp_path / "policy.json", {
        "schema_version": "andyur.agent-resolution/v1", "agent_id": "agt_platform_policy", "name": "platform-policy",
        "instructions": "policy", "model": None, "tools": [], "ceiling": {"actions": [], "resources": []}})
    return package_agents([root / "demos" / "opensre" / "agent.json"], policy, tmp_path / "snap",
                          approved_models=(model,), policy_revision="r1", max_lifetime_seconds=3600)


def _publish(snapshot, evidence, gate, tmp_path):
    key = _write(tmp_path / "cosign.key", {"k": 1})
    calls = []

    def runner(argv, **kw):
        import types
        calls.append(argv)
        out = '{"reference": "registry.example/snap@sha256:' + "ab" * 32 + '"}' if argv[0] == "oras" else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    return publisher.publish_snapshot(snapshot, "registry.example/snap:t", key,
                                      conformance_evidence=(evidence,), gate_dir=gate, runner=runner)


def test_publication_binds_interface_input_mode_and_granted_model(tmp_path):
    """R MED-3: image+command alone let evidence from another interface, input
    mode or model (or from the runtime-v1 gate) publish an exec/v1 runtime."""
    gate = _exec_gate_dir(tmp_path)
    snapshot = _exec_snapshot(tmp_path)
    image = "ghcr.io/tracer-cloud/opensre@sha256:80e530dd06128d8b63016fbd371ac683c8744f1e187d14fbcfb5298ed4567cd2"
    command = ["opensre", "investigate", "-i", "-"]
    good = _green_exec_evidence(gate, image, command)
    assert _publish(snapshot, _write(tmp_path / "good.json", good), gate, tmp_path).endswith("@sha256:" + "ab" * 32)
    for field, value, why in (("granted_model", "qwen3:8b", "ran with model"),
                              ("input_mode", "argv", "delivered input by"),
                              ("interface", "andyur-agent-runtime/v1", "proved interface")):
        bad = json.loads(json.dumps(good)); bad["inputs"][field] = value
        with pytest.raises(InvalidManifest, match=why):
            _publish(snapshot, _write(tmp_path / f"bad-{field}.json", bad), gate, tmp_path)
    # runtime-v1 gate evidence for an exec/v1 runtime is refused outright
    v1 = _green_evidence(gate, image, command)
    with pytest.raises(InvalidManifest, match="needs exec/v1 conformance evidence"):
        _publish(snapshot, _write(tmp_path / "v1.json", v1), gate, tmp_path)
    # and an exec/v1 artifact missing a binding field is not this gate's
    partial = json.loads(json.dumps(good)); del partial["inputs"]["granted_model"]
    with pytest.raises(InvalidManifest, match="records no granted_model"):
        publisher.load_conformance_evidence(_write(tmp_path / "partial.json", partial), gate_dir=gate)

