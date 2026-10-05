from __future__ import annotations

import hashlib
import errno
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from andyur.dataplane import brokeruds, extauthz


def _load_gate():
    import importlib.util
    path = Path(__file__).parents[1] / "infra" / "authorization-broker" / \
        "deny_only_envoy_gate.py"
    spec = importlib.util.spec_from_file_location("deny_only_envoy_gate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def broker_directory():
    root = Path(tempfile.mkdtemp(
        prefix="andyur-uds-", dir=str(Path("/tmp").resolve())))
    directory = root / "broker"
    directory.mkdir(mode=brokeruds.BROKER_DIRECTORY_MODE)
    os.chown(directory, os.getuid(), os.getgid())
    directory.chmod(brokeruds.BROKER_DIRECTORY_MODE)
    yield directory
    shutil.rmtree(root, ignore_errors=True)


def _app():
    envelope = extauthz.SealedAuthorityEnvelope(
        agent="scout", run_id="r1",
        expected_subject="alice",
        expected_actor="spiffe://andyur.local/agent/scout/run/r1",
        audience="resource:calendar", actions=("calendar:read",),
        resource_pin_json=None,
        registry_sha256=hashlib.sha256(b"registry").hexdigest())
    return extauthz.build_deny_only_broker(
        envelope=envelope, liveness_fn=lambda *_: True,
        identity_fn=lambda *_: (envelope.expected_subject,
                                envelope.expected_actor),
        registry_digest_fn=lambda *_: envelope.registry_sha256,
        authority_fn=lambda *_: {"audience": envelope.audience,
                                 "actions": list(envelope.actions), "pin": None})


def test_uds_server_uses_uvicorns_mature_concurrency_bound(broker_directory):
    server = brokeruds.BrokerUdsServer(
        _app(), broker_directory / "authz.sock", limit_concurrency=64)
    assert server._server.config.limit_concurrency == 64
    with pytest.raises(ValueError, match="concurrency limit"):
        brokeruds.BrokerUdsServer(
            _app(), broker_directory / "bad.sock", limit_concurrency=0)


def test_private_uds_serves_real_deny_only_broker_and_cleans_up(broker_directory):
    path = broker_directory / "authz.sock"
    server = brokeruds.BrokerUdsServer(_app(), path)
    with server:
        info = path.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == brokeruds.BROKER_SOCKET_MODE
        assert (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
        transport = httpx.HTTPTransport(uds=str(path))
        with httpx.Client(transport=transport, base_url="http://broker") as client:
            assert client.get("/ready").status_code == 200
            denied = client.post("/authz", content=b'{}')
            assert denied.status_code == 403
            assert denied.text == "credential issuance is disabled"
            assert "authorization" not in denied.headers
    assert not path.exists()


@pytest.mark.parametrize("mode", [0o700, 0o755, 0o770, 0o777])
def test_private_uds_refuses_wrong_parent_mode(broker_directory, mode):
    broker_directory.chmod(mode)
    with pytest.raises(PermissionError, match="0750"):
        brokeruds.bind_private_broker_socket(broker_directory / "authz.sock")


def test_private_uds_refuses_existing_path_without_deleting_it(broker_directory):
    path = broker_directory / "authz.sock"
    path.write_text("owned by another generation")
    with pytest.raises(FileExistsError):
        brokeruds.bind_private_broker_socket(path)
    assert path.read_text() == "owned by another generation"


def _socket_path(directory, *, listening=False):
    path = directory / "authz.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(path))
    os.chown(path, os.getuid(), os.getgid())
    path.chmod(brokeruds.BROKER_SOCKET_MODE)
    if listening:
        stale.listen(1)
    return path, stale


def test_supervised_restart_adopts_exact_owned_stale_socket(broker_directory):
    path, stale = _socket_path(broker_directory)
    stale.close()  # ungraceful process death leaves the filesystem entry
    replacement, _ = brokeruds.bind_private_broker_socket(
        path, adopt_stale=True)
    try:
        assert path.is_socket()
        assert replacement.getsockname() == str(path)
    finally:
        replacement.close()
        path.unlink(missing_ok=True)


@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="Linux O_PATH required")
def test_supervised_restart_pins_stale_inode_with_o_path(
        broker_directory, monkeypatch):
    path, stale = _socket_path(broker_directory)
    stale.close()
    real_open = os.open
    opened_flags = []

    def recording_open(target, flags, *args, **kwargs):
        opened_flags.append(flags)
        return real_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    replacement, _ = brokeruds.bind_private_broker_socket(
        path, adopt_stale=True)
    try:
        assert opened_flags
        assert opened_flags[0] & os.O_PATH == os.O_PATH
    finally:
        replacement.close()
        path.unlink(missing_ok=True)


def test_supervised_restart_refuses_live_socket(broker_directory):
    path, live = _socket_path(broker_directory, listening=True)
    try:
        with pytest.raises(FileExistsError, match="live listener"):
            brokeruds.bind_private_broker_socket(path, adopt_stale=True)
        assert path.is_socket()
    finally:
        live.close()
        path.unlink(missing_ok=True)


def test_supervised_restart_refuses_wrong_owner_socket(broker_directory):
    path, stale = _socket_path(broker_directory)
    stale.close()
    with pytest.raises(PermissionError, match="attributes"):
        brokeruds._adopt_stale_socket(path, os.getuid() + 1, os.getgid())
    assert path.is_socket()
    path.unlink()


@pytest.mark.parametrize("defect", ["type", "mode"])
def test_supervised_restart_refuses_wrong_socket_attributes(
        broker_directory, defect):
    path = broker_directory / "authz.sock"
    if defect == "type":
        path.write_text("not a socket")
        path.chmod(brokeruds.BROKER_SOCKET_MODE)
    else:
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(path))
        stale.close()
        path.chmod(0o600)
    with pytest.raises(PermissionError, match="attributes"):
        brokeruds.bind_private_broker_socket(path, adopt_stale=True)
    assert os.path.lexists(path)


def test_supervised_restart_refuses_ambiguous_socket_liveness(
        broker_directory, monkeypatch):
    path, stale = _socket_path(broker_directory)
    stale.close()
    monkeypatch.setattr(socket.socket, "connect_ex", lambda *_: errno.ENOENT)
    with pytest.raises(OSError, match="liveness is ambiguous"):
        brokeruds.bind_private_broker_socket(path, adopt_stale=True)
    assert path.is_socket()


def test_supervised_restart_never_unlinks_a_racing_replacement(
        broker_directory, monkeypatch):
    path, stale = _socket_path(broker_directory)
    stale.close()
    original_rename = Path.rename
    replacement = None

    def swap_then_rename(source, target):
        nonlocal replacement
        source.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(source))
        source.chmod(brokeruds.BROKER_SOCKET_MODE)
        return original_rename(source, target)

    monkeypatch.setattr(Path, "rename", swap_then_rename)
    with pytest.raises(RuntimeError, match="quarantined"):
        brokeruds.bind_private_broker_socket(path, adopt_stale=True)
    assert not path.exists()
    quarantined = list(broker_directory.glob(".authz.sock.stale-*"))
    assert len(quarantined) == 1
    assert quarantined[0].is_socket()
    replacement.close()
    quarantined[0].unlink()


def test_private_uds_refuses_a_symlinked_parent(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=brokeruds.BROKER_DIRECTORY_MODE)
    real.chmod(brokeruds.BROKER_DIRECTORY_MODE)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        brokeruds.bind_private_broker_socket(linked / "authz.sock")


def test_stop_does_not_unlink_a_replaced_generation_path(broker_directory):
    path = broker_directory / "authz.sock"
    server = brokeruds.BrokerUdsServer(_app(), path)
    server.start()
    path.unlink()
    path.write_text("new generation")
    server.stop()
    assert path.read_text() == "new generation"


def test_bind_failure_does_not_unlink_a_replacement_socket(
        broker_directory, monkeypatch):
    path = broker_directory / "authz.sock"
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def replace_then_fail(*_):
        path.unlink()
        replacement.bind(str(path))
        raise PermissionError("forced setup failure")

    monkeypatch.setattr(os, "chown", replace_then_fail)
    try:
        with pytest.raises(PermissionError, match="forced"):
            brokeruds.bind_private_broker_socket(path)
        assert path.is_socket()
    finally:
        replacement.close()
        path.unlink(missing_ok=True)


def test_live_gate_result_proves_secure_mutated_and_restored_enforcement():
    import json
    import yaml
    gate = _load_gate()
    result = json.loads((Path(__file__).parents[1] / "infra" /
        "authorization-broker" /
        "result-deny-only-envoy-2026-08-19-macos-arm64.json").read_text())
    assert result["secure"]["status"] == 403
    assert result["secure"]["dispatch"] is False
    assert result["secure"]["broker_calls"] == 4
    assert result["mutation_red"] == {"dispatch": True, "status": 200}
    assert result["restored"] == {
        "broker_calls": 4, "dispatch": False, "status": 403}
    assert result["uds_attributes"] == [
        "750 0 1337 directory", "660 0 1337 socket"]
    assert result["agent_socket_absent"] is True
    assert result["teardown_socket_absent"] is True
    assert result["broker_unavailable"]["status"] == 403
    assert result["broker_unavailable"]["dispatch"] is False
    assert result["broker_bypass_mutation_red"] == {
        "authority_calls": 0, "dispatch": False, "status": 403,
        "transport_calls": 1}
    assert "@sha256:" in result["envoy_image"]
    assert result["app_image_id"].startswith("sha256:")
    secure_bytes = yaml.safe_dump(gate.config(include_authz=True)).encode()
    assert result["secure_config_sha256"] == hashlib.sha256(secure_bytes).hexdigest()
    root = Path(__file__).parents[1]
    expected_sources = {
        "andyur/dataplane/extauthz.py",
        "andyur/dataplane/brokeruds.py",
        "andyur/dataplane/envoyconfig.py",
        "infra/authorization-broker/deny_broker_fixture.py",
        "infra/authorization-broker/upstream_fixture.py",
        "infra/authorization-broker/deny_only_envoy_gate.py",
        "infra/authorization-broker/verify-deny-only-envoy.sh",
    }
    assert set(gate.EVIDENCE_SOURCES) == expected_sources
    assert set(result["source_sha256"]) == expected_sources
    assert result["source_sha256"] == {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in result["source_sha256"]}


def test_gate_deadline_and_cleanup_are_bounded_and_attempt_every_resource(monkeypatch):
    gate = _load_gate()

    monkeypatch.setattr(gate, "_gate_deadline", time.monotonic() - 1)
    called = False

    def must_not_run(*_, **__):
        nonlocal called
        called = True

    monkeypatch.setattr(gate.subprocess, "run", must_not_run)
    with pytest.raises(subprocess.TimeoutExpired):
        gate.run("docker", "ps")
    assert called is False

    attempts = []

    def always_timeout(*args):
        attempts.append(args)
        raise subprocess.TimeoutExpired(args, 0.01)

    expected = gate.cleanup_resources(always_timeout)
    assert attempts == expected
    assert len(attempts) == 6
