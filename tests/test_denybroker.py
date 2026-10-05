import pytest
from starlette.testclient import TestClient

from andyur.dataplane import denybroker
from andyur.dataplane.denybroker import (
    BrokerState,
    ControlPlaneState,
    build_state_bound_broker,
    build_state_bound_broker_after_transport_ready,
)


def test_kubernetes_parent_provisioning_safely_adopts_restart_and_fs_group(tmp_path):
    socket_path = tmp_path / "broker" / "authz.sock"
    denybroker.provision_socket_parent(str(socket_path))
    parent = socket_path.parent.stat()
    assert parent.st_mode & 0o777 == 0o750
    assert (parent.st_uid, parent.st_gid) == (denybroker.os.getuid(),
                                             denybroker.os.getgid())
    denybroker.provision_socket_parent(str(socket_path))
    socket_path.parent.chmod(0o2750)
    denybroker.provision_socket_parent(str(socket_path))
    socket_path.parent.chmod(0o2770)
    with pytest.raises(RuntimeError, match="not exact"):
        denybroker.provision_socket_parent(str(socket_path))


def test_cold_start_retries_only_transport_connect_until_envoy_is_ready():
    attempts = 0

    def fetch():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise denybroker.httpx.ConnectError("Envoy UDS absent")
        return _state()

    app = build_state_bound_broker_after_transport_ready(
        fetch, denybroker.threading.Event(), timeout=1, retry_interval=0)
    assert attempts == 3
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200


def test_cold_start_transport_retry_is_bounded_and_semantic_errors_are_not_retried():
    stopping = denybroker.threading.Event()
    with pytest.raises(RuntimeError, match="unavailable at startup"):
        build_state_bound_broker_after_transport_ready(
            lambda: (_ for _ in ()).throw(
                denybroker.httpx.ConnectError("Envoy UDS absent")),
            stopping, timeout=0, retry_interval=0)

    attempts = 0

    def invalid_state():
        nonlocal attempts
        attempts += 1
        return _state(live=False)

    with pytest.raises(ValueError, match="terminal run"):
        build_state_bound_broker_after_transport_ready(
            invalid_state, stopping, timeout=1, retry_interval=0)
    assert attempts == 1


@pytest.mark.parametrize("transient", [
    denybroker.TransientBrokerStartup("identity unavailable"),
    denybroker.httpx.ConnectTimeout("Envoy connect timeout"),
    denybroker.httpx.ReadError("Envoy reset while reading"),
    denybroker.httpx.WriteError("Envoy reset while writing"),
    denybroker.httpx.RemoteProtocolError("Envoy warming protocol"),
])
def test_cold_start_retries_explicit_transient_identity_and_transport(transient):
    attempts = 0

    def fetch():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise transient
        return _state()

    build_state_bound_broker_after_transport_ready(
        fetch, denybroker.threading.Event(), timeout=1, retry_interval=0)
    assert attempts == 2


def test_control_plane_state_classifies_identity_and_503_as_transient(
        monkeypatch):
    state = ControlPlaneState("/run/state.sock", "r1", "broker")
    monkeypatch.setattr(
        denybroker.identity, "auth_header",
        lambda **_: (_ for _ in ()).throw(TimeoutError("SVID pending")))
    with pytest.raises(denybroker.TransientBrokerStartup, match="identity"):
        state.fetch()


def test_identity_programming_error_is_not_hidden_as_transient(monkeypatch):
    state = ControlPlaneState("/run/state.sock", "r1", "broker")
    monkeypatch.setattr(
        denybroker.identity, "auth_header",
        lambda **_: (_ for _ in ()).throw(ValueError("bad SPIFFE subject")))
    with pytest.raises(ValueError, match="bad SPIFFE subject"):
        state.fetch()

    monkeypatch.setattr(denybroker.identity, "auth_header", lambda **_: {
        "Authorization": "Bearer test"})

    class Response:
        status_code = 503
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *_): return None

    class Client:
        def __init__(self, **_): pass
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def stream(self, *_args, **_kwargs): return Response()

    monkeypatch.setattr(denybroker.httpx, "Client", Client)
    with pytest.raises(denybroker.TransientBrokerStartup, match=r"warming \(503\)"):
        state.fetch()


def test_control_plane_state_does_not_reclassify_authorization_refusal(monkeypatch):
    state = ControlPlaneState("/run/state.sock", "r1", "broker")
    monkeypatch.setattr(denybroker.identity, "auth_header", lambda **_: {
        "Authorization": "Bearer test"})

    class Response:
        status_code = 403
        headers = {}
        request = denybroker.httpx.Request("GET", "http://state")
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def raise_for_status(self):
            raise denybroker.httpx.HTTPStatusError(
                "forbidden", request=self.request,
                response=denybroker.httpx.Response(403, request=self.request))

    class Client:
        def __init__(self, **_): pass
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def stream(self, *_args, **_kwargs): return Response()

    monkeypatch.setattr(denybroker.httpx, "Client", Client)
    with pytest.raises(denybroker.httpx.HTTPStatusError):
        state.fetch()


@pytest.mark.parametrize("transport_error", [
    denybroker.httpx.ReadError("read reset"),
    denybroker.httpx.WriteError("write reset"),
    denybroker.httpx.RemoteProtocolError("protocol reset"),
])
def test_control_plane_state_classifies_transient_wire_errors(
        monkeypatch, transport_error):
    state = ControlPlaneState("/run/state.sock", "r1", "broker")
    monkeypatch.setattr(denybroker.identity, "auth_header", lambda **_: {
        "Authorization": "Bearer test"})

    class Client:
        def __init__(self, **_): pass
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def stream(self, *_args, **_kwargs): raise transport_error

    monkeypatch.setattr(denybroker.httpx, "Client", Client)
    with pytest.raises(denybroker.TransientBrokerStartup, match="not ready"):
        state.fetch()


def test_process_entrypoint_survives_envoy_uds_starting_late(monkeypatch):
    attempts = 0
    lifecycle = []

    class State:
        def __init__(self, socket_path, run_id, token):
            assert (socket_path, run_id, token) == ("/run/state.sock", "r1", "token")

        def fetch(self):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise denybroker.httpx.ConnectError("Envoy UDS absent")
            return _state()

    class Server:
        def __init__(self, app, socket_path, **kwargs):
            assert app is not None
            assert socket_path == "/run/broker/authz.sock"
            assert kwargs["adopt_stale_socket"] is False

        def start(self):
            lifecycle.append("start")

        def stop(self):
            lifecycle.append("stop")

    class Event:
        def is_set(self):
            return False

        def set(self):
            pass

        def wait(self, _timeout=None):
            return False

    monkeypatch.setattr(denybroker, "ControlPlaneState", State)
    monkeypatch.setattr(denybroker, "BrokerUdsServer", Server)
    monkeypatch.setattr(denybroker.threading, "Event", Event)
    monkeypatch.setattr(denybroker.signal, "signal", lambda *_: None)
    monkeypatch.setattr(denybroker.sys, "argv", ["denybroker"])
    monkeypatch.setenv("ANDYUR_RUN_ID", "r1")
    monkeypatch.setenv("ANDYUR_BROKER_TOKEN", "token")
    monkeypatch.setenv("ANDYUR_BROKER_STATE_SOCKET", "/run/state.sock")
    monkeypatch.setenv("ANDYUR_BROKER_SOCKET", "/run/broker/authz.sock")

    denybroker.main()

    assert attempts == 2
    assert lifecycle == ["start", "stop"]


def test_permanent_startup_refusal_stays_unready_without_restart_exit(monkeypatch):
    waits = []

    class State:
        def __init__(self, *_): pass
        def fetch(self): return _state(live=False)

    class Event:
        def is_set(self): return False
        def set(self): pass
        def wait(self, timeout=None):
            waits.append(timeout)
            return True

    monkeypatch.setattr(denybroker, "ControlPlaneState", State)
    monkeypatch.setattr(denybroker.threading, "Event", Event)
    monkeypatch.setattr(denybroker.signal, "signal", lambda *_: None)
    monkeypatch.setattr(
        denybroker, "BrokerUdsServer",
        lambda *_args, **_kwargs: pytest.fail("permanent refusal bound a socket"))
    monkeypatch.setattr(denybroker.sys, "argv", ["denybroker"])
    monkeypatch.setenv("ANDYUR_RUN_ID", "r1")
    monkeypatch.setenv("ANDYUR_BROKER_TOKEN", "token")
    monkeypatch.setenv("ANDYUR_BROKER_STATE_SOCKET", "/run/state.sock")

    denybroker.main()
    assert waits == [None]


def _state(*, live=True, run_id="r1", **changes):
    raw = {
        "schema": "andyur.deny-broker-state/v1",
        "run_id": run_id,
        "agent": "scout",
        "live": live,
        "expected_subject": "alice",
        "expected_actor": f"spiffe://andyur.local/agent/scout/run/{run_id}",
        "registry_sha256": "a" * 64,
        "audiences": ["urn:calendar"],
        "actions": ["read"],
        "pin": {"account": "447"},
    }
    raw.update(changes)
    return BrokerState.parse(raw)


def test_live_exact_state_is_ready_but_issuance_stays_structurally_disabled():
    app = build_state_bound_broker(lambda: _state())
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200
        response = client.post("/authz", content=b"request")
    assert response.status_code == 403
    assert response.text == "credential issuance is disabled"
    assert "authorization" not in response.headers


def test_halt_withdraws_readiness_and_authz_on_the_next_snapshot():
    calls = 0

    def fetch():
        nonlocal calls
        calls += 1
        return _state(live=calls < 3)

    app = build_state_bound_broker(fetch)
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200
        assert client.post("/authz").status_code == 403
        assert client.get("/ready").status_code == 503


def test_startup_refuses_terminal_or_ambiguous_authority():
    with pytest.raises(ValueError, match="terminal"):
        build_state_bound_broker(lambda: _state(live=False))
    raw = _state().__dict__ | {"audiences": ()}
    with pytest.raises((ValueError, IndexError)):
        BrokerState(**raw).envelope()


@pytest.mark.parametrize("changed", [
    {"expected_subject": "mallory"},
    {"expected_actor": "spiffe://andyur.local/agent/scout/run/other"},
    {"registry_sha256": "b" * 64},
    {"audiences": ["urn:other"]},
    {"actions": ["write"]},
    {"pin": {"account": "other"}},
])
def test_every_atomic_authority_dimension_withdraws_readiness(changed):
    calls = 0

    def fetch():
        nonlocal calls
        calls += 1
        return _state(**({} if calls == 1 else changed))

    app = build_state_bound_broker(fetch)
    with TestClient(app) as client:
        response = client.get("/ready")
        denied = client.post("/authz")
    assert response.status_code == 503
    assert denied.status_code == 403
    assert "authorization" not in denied.headers


def test_control_plane_state_streams_and_stops_at_the_byte_bound(monkeypatch):
    class Response:
        status_code = 200
        headers = {}
        def raise_for_status(self): pass
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def iter_bytes(self):
            yield b"{" + b"x" * (denybroker.MAX_STATE_BYTES // 2)
            yield b"y" * (denybroker.MAX_STATE_BYTES // 2 + 2)

    class Client:
        kwargs = None
        def __init__(self, **kwargs): Client.kwargs = kwargs
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def stream(self, *args, **kwargs): return Response()

    class Transport:
        uds = None
        def __init__(self, *, uds): Transport.uds = uds

    monkeypatch.setattr(denybroker.identity, "auth_header", lambda **_: {
        "Authorization": "Bearer test"})
    monkeypatch.setattr(denybroker.httpx, "HTTPTransport", Transport)
    monkeypatch.setattr(denybroker.httpx, "Client", Client)
    with pytest.raises(ValueError, match="64 KiB"):
        ControlPlaneState("/run/state.sock", "r1", "broker").fetch()
    assert Client.kwargs["trust_env"] is False
    assert Transport.uds == "/run/state.sock"
