"""The Temporal provider, tested without a Temporal service.

Almost everything worth asserting about this provider is assertable without the
SDK installed, and those assertions are the ones that protect the seam: that it
constructs, that it refuses what it has not implemented, that its asynchrony
stops inside it, and that no part of it leaks upward.

What is NOT here is a live round trip. That belongs to Stage 9's failure and
replay campaign against a real service, and pretending a mock provides it would
be the more dangerous kind of green.
"""

import asyncio
import importlib.util
import inspect
import pathlib

import pytest

from andyur import orchestration
from andyur.orchestration import capabilities, errors, models
from andyur.orchestration.temporal import TemporalConfig, TemporalWorkflowProvider
from andyur.orchestration.temporal.client import LoopThread

HAS_SDK = importlib.util.find_spec("temporalio") is not None
ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def provider():
    return TemporalWorkflowProvider()


# --- it is a provider, with or without the SDK -------------------------------

def test_the_temporal_provider_satisfies_the_interface(provider):
    assert isinstance(provider, orchestration.WorkflowProvider)
    assert provider.name == "temporal"


def test_it_constructs_without_the_sdk_installed(provider):
    """The registry builds providers lazily so that an installation without the
    optional extra is unaffected by this package existing. Construction must
    therefore not import the SDK -- only actually talking to a service may."""
    assert provider.capabilities().provider == "temporal"


def test_health_reports_rather_than_raising_when_it_cannot_connect(provider):
    """A provider that is unwell must say so, so the control plane can refuse
    new durable work while still serving reads of Andyur's own record."""
    health = provider.health()

    assert isinstance(health, models.ProviderHealth)
    assert health.reachable is False or HAS_SDK
    if not HAS_SDK:
        assert "not installed" in (health.detail or "")


# --- it claims only what this slice implements -------------------------------

def test_it_claims_only_what_it_implements(provider):
    """CONSERVATIVE BY POLICY, and the list moves as slices land.

    Schedules became True when `create_schedule` started creating one; child
    workflows are still False, so a workflow kind needing them is refused by
    the capability check before it reaches a method that would have to invent
    something.
    """
    caps = provider.capabilities()

    assert caps.durable_execution is True
    assert caps.durable_timers is True
    assert caps.durable_signals is True
    assert caps.long_running_waits is True
    assert caps.schedules is True
    assert caps.child_workflows is False


def test_it_does_not_claim_failover_a_build_cannot_know(provider):
    """A single-node dev service and a replicated cluster answer the same API.
    Claiming failover here would put a deployment's property in a build's
    mouth."""
    assert provider.capabilities().provider_failover is False


def test_a_kind_needing_an_unimplemented_capability_is_refused(provider):
    caps = provider.capabilities()

    capabilities.check("durable_approval", caps)          # the point of adopting it
    capabilities.check("scheduled_agent", caps)           # since Stage 10
    with pytest.raises(errors.ProviderCapabilityMissing):
        capabilities.check("delegated_fanout", caps)      # child workflows: not yet


def test_an_overlap_rule_the_engine_cannot_express_is_still_refused(provider):
    """Schedules are implemented now, but Andyur's overlap rule is not
    negotiable: no native policy is skip-and-retry-soon, so a caller asking for
    buffering is told no rather than quietly given SKIP.

    Checked before any connection is attempted, so it holds without a service.
    """
    spec = models.ScheduleSpec(schedule_id="s1", agent="a", cron="0 3 * * *",
                               reason="nightly", on_overlap="buffer_all")
    with pytest.raises(errors.ProviderCapabilityMissing):
        provider.create_schedule(spec)


# --- the bridge, which is the measured part ----------------------------------

def test_the_bridge_works_from_a_plain_synchronous_caller():
    loop = LoopThread()

    async def work():
        await asyncio.sleep(0)
        return "done"

    try:
        assert loop.call(work(), timeout=5) == "done"
    finally:
        loop.close()


def test_the_bridge_works_from_inside_a_running_event_loop():
    """THE CASE THAT DECIDED THE DESIGN, and it was measured rather than
    argued.

    `asyncio.run` inside a synchronous function works from a threadpool
    endpoint and RAISES from anywhere already inside a loop. Andyur has both
    callers: `trigger_agent` is sync in a threadpool, while `fire_due` and
    `drain_pending_work` are called synchronously by the heartbeat from inside
    its loop. A private loop in its own thread serves both; the naive bridge
    fails exactly on the heartbeat path.
    """
    loop = LoopThread()

    async def work():
        await asyncio.sleep(0)
        return "done"

    async def like_the_heartbeat():
        return loop.call(work(), timeout=5)       # synchronous call, inside a loop

    try:
        assert asyncio.run(like_the_heartbeat()) == "done"
    finally:
        loop.close()


def test_the_bridge_bounds_its_wait():
    """Called on request paths, so an unbounded wait is a trigger endpoint that
    hangs instead of failing -- and a caller cannot tell those apart."""
    loop = LoopThread()

    async def never():
        await asyncio.sleep(30)

    try:
        with pytest.raises(errors.ProviderUnavailable, match="did not answer"):
            loop.call(never(), timeout=0.2)
    finally:
        loop.close()


# --- configuration ------------------------------------------------------------

def test_configuration_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("ANDYUR_TEMPORAL_ADDRESS", "temporal.example:7233")
    monkeypatch.setenv("ANDYUR_TEMPORAL_NAMESPACE", "prod")
    monkeypatch.setenv("ANDYUR_TEMPORAL_TLS", "on")

    c = TemporalConfig.from_env()

    assert (c.address, c.namespace, c.tls) == ("temporal.example:7233", "prod", True)


def test_the_same_provider_serves_cloud_by_configuration_alone():
    """Cloud differs in address, namespace and credentials and nothing else
    Andyur cares about, so there is no branch for it anywhere."""
    import andyur.orchestration.temporal.provider as mod

    source = inspect.getsource(mod) + inspect.getsource(TemporalConfig)
    assert "cloud" not in source.lower().replace("cloud, or any tls", "")


def test_describe_never_prints_the_api_key(monkeypatch):
    """This string is the one most likely to be pasted into an issue."""
    monkeypatch.setenv("ANDYUR_TEMPORAL_API_KEY", "super-secret-value")

    c = TemporalConfig.from_env()

    assert c.api_key == "super-secret-value"
    assert "super-secret-value" not in c.describe()


# --- nothing leaks upward ------------------------------------------------------

def test_the_sdk_is_imported_only_inside_this_package():
    """The architecture rule, checked over the whole tree rather than the
    orchestration package alone: an import of the engine anywhere else is the
    coupling the seam exists to remove."""
    import ast

    offenders = []
    allowed = ROOT / "andyur" / "orchestration" / "temporal"
    for path in (ROOT / "andyur").rglob("*.py"):
        if path.is_relative_to(allowed):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(n.split(".")[0] == "temporalio" for n in names):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert offenders == [], offenders


def test_the_optional_extra_is_declared():
    """Andyur installs and runs without the SDK; `ANDYUR_WORKFLOW_PROVIDER=local`
    never imports it. That is only true while it stays an extra."""
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "optional-dependencies.temporal" in pyproject
    assert (ROOT / "requirements-temporal.txt").exists()
    assert "temporalio" not in (ROOT / "requirements.txt").read_text()


def test_both_providers_are_registered_and_selectable():
    from andyur.orchestration import registry

    assert set(registry.BUILDERS) == {"local", "temporal"}
    assert registry.build_workflow_provider("temporal").name == "temporal"


def test_workflow_code_does_not_import_the_platform():
    """WHAT MAKES THE SANDBOX PASSTHROUGH SAFE, and the worker cites this test
    by name.

    `build_worker` passes `andyur` through the workflow sandbox, because
    otherwise importing the workflow module pulls the package `__init__` chain
    into the sandbox and the worker refuses to start. That is accurate only
    while no workflow actually touches the platform: every read and every
    effect must be an activity, which runs outside the sandbox.

    If a workflow ever did import Andyur directly, the passthrough would stop
    being a convenience and start hiding a determinism bug -- the workflow would
    read live state on replay and take a branch history does not record. So the
    rule is enforced here rather than trusted.
    """
    import ast

    workflows = ROOT / "andyur" / "orchestration" / "temporal" / "workflows.py"
    tree = ast.parse(workflows.read_text())
    offenders = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            # A relative import inside this package is fine; the activities
            # module is imported for its dataclass and its activity handles.
            if node.level and node.module in {"activities"}:
                continue
            if node.level == 0 and node.module.split(".")[0] == "andyur":
                offenders.append(f"workflows.py:{node.lineno} imports {node.module}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] == "andyur":
                    offenders.append(f"workflows.py:{node.lineno} imports {a.name}")

    assert offenders == [], (
        f"{offenders} -- workflow code must reach the platform only through "
        "activities, or the sandbox passthrough hides a determinism bug")


# --- mTLS against a SPIFFE-issued engine --------------------------------------

def test_the_server_ca_is_read_from_the_environment(monkeypatch):
    """A SPIFFE-issued server certificate is signed by the trust domain's own
    CA, which is in no system root store. Without a way to name that CA the
    client cannot verify a correctly configured engine at all."""
    monkeypatch.setenv("ANDYUR_TEMPORAL_SERVER_CA", "/svid/ca.crt")
    assert TemporalConfig.from_env().server_ca_path == "/svid/ca.crt"


def test_the_client_offers_its_certificate_and_verifies_the_server(tmp_path):
    """BOTH HALVES, because either alone is a different protocol.

    A client cert with no server CA is a client that proves who it is to
    whatever answers; a server CA with no client cert is one the engine will
    refuse when it requires client auth. mTLS is the pair.
    """
    from andyur.orchestration.temporal.client import TemporalConnection

    cert = tmp_path / "tls.crt"; cert.write_bytes(b"CERT")
    key = tmp_path / "tls.key"; key.write_bytes(b"KEY")
    ca = tmp_path / "ca.crt"; ca.write_bytes(b"CA")

    conn = TemporalConnection(TemporalConfig(
        tls=True, client_cert_path=str(cert), client_key_path=str(key),
        server_ca_path=str(ca)))
    tls = conn._tls()

    assert tls.client_cert == b"CERT"
    assert tls.client_private_key == b"KEY"
    assert tls.server_root_ca_cert == b"CA", (
        "the server's CA was not passed, so the client would verify a "
        "SPIFFE-issued engine against the system root store")


def test_a_ca_on_its_own_is_still_configured(tmp_path):
    """The engine may present a certificate without requiring one: verifying
    the server is worth doing whether or not this client authenticates."""
    from andyur.orchestration.temporal.client import TemporalConnection

    ca = tmp_path / "ca.crt"; ca.write_bytes(b"CA")
    conn = TemporalConnection(TemporalConfig(tls=True, server_ca_path=str(ca)))
    tls = conn._tls()

    assert tls.server_root_ca_cert == b"CA"
    assert tls.client_cert is None


def test_tls_with_nothing_configured_is_the_systems_own_trust():
    """A public, TLS-fronted deployment needs no files. `True` means "use the
    system roots", which is right for Temporal Cloud and wrong for SPIFFE --
    and the difference is what the paths above express."""
    from andyur.orchestration.temporal.client import TemporalConnection

    assert TemporalConnection(TemporalConfig(tls=True))._tls() is True


# --- the connection survives the things that happen to connections ----------

def _conn_with_certs(tmp_path, connect):
    from andyur.orchestration.temporal.client import TemporalConnection

    cert = tmp_path / "tls.crt"; cert.write_bytes(b"CERT-1")
    key = tmp_path / "tls.key"; key.write_bytes(b"KEY-1")
    ca = tmp_path / "ca.crt"; ca.write_bytes(b"CA-1")
    conn = TemporalConnection(TemporalConfig(
        tls=True, client_cert_path=str(cert), client_key_path=str(key),
        server_ca_path=str(ca), rpc_timeout_seconds=2))
    conn._connect = connect
    return conn, cert


def test_a_rotated_certificate_makes_the_next_call_reconnect(tmp_path):
    """THE CLIENT WAS CACHED FOR THE LIFE OF THE PROCESS, and the SVID it
    presented lives fifteen minutes. The first reconnect after a rotation
    presented an expired certificate and failed forever -- proven live, with a
    fresh client in the same container connecting at once beside it.

    Asserted as "a SECOND connect happens", because that is the only thing that
    puts the new certificate on the wire. Reading the files again without
    reconnecting would change nothing.
    """
    connects = []

    async def connect():
        connects.append(1)
        return object()

    conn, cert = _conn_with_certs(tmp_path, connect)
    try:
        first = conn.client()
        assert conn.client() is first and len(connects) == 1, (
            "a steady client must be reused, or this reconnects on every call")

        cert.write_bytes(b"CERT-2-ROTATED")           # what spiffe-helper does

        second = conn.client()
        assert len(connects) == 2, (
            "the certificate rotated and the client did not reconnect -- the "
            "next reconnect would present an expired certificate")
        assert second is not first
    finally:
        conn.close()


def test_a_same_size_rotation_is_noticed(tmp_path):
    """PEM files of one key type are the same size every rotation, so size
    alone would miss nearly all of them; the nanosecond mtime is what sees it."""
    import os

    connects = []

    async def connect():
        connects.append(1)
        return object()

    conn, cert = _conn_with_certs(tmp_path, connect)
    try:
        conn.client()
        before = cert.stat()
        cert.write_bytes(b"CERT-9")                       # same length as CERT-1
        os.utime(cert, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        assert cert.stat().st_size == before.st_size

        conn.client()
        assert len(connects) == 2, "a same-size rotation was not noticed"
    finally:
        conn.close()


@pytest.mark.parametrize("which", ["tls.key", "ca.crt"])
def test_a_rotated_key_or_bundle_is_noticed(tmp_path, which):
    """The key rotates with the certificate, and the trust bundle rotates on
    its own schedule; either one changing means the next handshake differs."""
    connects = []

    async def connect():
        connects.append(1)
        return object()

    conn, _cert = _conn_with_certs(tmp_path, connect)
    try:
        conn.client()
        (tmp_path / which).write_bytes(b"ROTATED-MATERIAL")
        conn.client()
        assert len(connects) == 2, f"a rotated {which} was not noticed"
    finally:
        conn.close()


def test_a_torn_rotation_keeps_the_working_client_and_recovers_when_the_files_settle(tmp_path):
    """spiffe-helper writes the certificate, then the key. A reconnect between
    the two loads a pair that does not match and fails. The client already held
    still works, so it is served; and the failure is remembered for THOSE
    files only, so the moment the key lands the next call reconnects rather
    than waiting out the memo."""
    from andyur.orchestration.errors import ProviderUnavailable

    connects = []
    key = tmp_path / "tls.key"

    async def connect():
        connects.append(1)
        cert_now = (tmp_path / "tls.crt").read_bytes()
        if cert_now.endswith(b"-2") and key.read_bytes().endswith(b"-1"):
            raise ProviderUnavailable("the certificate does not match the key")
        return object()

    conn, cert = _conn_with_certs(tmp_path, connect)
    try:
        first = conn.client()
        cert.write_bytes(b"CERT-2")                       # half-way through a rotation

        try:
            during = conn.client()
        except ProviderUnavailable as exc:
            pytest.fail(f"a failed reconnect refused the caller ({exc}) while "
                        "the client already held still works")
        assert len(connects) == 2, "the rotation was not attempted"
        assert during is first, (
            "a failed reconnect dropped the client that still works; every "
            "caller in the rotation window was refused")

        key.write_bytes(b"KEY-2")                         # the rotation completes
        after = conn.client()
        assert len(connects) == 3, (
            "the settled files were not tried: the failure memo outlived the "
            "material that failed")
        assert after is not first
    finally:
        conn.close()


def test_after_the_backoff_a_failed_connect_is_tried_again(tmp_path, monkeypatch):
    """The memo makes queued callers fail fast; it must also END, or one bad
    moment is a permanent outage."""
    from andyur.orchestration.errors import ProviderUnavailable
    from andyur.orchestration.temporal import client as client_mod

    connects = []

    async def connect():
        connects.append(1)
        raise ProviderUnavailable("unreachable")

    conn, _cert = _conn_with_certs(tmp_path, connect)
    try:
        for _ in range(2):
            with pytest.raises(ProviderUnavailable):
                conn.client()
        assert len(connects) == 1, "the memo did not spare the second caller"

        # A FIXED six seconds, not "the configured backoff plus one": the
        # contract is a short memo, and a test that scaled with the constant
        # would pass a memo of a year.
        real = client_mod.time.monotonic
        monkeypatch.setattr(client_mod.time, "monotonic", lambda: real() + 6)
        with pytest.raises(ProviderUnavailable):
            conn.client()
        assert len(connects) == 2, "the connect was never tried again after the backoff"
    finally:
        conn.close()


def test_a_queue_of_callers_does_not_each_pay_the_full_timeout(tmp_path):
    """Measured before the fix: 3.0s, 6.0s and 9.0s for three callers against
    an address that drops packets, because each waiter made its own full
    attempt after the one ahead of it failed.

    A remembered failure makes the others fail fast. The assertion is on the
    SLOWEST caller, because the first one always pays the bound and that is
    correct.
    """
    import threading
    import time

    from andyur.orchestration.errors import ProviderUnavailable

    async def slow_failure():
        import asyncio
        await asyncio.sleep(0.6)
        raise ProviderUnavailable("unreachable")

    conn, _cert = _conn_with_certs(tmp_path, slow_failure)
    elapsed = []

    def call():
        t0 = time.monotonic()
        try:
            conn.client()
        except ProviderUnavailable:
            pass
        elapsed.append(time.monotonic() - t0)

    try:
        threads = [threading.Thread(target=call) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
    finally:
        conn.close()

    assert len(elapsed) == 3
    assert max(elapsed) < 1.5, (
        f"callers waited {sorted(round(e, 2) for e in elapsed)}s -- each paid "
        "the full connect in turn instead of failing fast behind the first")


def test_the_worker_does_not_exit_because_the_engine_is_down(monkeypatch):
    """IT USED TO, and it took the API down with it: the process exited, the
    container crash-looped, and because it shares a Pod with the API server the
    whole Pod went NotReady and the control plane lost its only endpoint.

    So the loop must still be RUNNING after several failed connects. A worker
    that raised out of `_run` would be finished, and `done()` says so.
    """
    import asyncio

    from andyur.orchestration.temporal import worker as worker_mod
    from temporalio.client import Client

    attempts = []

    async def refuse(**_kwargs):
        attempts.append(1)
        raise ConnectionRefusedError("engine down")

    monkeypatch.setattr(Client, "connect", refuse)
    monkeypatch.setattr(worker_mod, "RETRY_SECONDS", (0.01,))

    async def main():
        task = asyncio.create_task(worker_mod._run(TemporalConfig(tls=False)))
        # BOUNDED, AND IT STOPS WHEN THE TASK DOES. The first version waited
        # for four attempts unconditionally -- so a worker that exited after
        # ONE made this spin forever. The bug was caught, as a hang: the right
        # outcome for the wrong reason, and in CI a timeout instead of a
        # message.
        deadline = asyncio.get_running_loop().time() + 3
        while (len(attempts) < 8 and not task.done()
               and asyncio.get_running_loop().time() < deadline):
            await asyncio.sleep(0.01)
        alive = not task.done()
        task.cancel()
        return alive

    assert asyncio.run(main()), (
        "the worker stopped after the engine refused it; in the Pod that is a "
        "crash loop, and the API goes down with it")
    # EIGHT, past the end of the backoff table: a loop that gave up after the
    # last entry would pass a count of four.
    assert len(attempts) >= 8


class _FakeWorker:
    """Stands in for the SDK Worker: it runs until cancelled, or fails at once
    when told to, and exposes `client` the way the real one does."""

    def __init__(self, client, fail=False):
        self.client = client
        self.fail = fail

    async def run(self):
        import asyncio

        if self.fail:
            raise RuntimeError("poll refused: namespace not found")
        await asyncio.Event().wait()


def _worker_harness(monkeypatch, tmp_path, *, connect=None, fail_first_run=False):
    """_run with a fake connect and fake workers, certificate files on disk and
    a fast rotation check. Returns (config, cert, connects, workers)."""
    from andyur.orchestration.temporal import worker as worker_mod
    from temporalio.client import Client

    cert = tmp_path / "tls.crt"; cert.write_bytes(b"CERT-1")
    key = tmp_path / "tls.key"; key.write_bytes(b"KEY-1")
    connects, workers = [], []

    async def fake_connect(**_kwargs):
        connects.append(1)
        if connect:
            return await connect(len(connects))
        return object()

    def fake_build(client, _config):
        w = _FakeWorker(client, fail=fail_first_run and not workers)
        workers.append(w)
        return w

    monkeypatch.setattr(Client, "connect", fake_connect)
    monkeypatch.setattr(worker_mod, "build_worker", fake_build)
    monkeypatch.setattr(worker_mod, "ROTATION_CHECK_SECONDS", 0.02)
    monkeypatch.setattr(worker_mod, "RETRY_SECONDS", (0.01,))
    cfg = TemporalConfig(tls=True, client_cert_path=str(cert), client_key_path=str(key))
    return cfg, cert, connects, workers


def _drive(cfg, until, *, seconds=3.0, between=None):
    """Run the worker loop until `until()` holds (or time runs out); return
    whether the loop was still alive at the end."""
    import asyncio

    from andyur.orchestration.temporal import worker as worker_mod

    async def main():
        task = asyncio.create_task(worker_mod._run(cfg))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        stepped = False
        while loop.time() < deadline and not task.done():
            if between and not stepped and between():
                stepped = True
            if until():
                break
            await asyncio.sleep(0.01)
        alive = not task.done()
        task.cancel()
        return alive

    return asyncio.run(main())


def test_a_rotation_swaps_the_client_into_the_running_worker(monkeypatch, tmp_path):
    """The worker holds its connection for hours, so it has to notice a rotation
    itself. And it hands the new client to the SAME worker: rebuilding the
    worker dropped its workflow cache every rotation, replaying every live run's
    history about every seven minutes."""
    cfg, cert, connects, workers = _worker_harness(monkeypatch, tmp_path)
    rotated = []

    def rotate():
        if workers and not rotated:
            cert.write_bytes(b"CERT-2-ROTATED")
            rotated.append(1)
            return True
        return False

    _drive(cfg, until=lambda: len(connects) >= 2, between=rotate)

    assert len(connects) >= 2, "the certificate rotated and the worker kept its old connection"
    assert len(workers) == 1, (
        f"the worker was rebuilt {len(workers) - 1} time(s) for a rotation, "
        "dropping its workflow cache")
    assert workers[0].client is not None and connects, "no client reached the worker"


def test_a_steady_worker_keeps_its_one_connection(monkeypatch, tmp_path):
    """With nothing rotating, the loop must not reconnect at every check."""
    import time

    cfg, _cert, connects, workers = _worker_harness(monkeypatch, tmp_path)
    started = time.monotonic()

    alive = _drive(cfg, until=lambda: time.monotonic() - started > 0.4)

    assert alive
    assert len(connects) == 1 and len(workers) == 1, (
        f"{len(connects)} connects and {len(workers)} workers in 0.4s of "
        "steady running (~20 rotation checks)")


def test_a_failed_reconnect_on_rotation_keeps_the_worker_serving(monkeypatch, tmp_path):
    """The new connect can fail (spiffe-helper mid-write); the connection the
    worker already has still works, so it keeps it and tries again later."""
    swapped = []

    async def connect(n):
        if n == 2:
            raise ConnectionRefusedError("certificate does not match key")
        swapped.append(n)
        return object()

    cfg, cert, connects, workers = _worker_harness(monkeypatch, tmp_path, connect=connect)
    first_client = []

    def rotate():
        if workers and not first_client:
            first_client.append(workers[0].client)
            cert.write_bytes(b"CERT-2-ROTATED")
            return True
        return False

    alive = _drive(cfg, until=lambda: len(connects) >= 3, between=rotate)

    assert alive, "a failed reconnect on rotation stopped the worker loop"
    assert len(workers) == 1, "a failed reconnect tore the running worker down"
    assert len(connects) >= 3, "the failed rotation was never retried"


def test_a_worker_that_stops_is_rebuilt_rather_than_left_dead(monkeypatch, tmp_path):
    """A poll refused, a namespace missing: the SDK's own context manager
    either re-raised (the process exited, taking the API's Pod down) or waited
    forever (the container stayed Running and polled nothing). Either way the
    engine lost its worker silently. The loop now sees the worker stop and
    builds another."""
    cfg, _cert, _connects, workers = _worker_harness(
        monkeypatch, tmp_path, fail_first_run=True)

    alive = _drive(cfg, until=lambda: len(workers) >= 2)

    assert alive, "a stopped worker ended the loop; in the Pod that is a crash loop"
    assert len(workers) >= 2, "the worker stopped and nothing rebuilt it"


# --- witnessed: the engine's half of a run is traced -------------------------

def test_every_connection_to_the_engine_is_traced():
    """The lane shipped with `ANDYUR_OTEL=on` in the manifest and no tracing on
    the engine path at all -- a run's trace stopped at the facade. The
    interceptor is what carries context into a workflow and turns its steps
    into spans, and it goes on the ONE function both clients connect through.
    """
    from temporalio.contrib.opentelemetry import TracingInterceptor

    from andyur.orchestration.temporal.client import TemporalConnection

    conn = TemporalConnection(TemporalConfig(tls=False))
    try:
        interceptors = conn.connect_kwargs().get("interceptors", [])
    finally:
        conn.close()

    assert any(isinstance(i, TracingInterceptor) for i in interceptors), (
        "a connection to the engine carries no tracing interceptor, so every "
        "workflow and activity is invisible")


def test_the_worker_sets_up_telemetry_before_it_serves(monkeypatch):
    """`otel.setup_tracing` is an explicit call -- the server, the daemon and the
    Kubernetes controller all make it -- and this process never did."""
    from andyur import otel
    from andyur.orchestration.temporal import worker as worker_mod

    order = []
    monkeypatch.setattr(otel, "setup_tracing", lambda name: order.append(("otel", name)))

    def fake_run(coro):
        order.append(("serve", None))
        coro.close()

    monkeypatch.setattr(worker_mod.asyncio, "run", fake_run)
    worker_mod.main()

    assert order[:2] == [("otel", "andyur-workflow-worker"), ("serve", None)], (
        f"telemetry was not configured before serving: {order}")


def test_the_workflow_module_is_not_passed_through_the_sandbox():
    """DETERMINISM CHECKS WERE OFF FOR EVERY ANDYUR WORKFLOW.

    The sandbox passes a module through if it OR ANY PARENT is listed, and
    `andyur` was listed -- so `andyur.orchestration.temporal.workflows` was the
    host's own object, never re-imported and never restricted. An adversarial
    review ran `time.time()` inside an `andyur` workflow and got a value back.

    The property is exactly the one that failed: nothing passed through may be
    the workflow module or one of its parents.
    """
    from andyur.orchestration.temporal.worker import SANDBOX_PASSTHROUGH

    target = "andyur.orchestration.temporal.workflows"
    lineage = {target[:i] for i, ch in enumerate(target) if ch == "."} | {target}
    offending = sorted(m for m in SANDBOX_PASSTHROUGH if m in lineage)

    assert not offending, (
        f"{offending} is passed through the sandbox and is {target} or a parent "
        "of it, so the workflow module is never re-imported and its determinism "
        "checks are OFF")


# --- halt: every run at once, and a missing namespace is not a missing run ----

class _RPCError(Exception):
    """Shaped like temporalio's RPCError: a status and the gRPC details."""

    def __init__(self, message, code_name, detail_type=None):
        super().__init__(message)
        self.status = type("S", (), {"name": code_name})()
        details = [type("D", (), {"type_url": detail_type})()] if detail_type else []
        self.grpc_status = type("G", (), {"details": details})()


def _halting_provider(signal):
    """A provider over the real connection loop, with a client whose signal
    is `signal(execution)`."""
    from andyur.orchestration.temporal.client import TemporalConnection

    class Handle:
        def __init__(self, execution):
            self.execution = execution

        async def signal(self, _name, rpc_timeout=None):
            await signal(self.execution)

    class FakeClient:
        def get_workflow_handle(self, execution):
            return Handle(execution)

    async def connect():
        return FakeClient()

    config = TemporalConfig(tls=False, rpc_timeout_seconds=5)
    conn = TemporalConnection(config)
    conn._connect = connect
    return TemporalWorkflowProvider(config, connection=conn), conn


def test_a_missing_namespace_does_not_read_as_already_halted():
    """The service answers a missing namespace and a missing execution with the
    same NOT_FOUND. Read as "already gone", every halt against a misconfigured
    namespace came back accepted and HALTED with nothing signalled -- the kill
    switch reporting success for runs it never reached."""
    from andyur.orchestration.errors import HaltNotAcknowledged
    from andyur.orchestration.models import HaltRequest

    async def signal(_execution):
        raise _RPCError("Namespace andyr is not found.", "NOT_FOUND",
                        "type.googleapis.com/temporal.api.errordetails.v1."
                        "NamespaceNotFoundFailure")

    provider, conn = _halting_provider(signal)
    try:
        with pytest.raises(HaltNotAcknowledged):
            provider.halt(HaltRequest(workflow_id="wf-1", reason="r",
                                      run_ids=("a" * 32, "b" * 32)))
    finally:
        conn.close()


def test_positive_control_a_missing_execution_is_still_already_halted():
    """The other NOT_FOUND must keep meaning "nothing to stop", or an operator
    racing a run that is starting is refused by the kill switch."""
    from andyur.orchestration.models import HaltRequest, WorkflowState

    async def signal(execution):
        raise _RPCError(f"workflow not found for ID: {execution}", "NOT_FOUND",
                        "type.googleapis.com/temporal.api.errordetails.v1.NotFoundFailure")

    provider, conn = _halting_provider(signal)
    try:
        outcome = provider.halt(HaltRequest(workflow_id="wf-1", reason="r",
                                            run_ids=("a" * 32,)))
        assert outcome.accepted and outcome.state == WorkflowState.HALTED
    finally:
        conn.close()


def test_halt_signals_every_run_at_once():
    """One after another, a hung service held the kill switch for N x the RPC
    timeout -- minutes, for exactly the runaway fan-out a halt is for."""
    import asyncio
    import time

    from andyur.orchestration.models import HaltRequest

    async def signal(_execution):
        await asyncio.sleep(0.3)

    provider, conn = _halting_provider(signal)
    try:
        started = time.monotonic()
        outcome = provider.halt(HaltRequest(
            workflow_id="wf-1", reason="r", run_ids=tuple(f"{i:032x}" for i in range(8))))
        elapsed = time.monotonic() - started
    finally:
        conn.close()

    assert outcome.accepted
    assert elapsed < 1.2, (
        f"eight signals took {elapsed:.1f}s; one at a time that is 8 x 0.3s, "
        "and a hung service turns it into 8 x the RPC timeout")


def test_health_reports_rather_than_raising_without_the_sdk(monkeypatch):
    """`health()` promises to report. Its import sat outside the `try`, so on
    an installation without the Temporal extra it raised instead."""
    import sys

    monkeypatch.setitem(sys.modules, "temporalio.api.workflowservice.v1", None)
    health = TemporalWorkflowProvider().health()
    assert health.reachable is False


def test_describe_addresses_the_newest_runs_execution():
    """Executions are per run; given Andyur's live runs, describe asks about
    the newest one's execution rather than an id the engine never started."""
    from andyur.orchestration.temporal.client import TemporalConnection
    from andyur.orchestration.temporal.provider import run_execution_id

    asked = []

    class Handle:
        def __init__(self, execution):
            asked.append(execution)

        async def describe(self):
            return type("D", (), {"status": type("S", (), {"name": "RUNNING"})(),
                                  "run_id": "r"})()

    class FakeClient:
        def get_workflow_handle(self, execution):
            return Handle(execution)

    async def connect():
        return FakeClient()

    config = TemporalConfig(tls=False, rpc_timeout_seconds=5)
    conn = TemporalConnection(config)
    conn._connect = connect
    provider = TemporalWorkflowProvider(config, connection=conn)
    try:
        provider.describe("wf-1", run_ids=("a" * 32, "b" * 32))
        provider.describe(run_execution_id("c" * 32))
    finally:
        conn.close()

    assert asked == [run_execution_id("b" * 32), run_execution_id("c" * 32)], asked


def test_the_worker_it_builds_passes_through_only_the_declared_leaves(monkeypatch):
    """The constant was checked; the worker built from it was not. Passing all
    of `andyur` through in `build_worker` -- which lets workflow code read the
    wall clock and live platform state unchecked -- kept every other test
    green. This inspects the runner the shipped `build_worker` constructs."""
    import temporalio.worker as sdk_worker

    from andyur.orchestration.temporal import worker as worker_mod

    captured = {}

    class Capture:
        def __init__(self, _client, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(sdk_worker, "Worker", Capture)
    worker_mod.build_worker(object(), TemporalConfig(tls=False))

    passthrough = set(captured["workflow_runner"].restrictions.passthrough_modules)
    declared = set(worker_mod.SANDBOX_PASSTHROUGH)
    assert declared <= passthrough, "the declared leaves are not passed through"
    ours = {m for m in passthrough if m == "andyur" or m.startswith("andyur.")}
    assert ours == declared, (
        f"the built worker passes through {sorted(ours - declared)} beyond the "
        "declared leaves; a parent package passes its children through with it")


def test_both_connections_are_made_with_the_tracing_interceptor(monkeypatch):
    """`connect_kwargs()` carrying the interceptor proves nothing if the code
    that connects does not use it. Captured at `Client.connect` itself, from
    the provider's connection and from the worker's."""
    import asyncio

    from temporalio.client import Client
    from temporalio.contrib.opentelemetry import TracingInterceptor

    from andyur.orchestration.temporal import worker as worker_mod
    from andyur.orchestration.temporal.client import TemporalConnection

    seen = []

    async def capture(**kwargs):
        seen.append(kwargs)
        return object()

    monkeypatch.setattr(Client, "connect", capture)
    config = TemporalConfig(tls=False)
    conn = TemporalConnection(config)
    try:
        conn.client()
    finally:
        conn.close()
    asyncio.run(worker_mod._connect(TemporalConnection(config), config))

    assert len(seen) == 2
    for kwargs in seen:
        assert any(isinstance(i, TracingInterceptor) for i in kwargs.get("interceptors", ())), (
            "a connection to the engine was made without the tracing interceptor")


def test_the_worker_connects_on_the_runtime_a_swap_requires(monkeypatch):
    """The SDK refuses a swapped client unless its runtime IS the worker's; a
    client connected without naming one carries None and was refused on the
    first live rotation. The fake-client tests above could not see this."""
    import asyncio

    from temporalio.client import Client
    from temporalio.runtime import Runtime

    from andyur.orchestration.temporal import worker as worker_mod
    from andyur.orchestration.temporal.client import TemporalConnection

    seen = {}

    async def capture(**kwargs):
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(Client, "connect", capture)
    config = TemporalConfig(tls=False)
    asyncio.run(worker_mod._connect(TemporalConnection(config), config))

    assert seen.get("runtime") is Runtime.default(), (
        "the worker's client does not name the default runtime; the SDK will "
        "refuse to swap it into a running worker")
