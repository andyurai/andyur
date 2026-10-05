"""The engine's authorizer, run for real: the SHIPPED Envoy config in front of a
real Temporal, with clients presenting real certificates.

What is swapped, and only this: where the certificates come from. In the
cluster the authorizer fetches its SVID and the trust bundle from the SPIRE
agent over SDS; here they are files from a throwaway CA, because a SPIRE agent
is not what is under test. The listener, the RBAC filter, the ALPN, the
proxying and the loopback frontend it proxies to are read out of
`infra/kubernetes/temporal.yaml` unchanged -- a hand-written copy of the config
would prove that the copy works.

Every refusal sits beside the admission it is compared with. A proxy that
refused everyone would pass every negative case here, and the provider with it
would be dead.
"""

import datetime
import os
import pathlib
import shutil
import subprocess
import time
import uuid

import pytest
import yaml

# Two image pulls and a cold Temporal start can outrun the suite's 120s
# default, and a timeout there kills the process before the fixture's cleanup.
pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "infra" / "kubernetes" / "temporal.yaml"

TOOLS = ("docker.io/temporalio/admin-tools@sha256:"
         "f048113e98748c6b902e1962e3225082f42a4760467aaeda139e67c4aa692231")


def _docker_ok():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


if not _docker_ok():
    # A SKIP IS NOT A PASS where the lane exists to run this. CI sets the
    # variable, so a runner that lost Docker fails instead of going green with
    # the authorizer untested.
    if os.environ.get("ANDYUR_REQUIRE_DOCKER") == "1":
        raise RuntimeError("ANDYUR_REQUIRE_DOCKER=1 and no Docker daemon is reachable")
    pytest.skip("needs a reachable Docker daemon", allow_module_level=True)

from cryptography import x509                                       # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization    # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec            # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID      # noqa: E402

# The execution worker's probe: a workflow that runs one heartbeating activity,
# which is the shape of `AndyurExecution` without Andyur behind it.
from datetime import timedelta as _timedelta                        # noqa: E402

from temporalio import activity, workflow                           # noqa: E402


@activity.defn(name="probe_activity")
async def probe_activity(value: str) -> str:
    activity.heartbeat("working")
    return value.upper()


@workflow.defn(name="ProbeExecution", sandboxed=False)
class ProbeExecution:
    @workflow.run
    async def run(self, value: str) -> str:
        return await workflow.execute_activity(
            probe_activity, value, start_to_close_timeout=_timedelta(seconds=30),
            heartbeat_timeout=_timedelta(seconds=10))


# Identity -> the SPIFFE ID its certificate carries.
IDENTITIES = {
    "control-plane": "spiffe://andyur.local/control-plane",
    "admin": "spiffe://andyur.local/workflow-engine-admin",
    "execution-worker": "spiffe://andyur.local/temporal-execution-worker",
    "worker": "spiffe://andyur.local/worker",
    "operator": "spiffe://andyur.local/operator",
    "run-proxy": "spiffe://andyur.local/ns/andyur-runs/sa/run-proxy",
    # A look-alike that shares the allowed ID as a PREFIX: what a prefix
    # matcher, or a check on "starts with", would let in.
    "look-alike": "spiffe://andyur.local/control-plane-evil",
    # The engine's own identity is in the trust domain and is not a client.
    "engine": "spiffe://andyur.local/workflow-engine",
}


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn)])


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pki(directory):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("test-trust-domain"))
          .issuer_name(_name("test-trust-domain")).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True,
                                       True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (directory / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(name, spiffe_id, dns=None):
        key = ec.generate_private_key(ec.SECP256R1())
        sans = [x509.UniformResourceIdentifier(spiffe_id)]
        if dns:
            sans.append(x509.DNSName(dns))
        cert = (x509.CertificateBuilder().subject_name(_name(name))
                .issuer_name(ca.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                      ExtendedKeyUsageOID.CLIENT_AUTH]),
                               critical=False)
                .sign(ca_key, hashes.SHA256()))
        (directory / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / f"{name}.key").write_bytes(_pem_key(key))
        (directory / f"{name}.key").chmod(0o644)   # read by the container's user

    # The engine's certificate carries the Service name, as the ClusterSPIFFEID
    # template makes the real one do.
    leaf("server", "spiffe://andyur.local/workflow-engine", "andyur-temporal")
    for name, spiffe_id in IDENTITIES.items():
        leaf(name, spiffe_id)

    # AN ALLOWED NAME FROM THE WRONG AUTHORITY. The RBAC list is only as good
    # as the chain check beneath it: this certificate claims the control
    # plane's exact SPIFFE ID and is signed by a CA the engine does not trust.
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_ca = (x509.CertificateBuilder().subject_name(_name("rogue"))
                .issuer_name(_name("rogue")).public_key(rogue_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=2))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(rogue_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    forged = (x509.CertificateBuilder().subject_name(_name("forged"))
              .issuer_name(rogue_ca.subject).public_key(key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(now - datetime.timedelta(minutes=5))
              .not_valid_after(now + datetime.timedelta(hours=1))
              .add_extension(x509.SubjectAlternativeName(
                  [x509.UniformResourceIdentifier(IDENTITIES["control-plane"])]), critical=False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                             critical=False)
              .sign(rogue_key, hashes.SHA256()))
    (directory / "forged.crt").write_bytes(forged.public_bytes(serialization.Encoding.PEM))
    (directory / "forged.key").write_bytes(_pem_key(key))
    (directory / "forged.key").chmod(0o644)


def _shipped_config():
    """The authorizer's config from the manifest, with ONLY the certificate
    source moved from SDS to files."""
    docs = [d for d in yaml.safe_load_all(MANIFEST.read_text()) if d]
    cm = next(d for d in docs if d.get("kind") == "ConfigMap"
              and d["metadata"]["name"] == "andyur-temporal-authz")
    cfg = yaml.safe_load(cm["data"]["envoy.yaml"])
    tls = (cfg["static_resources"]["listeners"][0]["filter_chains"][0]
           ["transport_socket"]["typed_config"]["common_tls_context"])
    tls.pop("tls_certificate_sds_secret_configs")
    tls.pop("validation_context_sds_secret_config")
    tls["tls_certificates"] = [{"certificate_chain": {"filename": "/pki/server.crt"},
                                "private_key": {"filename": "/pki/server.key"}}]
    tls["validation_context"] = {"trusted_ca": {"filename": "/pki/ca.crt"}}
    clusters = cfg["static_resources"]["clusters"]
    cfg["static_resources"]["clusters"] = [c for c in clusters if c["name"] != "spire_agent"]
    # The admin interface on loopback rather than a socket file, so the test can
    # read Envoy's own counters from the shared network namespace. Test-only:
    # the shipped admin stays a mode-0600 socket.
    cfg["admin"] = {"address": {"socket_address": {"address": "127.0.0.1",
                                                   "port_value": 9901}}}
    return cfg


def _authz_image():
    docs = [d for d in yaml.safe_load_all(MANIFEST.read_text()) if d]
    dep = next(d for d in docs if d.get("kind") == "Deployment"
               and d["metadata"]["name"] == "andyur-temporal")
    return next(c["image"] for c in dep["spec"]["template"]["spec"]["containers"]
                if c["name"] == "authz")


def _frontend_port(cfg):
    frontend = next(c for c in cfg["static_resources"]["clusters"] if c["name"] == "frontend")
    addr = (frontend["load_assignment"]["endpoints"][0]["lb_endpoints"][0]
            ["endpoint"]["address"]["socket_address"])
    assert addr["address"] == "127.0.0.1", "the authorizer no longer proxies to loopback"
    return addr["port_value"]


def _docker(*args, check=True, timeout=120):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=check, timeout=timeout)


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    work = tmp_path_factory.mktemp("engine-authz")
    pki = work / "pki"
    pki.mkdir()
    _pki(pki)
    cfg = _shipped_config()
    (work / "envoy.yaml").write_text(yaml.safe_dump(cfg))

    tag = uuid.uuid4().hex[:8]
    net, temporal, envoy = f"authz-{tag}", f"authz-temporal-{tag}", f"authz-envoy-{tag}"
    _docker("network", "create", net)
    try:
        # The frontend on loopback at the port the manifest gives it, as the
        # engine's `BIND_ON_IP=127.0.0.1` puts it; the authorizer shares the
        # network namespace, as a sidecar does.
        # 7233 published on loopback so an SDK client on this host can speak
        # to the authorizer as a real worker would (see the execution worker's
        # test below); every other test still calls from inside the network.
        _docker("run", "-d", "--name", temporal, "--network", net,
                "-p", "127.0.0.1::7233",
                "--entrypoint", "temporal", TOOLS, "server", "start-dev",
                "--ip", "127.0.0.1", "--port", str(_frontend_port(cfg)),
                "--headless", "--namespace", "andyur")
        _docker("run", "-d", "--name", envoy, "--network", f"container:{temporal}",
                "-v", f"{pki}:/pki:ro", "-v", f"{work / 'envoy.yaml'}:/c.yaml:ro",
                _authz_image(), "-c", "/c.yaml", "--disable-hot-restart")
        address = _docker("inspect", "-f",
                          "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % net,
                          temporal).stdout.strip()

        def call(identity):
            """List one workflow as `identity`; None means no client cert."""
            tls = ["--tls", "--tls-ca-path", "/pki/ca.crt",
                   "--tls-server-name", "andyur-temporal"]
            if identity:
                tls += ["--tls-cert-path", f"/pki/{identity}.crt",
                        "--tls-key-path", f"/pki/{identity}.key"]
            result = _docker("run", "--rm", "--network", net, "-v", f"{pki}:/pki:ro",
                             "--entrypoint", "temporal", TOOLS, "workflow", "list",
                             "--namespace", "andyur", "--limit", "1",
                             "--address", f"{address}:7233", *tls, check=False)
            return result.returncode == 0, result.stdout + result.stderr

        deadline = time.monotonic() + 90
        while not call("control-plane")[0]:
            if time.monotonic() > deadline:
                logs = _docker("logs", envoy, check=False)
                pytest.fail("the engine never answered the control plane through "
                            f"the authorizer:\n{logs.stdout}{logs.stderr}")
            time.sleep(2)

        def envoy_log():
            # The access log is flushed on an interval (10s by default).
            time.sleep(15)
            logs = _docker("logs", envoy, check=False)
            return logs.stdout + logs.stderr

        def upstreams(stat="upstream_cx_total"):
            """Envoy's own counter for the frontend cluster -- connections by
            default, which a short call cannot slip between samples of."""
            out = _docker("exec", temporal, "curl", "-s",
                          f"http://127.0.0.1:9901/stats?filter=^cluster.frontend.{stat}$",
                          check=False).stdout
            return int(out.split(":")[-1].strip()) if ":" in out else -1

        def idle_connections(count, hold):
            """`count` raw TCP connections to the authorizer that send nothing,
            held open for `hold` seconds, from a container on the network."""
            return subprocess.Popen(
                ["docker", "run", "--rm", "--network", net, "--entrypoint", "sh", TOOLS,
                 "-c", f"for i in $(seq {count}); do sleep {hold} | nc {address} 7233 & "
                       f"done; wait"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        published = _docker("port", temporal, "7233/tcp").stdout.strip().splitlines()[0]
        call.sdk_address = published.replace("0.0.0.0", "127.0.0.1")
        call.pki = pki
        yield call, envoy_log, upstreams, idle_connections
    finally:
        _docker("rm", "-f", temporal, envoy, check=False)
        _docker("network", "rm", net, check=False)


def test_the_control_plane_is_admitted(engine):
    """The positive control. The provider and the workflow worker both hold
    this identity; refusing it would take the durable engine offline."""
    call, *_ = engine
    ok, out = call("control-plane")
    assert ok, f"the control plane was refused by the engine's authorizer:\n{out}"


def test_the_execution_worker_may_not_administer_the_engine(engine):
    """B+ ADVERSARIAL REVIEW: admitted with the whole API, the execution
    worker's identity could start the control plane's own workflows. It is a
    worker; listing workflows is not a worker's call."""
    call, *_ = engine
    ok, out = call("execution-worker")
    assert not ok, "the execution worker listed workflows through the authorizer"
    assert "RBAC: access denied" in out, out
    assert call("control-plane")[0], "the engine stopped answering; this refusal proves nothing"


def test_the_execution_worker_can_work_and_cannot_command(engine):
    """THE POSITIVE HALF, with the real SDK: under the execution worker's
    certificate a worker polls, runs a workflow and an activity that
    heartbeats, and completes both -- every call a worker makes is admitted.
    The same client then may not start or terminate a workflow. And the
    authorizer's own log names the refused methods and ONLY those: a worker
    call the allowlist missed would appear there too."""
    import asyncio
    from datetime import timedelta

    from temporalio.client import Client, TLSConfig
    from temporalio.service import RPCError, RPCStatusCode
    from temporalio.worker import UnsandboxedWorkflowRunner, Worker

    call, envoy_log, *_ = engine
    pki = call.pki

    def tls(identity):
        return TLSConfig(server_root_ca_cert=(pki / "ca.crt").read_bytes(),
                         client_cert=(pki / f"{identity}.crt").read_bytes(),
                         client_private_key=(pki / f"{identity}.key").read_bytes(),
                         domain="andyur-temporal")

    async def go():
        platform = await Client.connect(call.sdk_address, namespace="andyur",
                                        tls=tls("control-plane"))
        worker_client = await Client.connect(call.sdk_address, namespace="andyur",
                                             tls=tls("execution-worker"))
        queue = f"probe-{uuid.uuid4().hex[:8]}"
        async with Worker(worker_client, task_queue=queue, workflows=[ProbeExecution],
                          activities=[probe_activity],
                          workflow_runner=UnsandboxedWorkflowRunner()):
            result = await platform.execute_workflow(
                ProbeExecution.run, "run-id-only", id=f"probe-{queue}",
                task_queue=queue, execution_timeout=timedelta(seconds=60))
        assert result == "RUN-ID-ONLY"
        for attempt in (
                lambda: worker_client.start_workflow(
                    ProbeExecution.run, "x", id=f"forged-{queue}", task_queue=queue),
                lambda: worker_client.get_workflow_handle(f"probe-{queue}").terminate()):
            with pytest.raises(RPCError) as refused:
                await attempt()
            assert refused.value.status == RPCStatusCode.PERMISSION_DENIED, refused.value
    asyncio.run(go())

    denied = {line.split("method=")[1].split()[0].rsplit("/", 1)[-1]
              for line in envoy_log().splitlines()
              if line.startswith("engine-authz-rpc ")
              and "peer=spiffe://andyur.local/temporal-execution-worker " in line}
    assert {"StartWorkflowExecution", "TerminateWorkflowExecution"} <= denied, denied
    assert denied <= {"StartWorkflowExecution", "TerminateWorkflowExecution",
                      "ListWorkflowExecutions"}, (
        f"a call the SDK worker makes was refused: {sorted(denied)}")


def test_the_registration_job_is_admitted(engine):
    call, *_ = engine
    ok, out = call("admin")
    assert ok, f"the namespace-registration identity was refused:\n{out}"


@pytest.mark.parametrize("identity", ["worker", "operator", "run-proxy", "engine"])
def test_every_other_identity_in_the_trust_domain_is_refused(engine, identity):
    """THE ATTACK THAT LANDED before the authorizer existed: any certificate
    that chained to the trust bundle was full engine administration.

    The control plane is asked again straight after, so a refusal here cannot
    be an engine or proxy that simply died."""
    call, *_ = engine
    ok, out = call(identity)
    assert not ok, (f"{IDENTITIES[identity]} administered the engine; only the "
                    "control plane and the registration Job may")
    assert call("control-plane")[0], "the engine stopped answering; this refusal proves nothing"


def test_the_control_planes_name_from_another_authority_is_refused(engine):
    """The allowlist names identities; the chain check is what makes a name
    mean anything. A certificate claiming the control plane's exact SPIFFE ID,
    signed by a CA the engine does not trust, must not get in."""
    call, *_ = engine
    ok, _ = call("forged")
    assert not ok, "a certificate from an untrusted CA was admitted on its name alone"
    assert call("control-plane")[0], "the engine stopped answering; this refusal proves nothing"


def test_an_identity_that_merely_starts_with_an_allowed_one_is_refused(engine):
    call, *_ = engine
    ok, _ = call("look-alike")
    assert not ok, ("spiffe://andyur.local/control-plane-evil was admitted: the "
                    "allowlist is matching a prefix, not the identity")


def test_no_client_certificate_is_refused(engine):
    call, *_ = engine
    ok, _ = call(None)
    assert not ok, "a client with no certificate at all reached the engine"
    assert call("control-plane")[0], "the engine stopped answering; this refusal proves nothing"


def test_connections_that_send_nothing_hold_no_connection_to_temporal(engine):
    """The proxy connected upstream at ACCEPT, before the handshake and before
    any authorization: 200 idle connections held 200 Temporal connections.
    It now connects only once a client has sent data past the RBAC filter."""
    call, _log, upstreams, idle_connections = engine
    before, requests = upstreams(), upstreams("upstream_rq_total")
    assert before >= 0, "Envoy's upstream counter could not be read"
    idle_connections(30, 3).wait(timeout=60)
    after = upstreams()
    assert upstreams("upstream_rq_total") == requests, (
        "connections that sent nothing produced requests to Temporal")

    assert after == before, (
        f"{after - before} connections to Temporal were opened for 30 TCP "
        "connections that never began a handshake")
    assert call("control-plane")[0], "the control plane was not served after the flood"


def test_positive_control_an_admitted_client_does_reach_temporal(engine):
    """The count above must be able to rise, or it proves nothing. Requests,
    not connections: behind the HTTP/2 connection manager an admitted call
    may reuse a pooled upstream connection, so it is the request counter that
    must move -- and the idle test checks it did not."""
    call, _log, upstreams, _idle = engine
    before = upstreams("upstream_rq_total")
    assert call("control-plane")[0]
    assert upstreams("upstream_rq_total") > before, (
        "an admitted call sent no request to Temporal, so the counters the "
        "test above relies on are not measuring anything")


def test_a_refusal_is_logged_with_who_was_refused(engine):
    """A refusal nobody can see is an outage nobody can diagnose -- and an
    attack nobody notices."""
    call, envoy_log, *_ = engine
    call("worker")
    log = envoy_log()
    refused = [line for line in log.splitlines()
               if "peer=spiffe://andyur.local/worker" in line]
    assert refused, f"no access-log line names the refused peer:\n{log[-2000:]}"
    assert any("rbac_access_denied" in line for line in refused), (
        f"the refused peer's log line does not say it was refused:\n{refused}")


def test_a_missing_certificate_is_logged_and_a_bare_probe_is_not(engine):
    """A client with no certificate is refused in the handshake and logged with
    that reason. A TCP connect that never starts a handshake -- the kubelet's
    probe -- is not logged: every five seconds it looked like a refusal."""
    call, envoy_log, _up, idle_connections = engine
    call(None)
    idle_connections(5, 1).wait(timeout=30)
    log = envoy_log()
    lines = [l for l in log.splitlines() if l.startswith("engine-authz ")]

    assert any("PEER_DID_NOT_RETURN_A_CERTIFICATE" in l for l in lines), (
        "the missing-certificate refusal was not logged with its reason")
    bare = [l for l in lines if "peer=- " in l and "tls_failure=- " in l
            and "bytes_in=0 " in l]
    assert not bare, f"bare TCP connects were logged as if refused:\n{bare[:3]}"
