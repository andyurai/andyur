#!/usr/bin/env python3
"""Disposable real-Envoy Phase-2c transport behavior gate."""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests
import yaml

if not __debug__:
    raise RuntimeError("the security gate refuses optimized Python")
FORBIDDEN_ENV = {
    "PYTHONPATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
}
present_forbidden = sorted(name for name in FORBIDDEN_ENV if os.environ.get(name))
if present_forbidden:
    raise RuntimeError(f"unsealed transport/import environment: {present_forbidden}")

IMAGE = "docker.io/envoyproxy/envoy@sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66"
AUTH_CANARY = "DPoP runtime-token-canary-7e890"
PROOF_CANARY = "runtime-proof-canary-4c012"
HOST = "resource.example:443"
PENDING_TARGET_BODY = b'{"jsonrpc":"2.0","method":"tools/call","id":"pending-target"}'
RUN_ID = os.environ.get("ANDYUR_ENVOY_RUNTIME_RUN_ID", str(os.getpid()))
if re.fullmatch(r"[a-zA-Z0-9-]+", RUN_ID) is None:
    raise ValueError("invalid ANDYUR_ENVOY_RUNTIME_RUN_ID")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.broker_mode = "allow"
        self.resource_mode = "ok"
        self.broker_requests: list[dict[str, Any]] = []
        self.as_requests: list[dict[str, Any]] = []
        self.as_port = 0
        self.count_as_attempts = False
        self.resource_requests: list[dict[str, Any]] = []
        self.resource_active = 0
        self.resource_max_active = 0
        self.pending_peak = 0
        self.cancellation_events = 0
        self.timeout_events = 0
        self.teardown_events = 0
        self.fixture_errors: list[str] = []
        self.resource_started = threading.Event()
        self.release_resource = threading.Event()

    def reset(self) -> None:
        with self.lock:
            self.broker_mode = "allow"
            self.resource_mode = "ok"
            self.count_as_attempts = False
            self.broker_requests.clear()
            self.as_requests.clear()
            self.resource_requests.clear()
            self.resource_active = 0
            self.resource_max_active = 0
            self.pending_peak = 0
            self.cancellation_events = 0
            self.timeout_events = 0
            self.teardown_events = 0
            self.fixture_errors.clear()
        self.resource_started.clear()
        self.release_resource.clear()


STATE = State()


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        pass


class FixtureServer(ThreadingHTTPServer):
    request_queue_size = 64


class BrokerHandler(QuietHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with STATE.lock:
            mode = STATE.broker_mode
            as_port = STATE.as_port
            count_as_attempts = STATE.count_as_attempts
            STATE.broker_requests.append({
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_length": len(body),
            })
        if count_as_attempts:
            connection = http.client.HTTPConnection("127.0.0.1", as_port, timeout=1)
            try:
                connection.request("POST", "/token", body=body, headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                response.read()
                if response.status != 200:
                    raise RuntimeError(f"counted AS returned {response.status}")
            finally:
                connection.close()
        if mode == "delay":
            time.sleep(1.1)
        if mode == "deny":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Authorization", AUTH_CANARY)
        self.send_header("DPoP", PROOF_CANARY)
        self.send_header("X-Andyur-Decision-ID", "decision-runtime-1")
        self.send_header("Content-Length", "0")
        self.end_headers()


class ASHandler(QuietHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with STATE.lock:
            STATE.as_requests.append({
                "path": self.path,
                "body_sha256": hashlib.sha256(body).hexdigest(),
            })
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


class ResourceHandler(QuietHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with STATE.lock:
            mode = STATE.resource_mode
            STATE.resource_active += 1
            STATE.resource_max_active = max(STATE.resource_max_active, STATE.resource_active)
            STATE.resource_requests.append({
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body": body.decode("utf-8", "replace"),
            })
            if STATE.resource_active >= 8:
                STATE.resource_started.set()
        try:
            if mode == "stall":
                if not STATE.release_resource.wait(timeout=8):
                    with STATE.lock:
                        STATE.fixture_errors.append("resource hold expired without explicit release")
                    self.close_connection = True
                    return
            if mode == "reset":
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
            status = 500 if mode == "500" else 200
            payload = b"resource-ok" if status == 200 else b"resource-error"
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with STATE.lock:
                STATE.resource_active -= 1


class Fixture:
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.server = FixtureServer(("0.0.0.0", 0), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_port)

    def __enter__(self) -> "Fixture":
        self.thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("fixture thread survived teardown")


def run(command: list[str], *, timeout: float = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=check)


def runtime_config(base: dict[str, Any], broker_port: int, resource_port: int,
                   evidence_dir: str, mutation: str = "none") -> dict[str, Any]:
    doc = copy.deepcopy(base)
    hcm = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
    doc["static_resources"]["listeners"][0]["address"]["socket_address"]["address"] = "0.0.0.0"
    hcm["route_config"]["virtual_hosts"][0]["domains"] = ["*"]
    hcm["access_log"] = [{
        "name": "envoy.access_loggers.file",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
            "path": f"{evidence_dir}/access.log",
            "log_format": {"text_format_source": {"inline_string": "%RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%\n"}},
        },
    }]
    clusters = {c["name"]: c for c in doc["static_resources"]["clusters"]}
    for name, port in (("broker", broker_port), ("resource", resource_port)):
        clusters[name]["type"] = "STRICT_DNS"
        clusters[name]["dns_lookup_family"] = "V4_ONLY"
        clusters[name]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"] = {
            "socket_address": {"address": "host.docker.internal", "port_value": port}
        }
    clusters["resource"].pop("transport_socket", None)
    doc["static_resources"]["clusters"] = [clusters["broker"], clusters["resource"]]
    # The behavior gate does not need an admin endpoint. The checked schema
    # separately validates the sidecar-filesystem UDS shape.
    doc.pop("admin", None)

    filters = hcm["http_filters"]
    ext = next(f for f in filters if f["name"] == "envoy.filters.http.ext_authz")["typed_config"]
    route = hcm["route_config"]["virtual_hosts"][0]["routes"][0]["route"]
    breaker = clusters["resource"]["circuit_breakers"]["thresholds"][0]
    if mutation == "remove_lua":
        hcm["http_filters"] = [f for f in filters if f["name"] != "envoy.filters.http.lua"]
    elif mutation == "failure_allow":
        ext["failure_mode_allow"] = True
    elif mutation == "retry_5xx":
        breaker["max_retries"] = 1
        route["retry_policy"] = {"retry_on": "5xx", "num_retries": 1}
    elif mutation == "pending_sixteen":
        breaker["max_pending_requests"] = 16
    elif mutation == "pending_seven":
        breaker["max_pending_requests"] = 7
    elif mutation == "zero_pending":
        breaker["max_pending_requests"] = 0
    elif mutation == "long_route_deadline":
        route["timeout"] = "4s"
    elif mutation == "partial_body":
        ext["with_request_body"]["allow_partial_message"] = True
    elif mutation == "leak_access_log":
        hcm["access_log"][0]["typed_config"]["log_format"]["text_format_source"]["inline_string"] = "%REQ(AUTHORIZATION)% %REQ(DPOP)%\n"
    elif mutation != "none":
        raise ValueError(mutation)
    selected_route = next(
        item["route"] for item in hcm["route_config"]["virtual_hosts"][0]["routes"]
        if item["match"].get("path") == "/mcp"
    )
    expected_timeout = "4s" if mutation == "long_route_deadline" else "2s"
    assert selected_route["timeout"] == expected_timeout
    return doc


class Envoy:
    def __init__(self, config: dict[str, Any], work: Path, suffix: str) -> None:
        self.port = free_port()
        self.name = f"andyur-envoy-runtime-{RUN_ID}-{suffix}"
        self.work = work
        self.config = work / f"{suffix}.yaml"
        self.stopped = False
        self.config.write_text(yaml.safe_dump(config, sort_keys=False))

    def start(self) -> None:
        result = run([
            "docker", "run", "-d", "--name", self.name, "--platform", "linux/arm64",
            "-p", f"127.0.0.1:{self.port}:10000",
            "-v", f"{self.config}:/config.yaml:ro",
            "-v", f"{self.work}:/evidence",
            IMAGE, "envoy", "-c", "/config.yaml", "--log-level", "warning",
            "--concurrency", "1",
        ])
        if not result.stdout.strip():
            raise RuntimeError("Envoy did not return a container id")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            running = run(["docker", "inspect", "-f", "{{.State.Running}}", self.name], check=False)
            if running.stdout.strip() != "true":
                raise RuntimeError(f"Envoy exited during startup: {self.logs()}")
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", self.port)) == 0:
                    # Docker publishes the host port before Envoy's workers
                    # necessarily enter their dispatch loops.
                    time.sleep(0.25)
                    return
            time.sleep(0.05)
        raise RuntimeError(f"Envoy did not listen: {self.logs()}")

    def logs(self) -> str:
        return run(["docker", "logs", self.name], check=False).stdout + run(
            ["docker", "logs", self.name], check=False).stderr

    def stop(self, *, hard: bool = False) -> str:
        if self.stopped:
            return ""
        if hard:
            run(["docker", "kill", self.name], check=False)
        else:
            run(["docker", "stop", "--time", "1", self.name], timeout=5, check=False)
        logs = self.logs()
        removed = run(["docker", "rm", "-f", self.name], timeout=5, check=False)
        if removed.returncode != 0:
            raise RuntimeError(f"failed to remove Envoy container: {removed.stderr}")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            absent = run(["docker", "inspect", self.name], check=False).returncode != 0
            with socket.socket() as sock:
                closed = sock.connect_ex(("127.0.0.1", self.port)) != 0
            if absent and closed:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("Envoy container or published listener survived teardown")
        if hard:
            with STATE.lock:
                STATE.teardown_events += 1
        self.stopped = True
        return logs


def post(port: int, body: bytes = b'{"jsonrpc":"2.0","method":"tools/call"}',
         headers: dict[str, str] | None = None, timeout: float = 4,
         path: str = "/mcp") -> requests.Response:
    merged = {"Host": HOST, "Content-Type": "application/json"}
    if headers:
        merged.update(headers)
    with requests.Session() as session:
        session.trust_env = False
        session.mount("http://", requests.adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1, max_retries=0, pool_block=False
        ))
        return session.post(f"http://127.0.0.1:{port}{path}", data=body, headers=merged,
                            timeout=timeout, allow_redirects=False)


def add_control_route(config: dict[str, Any]) -> None:
    """Add a gate-only long deadline without changing the selected /mcp route."""
    hcm = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
    routes = hcm["route_config"]["virtual_hosts"][0]["routes"]
    routes.insert(0, {
        "match": {"path": "/hold"},
        "route": {"cluster": "resource", "timeout": "10s"},
    })


def wait_for_counts(*, broker: int | None = None, resource: int | None = None,
                    active: int | None = None, timeout: float = 3) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with STATE.lock:
            observed = (len(STATE.broker_requests), len(STATE.resource_requests),
                        STATE.resource_active)
        expected = (broker, resource, active)
        if all(want is None or want == got for want, got in zip(expected, observed)):
            if broker is not None and resource is not None:
                with STATE.lock:
                    STATE.pending_peak = max(STATE.pending_peak, broker - resource)
            return
        time.sleep(0.01)
    raise AssertionError(f"counts did not reach {(broker, resource, active)}; got {observed}")


def lifecycle_config(base: dict[str, Any], broker: Fixture, resource: Fixture,
                     mutation: str = "none") -> dict[str, Any]:
    config = runtime_config(base, broker.port, resource.port, "/evidence", mutation)
    add_control_route(config)
    return config


def start_active_slots(envoy: Envoy, pool: concurrent.futures.ThreadPoolExecutor
                       ) -> list[concurrent.futures.Future[requests.Response]]:
    STATE.resource_mode = "stall"
    active = [pool.submit(
        post, envoy.port,
        f'{{"jsonrpc":"2.0","method":"tools/call","id":"active-{index}"}}'.encode(),
        path="/hold", timeout=12,
    ) for index in range(8)]
    wait_for_counts(broker=8, resource=8, active=8)
    return active


def release_active_slots(active: list[concurrent.futures.Future[requests.Response]]) -> None:
    STATE.release_resource.set()
    assert all(future.result(timeout=3).status_code == 200 for future in active)
    wait_for_counts(active=0)


def lifecycle_counts(*, target_status: int | str) -> dict[str, Any]:
    target_hash = hashlib.sha256(PENDING_TARGET_BODY).hexdigest()
    with STATE.lock:
        counts = {
            "active_slots": STATE.resource_max_active,
            "pending_slots_peak": STATE.pending_peak,
            "broker_attempts": len(STATE.broker_requests),
            "as_attempts": len(STATE.as_requests),
            "resource_attempts": len(STATE.resource_requests),
            "target_broker_attempts": sum(
                request["body_sha256"] == target_hash for request in STATE.broker_requests
            ),
            "target_as_attempts": sum(
                request["body_sha256"] == target_hash for request in STATE.as_requests
            ),
            "target_resource_attempts": sum(
                request["body_sha256"] == target_hash for request in STATE.resource_requests
            ),
            "cancellations": STATE.cancellation_events,
            "timeouts": STATE.timeout_events,
            "teardowns": STATE.teardown_events,
            "target_status": target_status,
        }
        assert not STATE.fixture_errors, STATE.fixture_errors
    return counts


def count() -> tuple[int, int]:
    with STATE.lock:
        return len(STATE.broker_requests), len(STATE.resource_requests)


def run_case(base: dict[str, Any], broker: Fixture, resource: Fixture, work: Path,
             mutation: str, suffix: str, action: Any) -> Any:
    STATE.reset()
    (work / "access.log").unlink(missing_ok=True)
    config = runtime_config(base, broker.port, resource.port, "/evidence", mutation)
    envoy = Envoy(config, work, suffix)
    envoy.start()
    try:
        return action(envoy)
    except Exception:
        print(envoy.logs())
        access_log = work / "access.log"
        if access_log.exists():
            print(access_log.read_text())
        raise
    finally:
        envoy.stop()


def gate(base_path: Path, output: Path) -> dict[str, Any]:
    base = yaml.safe_load(base_path.read_text())
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="andyur-envoy-runtime-") as tmp, \
            Fixture(ASHandler) as counted_as, Fixture(BrokerHandler) as broker, \
            Fixture(ResourceHandler) as resource:
        work = Path(tmp)
        STATE.as_port = counted_as.port

        def positive(envoy: Envoy) -> None:
            body = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"query_metrics"}}'
            response = post(envoy.port, body, {
                "Authorization": "Bearer hostile-agent-token",
                "DPoP": "hostile-agent-proof",
                "Cookie": "hostile-cookie",
                "X-Hostile": "must-disappear",
                "X-Forwarded-For": "203.0.113.9",
                "X-Forwarded-Proto": "gopher",
                "X-Forwarded-Port": "9",
                "X-Request-ID": "agent-controlled-id",
            })
            assert response.status_code == 200, (response.status_code, response.text, count())
            assert count() == (1, 1)
            broker_request = STATE.broker_requests[0]
            request = STATE.resource_requests[0]
            expected_hash = hashlib.sha256(body).hexdigest()
            assert broker_request["body_sha256"] == expected_hash
            assert broker_request["body_length"] == len(body)
            assert request["body_sha256"] == expected_hash
            assert request["headers"]["authorization"] == AUTH_CANARY
            assert request["headers"]["dpop"] == PROOF_CANARY
            assert "cookie" not in request["headers"] and "x-hostile" not in request["headers"]
            hostile_fragments = ("203.0.113.9", "gopher", "agent-controlled-id")
            assert all(name not in STATE.broker_requests[0]["headers"] for name in (
                "x-forwarded-for", "x-forwarded-proto", "x-forwarded-port", "x-request-id"
            ))
            serialized_headers = json.dumps(request["headers"], sort_keys=True)
            assert not any(fragment in serialized_headers for fragment in hostile_fragments)
            assert request["headers"]["x-forwarded-proto"] == "http"
            assert "x-forwarded-port" not in request["headers"]
            results["normalized_http1_json_header_body_hash_continuity"] = True

        run_case(base, broker, resource, work, "none", "positive", positive)

        def zero_pending_cold_start(envoy: Envoy) -> None:
            response = post(envoy.port)
            assert response.status_code == 503
            assert count() == (1, 0)
            results["zero_pending_cold_start_refusal"] = True

        run_case(base, broker, resource, work, "zero_pending", "zero-pending", zero_pending_cold_start)

        def oversize(envoy: Envoy) -> None:
            response = post(envoy.port, b"x" * 65537)
            assert response.status_code in {400, 413}
            assert count() == (0, 0)
            results["oversize_denied_before_authz"] = response.status_code

        run_case(base, broker, resource, work, "none", "oversize", oversize)

        def late_allow(envoy: Envoy) -> None:
            STATE.broker_mode = "delay"
            response = post(envoy.port)
            assert response.status_code in {403, 500}
            time.sleep(1.2)
            assert len(STATE.resource_requests) == 0
            results["late_authz_allow_discarded"] = response.status_code

        run_case(base, broker, resource, work, "none", "late", late_allow)

        def no_retry(envoy: Envoy) -> None:
            STATE.resource_mode = "500"
            response = post(envoy.port)
            assert response.status_code == 500
            assert count() == (1, 1)
            results["five_xx_one_attempt"] = True

        run_case(base, broker, resource, work, "none", "noretry", no_retry)

        def capacity(envoy: Envoy, result_key: str) -> None:
            STATE.resource_mode = "stall"
            with concurrent.futures.ThreadPoolExecutor(max_workers=17) as pool:
                first = [pool.submit(post, envoy.port) for _ in range(8)]
                assert STATE.resource_started.wait(timeout=3)
                pending = [pool.submit(post, envoy.port) for _ in range(8)]
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with STATE.lock:
                        broker_count = len(STATE.broker_requests)
                    if broker_count == 16:
                        break
                    time.sleep(0.01)
                assert broker_count == 16
                seventeenth = post(envoy.port)
                assert seventeenth.status_code == 503, (
                    seventeenth.status_code, seventeenth.text, count()
                )
                time.sleep(0.1)
                assert len(STATE.resource_requests) == 8
                STATE.release_resource.set()
                assert all(f.result(timeout=3).status_code == 200 for f in first)
                assert all(f.result(timeout=3).status_code == 200 for f in pending)
            assert STATE.resource_max_active == 8
            assert count() == (17, 16)
            results[result_key] = {
                "broker_attempts": 17,
                "resource_requests": 16,
                "resource_max_active": 8,
                "pending_completed": 8,
                "overflow_status": 503,
            }

        run_case(base, broker, resource, work, "none", "capacity",
                 lambda envoy: capacity(envoy, "capacity_initial"))

        def pending_seven(envoy: Envoy) -> None:
            STATE.resource_mode = "stall"
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                active = [pool.submit(post, envoy.port) for _ in range(7)]
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with STATE.lock:
                        resource_count = len(STATE.resource_requests)
                    if resource_count == 7:
                        break
                    time.sleep(0.01)
                assert resource_count == 7
                active.append(pool.submit(post, envoy.port))
                assert STATE.resource_started.wait(timeout=3)
                with STATE.lock:
                    assert len(STATE.resource_requests) == 8
                    assert STATE.resource_active == 8
                candidates = [pool.submit(post, envoy.port) for _ in range(8)]
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with STATE.lock:
                        broker_count = len(STATE.broker_requests)
                    if broker_count == 16:
                        break
                    time.sleep(0.01)
                assert broker_count == 16
                STATE.release_resource.set()
                assert all(f.result(timeout=3).status_code == 200 for f in active)
                statuses = sorted(f.result(timeout=3).status_code for f in candidates)
                assert statuses == [200] * 7 + [503]
            assert count() == (16, 15)
            assert STATE.resource_max_active == 8
            results["mutation_pending_seven_red"] = {
                "phase": "saturated_pending",
                "broker_attempts": 16,
                "resource_requests": 15,
                "resource_max_active": 8,
                "pending_completed": 7,
                "overflow_status": 503,
            }

        run_case(base, broker, resource, work, "pending_seven", "mut-pending", pending_seven)
        run_case(base, broker, resource, work, "none", "capacity-restored",
                 lambda envoy: capacity(envoy, "capacity_restored"))

        def cancel_before_allow(envoy: Envoy) -> None:
            STATE.broker_mode = "delay"
            try:
                post(envoy.port, timeout=0.1)
            except requests.Timeout:
                pass
            else:
                raise AssertionError("downstream cancellation did not occur")
            time.sleep(1.3)
            assert len(STATE.resource_requests) == 0
            results["cancel_before_allow_zero_resource"] = True

        run_case(base, broker, resource, work, "none", "cancel", cancel_before_allow)

        def run_pending_case(mutation: str, suffix: str, action: Any) -> Any:
            STATE.reset()
            STATE.count_as_attempts = True
            (work / "access.log").unlink(missing_ok=True)
            config = lifecycle_config(base, broker, resource, mutation)
            envoy = Envoy(config, work, suffix)
            envoy.start()
            try:
                return action(envoy)
            except Exception:
                print(envoy.logs())
                raise
            finally:
                STATE.release_resource.set()
                envoy.stop()

        def pending_timeout(envoy: Envoy, result_key: str) -> None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
                active = start_active_slots(envoy, pool)
                started = time.monotonic()
                target = pool.submit(post, envoy.port, PENDING_TARGET_BODY, timeout=4)
                wait_for_counts(broker=9, resource=8, active=8)
                response = target.result(timeout=3)
                elapsed = time.monotonic() - started
                assert response.status_code == 504, response.status_code
                assert 1.5 <= elapsed < 3.0, elapsed
                assert count() == (9, 8)
                with STATE.lock:
                    STATE.timeout_events += 1
                release_active_slots(active)
            counts = lifecycle_counts(target_status=response.status_code)
            assert counts == {
                "active_slots": 8, "pending_slots_peak": 1, "broker_attempts": 9,
                "as_attempts": 9,
                "resource_attempts": 8, "target_broker_attempts": 1,
                "target_as_attempts": 1, "target_resource_attempts": 0,
                "cancellations": 0, "timeouts": 1,
                "teardowns": 0, "target_status": 504,
            }
            counts["selected_route_deadline_seconds"] = 2
            counts["observed_elapsed_seconds"] = round(elapsed, 3)
            results[result_key] = counts

        run_pending_case("none", "pending-timeout",
                         lambda envoy: pending_timeout(envoy, "pending_timeout_initial"))

        def long_deadline_red(envoy: Envoy) -> None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
                active = start_active_slots(envoy, pool)
                target = pool.submit(post, envoy.port, PENDING_TARGET_BODY, timeout=6)
                wait_for_counts(broker=9, resource=8, active=8)
                time.sleep(2.4)
                assert not target.done(), "long-deadline mutation did not keep request pending"
                release_active_slots(active)
                assert target.result(timeout=3).status_code == 200
            assert count() == (9, 9)
            results["mutation_long_route_deadline_red"] = {
                "mutation_applied_seconds": 4,
                "selected_deadline_observation_seconds": 2.4,
                "broker_attempts": 9,
                "as_attempts": 9,
                "resource_attempts": 9,
                "target_broker_attempts": 1,
                "target_as_attempts": 1,
                "target_resource_attempts": 1,
            }

        run_pending_case("long_route_deadline", "mut-pending-timeout", long_deadline_red)
        run_pending_case("none", "pending-timeout-restored",
                         lambda envoy: pending_timeout(envoy, "pending_timeout_restored"))

        def pending_cancel(envoy: Envoy, result_key: str) -> None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                active = start_active_slots(envoy, pool)
                try:
                    post(envoy.port, PENDING_TARGET_BODY, timeout=0.15)
                except requests.Timeout:
                    with STATE.lock:
                        STATE.cancellation_events += 1
                else:
                    raise AssertionError("pending downstream cancellation did not occur")
                wait_for_counts(broker=9, resource=8, active=8)
                # Give Envoy's one worker a bounded dispatch turn to observe
                # the closed downstream socket before an upstream slot opens.
                time.sleep(0.5)
                assert count() == (9, 8), count()
                release_active_slots(active)
                # Keep Envoy alive beyond the selected route deadline. Teardown
                # cannot be what prevents a late dispatch.
                time.sleep(2.3)
            assert count() == (9, 8), count()
            counts = lifecycle_counts(target_status="downstream_closed")
            assert counts == {
                "active_slots": 8, "pending_slots_peak": 1, "broker_attempts": 9,
                "as_attempts": 9,
                "resource_attempts": 8, "target_broker_attempts": 1,
                "target_as_attempts": 1, "target_resource_attempts": 0,
                "cancellations": 1, "timeouts": 0,
                "teardowns": 0, "target_status": "downstream_closed",
            }
            results[result_key] = counts

        run_pending_case("none", "pending-cancel",
                         lambda envoy: pending_cancel(envoy, "pending_cancel_initial"))

        def cancellation_removed_red(envoy: Envoy) -> None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
                active = start_active_slots(envoy, pool)
                target = pool.submit(post, envoy.port, PENDING_TARGET_BODY, timeout=4)
                wait_for_counts(broker=9, resource=8, active=8)
                release_active_slots(active)
                assert target.result(timeout=3).status_code == 200
            assert count() == (9, 9)
            target_hash = hashlib.sha256(PENDING_TARGET_BODY).hexdigest()
            try:
                assert not any(
                    request["body_sha256"] == target_hash
                    for request in STATE.resource_requests
                ), "cancelled target executed"
            except AssertionError:
                regression_red = True
            else:
                raise AssertionError("removing downstream close did not turn regression red")
            results["mutation_remove_downstream_cancel_red"] = {
                "mutation_applied": "keep_downstream_open",
                "regression_assertion_red": regression_red,
                "broker_attempts": 9,
                "as_attempts": 9,
                "resource_attempts": 9,
                "target_broker_attempts": 1,
                "target_as_attempts": 1,
                "target_resource_attempts": 1,
            }

        run_pending_case("none", "mut-pending-cancel", cancellation_removed_red)
        run_pending_case("none", "pending-cancel-restored",
                         lambda envoy: pending_cancel(envoy, "pending_cancel_restored"))

        def pending_halt(result_key: str, suffix: str) -> None:
            STATE.reset()
            STATE.count_as_attempts = True
            config = lifecycle_config(base, broker, resource)
            envoy = Envoy(config, work, suffix)
            envoy.start()
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=9)
            try:
                active = start_active_slots(envoy, pool)
                target = pool.submit(post, envoy.port, PENDING_TARGET_BODY, timeout=4)
                wait_for_counts(broker=9, resource=8, active=8)
                logs = envoy.stop(hard=True)
                deadline = time.monotonic() + 2
                while not target.done() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not target.done():
                    raise AssertionError("halt did not terminate pending downstream within two seconds")
                try:
                    target.result()
                except requests.ConnectionError:
                    pass
                except requests.Timeout as exc:
                    raise AssertionError("client timeout is not halt termination evidence") from exc
                else:
                    raise AssertionError("pending request survived hard security halt")
                STATE.release_resource.set()
                for future in active:
                    try:
                        future.result(timeout=2)
                    except Exception:
                        pass
                time.sleep(0.3)
                assert count() == (9, 8)
                assert AUTH_CANARY not in logs and PROOF_CANARY not in logs
                counts = lifecycle_counts(target_status="envoy_terminated")
                assert counts == {
                    "active_slots": 8, "pending_slots_peak": 1, "broker_attempts": 9,
                    "as_attempts": 9,
                    "resource_attempts": 8, "target_broker_attempts": 1,
                    "target_as_attempts": 1, "target_resource_attempts": 0,
                    "cancellations": 0, "timeouts": 0,
                    "teardowns": 1, "target_status": "envoy_terminated",
                }
                results[result_key] = counts
            finally:
                STATE.release_resource.set()
                envoy.stop(hard=True)
                pool.shutdown(wait=True, cancel_futures=True)

        pending_halt("pending_halt_initial", "pending-halt")

        def halt_removed_red(envoy: Envoy) -> None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
                active = start_active_slots(envoy, pool)
                target = pool.submit(post, envoy.port, PENDING_TARGET_BODY, timeout=4)
                wait_for_counts(broker=9, resource=8, active=8)
                release_active_slots(active)
                assert target.result(timeout=3).status_code == 200
            assert count() == (9, 9)
            target_hash = hashlib.sha256(PENDING_TARGET_BODY).hexdigest()
            try:
                assert not any(
                    request["body_sha256"] == target_hash
                    for request in STATE.resource_requests
                ), "halted target executed"
            except AssertionError:
                regression_red = True
            else:
                raise AssertionError("removing hard halt did not turn regression red")
            results["mutation_remove_hard_halt_red"] = {
                "mutation_applied": "leave_envoy_running",
                "regression_assertion_red": regression_red,
                "broker_attempts": 9,
                "as_attempts": 9,
                "resource_attempts": 9,
                "target_broker_attempts": 1,
                "target_as_attempts": 1,
                "target_resource_attempts": 1,
                "teardowns": 0,
            }

        run_pending_case("none", "mut-pending-halt", halt_removed_red)
        pending_halt("pending_halt_restored", "pending-halt-restored")

        # Exact enforcement mutations.
        def lua_removed(envoy: Envoy) -> None:
            response = post(envoy.port, headers={
                "X-Hostile": "leaks-now", "X-Forwarded-For": "203.0.113.9",
                "X-Forwarded-Port": "9",
            })
            assert response.status_code == 200
            assert STATE.resource_requests[0]["headers"]["x-hostile"] == "leaks-now"
            assert "203.0.113.9" in STATE.resource_requests[0]["headers"]["x-forwarded-for"]
            assert STATE.resource_requests[0]["headers"]["x-forwarded-port"] == "9"
            results["mutation_remove_lua_red"] = True

        run_case(base, broker, resource, work, "remove_lua", "mut-lua", lua_removed)

        def retry_enabled(envoy: Envoy) -> None:
            STATE.resource_mode = "500"
            response = post(envoy.port)
            assert response.status_code == 500
            assert len(STATE.resource_requests) == 2
            results["mutation_retry_red"] = True

        run_case(base, broker, resource, work, "retry_5xx", "mut-retry", retry_enabled)

        def partial_enabled(envoy: Envoy) -> None:
            response = post(envoy.port, b"x" * 65537)
            assert response.status_code == 200
            assert len(STATE.broker_requests) == 1 and len(STATE.resource_requests) == 1
            results["mutation_partial_body_red"] = True

        run_case(base, broker, resource, work, "partial_body", "mut-partial", partial_enabled)

        def leaked_log(envoy: Envoy) -> None:
            response = post(envoy.port)
            assert response.status_code == 200
            time.sleep(0.1)
            access = (work / "access.log").read_text()
            assert AUTH_CANARY in access and PROOF_CANARY in access
            results["mutation_access_log_red"] = True

        run_case(base, broker, resource, work, "leak_access_log", "mut-log", leaked_log)

        # Security halt: terminate Envoy while ext_authz is paused; no resource send.
        STATE.reset()
        STATE.broker_mode = "delay"
        config = runtime_config(base, broker.port, resource.port, "/evidence")
        envoy = Envoy(config, work, "halt")
        envoy.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(post, envoy.port)
            deadline = time.monotonic() + 2
            while len(STATE.broker_requests) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(STATE.broker_requests) == 1
            logs = envoy.stop(hard=True)
            try:
                future.result(timeout=2)
            except Exception:  # expected connection termination
                pass
            else:
                raise AssertionError("halted request unexpectedly completed")
        time.sleep(1.2)
        assert len(STATE.resource_requests) == 0
        assert AUTH_CANARY not in logs and PROOF_CANARY not in logs
        results["hard_halt_paused_authz_zero_resource"] = True

        # Restored final positive and secret scan.
        def restored(envoy: Envoy) -> None:
            response = post(envoy.port)
            assert response.status_code == 200
            time.sleep(0.1)
            access = (work / "access.log").read_text()
            logs = envoy.logs()
            assert AUTH_CANARY not in access and PROOF_CANARY not in access
            assert AUTH_CANARY not in logs and PROOF_CANARY not in logs
            results["restored_positive_and_canary_absent"] = True

        run_case(base, broker, resource, work, "none", "restored", restored)

    result = {
        "status": "pass",
        "scope": "disposable-real-envoy-runtime-subset",
        "image_index": IMAGE.rsplit("@", 1)[1],
        "executed_platform": "linux/arm64",
        "envoy_concurrency": 1,
        "http_peer": "127.0.0.1:<ephemeral-published-port>",
        "sealed_environment": sorted(FORBIDDEN_ENV),
        "results": results,
        "remaining": [
            "upstream_tls_and_spire_sds_live_negotiation",
            "http1_and_http2_raw_ambiguity_matrix",
            "full_body_framing_and_exact_byte_matrix",
            "reset_attempt_and_failure_mode_allow_mutations",
            "supervisor_process_contract",
            "full_enumerated_secret_sinks",
            "pod_shared_network_saturation",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, output)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(gate(args.config, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
