#!/usr/bin/env python3
"""Reproducible OAuth-client concurrency smoke gate.

This deliberately tests transport/lifecycle behavior against a local TLS token
endpoint. Keycloak and the reference AS are separate semantic gates composed by
verify.sh; this program must never imply that its fixture is an AS.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import importlib.metadata
from pathlib import Path
import platform
import ssl
import statistics
import threading
import time
import urllib.parse


EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
EXPECTED_FORM = {
    "grant_type": [EXCHANGE_GRANT],
    "subject_token": ["subject"],
    "subject_token_type": [ACCESS_TOKEN],
    "actor_token": ["actor"],
    "actor_token_type": ["urn:ietf:params:oauth:token-type:jwt"],
    "audience": ["observability-api"],
    "scope": ["telemetry:read"],
}
EXPECTED_BASIC = "Basic " + base64.b64encode(b"client:secret").decode()


@dataclass
class State:
    lock: threading.Lock = field(default_factory=threading.Lock)
    started: Counter = field(default_factory=Counter)
    issued: Counter = field(default_factory=Counter)
    active: Counter = field(default_factory=Counter)
    max_active: Counter = field(default_factory=Counter)
    methods: dict = field(default_factory=lambda: defaultdict(Counter))
    invalid_requests: Counter = field(default_factory=Counter)

    def begin(self, case: str, method: str, form: dict) -> None:
        with self.lock:
            self.started[case] += 1
            self.active[case] += 1
            self.max_active[case] = max(self.max_active[case], self.active[case])
            self.methods[case][method] += 1
            if case.endswith("_load") and form != EXPECTED_FORM:
                self.invalid_requests[case] += 1

    def end(self, case: str, issued: bool = False) -> None:
        with self.lock:
            self.active[case] -= 1
            if issued:
                self.issued[case] += 1


STATE = State()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        pass

    def _case(self) -> str:
        return self.headers.get("X-Case", "unknown")

    def do_GET(self) -> None:
        case = self._case()
        STATE.begin(case, "GET", {})
        body = b'{"error":"redirect_followed"}'
        self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        STATE.end(case)

    def do_POST(self) -> None:
        case = self._case()
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(
            self.rfile.read(length).decode("utf-8", "replace"),
            keep_blank_values=True,
        )
        STATE.begin(case, "POST", form)
        if case.endswith("_load") and self.headers.get("Authorization") != EXPECTED_BASIC:
            with STATE.lock:
                STATE.invalid_requests[case] += 1
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location", f"https://localhost:{self.server.server_port}/token"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            STATE.end(case)
            return
        delay = float(urllib.parse.parse_qs(parsed.query).get("delay", ["0"])[0])
        if delay:
            time.sleep(delay)
        body = json.dumps(
            {
                "access_token": f"token-{case}",
                "token_type": "Bearer",
                "issued_token_type": ACCESS_TOKEN,
                "expires_in": 60,
                "scope": "telemetry:read",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
            pass
        STATE.end(case, issued=True)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def _summary(case: str, elapsed: float, latencies: list[float], errors: list[str]) -> dict:
    total = len(latencies) + len(errors)
    return {
        "elapsed_s": round(elapsed, 4),
        "throughput_rps": round(total / elapsed, 1),
        "p50_ms": round(statistics.median(latencies) * 1000, 1),
        "p95_ms": round(_percentile(latencies, 0.95) * 1000, 1),
        "errors": dict(Counter(errors)),
        "server_started": STATE.started[case],
        "server_issued": STATE.issued[case],
        "server_max_active": STATE.max_active[case],
        "invalid_requests": STATE.invalid_requests[case],
    }


async def run_gate(base: str, ca: str, operations: int, concurrency: int) -> dict:
    global STATE
    STATE = State()
    import httpx
    from authlib.integrations.httpx_client import AsyncOAuth2Client
    from requests.adapters import HTTPAdapter
    from requests_oauth2client import ClientSecretBasic, OAuth2Client

    common = {
        "grant_type": EXCHANGE_GRANT,
        "subject_token": "subject",
        "subject_token_type": ACCESS_TOKEN,
        "actor_token": "actor",
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "audience": "observability-api",
        "scope": "telemetry:read",
    }

    async def authlib_load() -> dict:
        case = "authlib_load"
        queue = asyncio.Queue()
        submitted = time.monotonic()
        for index in range(operations):
            queue.put_nowait((index, submitted))
        rows = [None] * operations

        async def worker():
            client = AsyncOAuth2Client(
                client_id="client", client_secret="secret",
                token_endpoint_auth_method="client_secret_basic",
                timeout=httpx.Timeout(2.0, connect=1.0),
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                follow_redirects=False, verify=ca, trust_env=False,
            )
            try:
                while not queue.empty():
                    index, started = queue.get_nowait()
                    try:
                        await client.fetch_token(
                            f"{base}/token?delay=.05", **common,
                            headers={"X-Case": case},
                        )
                        rows[index] = (time.monotonic() - started, None)
                    except Exception as exc:
                        rows[index] = (time.monotonic() - started,
                                       type(exc).__name__)
                    finally:
                        queue.task_done()
            finally:
                await client.aclose()

        before = time.monotonic()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        elapsed = time.monotonic() - before
        return _summary(case, elapsed, [v for v, e in rows if not e],
                        [e for _, e in rows if e])

    async def requests_load() -> dict:
        case = "requests_load"
        local = threading.local()
        clients = []
        clients_lock = threading.Lock()
        executor = ThreadPoolExecutor(max_workers=concurrency,
                                      thread_name_prefix="oauth-bakeoff")

        def client_for_thread():
            client = getattr(local, "client", None)
            if client is None:
                client = OAuth2Client(f"{base}/token?delay=.05",
                                      auth=ClientSecretBasic("client", "secret"))
                client.session.trust_env = False
                client.session.cookies.clear()
                client.session.mount(
                    "https://",
                    HTTPAdapter(max_retries=0, pool_connections=1,
                                pool_maxsize=1, pool_block=True),
                )
                local.client = client
                with clients_lock:
                    clients.append(client)
            return client

        def one(started):
            try:
                client_for_thread().token_exchange(
                    subject_token="subject", subject_token_type="access_token",
                    actor_token="actor", actor_token_type="jwt",
                    audience="observability-api", scope="telemetry:read",
                    requests_kwargs={"headers": {"X-Case": case},
                                     "allow_redirects": False,
                                     "timeout": (1.0, 2.0), "verify": ca},
                )
                return time.monotonic() - started, None
            except Exception as exc:
                return time.monotonic() - started, type(exc).__name__

        loop = asyncio.get_running_loop()
        before = time.monotonic()
        rows = await asyncio.gather(
            *(loop.run_in_executor(executor, one, before) for _ in range(operations))
        )
        elapsed = time.monotonic() - before
        executor.shutdown(wait=True)
        for client in clients:
            client.session.close()
        return _summary(case, elapsed, [v for v, e in rows if not e],
                        [e for _, e in rows if e])

    async def redirect(client_name: str) -> dict:
        case = f"{client_name}_redirect"
        if client_name == "authlib":
            client = AsyncOAuth2Client(client_id="client", client_secret="secret",
                                       follow_redirects=False, verify=ca,
                                       trust_env=False, timeout=2)
            try:
                await client.fetch_token(f"{base}/redirect", **common,
                                         headers={"X-Case": case})
                outcome = "success"
            except Exception as exc:
                outcome = type(exc).__name__
            await client.aclose()
        else:
            client = OAuth2Client(f"{base}/redirect",
                                  auth=ClientSecretBasic("client", "secret"))
            client.session.trust_env = False
            try:
                await asyncio.to_thread(
                    client.token_exchange,
                    subject_token="subject", subject_token_type="access_token",
                    requests_kwargs={"headers": {"X-Case": case},
                                     "allow_redirects": False,
                                     "timeout": 2, "verify": ca},
                )
                outcome = "success"
            except Exception as exc:
                outcome = type(exc).__name__
            client.session.close()
        return {"outcome": outcome, "started": STATE.started[case],
                "methods": dict(STATE.methods[case])}

    results = {
        "schema": "andyur-oauth-client-bakeoff/v1",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "authlib": importlib.metadata.version("Authlib"),
            "httpx": importlib.metadata.version("httpx"),
            "requests": importlib.metadata.version("requests"),
            "requests_oauth2client": importlib.metadata.version(
                "requests-oauth2client"
            ),
        },
        "configuration": {"operations": operations, "concurrency": concurrency},
        "authlib_load": await authlib_load(),
        "requests_load": await requests_load(),
        "authlib_redirect": await redirect("authlib"),
        "requests_redirect": await redirect("requests"),
        "request_shape": {
            "expected": EXPECTED_FORM,
            "client_auth": "HTTP Basic client:secret (secret not recorded on wire)",
            "authlib_invalid": STATE.invalid_requests["authlib_load"],
            "requests_invalid": STATE.invalid_requests["requests_load"],
        },
    }
    results["passed"], results["failures"] = validate_results(results)
    return results


def validate_results(result: dict) -> tuple[bool, list[str]]:
    failures = []
    expected = result["configuration"]["operations"]
    limit = result["configuration"]["concurrency"]
    for name in ("authlib_load", "requests_load"):
        row = result[name]
        if row["server_started"] != expected or row["server_issued"] != expected:
            failures.append(f"{name}: wire attempt/issuance count mismatch")
        if row["server_max_active"] > limit:
            failures.append(f"{name}: concurrency limit exceeded")
        if row["errors"]:
            failures.append(f"{name}: unexpected errors")
    shape = result.get("request_shape", {})
    if shape.get("authlib_invalid") or shape.get("requests_invalid"):
        failures.append("client serialized an invalid exchange request")
    for name in ("authlib_redirect", "requests_redirect"):
        row = result[name]
        if row["started"] != 1 or row["methods"].get("GET", 0):
            failures.append(f"{name}: redirect was followed")
    return not failures, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--operations", type=int, default=80)
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 64 or not args.concurrency <= args.operations <= 5000:
        parser.error("require 1 <= concurrency <= operations <= 5000")

    class Server(ThreadingHTTPServer):
        request_queue_size = 256

    server = Server(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.cert, args.key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = asyncio.run(run_gate(f"https://localhost:{server.server_port}",
                                      args.cert, args.operations, args.concurrency))
        Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
