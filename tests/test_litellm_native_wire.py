"""Real Claude CLI -> pinned LiteLLM -> fake Anthropic wire conformance."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
import httpx


ROOT = Path(__file__).resolve().parents[1]
IMAGE = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text())["services"]["litellm"]["image"]
assert "@sha256:" in IMAGE


# `integration`, so the fast CI lane deliberately DESELECTS this (a
# `-m "not integration"` exclusion that shows in the run summary) rather than
# COLLECTING it and skipping silently -- which read as "ran, fine" while the
# pinned-image wire compatibility was never actually checked. The integration
# lane must set ANDYUR_TEST_LITELLM=1, install the pinned Claude CLI, and have
# docker; until it does, this is honestly-not-run, not falsely-green.
# (Red-team A3, 2026-08-13.)
@pytest.mark.integration
@pytest.mark.skipif(
    os.getenv("ANDYUR_TEST_LITELLM") != "1",
    reason="integration: needs ANDYUR_TEST_LITELLM=1, the pinned Claude CLI, and docker",
)
def test_pinned_litellm_speaks_native_anthropic_sse_to_the_real_claude_cli():
    """This is the executable compatibility property, not a source assertion."""
    cli = shutil.which("claude")
    assert cli, "CI must install the runner-pinned Claude CLI"
    assert shutil.which("docker"), "CI must provide Docker"
    seen = []
    otel_payloads = []

    class Anthropic(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_POST(self):
            body = self.rfile.read(int(self.headers["content-length"]))
            if self.path == "/v1/traces":
                otel_payloads.append(body)
                self.send_response(200)
                self.send_header("content-length", "0")
                self.end_headers()
                return
            seen.append((self.path, self.headers.get("x-api-key"), json.loads(body)))
            events = [
                ("message_start", {"type": "message_start", "message": {
                    "id": "msg_litellm", "type": "message", "role": "assistant",
                    "content": [], "model": "claude-haiku-4-5", "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 0}}}),
                ("content_block_start", {"type": "content_block_start", "index": 0,
                    "content_block": {"type": "text", "text": ""}}),
                ("content_block_delta", {"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": "ANDYUR_LITELLM_OK"}}),
                ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                ("message_delta", {"type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 1}}),
                ("message_stop", {"type": "message_stop"}),
            ]
            payload = "".join(
                f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("0.0.0.0", 0), Anthropic)
    upstream_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    name = f"andyur-litellm-wire-{os.getpid()}"
    with tempfile.TemporaryDirectory() as temp:
        config = ROOT / "infra/litellm/config.yaml"
        try:
            subprocess.run([
                "docker", "run", "-d", "--name", name,
                "--add-host", "host.docker.internal:host-gateway",
                "-p", "127.0.0.1::4000",
                "-v", f"{config}:/app/config.yaml:ro",
                "-e", "ANTHROPIC_API_KEY=provider-secret",
                "-e", f"ANTHROPIC_API_BASE=http://host.docker.internal:{upstream_port}",
                "-e", "LITELLM_MASTER_KEY=gateway-secret",
                "-e", "OTEL_EXPORTER=otlp_http",
                "-e", f"OTEL_EXPORTER_OTLP_ENDPOINT=http://host.docker.internal:{upstream_port}",
                "-e", "OTEL_SERVICE_NAME=andyur-litellm", IMAGE,
                "--config", "/app/config.yaml", "--host", "0.0.0.0",
                "--port", "4000", "--telemetry", "False",
            ], check=True, capture_output=True, text=True, timeout=120)
            mapped = subprocess.run(
                ["docker", "port", name, "4000/tcp"], check=True,
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            proxy_port = int(mapped.rsplit(":", 1)[1])
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                health = subprocess.run([
                    "curl", "-fsS", f"http://127.0.0.1:{proxy_port}/health/liveliness"
                ], capture_output=True)
                if health.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(subprocess.run(
                    ["docker", "logs", name], capture_output=True, text=True
                ).stdout)

            env = {**os.environ, "HOME": temp,
                   "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{proxy_port}",
                   "ANTHROPIC_AUTH_TOKEN": "gateway-secret", "ANTHROPIC_API_KEY": ""}
            result = subprocess.run([
                cli, "-p", "reply exactly ANDYUR_LITELLM_OK", "--model",
                "claude-haiku-4-5", "--output-format", "json",
            ], env=env, capture_output=True, text=True, timeout=45)
            assert result.returncode == 0, result.stderr or result.stdout
            assert json.loads(result.stdout)["result"] == "ANDYUR_LITELLM_OK"
            assert seen
            path, provider_key, request = seen[-1]
            assert path == "/v1/messages"
            assert provider_key == "provider-secret"
            assert request["model"] == "claude-haiku-4-5"
            deadline = time.monotonic() + 10
            while not otel_payloads and time.monotonic() < deadline:
                time.sleep(0.1)
            assert otel_payloads, "shipped OTEL callback exported no spans"
            spans = b"".join(otel_payloads)
            assert b"litellm_request" in spans
            forbidden = (b"ANDYUR_LITELLM_OK", b"gateway-secret", b"provider-secret")
            assert all(value not in spans for value in forbidden)
            log_result = subprocess.run(
                ["docker", "logs", name], check=True, capture_output=True,
                timeout=10,
            )
            logs = log_result.stdout + log_result.stderr
            assert all(value not in logs for value in forbidden)

            # LiteLLM must join the run's distributed trace rather than start
            # an uncorrelated gateway trace. The per-run sidecar preserves this
            # header; this check freezes the shared-gateway half of that seam.
            trace_hex = "11" * 16
            before = len(otel_payloads)
            traced = httpx.post(
                f"http://127.0.0.1:{proxy_port}/v1/messages",
                headers={
                    "x-api-key": "gateway-secret",
                    "anthropic-version": "2023-06-01",
                    "traceparent": f"00-{trace_hex}-{'22' * 8}-01",
                },
                json={"model": "claude-haiku-4-5", "max_tokens": 8,
                      "messages": [{"role": "user", "content": "trace-check"}]},
                timeout=15,
            )
            assert traced.status_code == 200
            deadline = time.monotonic() + 10
            while len(otel_payloads) == before and time.monotonic() < deadline:
                time.sleep(0.1)
            assert len(otel_payloads) > before
            assert bytes.fromhex(trace_hex) in b"".join(otel_payloads[before:])
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive()
