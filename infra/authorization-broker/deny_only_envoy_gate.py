"""Pinned live Envoy -> private UDS -> real deny-only broker composition gate."""
from __future__ import annotations

import json
import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from andyur.dataplane import envoyconfig

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ENVOY = "docker.io/envoyproxy/envoy@sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66"
APP_IMAGE = os.environ.get("ANDYUR_IMAGE", "andyur-server")
PREFIX = f"andyur-deny-gate-{os.getpid()}"
NETWORK, VOLUME = PREFIX + "-net", PREFIX + "-uds"
BROKER, UPSTREAM, ENVOY_NAME, AGENT = (PREFIX + suffix for suffix in (
    "-broker", "-upstream", "-envoy", "-agent"))
GATE_TIMEOUT_SECONDS = 180
_gate_deadline: float | None = None
EVIDENCE_SOURCES = (
    "andyur/dataplane/extauthz.py",
    "andyur/dataplane/brokeruds.py",
    "andyur/dataplane/envoyconfig.py",
    "infra/authorization-broker/deny_broker_fixture.py",
    "infra/authorization-broker/upstream_fixture.py",
    "infra/authorization-broker/deny_only_envoy_gate.py",
    "infra/authorization-broker/verify-deny-only-envoy.sh",
)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    remaining = 30.0 if _gate_deadline is None else _gate_deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(args, GATE_TIMEOUT_SECONDS)
    return subprocess.run(
        args, check=check, text=True, capture_output=True,
        timeout=min(30.0, remaining))


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("docker", *args, check=check)


def cleanup_resources(call) -> list[tuple[str, ...]]:
    attempted: list[tuple[str, ...]] = []
    commands = [("rm", "-f", name) for name in
                (ENVOY_NAME, BROKER, UPSTREAM, AGENT)]
    commands += [("network", "rm", NETWORK), ("volume", "rm", VOLUME)]
    for command in commands:
        attempted.append(command)
        try:
            call(*command)
        except Exception:  # noqa: BLE001 - cleanup must continue across resources
            pass
    return attempted


def cleanup_docker(*args: str) -> None:
    subprocess.run(("docker", *args), check=False, text=True,
                   capture_output=True, timeout=5)


def config(*, include_authz: bool) -> dict:
    filters = []
    if include_authz:
        filters.append(envoyconfig._ext_authz_filter(
            "andyur-authz", "/authz", timeout_ms=850))
    filters.append({"name": "envoy.filters.http.router", "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}})
    return {
        "admin": {"address": {"pipe": {"path": "/tmp/envoy-admin.sock"}}},
        "static_resources": {
            "listeners": [{"name": "listener", "address": {"socket_address": {
                "address": "0.0.0.0", "port_value": 15000}},
                "filter_chains": [{"filters": [{
                    "name": "envoy.filters.network.http_connection_manager",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                        "stat_prefix": "deny_gate", "route_config": {
                            "name": "route", "virtual_hosts": [{"name": "tool",
                            "domains": ["*"], "routes": [{"match": {"path": "/mcp"},
                            "route": {"cluster": "upstream"}}]}]},
                        "http_filters": filters}}]}]}],
            "clusters": [
                envoyconfig._authz_cluster("andyur-authz", "/authz/authz.sock"),
                {"name": "upstream", "connect_timeout": "0.5s", "type": "STRICT_DNS",
                 "load_assignment": {"cluster_name": "upstream", "endpoints": [
                    {"lb_endpoints": [{"endpoint": {"address": {"socket_address": {
                        "address": "upstream", "port_value": 8080}}}}]}]}}]}}


def wait_log(name: str, marker: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if marker in docker("logs", name, check=False).stdout:
            return
        time.sleep(0.2)
    raise RuntimeError(f"{name} did not become ready: {docker('logs', name, check=False).stdout}")


def start_broker(app_image_id: str, *, bypass: bool = False) -> None:
    docker("rm", "-f", BROKER, check=False)
    args = ["run", "-d", "--name", BROKER, "--network", "none",
            "-v", f"{VOLUME}:/authz", "-v", f"{ROOT}:/workspace:ro",
            "-v", f"{HERE / 'deny_broker_fixture.py'}:/fixture.py:ro",
            "-e", "PYTHONPATH=/workspace", "-e", "ANDYUR_GATE_TRUSTED_GID=1337"]
    if bypass:
        args += ["-e", "ANDYUR_GATE_BYPASS=1"]
    args += ["--entrypoint", "python", app_image_id, "/fixture.py"]
    docker(*args)
    wait_log(BROKER, "deny-only broker ready")


def start_envoy(path: Path) -> int:
    docker("rm", "-f", ENVOY_NAME, check=False)
    docker("run", "-d", "--name", ENVOY_NAME, "--network", NETWORK,
           "--user", "1338:1337", "-p", "127.0.0.1::15000",
           "-v", f"{VOLUME}:/authz", "-v", f"{path}:/config.yaml:ro",
           ENVOY, "envoy", "-c", "/config.yaml", "--log-level", "warning")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        mapped = docker("port", ENVOY_NAME, "15000/tcp", check=False).stdout.strip()
        if mapped:
            port = int(mapped.rsplit(":", 1)[1])
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/missing", timeout=.2)
            except urllib.error.HTTPError:
                return port
            except OSError:
                pass
        time.sleep(.2)
    raise RuntimeError("Envoy listener did not become ready")


def post(port: int) -> tuple[int, str, float]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp", data=b'{}', method="POST")
    started = time.monotonic()
    try:
        remaining = 3.0 if _gate_deadline is None else \
            _gate_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("deny-only Envoy gate deadline expired")
        remaining = min(3.0, remaining)
        with urllib.request.urlopen(request, timeout=remaining) as response:
            return response.status, response.read().decode(), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), time.monotonic() - started


def main() -> None:
    global _gate_deadline
    _gate_deadline = time.monotonic() + GATE_TIMEOUT_SECONDS
    results: dict[str, object] = {}
    app_image_id = docker(
        "image", "inspect", APP_IMAGE, "--format", "{{.Id}}").stdout.strip()
    assert app_image_id.startswith("sha256:")
    work = Path(tempfile.mkdtemp(prefix="andyur-deny-envoy-"))
    evidence = work / "evidence"
    evidence.mkdir()
    try:
        docker("network", "create", NETWORK)
        docker("volume", "create", VOLUME)
        docker("run", "-d", "--name", UPSTREAM, "--network", NETWORK,
               "--network-alias", "upstream", "-v", f"{evidence}:/evidence",
               "-v", f"{HERE / 'upstream_fixture.py'}:/fixture.py:ro",
               "--entrypoint", "python", app_image_id, "/fixture.py")
        start_broker(app_image_id)
        attrs = docker("exec", BROKER, "stat", "-c", "%a %u %g %F",
                       "/authz", "/authz/authz.sock").stdout.splitlines()
        assert attrs == ["750 0 1337 directory", "660 0 1337 socket"]
        results["uds_attributes"] = attrs

        secure_path = work / "secure.yaml"
        secure = config(include_authz=True)
        secure_names = [f["name"] for f in secure["static_resources"][
            "listeners"][0]["filter_chains"][0]["filters"][0][
                "typed_config"]["http_filters"]]
        assert secure_names == ["envoy.filters.http.ext_authz",
                                "envoy.filters.http.router"]
        secure_bytes = yaml.safe_dump(secure).encode()
        secure_path.write_bytes(secure_bytes)
        docker("exec", BROKER, "rm", "-f", "/authz/observed")
        port = start_envoy(secure_path)
        status, body, elapsed = post(port)
        assert status == 403, \
            (status, body, docker("logs", ENVOY_NAME, check=False).stdout,
             docker("logs", BROKER, check=False).stdout)
        assert not (evidence / "dispatched").exists()
        observed = docker("exec", BROKER, "cat", "/authz/observed").stdout.splitlines()
        expected_state = [
            '["liveness","r1"]', '["identity","r1"]',
            '["registry","scout","r1"]',
            '["authority","scout","r1","resource:calendar",null,null]']
        assert observed == expected_state
        results["secure"] = {"status": status, "dispatch": False,
                             "broker_calls": len(observed),
                             "elapsed_ms": round(elapsed * 1000, 1)}

        # Exact enforcement mutation: remove only ext_authz; the same request
        # must reach the positive-control upstream.
        mutated = config(include_authz=False)
        names = [f["name"] for f in mutated["static_resources"]["listeners"][0][
            "filter_chains"][0]["filters"][0]["typed_config"]["http_filters"]]
        assert "envoy.filters.http.ext_authz" not in names
        mutation_path = work / "mutation.yaml"
        mutation_path.write_text(yaml.safe_dump(mutated))
        docker("exec", BROKER, "rm", "-f", "/authz/observed")
        port = start_envoy(mutation_path)
        status, body, _ = post(port)
        assert status == 200 and body == "upstream executed"
        assert (evidence / "dispatched").read_text() == "yes"
        assert docker("exec", BROKER, "test", "!", "-e",
                      "/authz/observed").returncode == 0
        results["mutation_red"] = {"status": status, "dispatch": True}

        (evidence / "dispatched").unlink()
        docker("exec", BROKER, "rm", "-f", "/authz/observed")
        port = start_envoy(secure_path)
        status, body, _ = post(port)
        assert status == 403, \
            (status, body, docker("logs", ENVOY_NAME, check=False).stdout,
             docker("logs", BROKER, check=False).stdout)
        assert not (evidence / "dispatched").exists()
        observed = docker("exec", BROKER, "cat", "/authz/observed").stdout.splitlines()
        assert observed == expected_state
        results["restored"] = {"status": status, "dispatch": False,
                               "broker_calls": len(observed)}

        docker("run", "--rm", "--name", AGENT, "--network", NETWORK,
               "--user", "2000:2000",
               "--entrypoint", "sh", app_image_id, "-c",
               "test ! -e /authz/authz.sock")
        results["agent_socket_absent"] = True

        docker("stop", "-t", "5", BROKER)
        status, _, elapsed = post(port)
        assert status == 403 and not (evidence / "dispatched").exists()
        results["broker_unavailable"] = {
            "status": status, "dispatch": False,
            "elapsed_ms": round(elapsed * 1000, 1)}
        start_broker(app_image_id, bypass=True)
        docker("exec", BROKER, "rm", "-f", "/authz/observed")
        docker("exec", BROKER, "rm", "-f", "/authz/bypass-observed")
        status, _, _ = post(port)
        assert status == 403 and not (evidence / "dispatched").exists()
        assert docker("exec", BROKER, "test", "!", "-e",
                      "/authz/observed").returncode == 0
        bypass_observed = docker(
            "exec", BROKER, "cat", "/authz/bypass-observed").stdout.splitlines()
        assert bypass_observed == ["/authz/mcp"]
        results["broker_bypass_mutation_red"] = {
            "status": status, "dispatch": False, "authority_calls": 0,
            "transport_calls": len(bypass_observed)}
        docker("stop", "-t", "5", BROKER)
        probe = docker("run", "--rm", "-v", f"{VOLUME}:/authz",
                       "--entrypoint", "sh", app_image_id, "-c",
                       "test ! -e /authz/authz.sock")
        assert probe.returncode == 0
        results["teardown_socket_absent"] = True
        results["envoy_image"] = ENVOY
        results["app_image_id"] = app_image_id
        results["envoy_version"] = docker(
            "run", "--rm", ENVOY, "envoy", "--version").stdout.strip()
        results["secure_config_sha256"] = hashlib.sha256(secure_bytes).hexdigest()
        results["source_sha256"] = {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in EVIDENCE_SOURCES}
        results["platform"] = platform.platform()
        output = HERE / "result-deny-only-envoy-2026-08-19-macos-arm64.json"
        output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
        print(json.dumps(results, indent=2, sort_keys=True))
    finally:
        cleanup_resources(cleanup_docker)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
