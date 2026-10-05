"""The Docker product contract is a complete, coherent installation shape."""

from __future__ import annotations

import pathlib

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text())


def test_docker_profile_contains_both_andyur_roles():
    services = COMPOSE["services"]
    assert services["andyur-server"]["profiles"] == ["andyur"]
    assert services["andyur-worker"]["profiles"] == ["andyur"]
    assert services["andyur-server"]["labels"]["andyur.role"] == "server"
    assert services["andyur-worker"]["labels"]["andyur.role"] == "worker"
    assert services["andyur-cli"]["labels"]["andyur.role"] == "operator"


def test_docker_roles_have_one_coherent_deployment_and_identity_plane():
    for role in ("andyur-server", "andyur-worker"):
        service = COMPOSE["services"][role]
        env = service["environment"]
        assert env["ANDYUR_PROFILE"] == "prod"
        assert env["ANDYUR_DEPLOYMENT"] == "docker"
        assert env["SPIFFE_ENDPOINT_SOCKET"].startswith("unix:")
        assert "andyur-spire-sockets:/run/spire/sockets:ro" in service["volumes"]


def test_runs_use_an_external_network_compose_cannot_weaken():
    network = COMPOSE["networks"]["andyur-runs"]
    assert network == {"external": True, "name": "andyur-runs"}
    for role in ("andyur-server", "andyur-worker"):
        assert "andyur-runs" in COMPOSE["services"][role]["networks"]
    worker = COMPOSE["services"]["andyur-worker"]
    assert worker["environment"]["ANDYUR_SANDBOX_NETWORK"] == "andyur-runs"
    assert worker["environment"]["ANDYUR_SECCOMP"] == "require"


def test_worker_can_launch_sibling_runs_without_receiving_server_state():
    worker_volumes = COMPOSE["services"]["andyur-worker"]["volumes"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in worker_volumes
    assert "andyur-worker-data:/var/lib/andyur" in worker_volumes
    assert "andyur-data:/var/lib/andyur" not in worker_volumes
