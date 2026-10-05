"""A run row records the registry snapshot digest that was in force (G05).

Provenance must be answerable from the run record ALONE: after the process
restarts on a newer snapshot, the row still says which approved definition
this run executed under. Uses the real server app and the real coordinator
insert; the governed registry is simulated through the factory seam with a
digest-bearing catalog, so no OCI infrastructure is needed here (the live
cosign/oras path has its own gate script).
"""

import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from andyur import db
from andyur.registry.manifest_registry import ManifestAgentRegistry
from andyur.registry.service import (configure_registry_factory,
                                     restore_default_registry)
from andyur.server.app import app

DIGEST = "sha256:" + "cd" * 32

MANIFEST = {
    "schema_version": "andyur.agent-resolution/v1",
    "agent_id": "agt_stamped",
    "name": "stamped",
    "instructions": "exists to prove run rows carry registry provenance",
    "model": None,
    "tools": [],
    "ceiling": {"actions": [], "resources": []},
}


class _DigestBearingCatalog:
    """What GovernedAgentRegistry looks like to the coordinator: the same
    resolution engine, and -- faithfully to the real governed registry --
    resolutions that CARRY the snapshot digest (not merely a .digest property
    on the catalog). The coordinator reads provenance off the resolution, so a
    fake that only set .digest would not exercise the real stamping path."""

    def __init__(self, directory):
        self._inner = ManifestAgentRegistry(directory)
        self.digest = DIGEST

    def resolve(self, agent_id):
        return replace(self._inner.resolve(agent_id), registry_digest=DIGEST)

    def list_agents(self):
        return [replace(r, registry_digest=DIGEST)
                for r in self._inner.list_agents()]


@pytest.fixture(autouse=True)
def _isolate_process_registry():
    """The process registry is a cached singleton; a factory installed by one
    test must not leak into the next. Restoring the DEFAULT factory is what
    undoes configure_registry_factory; dropping the snapshot alone leaves the
    installed factory live and leaks it into the next module."""
    restore_default_registry()
    yield
    restore_default_registry()


@pytest.fixture()
def client(tmp_path, env):
    (tmp_path / "stamped.json").write_text(json.dumps(MANIFEST))
    configure_registry_factory(lambda: _DigestBearingCatalog(tmp_path))
    yield TestClient(app)
    restore_default_registry()


def _run_digest(agent_name: str):
    with db.connect() as conn:
        row = conn.execute(
            "SELECT registry_digest FROM runs WHERE agent = ? "
            "ORDER BY created_at DESC", (agent_name,)).fetchone()
    return row["registry_digest"]


def test_a_registry_bound_agents_run_records_the_snapshot_digest(client):
    r = client.post("/agents", json={"name": "stamped",
                                     "registry_agent_id": "agt_stamped"})
    assert r.status_code in (200, 201), r.text
    r = client.post("/agents/stamped/trigger", json={"reason": "provenance probe"})
    assert r.status_code == 201, r.text
    assert _run_digest("stamped") == DIGEST


def test_an_unbound_agents_run_records_no_digest(client):
    r = client.post("/agents", json={"name": "freehand"})
    assert r.status_code in (200, 201), r.text
    r = client.post("/agents/freehand/trigger", json={"reason": "no provenance"})
    assert r.status_code == 201, r.text
    assert _run_digest("freehand") is None


def test_a_stale_binding_not_in_the_snapshot_stamps_none_not_a_false_digest(
        client, tmp_path):
    """The stamp comes from the agent's own resolution, not the process digest.
    Simulate a restart onto a NEWER snapshot that dropped the agent: bind while
    it resolves, then swap the catalog to one without it, then trigger. The run
    must stamp None -- never a digest for a snapshot that did not define it --
    rather than inheriting the process-wide .digest."""
    r = client.post("/agents", json={"name": "stale_probe",
                                     "registry_agent_id": "agt_stamped"})
    assert r.status_code in (200, 201), r.text
    # The binding survives in the DB; the live registry no longer defines it.
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "other.json").write_text(json.dumps(
        {**MANIFEST, "agent_id": "agt_other", "name": "other"}))
    configure_registry_factory(lambda: _DigestBearingCatalog(empty))
    r = client.post("/agents/stale_probe/trigger", json={"reason": "stale binding"})
    assert r.status_code == 201, r.text
    assert _run_digest("stale_probe") is None
