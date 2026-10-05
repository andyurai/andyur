"""The installed SOC grant must enforce its advertised human-approval boundary."""

from pathlib import Path

from andyur import actions
from andyur.registry.manifest_registry import ManifestAgentRegistry
from andyur.server import actionrequests
from test_lane_a_action_api import FakeCluster, _request, _run, client


def test_installed_soc_response_waits_for_approval_before_any_cluster_write(env, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    response = next(a for a in ManifestAgentRegistry(root / "demos/bundles").list_agents()
                    if a.name == "soc-response")
    cluster = FakeCluster()
    monkeypatch.setattr(actionrequests, "_client_factory", lambda: cluster)
    monkeypatch.setattr(actionrequests, "OBSERVE_SECONDS", 0)
    headers = _run(env, "soc-response-probe", "soc-approval-probe",
                   list(response.ceiling.actions))
    requested = _request(headers, "soc-approval-probe")
    assert requested.status_code == 201
    row = requested.json()
    assert row["decision"] == actions.APPROVAL_REQUIRED
    assert row["approved_by"] is None and cluster.writes == []
    approved = client.post(f"/runs/soc-approval-probe/actions/{row['id']}/approve",
                           json={"approver": "operator"})
    assert approved.status_code == 200
    assert approved.json()["result"] == actions.SUCCEEDED
    assert approved.json()["approved_by"] == "operator"
    assert len(cluster.writes) == 1
