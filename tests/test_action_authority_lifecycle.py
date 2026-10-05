"""A queued human decision is not a durable capability to revive a dead run."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from andyur import actions, db
from andyur.server import actionrequests, coordinator, pdp, runtoken
from test_lane_a_action_api import PIN, _request, _run, client, cluster, _no_waiting


@pytest.mark.parametrize("state", ["cancelled", "failed", "completed"])
def test_approval_cannot_revive_finished_run(env, cluster, state):
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    queued = _request(headers, "r").json()
    with db.connect() as conn:
        conn.execute("UPDATE runs SET state = ? WHERE id = 'r'", (state,))
    assert _request(headers, "r").status_code == 401
    response = client.post(f"/runs/r/actions/{queued['id']}/approve",
                           json={"approver": "alice"})
    assert response.status_code == 200
    assert response.json()["decision"] == actions.DENIED
    assert response.json()["decision_reason"] == "run_inactive"
    assert response.json()["result"] == actions.NOT_ATTEMPTED
    assert cluster.writes == []


def test_current_policy_can_withdraw_queued_authority(env, cluster, monkeypatch):
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    queued = _request(headers, "r").json()
    monkeypatch.setattr(pdp, "evaluate", lambda *a, **k: False)
    assert _request(headers, "r").json()["decision"] == actions.DENIED
    response = client.post(f"/runs/r/actions/{queued['id']}/approve",
                           json={"approver": "alice"})
    assert response.json()["decision"] == actions.DENIED
    assert response.json()["decision_reason"] == actions.REASON_POLICY_DENIED
    assert cluster.writes == []


def test_halted_workflow_denies_action_before_worker_kills_run(env, cluster):
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    with db.connect() as conn:
        conn.execute("UPDATE runs SET workflow_id = 'wf' WHERE id = 'r'")
    queued = _request(headers, "r").json()
    coordinator.halt_workflow("wf")
    response = client.post(f"/runs/r/actions/{queued['id']}/approve",
                           json={"approver": "alice"})
    assert response.json()["decision"] == actions.DENIED
    assert response.json()["decision_reason"] == "workflow_halted"
    assert cluster.writes == []


@pytest.mark.parametrize("condition,reason", [
    ("expired", "grant_expired"),
    ("legacy", "authority_missing"),
    ("revoked", "run_inactive"),
    ("bad_pin", "target_not_pinned"),
])
def test_approval_fails_closed_when_authority_is_no_longer_usable(
        env, cluster, monkeypatch, condition, reason):
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    queued = _request(headers, "r").json()
    expiry = runtoken.verify(headers["X-Andyur-Run-Token"])["expires_at"]
    with db.connect() as conn:
        stored = conn.execute("SELECT * FROM action_requests WHERE id = ?",
                              (queued["id"],)).fetchone()
        assert stored["grant_expires_at"] == expiry
        if condition == "legacy":
            conn.execute("UPDATE action_requests SET authorization_snapshot = NULL")
        elif condition == "revoked":
            conn.execute("UPDATE runs SET revoked_at = ? WHERE id = 'r'", (db.utcnow(),))
        elif condition == "bad_pin":
            conn.execute("UPDATE action_requests SET target = 'prod/payments'")
    if condition == "expired":
        monkeypatch.setattr(actionrequests.time, "time", lambda: expiry)
    response = client.post(f"/runs/r/actions/{queued['id']}/approve",
                           json={"approver": "alice"})
    assert response.status_code == 200
    assert response.json()["decision"] == actions.DENIED
    assert response.json()["decision_reason"] == reason
    assert response.json()["result"] == actions.NOT_ATTEMPTED
    assert cluster.writes == []
    assert client.post(f"/runs/r/actions/{queued['id']}/approve",
                       json={"approver": "alice"}).status_code == 409


def test_halt_during_policy_request_wins_before_action_admission(env, cluster, monkeypatch):
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    with db.connect() as conn:
        conn.execute("UPDATE runs SET workflow_id = 'wf' WHERE id = 'r'")
    queued = _request(headers, "r").json()

    def policy(subject, held):
        assert subject.id == "r" and subject.scope == [actions.SCOPE_ROLLBACK_WITH_APPROVAL]
        assert held == actions.SCOPE_ROLLBACK_WITH_APPROVAL
        # A separate connection completes this kill switch while policy is in
        # flight. Holding a lifecycle lock across the PDP call would deadlock.
        coordinator.halt_workflow("wf")
        return True

    monkeypatch.setattr(pdp, "evaluate", policy)
    response = client.post(f"/runs/r/actions/{queued['id']}/approve",
                           json={"approver": "alice"})
    assert response.json()["decision_reason"] == "workflow_halted"
    assert cluster.writes == []


def test_direct_action_rechecks_halt_after_authentication(env, cluster, monkeypatch):
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK])
    with db.connect() as conn:
        conn.execute("UPDATE runs SET workflow_id = 'wf' WHERE id = 'r'")

    def policy(*args):
        coordinator.halt_workflow("wf")
        return True

    monkeypatch.setattr(pdp, "evaluate", policy)
    response = _request(headers, "r")
    assert response.json()["decision_reason"] == "workflow_halted"
    assert cluster.writes == []


def test_concurrent_requests_cannot_overdraw_action_budget(env, cluster, monkeypatch):
    _run(env, "sre", "r", [actions.SCOPE_ROLLBACK])
    monkeypatch.setattr(actionrequests, "MAX_ACTIONS_PER_RUN", 1)
    original = db._Conn.execute
    first_count = threading.Event()
    release_count = threading.Event()
    second_entered = threading.Event()
    seen = []

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            row = self.cursor.fetchone()
            seen.append(row["n"])
            if len(seen) == 1:
                first_count.set()
                assert release_count.wait(5)
            return row

    def execute(conn, sql, params=()):
        cursor = original(conn, sql, params)
        return Cursor(cursor) if "SELECT COUNT(*) AS n FROM action_requests" in sql else cursor

    monkeypatch.setattr(db._Conn, "execute", execute)

    def request(second=False):
        if second:
            second_entered.set()
        try:
            return actionrequests.request("r", actions.ROLLBACK_DEPLOYMENT,
                                          "prod", "checkout-service",
                                          granted_scope=[actions.SCOPE_ROLLBACK], pin=PIN,
                                          grant_expires_at=int(time.time()) + 60)
        except actionrequests.ActionExhausted:
            return "exhausted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(request)
        assert first_count.wait(5)
        second = pool.submit(request, True)
        assert second_entered.wait(5)
        # If the second COUNT is serialized, it cannot complete before release.
        # The timeout gives the old unlocked implementation a deterministic
        # opportunity to read and insert while the first caller is paused.
        try:
            second.result(timeout=0.25)
        except TimeoutError:
            pass
        finally:
            release_count.set()
        results = [first.result(timeout=5), second.result(timeout=5)]
    assert results.count("exhausted") == 1, (seen, results)
    assert len(actionrequests.list_for_run("r")) == 1
    assert len(cluster.writes) == 1
