"""Server liveness is shallow; readiness proves mandatory local dependencies."""

from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module


client = TestClient(app_module.app)


def _ready_config(monkeypatch):
    monkeypatch.setattr(config, "PROD", False)
    monkeypatch.setattr(config, "assert_profile", lambda: None)
    monkeypatch.setattr(config, "assert_user_auth", lambda: None)
    monkeypatch.setattr(config, "as_problems", lambda: [])
    monkeypatch.setattr(app_module.identity, "assert_live_x509_identity", lambda _id: None)


def test_ready_positive_checks_database(monkeypatch, env):
    _ready_config(monkeypatch)
    assert client.get("/ready").json() == {
        "ready": True, "service": "andyur-server"}


def test_ready_turns_red_while_liveness_stays_green_on_database_failure(
        monkeypatch, env):
    _ready_config(monkeypatch)

    def unavailable():
        raise OSError("database unavailable")

    monkeypatch.setattr(db, "connect", unavailable)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["detail"]["problems"] == ["database: OSError"]
    assert client.get("/health").status_code == 200


def test_ready_turns_red_on_authorization_configuration(monkeypatch, env):
    _ready_config(monkeypatch)
    monkeypatch.setattr(config, "as_problems", lambda: ["candidate is uncertified"])
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["detail"]["problems"] == [
        "authorization-server: candidate is uncertified"]


def test_ready_turns_red_on_profile_or_identity_prerequisite(monkeypatch, env):
    _ready_config(monkeypatch)
    monkeypatch.setattr(config, "assert_profile",
                        lambda: (_ for _ in ()).throw(config.InsecureProfile("bad")))
    assert client.get("/ready").status_code == 503

    monkeypatch.setattr(config, "assert_profile", lambda: None)
    monkeypatch.setattr(config, "PROD", True)

    seen = []

    def unavailable(expected):
        seen.append(expected)
        raise TimeoutError("stale Workload API socket")

    monkeypatch.setattr(app_module.identity, "assert_live_x509_identity", unavailable)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["detail"]["problems"] == [
        "identity: TimeoutError"]
    assert seen == ["spiffe://andyur.local/control-plane"]
