"""`andyur create --registry-agent-id` binds a new agent to a registry manifest.

Setup only: build the real parser and hand cmd_create a fake HTTP client that
captures the posted body, then assert on what the command actually sends. No
network, no server.
"""
from andyur import cli


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, captured):
        self._captured = captured

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, path, json=None):
        self._captured["path"] = path
        self._captured["body"] = json
        return _Resp(201, {"name": json["name"]})

    def put(self, *a, **k):        # unused here (no --*-file args)
        return _Resp(200)


def _run_create(monkeypatch, argv):
    captured = {}
    monkeypatch.setattr(cli, "_client", lambda: _FakeClient(captured))
    args = cli.build_parser().parse_args(argv)
    args.func(args)
    return captured


def test_create_binds_to_a_registry_agent_id(monkeypatch):
    cap = _run_create(
        monkeypatch,
        ["agents", "create", "classy", "--registry-agent-id", "agt_classifier"])
    assert cap["path"] == "/agents"
    assert cap["body"]["name"] == "classy"
    assert cap["body"]["registry_agent_id"] == "agt_classifier"


def test_a_plain_create_sends_no_registry_agent_id(monkeypatch):
    # the flag is additive: a normal create posts the same body as before, with
    # no registry key (so it is never bound to a manifest by accident).
    cap = _run_create(monkeypatch, ["agents", "create", "plain"])
    assert "registry_agent_id" not in cap["body"]


# --- `andyur registry list` / `registry resolve` (browse the catalog) ---------

class _GetClient:
    """Captures GET calls and returns a canned payload, so the registry commands
    can be exercised without a server."""
    def __init__(self, captured, payload):
        self._captured, self._payload = captured, payload
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def get(self, path):
        self._captured["path"] = path
        return _Resp(200, self._payload)


def _run(monkeypatch, argv, payload):
    captured = {}
    monkeypatch.setattr(cli, "_client", lambda: _GetClient(captured, payload))
    args = cli.build_parser().parse_args(argv)
    args.func(args)
    return captured


def test_registry_list_hits_the_catalog_endpoint(monkeypatch, capsys):
    cap = _run(monkeypatch, ["registry", "list"],
               {"agents": [{"agent_id": "agt_x", "name": "xa"}]})
    assert cap["path"] == "/v1/registry/agents"
    out = capsys.readouterr().out
    assert "agt_x" in out and "xa" in out


def test_registry_resolve_hits_the_resolve_endpoint(monkeypatch, capsys):
    cap = _run(monkeypatch, ["registry", "resolve", "agt_x"],
               {"agent_id": "agt_x", "ceiling": {"actions": ["files:read"]}})
    assert cap["path"] == "/v1/registry/agents/agt_x/resolve"
    assert "files:read" in capsys.readouterr().out
