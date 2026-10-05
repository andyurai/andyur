"""The consequential action, end to end over the API.

Board rows 9-12. `test_lane_a_actions.py` covers the decision and
`test_lane_a_rollback.py` the mechanism; this covers the thing the MVP actually
claims -- an agent asks, Andyur decides, the cluster moves or provably does not,
and an operator can read the whole story off the HTTP API.

THE FAKE CLUSTER IS THE INSTRUMENT. Every test here asserts against what the
fake was ASKED to do, not only against what the API answered: a denial that
returns "denied" while patching the deployment anyway would pass a
response-shaped assertion and is exactly the failure this lane exists to
prevent. So the fake records every call and the denial tests assert the write
list is EMPTY.
"""

import copy
import json

import pytest
from fastapi.testclient import TestClient

from andyur import actions, config, db
from andyur.server import actionrequests, app as app_module, runtoken

client = TestClient(app_module.app)

NAMESPACE, DEPLOYMENT = "prod", "checkout-service"
PIN = {"namespace": NAMESPACE, "deployment": DEPLOYMENT}


class FakeCluster:
    """A Deployment with two revisions, and a record of everything asked of it."""

    def __init__(self, *, revision="7", moves=True):
        self.revision = revision
        self.moves = moves          # does the write actually change the cluster?
        self.writes = []            # every mutation attempted, in order
        self.reads = 0
        self.generation = int(revision)
        self.template = {"spec": {"containers": [{"name": "app", "image": "checkout:1.1"}]}}

    def read_deployment(self, namespace, deployment):
        self.reads += 1
        return self._state(namespace, deployment)

    def _state(self, namespace, deployment):
        return {"metadata": {"name": deployment, "namespace": namespace,
                             "uid": "dep-uid",
                             "resourceVersion": str(self.generation),
                             "generation": self.generation,
                             "annotations": {"deployment.kubernetes.io/revision":
                                             self.revision}},
                "spec": {"template": copy.deepcopy(self.template)},
                "status": {"observedGeneration": int(self.revision)}}

    def list_replicasets(self, namespace, deployment, *, owner):
        assert owner["metadata"]["uid"] == "dep-uid"
        return [
            {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "6"}},
             "spec": {"template": {"metadata": {"labels": {"app": "checkout"}},
                                   "spec": {"containers": [{"name": "app",
                                                            "image": "checkout:1.0"}]}}}},
            {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "7"}},
             "spec": {"template": {"spec": {"containers": [{"name": "app",
                                                            "image": "checkout:1.1"}]}}}},
        ]

    def patch_deployment_template(self, namespace, deployment, template, *, expected):
        assert expected["metadata"]["resourceVersion"] == str(self.generation)
        self.writes.append((namespace, deployment, template))
        self.template = copy.deepcopy(template)
        self.generation += 1
        if self.moves:
            self.revision = str(int(self.revision) + 1)
        return self._state(namespace, deployment)


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    """The read-back watches a real cluster for up to a minute, because the
    consequence of the write is asynchronous. A fake cluster has already made
    its decision by the time it returns, so watching it is pure delay."""
    monkeypatch.setattr(actionrequests, "OBSERVE_SECONDS", 0)


@pytest.fixture
def cluster(monkeypatch):
    fake = FakeCluster()
    monkeypatch.setattr(actionrequests, "_client_factory", lambda: fake)
    return fake


def _run(env, agent, run_id, scope, pin=PIN):
    """A live run holding `scope` and pinned to `pin`, and its run-token header.

    The scope and pin go into the SIGNED GRANT as well as the row, because that
    is where the endpoint reads them from -- a test that seeded only the row
    would be checking a path the product does not take.
    """
    env.agent(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, scope, subject_context, "
            "pin_asserted_by, input) VALUES (?, ?, 'running', ?, ?, ?, 'user:alice', ?)",
            (run_id, agent, db.utcnow(),
             json.dumps(scope) if scope is not None else None,
             json.dumps(pin) if pin is not None else None,
             json.dumps({"incident": "INC-4471"})),
        )
    return {"X-Andyur-Run-Token": runtoken.mint(agent, run_id, "wf", scope=scope,
                                                pin=pin)}


def _request(headers, run_id, **overrides):
    body = {"tool": actions.ROLLBACK_DEPLOYMENT, "namespace": NAMESPACE,
            "deployment": DEPLOYMENT}
    body.update(overrides)
    return client.post(f"/runs/{run_id}/actions", json=body, headers=headers)


# --- outcome 1: a read-only run is DENIED, and nothing happens --------------

def test_a_read_only_run_is_denied_and_the_cluster_is_never_touched(env, cluster):
    headers = _run(env, "sre", "r-deny", ["files:read"])
    r = _request(headers, "r-deny")
    assert r.status_code == 201
    row = r.json()
    assert row["decision"] == actions.DENIED
    assert row["decision_reason"] == actions.REASON_NO_WRITE_AUTHORITY
    # The result is DEFINITE, not absent: the console must never have to infer
    # "nothing happened" from a null.
    assert row["result"] == actions.NOT_ATTEMPTED
    # THE PROPERTY, not the response: zero mutations, and not even a read --
    # a denied action does not reach the cluster credential at all.
    assert cluster.writes == []
    assert cluster.reads == 0


def test_an_unscoped_run_is_denied_although_the_pdp_calls_it_unrestricted(env, cluster):
    """`scope is None` means NO SCOPE MODEL IS ACTIVE, which the PDP reads as
    unrestricted for ordinary operations -- and this endpoint asks the PDP,
    which duly permits.

    A consequential production change still requires a grant that NAMES it.
    Otherwise every run in every deployment that has never used scopes acquires
    the ability to roll back production the moment this ships: a security
    regression delivered as a feature, and invisible because each half is
    behaving as designed."""
    from andyur.server import pdp
    headers = _run(env, "sre", "r-unscoped", None)
    assert pdp.evaluate(pdp.Subject(type="run", id="r-unscoped", scope=None),
                        actions.SCOPE_ROLLBACK) is True
    row = _request(headers, "r-unscoped").json()
    assert row["decision"] == actions.DENIED
    assert row["decision_reason"] == actions.REASON_NO_WRITE_AUTHORITY
    assert cluster.writes == []


def test_a_target_outside_the_pin_is_denied_even_with_full_authority(env, cluster):
    """The pin is sealed in the signed grant, so a prompt-injected agent can
    change what it ASKS for and nothing about what it may have. An authorised
    run aiming at a deployment its grant does not name is denied by NAME, with
    the row saying which."""
    headers = _run(env, "sre", "r-elsewhere", [actions.SCOPE_ROLLBACK])
    row = _request(headers, "r-elsewhere", deployment="payments-service").json()
    assert row["decision"] == actions.DENIED
    assert row["decision_reason"] == actions.REASON_TARGET_NOT_PINNED
    assert row["target"] == "prod/payments-service"      # what it ASKED for, on record
    assert cluster.writes == []


def test_an_unpinned_run_cannot_perform_a_consequential_action(env, cluster):
    headers = _run(env, "sre", "r-nopin", [actions.SCOPE_ROLLBACK], pin=None)
    row = _request(headers, "r-nopin").json()
    assert row["decision"] == actions.DENIED
    assert row["decision_reason"] == actions.REASON_TARGET_NOT_PINNED
    assert cluster.writes == []


def test_a_denied_policy_refuses_an_otherwise_authorised_run(env, cluster, monkeypatch):
    """The PDP can only NARROW. It cannot supply authority the grant does not
    name (the test above), and when it refuses, an enumerated grant does not
    override it -- including when it refuses because it was unreachable, which
    `pdp` reads as a denial."""
    from andyur.server import pdp
    monkeypatch.setattr(pdp, "evaluate", lambda *a, **k: False)
    headers = _run(env, "sre", "r-policy", [actions.SCOPE_ROLLBACK])
    row = _request(headers, "r-policy").json()
    assert row["decision"] == actions.DENIED
    assert row["decision_reason"] == actions.REASON_POLICY_DENIED
    assert cluster.writes == []


# --- outcome 2: a write-authorised run rolls the deployment back ------------

def test_an_authorised_run_rolls_back_and_the_result_is_an_observation(env, cluster):
    headers = _run(env, "sre", "r-allow", ["files:read", actions.SCOPE_ROLLBACK])
    row = _request(headers, "r-allow").json()
    assert row["decision"] == actions.ALLOWED
    assert row["decision_reason"] == actions.REASON_WRITE_AUTHORIZED
    assert row["result"] == actions.SUCCEEDED
    # The write happened, with the PREVIOUS revision's template.
    assert len(cluster.writes) == 1
    namespace, deployment, template = cluster.writes[0]
    assert (namespace, deployment) == (NAMESPACE, DEPLOYMENT)
    assert template["spec"]["containers"][0]["image"] == "checkout:1.0"
    # And `succeeded` is a claim about the CLUSTER: the revision read back
    # afterwards is on the row, so the console renders an observation.
    assert "7 -> 8" in row["result_detail"]
    assert row["finished_at"] is not None


def test_a_write_the_cluster_does_not_honour_is_not_a_success(env, monkeypatch):
    """THE FALSE GREEN THIS LANE EXISTS TO PREVENT. The patch is accepted --
    no exception, no error status -- and the deployment does not move. A result
    derived from our own dispatch would say `succeeded`; a result derived from
    the read-back says what actually happened."""
    fake = FakeCluster(moves=False)
    monkeypatch.setattr(actionrequests, "_client_factory", lambda: fake)
    headers = _run(env, "sre", "r-nomove", [actions.SCOPE_ROLLBACK])
    row = _request(headers, "r-nomove").json()
    assert row["decision"] == actions.ALLOWED       # the decision was still allow
    assert row["result"] == actions.FAILED
    assert "did not roll back" in row["result_detail"]
    assert fake.writes, "the write was attempted; only the outcome differs"


def test_a_cluster_failure_is_recorded_as_failed_not_raised(env, monkeypatch):
    class Broken(FakeCluster):
        def patch_deployment_template(self, *a, **kw):
            raise RuntimeError("Forbidden: deployments.apps is forbidden")

    monkeypatch.setattr(actionrequests, "_client_factory", lambda: Broken())
    headers = _run(env, "sre", "r-broken", [actions.SCOPE_ROLLBACK])
    r = _request(headers, "r-broken")
    assert r.status_code == 201
    assert r.json()["result"] == actions.FAILED
    assert r.json()["result_detail"] == "cluster_error: rollback execution failed"


def test_privileged_backend_diagnostics_never_cross_back_to_the_run(env, monkeypatch,
                                                                  caplog):
    from kubernetes.client.exceptions import ApiException
    canary = "Bearer synthetic-cluster-secret-AR-005"

    class Broken(FakeCluster):
        def patch_deployment_template(self, *args, **kwargs):
            error = ApiException(status=422, reason="backend admission refused")
            error.body = json.dumps({"Authorization": canary})
            error.headers = {"X-Diagnostic": canary}
            raise error

    monkeypatch.setattr(actionrequests, "_client_factory", Broken)
    headers = _run(env, "sre", "r-private-error", [actions.SCOPE_ROLLBACK])
    response = _request(headers, "r-private-error")
    assert response.status_code == 201
    assert response.json()["result"] == actions.FAILED
    assert response.json()["result_detail"] == "cluster_error: rollback execution failed"
    with db.connect() as conn:
        stored = conn.execute("SELECT result_detail FROM action_requests WHERE id = ?",
                              (response.json()["id"],)).fetchone()["result_detail"]
    assert canary not in response.text + stored + caplog.text


# --- outcome 3: approval holds the action until a human consents ------------

def test_approval_required_holds_the_action_then_an_operator_releases_it(env, cluster):
    headers = _run(env, "sre", "r-appr", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    row = _request(headers, "r-appr").json()
    assert row["decision"] == actions.APPROVAL_REQUIRED
    assert row["decision_reason"] == actions.REASON_APPROVAL_POLICY
    # WAITING means the cluster has not been touched. This is the assertion an
    # "approval required" badge in a console is worth nothing without.
    assert cluster.writes == []
    assert row["result"] is None and row["approved_by"] is None

    approved = client.post(f"/runs/r-appr/actions/{row['id']}/approve",
                           json={"approver": "alice"})
    assert approved.status_code == 200
    after = approved.json()
    assert after["decision"] == actions.ALLOWED
    assert after["decision_reason"] == actions.REASON_APPROVED
    assert after["result"] == actions.SUCCEEDED
    # WHO, AND SAYS WHO. Never the bare name: an approver rendered without
    # provenance claims an identity was proven when it was asserted.
    assert after["approved_by"] == "alice"
    assert after["approved_by_asserted_by"] == "operator_api"
    assert after["approved_at"] is not None
    assert len(cluster.writes) == 1


def test_an_approval_with_nobody_s_name_on_it_is_refused(env, cluster):
    headers = _run(env, "sre", "r-anon", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    row = _request(headers, "r-anon").json()
    r = client.post(f"/runs/r-anon/actions/{row['id']}/approve", json={})
    assert r.status_code == 422
    assert cluster.writes == []


def test_the_same_approval_cannot_execute_twice(env, cluster):
    headers = _run(env, "sre", "r-twice", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    row = _request(headers, "r-twice").json()
    first = client.post(f"/runs/r-twice/actions/{row['id']}/approve",
                        json={"approver": "alice"})
    second = client.post(f"/runs/r-twice/actions/{row['id']}/approve",
                         json={"approver": "mallory"})
    assert first.status_code == 200 and second.status_code == 409
    # ONE rollback, not two: the compare-and-swap on the decision is what makes
    # a double-click, a retry or a race a single consequential action.
    assert len(cluster.writes) == 1


def test_approval_cannot_be_granted_to_an_action_that_was_denied(env, cluster):
    headers = _run(env, "sre", "r-denied", ["files:read"])
    row = _request(headers, "r-denied").json()
    r = client.post(f"/runs/r-denied/actions/{row['id']}/approve",
                    json={"approver": "alice"})
    assert r.status_code == 409, "approval must never launder a denial"
    assert cluster.writes == []


def test_an_agent_cannot_approve_its_own_action(env, cluster):
    """The one property the whole approval outcome rests on. The endpoint is
    operator-gated, and `auth.require` refuses a run token in EVERY
    configuration -- so this is not a rule the agent is asked to respect."""
    headers = _run(env, "sre", "r-self", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    row = _request(headers, "r-self").json()
    r = client.post(f"/runs/r-self/actions/{row['id']}/approve",
                    json={"approver": "sre"}, headers=headers)
    assert r.status_code == 403
    assert cluster.writes == []


# --- who may ask, and who may read -----------------------------------------

def test_an_operator_cannot_forge_a_request_on_the_run_s_behalf(env, cluster):
    _run(env, "sre", "r-op", [actions.SCOPE_ROLLBACK])
    r = client.post("/runs/r-op/actions",
                    json={"tool": actions.ROLLBACK_DEPLOYMENT,
                          "namespace": NAMESPACE, "deployment": DEPLOYMENT})
    assert r.status_code == 403
    assert client.get("/runs/r-op/actions").json() == []


def test_a_run_cannot_request_an_action_for_another_run(env, cluster):
    headers = _run(env, "sre", "r-mine", [actions.SCOPE_ROLLBACK])
    env.agent("other")
    with db.connect() as c:
        c.execute("INSERT INTO runs (id, agent, state, created_at) "
                  "VALUES ('r-theirs', 'other', 'running', ?)", (db.utcnow(),))
    assert _request(headers, "r-theirs").status_code == 403
    assert cluster.writes == []


def test_only_the_one_remediation_is_admitted(env, cluster):
    headers = _run(env, "sre", "r-tool", [actions.SCOPE_ROLLBACK])
    r = _request(headers, "r-tool", tool="delete_namespace")
    assert r.status_code == 422, "an unknown tool is REFUSED, never decided"
    assert client.get("/runs/r-tool/actions").json() == []
    assert cluster.writes == []


def test_a_target_that_needs_cleaning_is_refused_without_a_row(env, cluster):
    headers = _run(env, "sre", "r-bad", [actions.SCOPE_ROLLBACK])
    assert _request(headers, "r-bad", deployment="checkout; rm -rf /").status_code == 422
    assert client.get("/runs/r-bad/actions").json() == []


def test_nothing_requested_and_evidence_unavailable_are_different_answers(env):
    """`[]` for a run that asked for nothing; 404 for a run that does not exist.
    A console that cannot tell them apart renders the second as the first."""
    _run(env, "sre", "r-empty", [actions.SCOPE_ROLLBACK])
    assert client.get("/runs/r-empty/actions").status_code == 200
    assert client.get("/runs/r-empty/actions").json() == []
    assert client.get("/runs/does-not-exist/actions").status_code == 404


def test_the_console_can_render_the_whole_story_from_the_api(env, cluster):
    """THE EXIT CRITERION, as an assertion: incident, actor, resource,
    diagnosis, requested, decision, approver, result and trace -- every field
    the console's story panel reads, from HTTP alone, with no database, no
    kubectl and no Jaeger."""
    headers = _run(env, "sre", "r-story", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    row = _request(headers, "r-story").json()
    client.post(f"/runs/r-story/actions/{row['id']}/approve", json={"approver": "alice"})

    run = client.get("/runs/r-story").json()
    assert json.loads(run["input"])["incident"] == "INC-4471"     # incident
    assert json.loads(run["subject_context"]) == PIN              # resource
    assert run["pin_asserted_by"] == "user:alice"                 # its provenance
    action = client.get("/runs/r-story/actions").json()[-1]
    assert action["tool"] == actions.ROLLBACK_DEPLOYMENT          # requested
    assert action["target"] == f"{NAMESPACE}/{DEPLOYMENT}"
    assert action["decision"] in actions.DECISIONS                # decision
    assert action["decision_reason"] in actions.REASONS
    assert action["approved_by_asserted_by"] == "operator_api"    # approver
    assert action["result"] == actions.SUCCEEDED                  # result
    assert "->" in action["result_detail"]                        # the observation


def test_the_row_carries_no_field_the_projection_did_not_name(env, cluster):
    """`action_view` lists what a client may see, so a column added later is a
    decision rather than an accident -- the argument `_RUN_WITHHELD` settled
    for runs, applied to the table this lane adds."""
    headers = _run(env, "sre", "r-fields", [actions.SCOPE_ROLLBACK])
    row = _request(headers, "r-fields").json()
    with db.connect() as c:
        columns = {d[0] for d in c.execute(
            "SELECT * FROM action_requests LIMIT 1").description}
    assert set(row) == set(actionrequests._VIEW_FIELDS)
    assert columns - set(row) == actionrequests._WITHHELD_FIELDS


# --- the budget: the agent is what drives this endpoint --------------------

def test_a_run_cannot_request_consequential_actions_without_limit(env, cluster,
                                                                  monkeypatch):
    """FOUND IN REVIEW, not by a failing test. There was no bound, and the
    caller here is the AGENT. Two costs: unbounded rows in a server-owned
    table, and -- worse -- an ALLOWED action EXECUTES, so an authorised run
    could ask for the same rollback in a loop and be obeyed every time, each
    one holding a request thread for as long as the read-back watches the
    cluster. A stuck agent retrying a tool call produces both."""
    monkeypatch.setattr(actionrequests, "MAX_ACTIONS_PER_RUN", 3)
    headers = _run(env, "sre", "r-loop", [actions.SCOPE_ROLLBACK])
    for _ in range(3):
        assert _request(headers, "r-loop").status_code == 201
    spent = _request(headers, "r-loop")
    # 429: the request is well formed and would have been decided on its merits
    # a moment earlier. It is the RATE that is refused.
    assert spent.status_code == 429
    assert len(client.get("/runs/r-loop/actions").json()) == 3
    assert len(cluster.writes) == 3, "the cap must stop the EXECUTION, not just the row"


def test_denied_requests_spend_the_budget_too(env, cluster, monkeypatch):
    """The row is the cost, so a denial counts. Otherwise a read-only run --
    the one most likely to be compromised, since it is the one that gets
    denied -- has an unbounded write into a server-owned table."""
    monkeypatch.setattr(actionrequests, "MAX_ACTIONS_PER_RUN", 2)
    headers = _run(env, "sre", "r-denied-loop", ["files:read"])
    assert _request(headers, "r-denied-loop").status_code == 201
    assert _request(headers, "r-denied-loop").status_code == 201
    assert _request(headers, "r-denied-loop").status_code == 429
    assert cluster.writes == []


def test_the_budget_is_per_run_not_per_agent(env, cluster, monkeypatch):
    """A run is the unit of authority here, so it is the unit of the budget.
    Per-agent would make one run's exhaustion silence the next legitimate one."""
    monkeypatch.setattr(actionrequests, "MAX_ACTIONS_PER_RUN", 1)
    first = _run(env, "sre-a", "r-first", [actions.SCOPE_ROLLBACK])
    assert _request(first, "r-first").status_code == 201
    assert _request(first, "r-first").status_code == 429
    second = _run(env, "sre-b", "r-second", [actions.SCOPE_ROLLBACK])
    assert _request(second, "r-second").status_code == 201
