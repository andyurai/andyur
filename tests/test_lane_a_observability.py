"""Every consequential decision is on ITS OWN span, by name.

The operator's 2026-08-26 rule is that a feature is not done without a live
trace proof, and the action contract §8 names five spans: the request, the
decision, the approval, the execution and the read-back. These drive the real
OTel SDK through an in-memory exporter and assert what a trace actually
carries.

THE DEFECT THESE EXIST FOR was found by the live gate, not by a unit test:
`_record_decision` took the AMBIENT span (`trace.get_current_span()`), so three
decisions in one process overwrote each other on whatever unrelated span the
caller happened to have open -- and with no span open at all, on a no-op. The
gate asked the trace what had been decided and got back nothing. A reader could
not tell which decision belonged to which action, which is the whole point of
recording it.
"""

import copy
import json
import time

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from andyur import actions, db
from andyur.server import actionrequests

NAMESPACE, DEPLOYMENT = "prod", "checkout-service"
PIN = {"namespace": NAMESPACE, "deployment": DEPLOYMENT}


class _Cluster:
    def __init__(self):
        self.revision = "7"
        self.generation = 7
        self.template = {"spec": {"containers": [{"name": "app", "image": "bad"}]}}

    def read_deployment(self, namespace, deployment):
        return {"metadata": {"uid": "u", "resourceVersion": str(self.generation),
                             "generation": self.generation, "annotations": {
            "deployment.kubernetes.io/revision": self.revision}},
                "spec": {"template": copy.deepcopy(self.template)},
                "status": {"observedGeneration": int(self.revision)}}

    def list_replicasets(self, namespace, deployment, *, owner):
        return [{"metadata": {"annotations": {
            "deployment.kubernetes.io/revision": "6"}},
            "spec": {"template": {"spec": {"containers": [{"name": "app"}]}}}}]

    def patch_deployment_template(self, namespace, deployment, template, *, expected):
        self.template = copy.deepcopy(template)
        self.generation += 1
        self.revision = "8"
        return self.read_deployment(namespace, deployment)


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(actionrequests, "OBSERVE_SECONDS", 0)


@pytest.fixture
def spans(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(actionrequests, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(actionrequests, "_client_factory", _Cluster)
    return exporter.get_finished_spans


def _run(env, agent, run_id):
    env.agent(agent)
    with db.connect() as c:
        c.execute("INSERT INTO runs (id, agent, state, created_at, subject_context) "
                  "VALUES (?, ?, 'running', ?, ?)",
                  (run_id, agent, db.utcnow(), json.dumps(PIN)))
    return run_id


def _named(spans, name):
    return [s for s in spans() if s.name == name]


def test_the_decision_is_on_a_span_of_its_own(env, spans):
    """Not on the caller's ambient span, and not on a no-op: the decision has a
    span named for it, carrying the outcome and the reason BY NAME."""
    run_id = _run(env, "sre", "r-1")
    actionrequests.request(run_id, actions.ROLLBACK_DEPLOYMENT, NAMESPACE,
                           DEPLOYMENT, granted_scope=["files:read"], pin=PIN,
                           grant_expires_at=int(time.time()) + 60)
    (decide,) = _named(spans, "action.decide")
    assert dict(decide.attributes)["andyur.action_decision"] == actions.DENIED
    assert dict(decide.attributes)["andyur.action_reason"] == \
        actions.REASON_NO_WRITE_AUTHORITY
    assert decide.attributes["andyur.agent_id"] == "sre"
    assert decide.attributes["andyur.component"] == "action-requests"


def test_two_decisions_in_one_process_do_not_overwrite_each_other(env, spans):
    """THE EXACT REGRESSION. One process, two runs, two different decisions:
    each must be readable on its own span afterwards. With the ambient-span
    version the second overwrote the first and the trace claimed one decision
    had been made twice."""
    denied = _run(env, "sre-a", "r-a")
    allowed = _run(env, "sre-b", "r-b")
    actionrequests.request(denied, actions.ROLLBACK_DEPLOYMENT, NAMESPACE,
                           DEPLOYMENT, granted_scope=["files:read"], pin=PIN,
                           grant_expires_at=int(time.time()) + 60)
    actionrequests.request(allowed, actions.ROLLBACK_DEPLOYMENT, NAMESPACE,
                           DEPLOYMENT, granted_scope=[actions.SCOPE_ROLLBACK],
                           pin=PIN, grant_expires_at=int(time.time()) + 60)
    decisions = [dict(s.attributes)["andyur.action_decision"]
                 for s in _named(spans, "action.decide")]
    assert decisions == [actions.DENIED, actions.ALLOWED]


def test_the_execution_and_its_result_are_their_own_span(env, spans):
    run_id = _run(env, "sre", "r-2")
    actionrequests.request(run_id, actions.ROLLBACK_DEPLOYMENT, NAMESPACE,
                           DEPLOYMENT, granted_scope=[actions.SCOPE_ROLLBACK],
                           pin=PIN, grant_expires_at=int(time.time()) + 60)
    (perform,) = _named(spans, "action.perform")
    attributes = dict(perform.attributes)
    assert attributes["andyur.action_result"] == actions.SUCCEEDED
    assert attributes["andyur.operation"] == "rollback"
    # The OBSERVED revision, because that is the evidence for the result. It is
    # a cluster value matched against a shape first: "it came from the cluster"
    # is not the same statement as "it is bounded".
    assert attributes["andyur.observed_revision"] == "8"
    assert attributes["andyur.run_id"] == run_id
    assert attributes["andyur.agent_id"] == "sre"
    assert attributes["andyur.rollback_reason"] == "rollback_applied"
    observed = [event for event in perform.events if event.name == "rollback.observed"]
    assert len(observed) == 1
    assert observed[0].attributes["andyur.rollback_reason"] == "rollback_applied"
    assert observed[0].attributes["andyur.duration_ms"] >= 0


@pytest.mark.parametrize("defect,reason", [
    ("uid", "deployment_replaced"),
    ("template", "rollback_target_changed"),
    ("observed", "controller_not_observed"),
])
def test_false_success_has_named_observation_and_latency(env, spans, monkeypatch,
                                                       defect, reason):
    class Interference(_Cluster):
        def read_deployment(self, namespace, deployment):
            state = super().read_deployment(namespace, deployment)
            if self.revision == "8" and getattr(self, "patched", False):
                if defect == "uid":
                    state["metadata"]["uid"] = "replacement"
                elif defect == "template":
                    state["spec"]["template"]["spec"]["extra"] = True
                else:
                    state["status"]["observedGeneration"] = 7
            return state

        def patch_deployment_template(self, *args, **kwargs):
            result = super().patch_deployment_template(*args, **kwargs)
            self.patched = True
            return result

    monkeypatch.setattr(actionrequests, "_client_factory", Interference)
    metrics = []
    monkeypatch.setattr(actionrequests.otel, "try_record_metric",
                        lambda *args, **kwargs: metrics.append((args, kwargs)))
    run_id = _run(env, "sre", "r-observed")
    row = actionrequests.request(
        run_id, actions.ROLLBACK_DEPLOYMENT, NAMESPACE, DEPLOYMENT,
        granted_scope=[actions.SCOPE_ROLLBACK], pin=PIN,
        grant_expires_at=int(time.time()) + 60)
    assert row["result"] == actions.FAILED
    (perform,) = _named(spans, "action.perform")
    assert perform.attributes["andyur.rollback_reason"] == reason
    events = [e for e in perform.events if e.name == "rollback.observed"]
    assert len(events) == 1 and events[0].attributes["andyur.rollback_reason"] == reason
    waits = [(a, k) for a, k in metrics if a[1] == "andyur.action.observation_seconds"]
    assert len(waits) == 1 and waits[0][0][2] >= 0
    assert waits[0][1] == {"andyur__rollback_reason": reason}


def test_the_approval_is_its_own_span_too(env, spans):
    run_id = _run(env, "sre", "r-3")
    row = actionrequests.request(
        run_id, actions.ROLLBACK_DEPLOYMENT, NAMESPACE, DEPLOYMENT,
        granted_scope=[actions.SCOPE_ROLLBACK_WITH_APPROVAL], pin=PIN,
        grant_expires_at=int(time.time()) + 60)
    assert not _named(spans, "action.perform"), "held, so nothing was performed"
    actionrequests.approve(row["id"], "alice", "operator_api")
    (approve,) = _named(spans, "action.approve")
    assert dict(approve.attributes)["andyur.action_decision"] == actions.ALLOWED
    assert dict(approve.attributes)["andyur.action_reason"] == actions.REASON_APPROVED
    assert approve.attributes["andyur.agent_id"] == "sre"
    assert _named(spans, "action.perform"), "and only then was it performed"


def test_stale_approval_denial_is_a_named_exported_decision(env, spans):
    run_id = _run(env, "sre", "r-stale")
    row = actionrequests.request(
        run_id, actions.ROLLBACK_DEPLOYMENT, NAMESPACE, DEPLOYMENT,
        granted_scope=[actions.SCOPE_ROLLBACK_WITH_APPROVAL], pin=PIN,
        grant_expires_at=int(time.time()) + 60)
    with db.connect() as conn:
        conn.execute("UPDATE runs SET state = 'cancelled' WHERE id = ?", (run_id,))
    result = actionrequests.approve(row["id"], "alice", "operator_api")
    assert result["result"] == actions.NOT_ATTEMPTED
    (approval,) = _named(spans, "action.approve")
    assert approval.attributes["andyur.action_decision"] == actions.DENIED
    assert approval.attributes["andyur.action_reason"] == actions.REASON_RUN_INACTIVE
    assert approval.attributes["andyur.run_id"] == run_id
    assert approval.attributes["andyur.action_result"] == actions.NOT_ATTEMPTED
    assert not _named(spans, "action.perform")


def test_no_span_carries_the_target_or_the_vendor_s_words(env, spans, monkeypatch):
    """Vendor errors become neither telemetry nor agent-readable row text."""
    class Broken(_Cluster):
        def patch_deployment_template(self, *a, **kw):
            raise RuntimeError("Forbidden: user cannot patch deployments in prod")

    monkeypatch.setattr(actionrequests, "_client_factory", Broken)
    run_id = _run(env, "sre", "r-4")
    row = actionrequests.request(
        run_id, actions.ROLLBACK_DEPLOYMENT, NAMESPACE, DEPLOYMENT,
        granted_scope=[actions.SCOPE_ROLLBACK], pin=PIN,
        grant_expires_at=int(time.time()) + 60)
    assert row["result_detail"] == "cluster_error: rollback execution failed"
    for span in spans():
        flat = json.dumps({k: str(v) for k, v in dict(span.attributes).items()})
        assert DEPLOYMENT not in flat and "Forbidden" not in flat, span.name
