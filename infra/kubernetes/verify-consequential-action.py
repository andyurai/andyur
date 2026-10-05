#!/usr/bin/env python3
"""The consequential action, against a REAL Kubernetes cluster.

Board rows 9-12, and the three outcomes the MVP claims: a read-only run is
DENIED and the cluster is untouched; a write-authorised run rolls a real
Deployment back; an approval-gated run WAITS until a human consents and only
then moves the cluster. Each is asserted against the API server's own view,
before and after, not against what Andyur returned about itself.

WHAT THIS GATE PROVES, and what it deliberately does not:

  PROVES   the decision path (`andyur.actions`), the durable row and its
           closed vocabularies (`andyur.server.actionrequests`), the rollback
           mechanism and its read-back (`andyur.rollback`), and the cluster
           adapter (`andyur.server.kubernetes_deployments`) against real k3s.
           The authority and the target are read from a real SIGNED RUN GRANT
           (`runtoken.mint` -> `runtoken.verify`), never passed in by hand, so
           the property "the agent cannot influence the decision" is exercised
           rather than assumed.
  DOES NOT the HTTP boundary and its identity checks. Those need SPIRE and the
           containerised control plane; they are covered in-suite against the
           real ASGI app and real `auth.require`/`require_run` (only the SVID
           cryptography is stubbed), in tests/test_lane_a_action_api.py. This
           gate says so in `not_covered` rather than implying otherwise.

A FAILED OR LUCKY RUN IS NEVER RECORDED: the artifact is written only when
every assertion held, and the namespace it created is deleted either way.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# The gate owns its own data directory: it must never write into a developer's
# database, and `andyur.config` reads this at import time.
_DATA = tempfile.mkdtemp(prefix="andyur-lane-a-gate-")
os.environ["ANDYUR_DATA_DIR"] = _DATA
os.environ.pop("ANDYUR_DB_URL", None)
os.environ["ANDYUR_PROFILE"] = "dev"
os.environ["ANDYUR_AGENT_AUTH"] = "on"
os.environ.setdefault("ANDYUR_RUN_TOKEN_SECRET", secrets.token_hex(16))
# Telemetry ON, because "every decision is a span" is an exit criterion and a
# gate that leaves it off cannot prove it (operator's rule, 2026-08-26).
os.environ["ANDYUR_OTEL"] = "on"
OTLP = os.environ.setdefault("ANDYUR_OTEL_ENDPOINT", "http://localhost:4318")
JAEGER = os.environ.get("ANDYUR_JAEGER_URL", "http://localhost:16686")
# The platform reaches the cluster with ITS OWN credential, resolved exactly as
# in production (the Pod's ServiceAccount) unless an operator opts into a host
# kubeconfig -- which is what a host-run gate is. Set explicitly rather than
# inherited: without it the adapter tries in-cluster config and fails with
# "Service host/port is not set", which the gate correctly recorded as a FAILED
# action rather than a crash, and which is how this line came to exist.
os.environ.setdefault("ANDYUR_KUBECONFIG",
                      os.environ.get("KUBECONFIG")
                      or os.path.expanduser("~/.kube/config"))

from andyur import actions, db, otel, rollback, runinput          # noqa: E402
from andyur.server import (actionrequests, coordinator,           # noqa: E402
                           kubernetes_deployments, runtoken)
from action_gate_resources import delete_owned                  # noqa: E402

GOOD_IMAGE = os.environ.get("ANDYUR_GATE_GOOD_IMAGE", "registry.k8s.io/pause:3.9")
BAD_IMAGE = os.environ.get("ANDYUR_GATE_BAD_IMAGE", "registry.k8s.io/pause:3.10")
DEPLOYMENT = "checkout-service"
INCIDENT = {"incident": "INC-4471",
            "detail": "checkout latency and 5xx since the last deploy"}
# The files whose behaviour this gate exercises. Recorded as hashes so the
# artifact goes STALE the moment any of them changes, and the gate has to be
# re-run before the claim is made again (infra/rc/evidence_currency.py).
EXECUTED = (
    "andyur/actions.py",
    "andyur/rollback.py",
    "andyur/server/actionrequests.py",
    "andyur/server/kubernetes_deployments.py",
    "andyur/server/runtoken.py",
    "andyur/server/pdp.py",
    "andyur/db.py",
    "andyur/observability.py",
    "infra/kubernetes/action_gate_resources.py",
    "infra/kubernetes/verify-consequential-action.py",
)

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
_failures: list[str] = []


def check(condition, description: str) -> bool:
    print(f"  {PASS if condition else FAIL} {description}")
    if not condition:
        _failures.append(description)
    return bool(condition)


def say(heading: str) -> None:
    print(f"\n\033[1m== {heading} ==\033[0m")


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


# --- the cluster fixture ----------------------------------------------------

def kube():
    from kubernetes import client, config
    kubeconfig = os.environ.get("ANDYUR_KUBECONFIG")
    if kubeconfig:
        config.load_kube_config(config_file=kubeconfig, context="rancher-desktop")
    else:
        config.load_kube_config(context="rancher-desktop")
    api = client.ApiClient()
    return client.CoreV1Api(api), client.AppsV1Api(api), client.VersionApi(api)


def deployment_state(apps, namespace: str) -> dict:
    """What the API SERVER says, which is the only thing this gate believes."""
    raw = json.loads(apps.read_namespaced_deployment(
        DEPLOYMENT, namespace, _preload_content=False).data)
    return {
        "revision": ((raw["metadata"].get("annotations") or {})
                     .get(rollback.REVISION)),
        "generation": raw["metadata"].get("generation"),
        "uid": raw["metadata"]["uid"],
        "template": kubernetes_deployments.strip_template_hash(raw["spec"]["template"]),
        "image": raw["spec"]["template"]["spec"]["containers"][0]["image"],
    }


def wait_for_revision(apps, namespace: str, expected: str, timeout: float = 60) -> dict:
    deadline = time.time() + timeout
    state = deployment_state(apps, namespace)
    while state["revision"] != expected and time.time() < deadline:
        time.sleep(0.5)
        state = deployment_state(apps, namespace)
    return state


def create_fixture(core, apps, namespace: str) -> dict:
    """A deployment with a HISTORY: revision 1 good, revision 2 the bad deploy
    that caused INC-4471. A single-revision deployment has nowhere to roll back
    to, so the fixture is the incident."""
    apps.create_namespaced_deployment(namespace, {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "labels": {"app": "checkout"}},
        "spec": {
            "replicas": 0,
            "revisionHistoryLimit": 5,
            "selector": {"matchLabels": {"app": "checkout"}},
            "template": {
                "metadata": {"labels": {"app": "checkout"}},
                "spec": {"containers": [{"name": "app", "image": GOOD_IMAGE}],
                         "terminationGracePeriodSeconds": 0},
            },
        },
    })
    wait_for_revision(apps, namespace, "1")
    good_template = deployment_state(apps, namespace)["template"]
    break_it(apps, namespace)
    return good_template


def break_it(apps, namespace: str) -> dict:
    """The bad deploy. Every rollback in this gate is a rollback of THIS."""
    apps.patch_namespaced_deployment(
        DEPLOYMENT, namespace,
        {"spec": {"template": {
            "metadata": {"labels": {"bad-release": "true"}},
            "spec": {"serviceAccountName": "bad-release-account", "containers": [
                {"name": "app", "image": BAD_IMAGE,
                 "env": [{"name": "BAD_RELEASE", "value": "true"}]},
                {"name": "bad-sidecar", "image": BAD_IMAGE}]}}}})
    time.sleep(1)
    return deployment_state(apps, namespace)


# --- the run, admitted the way the platform admits runs ---------------------

def make_run(agent: str, scope: list[str], pin: dict) -> tuple[str, dict]:
    """A run with a real sealed grant, and the ctx a run token proves.

    The scope and the pin are read back out of a MINTED AND VERIFIED run token
    rather than passed straight through, because that is the path the product
    takes: the decision reads the authority from a signature the agent cannot
    forge. A gate that handed the decision its inputs directly would prove the
    arithmetic and not the property.
    """
    with db.connect() as conn:
        conn.execute("INSERT INTO agents (name, description, paused, created_at) "
                     "VALUES (?, '', 0, ?)", (agent, db.utcnow()))
    run_id = coordinator.maybe_wakeup(
        agent, "INC-4471 checkout errors", "work",
        trace_ctx=otel.current_traceparent(), user="alice", scope=scope,
        subject_context=pin, pin_asserted_by="user:alice",
        run_input=runinput.seal(INCIDENT))
    token = runtoken.mint(agent, run_id, None, scope=scope, pin=pin)
    return run_id, runtoken.verify(token)


def main() -> int:
    namespace = f"andyur-action-{secrets.token_hex(8)}"
    namespace_uid = None
    trace_ctx = None
    pin = {"namespace": namespace, "deployment": DEPLOYMENT}
    tracer = otel.setup_tracing("andyur-server")
    core, apps, version = kube()
    cluster_version = version.get_code().git_version
    result: dict = {"gate": "consequential-action",
                    "host": platform.platform(),
                    "cluster_version": cluster_version,
                    "namespace": namespace,
                    "images": {"good": GOOD_IMAGE, "bad": BAD_IMAGE},
                    "started_at_epoch": time.time()}
    db.init_db()
    # Andyur reaches the cluster with ITS OWN credential, resolved exactly as it
    # is in production (in-cluster ServiceAccount) or, here, from the operator's
    # kubeconfig. The agent has none and never will.
    # The real SDK client is pinned to the selected context once. Do not reread
    # mutable global kubeconfig between fixture creation and enforcement.
    def adapter():
        bound = kubernetes_deployments.DeploymentsApi.__new__(
            kubernetes_deployments.DeploymentsApi)
        bound._apps = apps
        return bound
    actionrequests._client_factory = adapter

    try:
        say(f"0. fixture: {namespace}/{DEPLOYMENT}, one bad deploy")
        namespace_uid = core.create_namespace(
            {"metadata": {"name": namespace}}, _request_timeout=10).metadata.uid
        good_template = create_fixture(core, apps, namespace)
        broken = wait_for_revision(apps, namespace, "2")
        check(broken["revision"] == "2", f"the incident is live at revision "
                                         f"{broken['revision']} on {broken['image']}")
        result["incident_state"] = broken

        with tracer.start_as_current_span("gate consequential-action") as span:
            trace_ctx = otel.current_traceparent()
            span.set_attribute("andyur.gate", "consequential-action")

            say("0b. API-server identity/version preconditions reject stale writes")
            from kubernetes.client.exceptions import ApiException
            bound = adapter()
            snapshot = bound.read_deployment(namespace, DEPLOYMENT)
            preconditions = {}
            for field in ("uid", "resourceVersion"):
                stale = json.loads(json.dumps(snapshot))
                stale["metadata"][field] = "not-the-live-value"
                try:
                    bound.patch_deployment_template(namespace, DEPLOYMENT,
                                                    good_template, expected=stale)
                except ApiException as exc:
                    status = exc.status
                else:
                    status = 200
                unchanged = deployment_state(apps, namespace) == broken
                check(status in (409, 422) and unchanged,
                      f"wrong {field}: HTTP {status}, unchanged={unchanged}")
                preconditions[field] = {"status": status, "unchanged": unchanged}
            result["atomic_preconditions"] = preconditions

            # --- 1. DENY -------------------------------------------------
            say("1. a read-only run requests a rollback")
            before = deployment_state(apps, namespace)
            _, ctx = make_run("sre-readonly", ["deployments:read"], pin)
            denied = actionrequests.request(
                ctx["run_id"], actions.ROLLBACK_DEPLOYMENT, namespace, DEPLOYMENT,
                granted_scope=ctx["scope"], pin=ctx["pin"],
                grant_expires_at=ctx["expires_at"])
            check(denied["decision"] == actions.DENIED
                  and denied["decision_reason"] == actions.REASON_NO_WRITE_AUTHORITY,
                  f"decision {denied['decision']} ({denied['decision_reason']})")
            check(denied["result"] == actions.NOT_ATTEMPTED,
                  "the result is definite, not absent")
            time.sleep(2)
            after = deployment_state(apps, namespace)
            # THE ASSERTION THAT MATTERS: not that we answered "denied", but
            # that the cluster is byte-for-byte where it was. Generation counts
            # every accepted spec write, so an attempted-and-reverted change
            # would show here even if the revision did not move.
            check(after == before, f"the cluster did not move: {after}")
            result["denied"] = {"row": denied, "before": before, "after": after,
                                "cluster_unchanged": after == before}

            # --- 2. ALLOW ------------------------------------------------
            say("2. a write-authorised run requests the same rollback")
            before = deployment_state(apps, namespace)
            _, ctx = make_run("sre-authorized",
                              ["deployments:read", actions.SCOPE_ROLLBACK], pin)
            allowed = actionrequests.request(
                ctx["run_id"], actions.ROLLBACK_DEPLOYMENT, namespace, DEPLOYMENT,
                granted_scope=ctx["scope"], pin=ctx["pin"],
                grant_expires_at=ctx["expires_at"])
            check(allowed["decision"] == actions.ALLOWED
                  and allowed["decision_reason"] == actions.REASON_WRITE_AUTHORIZED,
                  f"decision {allowed['decision']} ({allowed['decision_reason']})")
            check(allowed["result"] == actions.SUCCEEDED,
                  f"result {allowed['result']}: {allowed['result_detail']}")
            after = wait_for_revision(apps, namespace, "3")
            check(after["revision"] != before["revision"],
                  f"the cluster moved: revision {before['revision']} -> "
                  f"{after['revision']}")
            check(after["image"] == GOOD_IMAGE,
                  f"the deployment is back on {after['image']}")
            check(after["template"] == good_template,
                  "exact good template restored: no bad sidecar/env/account/labels")
            # `succeeded` is an OBSERVATION: the revision the platform recorded
            # is the revision the API server reports, not a number we chose.
            check(after["revision"] in (allowed["result_detail"] or ""),
                  f"the recorded detail names the observed revision: "
                  f"{allowed['result_detail']!r}")
            result["allowed"] = {"row": allowed, "before": before, "after": after}

            # --- 3. APPROVAL ---------------------------------------------
            say("3. an approval-gated run requests it, and WAITS")
            rebroken = break_it(apps, namespace)
            before = wait_for_revision(apps, namespace, "4")
            check(before["image"] == BAD_IMAGE, "the incident is live again")
            _, ctx = make_run("sre-approval",
                              [actions.SCOPE_ROLLBACK_WITH_APPROVAL], pin)
            held = actionrequests.request(
                ctx["run_id"], actions.ROLLBACK_DEPLOYMENT, namespace, DEPLOYMENT,
                granted_scope=ctx["scope"], pin=ctx["pin"],
                grant_expires_at=ctx["expires_at"])
            check(held["decision"] == actions.APPROVAL_REQUIRED
                  and held["decision_reason"] == actions.REASON_APPROVAL_POLICY,
                  f"decision {held['decision']} ({held['decision_reason']})")
            time.sleep(2)
            waiting = deployment_state(apps, namespace)
            check(waiting == before,
                  "WAITING means the cluster is untouched, not that a badge says so")
            approved = actionrequests.approve(held["id"], "alice", "operator_api")
            check(approved["decision"] == actions.ALLOWED
                  and approved["decision_reason"] == actions.REASON_APPROVED,
                  f"after approval: {approved['decision']} "
                  f"({approved['decision_reason']})")
            check(approved["approved_by"] == "alice"
                  and approved["approved_by_asserted_by"] == "operator_api",
                  "the approver is recorded WITH how the identity was established")
            after = wait_for_revision(apps, namespace, "5")
            check(approved["result"] == actions.SUCCEEDED
                  and after["image"] == GOOD_IMAGE,
                  f"only then did the cluster move: {before['revision']} -> "
                  f"{after['revision']} on {after['image']}")
            check(after["template"] == good_template,
                  "approved rollback also restores the complete intended template")
            result["approval_required"] = {
                "row": held, "approved": approved, "before": before,
                "while_waiting": waiting, "after": after,
                "cluster_unchanged_while_waiting": waiting == before,
                "rebroken": rebroken}

            # --- 4. the row an operator reads ----------------------------
            say("4. the whole story is readable from the platform's own records")
            rows = actionrequests.list_for_run(ctx["run_id"])
            check(len(rows) == 1 and rows[0]["id"] == held["id"],
                  "the run's action is listed by run id (what GET "
                  "/runs/{run_id}/actions serves)")
            check(all(row["decision"] in actions.DECISIONS
                      and row["decision_reason"] in actions.REASONS
                      and (row["result"] is None or row["result"] in actions.RESULTS)
                      for row in rows),
                  "every recorded value is inside the closed vocabularies")

            say("4b. a cancelled run's queued approval cannot mutate Kubernetes")
            _, stale_ctx = make_run("sre-cancelled",
                                    [actions.SCOPE_ROLLBACK_WITH_APPROVAL], pin)
            stale = actionrequests.request(
                stale_ctx["run_id"], actions.ROLLBACK_DEPLOYMENT, namespace, DEPLOYMENT,
                granted_scope=stale_ctx["scope"], pin=stale_ctx["pin"],
                grant_expires_at=stale_ctx["expires_at"])
            before_cancel = deployment_state(apps, namespace)
            with db.connect() as conn:
                conn.execute("UPDATE runs SET state='cancelled' WHERE id=?",
                             (stale_ctx["run_id"],))
            refused = actionrequests.approve(stale["id"], "alice", "operator_api")
            unchanged = deployment_state(apps, namespace) == before_cancel
            check(refused["decision_reason"] == actions.REASON_RUN_INACTIVE
                  and refused["result"] == actions.NOT_ATTEMPTED and unchanged,
                  "cancelled approval denied by name, actual cluster unchanged")
            result["cancelled_approval"] = {"row": refused, "cluster_unchanged": unchanged}

            say("4c. a concurrent release cannot masquerade as successful rollback")
            break_it(apps, namespace)
            wait_for_revision(apps, namespace, "6")

            class Interfered(kubernetes_deployments.DeploymentsApi):
                def patch_deployment_template(self, *args, **kwargs):
                    patched = super().patch_deployment_template(*args, **kwargs)
                    apps.patch_namespaced_deployment(DEPLOYMENT, namespace, {
                        "spec": {"template": {"metadata": {
                            "labels": {"concurrent-release": "true"}}}}})
                    return patched

            interference = Interfered.__new__(Interfered)
            interference._apps = apps
            actionrequests._client_factory = lambda: interference
            _, race_ctx = make_run("sre-race", [actions.SCOPE_ROLLBACK], pin)
            raced = actionrequests.request(
                race_ctx["run_id"], actions.ROLLBACK_DEPLOYMENT, namespace, DEPLOYMENT,
                granted_scope=race_ctx["scope"], pin=race_ctx["pin"],
                grant_expires_at=race_ctx["expires_at"])
            check(raced["result"] == actions.FAILED
                  and "rollback_target_changed" in raced["result_detail"],
                  "real concurrent template change is a named failure, not success")
            result["concurrent_release"] = {"row": raced,
                                             "after": deployment_state(apps, namespace)}
            actionrequests._client_factory = adapter

            # Cleanup belongs to the same trace and MUST complete before any
            # PASS artifact or telemetry shutdown. API-server UID is authority.
            delete_owned(core, namespace, namespace_uid)
            namespace_uid = None
            result["owned_cleanup_complete"] = True

        # --- 5. the trace -----------------------------------------------
        say("5. the decisions are in one trace")
        # 30 s: this flush decides whether the spans exist at all, and it is
        # the one place where impatience loses evidence rather than time.
        otel.shutdown_bounded(30)
        sys.path.insert(0, str(ROOT / "infra/observability"))
        import trace_readback
        trace_id = trace_ctx.split("-")[1]
        # Delivery is batched three times over, so the FIRST spans of a trace
        # arrive before the LAST: wait for the span this gate needs by NAME
        # rather than reading at first sight (PR #24: a run read back as 5
        # spans that was 8 minutes later).
        # WAIT FOR ALL THREE, not just for the execution. This asked for
        # `action.perform` and then asserted on three names, so it returned as
        # soon as the fastest one landed and reported the others missing:
        # "4 spans; missing: ['action.approve']", about an approval that had
        # demonstrably happened, on a row that recorded it. The same
        # read-at-first-sight defect this file's own comment warns about, two
        # lines above, in the call that was supposed to prevent it.
        #
        # 180 s because delivery is batched three times over and this ran
        # inside a full RC gate, where the host is doing everything at once.
        trace = trace_readback.wait_for_trace(
            JAEGER, trace_id, wait=180,
            expected=["action.decide", "action.approve", "action.perform", "kubernetes.cleanup"])
        if trace is None:
            check(False, "the trace never arrived in Jaeger (trace_not_found)")
            result["otel"] = {"trace_id": trace_id, "error": "trace_not_found"}
        else:
            summary = trace_readback.summarize(trace_id, trace)
            missing = trace_readback.missing_names(
                trace, ["action.decide", "action.approve", "action.perform", "kubernetes.cleanup"])
            check(not missing,
                  f"Jaeger returned the trace with {summary['span_count']} spans; "
                  f"missing: {missing}")
            # The DECISION is on the span by name, which is the exit criterion:
            # an operator asking "what did the platform decide" gets an answer
            # from telemetry as well as from the row.
            decided = sorted({
                span["attributes"].get("andyur.action_decision")
                for span in summary["spans"]
                if span["attributes"].get("andyur.action_decision")})
            check(decided == ["allowed", "approval_required", "denied"],
                  f"every decision is on its own span, by name: {decided}")
            observed_reasons = sorted({
                item["attributes"].get("andyur.rollback_reason")
                for item in summary["spans"]
                if item["attributes"].get("andyur.rollback_reason")})
            check(observed_reasons == ["rollback_applied", "rollback_target_changed"],
                  f"positive and concurrent-change observations exported: {observed_reasons}")
            result["otel"] = {"trace_id": trace_id, "jaeger": JAEGER,
                              "span_count": summary["span_count"],
                              "span_names": summary["span_names"],
                              "decisions_on_spans": decided,
                              "rollback_reasons": observed_reasons}

    finally:
        say("teardown")
        if namespace_uid is not None:
            with tracer.start_as_current_span("gate.cleanup", context=otel.context_from(trace_ctx)):
                delete_owned(core, namespace, namespace_uid)
        print("  only the successfully created, UID-bound namespace was removed")

    result["ok"] = not _failures
    result["failures"] = _failures
    result["finished_at_epoch"] = time.time()
    result["source_sha256"] = {path: sha256(path) for path in EXECUTED}
    result["executed_source_sha256"] = dict(result["source_sha256"])
    result["not_covered"] = (
        "the HTTP boundary and its identity checks (auth.require_run, the "
        "operator gate on approval): they need SPIRE and the containerised "
        "control plane, and are covered in-suite against the real ASGI app in "
        "tests/test_lane_a_action_api.py")
    print()
    if _failures:
        # NEVER RECORD A FAILED RUN. An artifact exists to say a property held.
        print(f"{FAIL} {len(_failures)} check(s) failed; no artifact written")
        for failure in _failures:
            print(f"    - {failure}")
        return 1
    # ONE GATE, ONE CURRENT RECORD. The filename carries the date, so a run on
    # a new day left yesterday's record beside today's -- and yesterday's binds
    # a version of this script that no longer exists, which the currency
    # checker correctly calls STALE and the release correctly refuses. Removed
    # at the point of WRITING, on the success path only: a failed run leaves
    # the previous record alone rather than deleting evidence it cannot replace.
    for superseded in (ROOT / "infra/kubernetes").glob(
            "result-consequential-action-*.json"):
        superseded.unlink()
    out = (ROOT / "infra/kubernetes" /
           f"result-consequential-action-{time.strftime('%Y-%m-%d')}-"
           f"{platform.system().lower()}-{platform.machine()}.json")
    out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print(f"{PASS} every check held; wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
