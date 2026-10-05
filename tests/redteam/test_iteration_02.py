"""ITERATION 02 -- seven-persona review of the workflow-engine lane, 21 September 2026.

Red-team regressions for the Temporal provider and its deployment. See
`tests/redteam/README.md` for the convention.

The review ran after the lane had been declared complete, and it should have
run before. Every attack below was run, or its precondition was verified live
against the cluster, rather than imagined. The ones that LANDED are fixed; each
is paired with a positive control, because a check that refuses everything
passes every negative test here.

What held is recorded too. The largest thing that held is worth stating: the
reviewers first claimed an agent's run proxy could administer the engine. It
cannot while the NetworkPolicy is enforced -- verified live, the run namespace
and even the operator are refused on 7233. That narrowed several findings, but
it also exposed the real one: the engine authenticated every workload in the
trust domain and authorized none, so the route was the ONLY barrier. The
authorizer tests at the end close that; the NetworkPolicy tests stay, because
the two barriers are meant to be independent.
"""

import ast
import pathlib

import pytest
import yaml

pytestmark = pytest.mark.redteam

ROOT = pathlib.Path(__file__).resolve().parents[2]
ACTIVITIES = ROOT / "andyur" / "orchestration" / "temporal" / "activities.py"
KUBE = ROOT / "infra" / "kubernetes"

# The transitions that belong to a RUN, announced over its own SVID-authenticated
# endpoints. No engine activity may perform them.
LIFECYCLE = {"start_run", "finish_run"}


def _registered_activity_calls():
    """For each registered activity: every name its body mentions.

    EVERY NAME, not "calls on `coordinator`": the first version recorded only
    `coordinator.<op>(...)`, so `coordinator as coord`, a direct
    `from ...coordinator import finish_run`, or a sync `def` activity all went
    unseen. A lifecycle name appearing anywhere in a registered activity -- as
    an attribute, a bare name or an import -- is what this refuses.
    """
    tree = ast.parse(ACTIVITIES.read_text())
    # REGISTERED MEANS SCHEDULABLE, however it got there: the registry list,
    # anything appended or extended onto it, and any `@activity.defn` function
    # (the decorator is what the worker needs; the list is only convention).
    registered = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "ALL_ACTIVITIES" for t in node.targets):
            registered |= {getattr(e, "id", None) for e in node.value.elts} - {None}
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and getattr(node.func.value, "id", None) == "ALL_ACTIVITIES"):
            for arg in node.args:
                elts = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
                registered |= {getattr(e, "id", None) for e in elts} - {None}
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and any(
                "defn" in ast.unparse(d) for d in node.decorator_list):
            registered.add(node.name)

    # Module-level imports count against every activity: an alias bound at the
    # top of the file is as reachable from an activity as one bound inside it.
    module_names = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                module_names |= {alias.name.split(".")[-1], alias.asname or ""}

    calls = {}
    for node in tree.body:
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name in registered:
            names = set(module_names)
            for sub in ast.walk(node):
                if isinstance(sub, ast.Attribute):
                    names.add(sub.attr)
                elif isinstance(sub, ast.Name):
                    names.add(sub.id)
                elif isinstance(sub, (ast.Import, ast.ImportFrom)):
                    for alias in sub.names:
                        names |= {alias.name.split(".")[-1], alias.asname or ""}
            calls[node.name] = names
    return registered, calls


# --------------------------------------------------------------------------
# LANDED: a registered activity could record any run's outcome
# --------------------------------------------------------------------------

def test_no_engine_activity_moves_a_run_through_its_lifecycle():
    """THE ATTACK THAT LANDED.

    `finish_run` was a registered activity that no workflow called. An activity
    is callable by anything that can schedule work on the task queue, and the
    engine accepts every SVID in the trust domain while authorizing none -- so
    from a Pod with a route to the engine (a compromised `andyur-worker` had
    one), starting any workflow and scheduling `finish_run` marked an arbitrary
    run done and nulled its subject token, bypassing the run's own
    SVID-authenticated `POST /runs/{id}/finish`.

    Its sibling `start_run` was removed earlier for a different reason (it
    stopped runs launching), and the review found this one had the same shape.
    Asserted over every REGISTERED activity rather than by name, because the
    next one will not be called `finish_run`.
    """
    _registered, calls = _registered_activity_calls()
    offenders = {name: sorted(ops & LIFECYCLE) for name, ops in calls.items()
                 if ops & LIFECYCLE}

    assert not offenders, (
        f"{offenders} -- a registered activity performs a run's own lifecycle "
        "transition, which anything able to schedule work on the task queue "
        "could then drive")


def test_positive_control_the_activity_scan_sees_real_activities():
    """Without this the test above passes vacuously if the scan finds nothing:
    an empty registry performs no lifecycle transition either."""
    registered, calls = _registered_activity_calls()

    assert "observe_state" in registered, (
        "the scan did not find the activity registry; the lifecycle check above "
        "would pass with nothing to check")
    assert set(calls) == registered, (
        f"registered {sorted(registered)} but parsed {sorted(calls)}: an "
        "activity body the scan cannot see is one it cannot refuse")
    # Since F-5 the tick is admitted through Andyur's schedule service, which
    # performs the schedule check once for every provider and then calls the
    # facade; the activity's own platform call is that service.
    assert "admit_engine_tick" in calls["admit_scheduled_run"], (
        "the platform call `admit_scheduled_run` makes was not seen, so the scan "
        "cannot tell a clean registry from one it failed to read")


# --------------------------------------------------------------------------
# LANDED: the run-launching daemon held a route to the engine it never used
# --------------------------------------------------------------------------

WILDCARD = "*"


def _covers_engine_port(rule):
    """A rule with no `ports` admits every port; a named port may be the
    engine's; otherwise the number must be 7233."""
    ports = rule.get("ports")
    if not ports:
        return True
    return any(p.get("port") in (7233, "grpc") or "port" not in p for p in ports)


def _peer_app(peer):
    """The app a peer selects, or WILDCARD for anything broader than one app:
    an empty podSelector, a matchExpressions selector, an ipBlock."""
    if set(peer) - {"podSelector"}:
        return WILDCARD
    selector = peer.get("podSelector") or {}
    labels = selector.get("matchLabels") or {}
    if selector.get("matchExpressions") or set(labels) != {"app"}:
        return WILDCARD
    return labels["app"]


def _engine_routes(doc_path, kind):
    """Pods granted a route to the engine on 7233, from one side of the policy.
    WILDCARD in the result means a rule admits more than named apps."""
    granted = set()
    for doc in yaml.safe_load_all(doc_path.read_text()):
        if not doc or doc.get("kind") != "NetworkPolicy":
            continue
        spec = doc["spec"]
        if kind == "ingress" and spec["podSelector"].get("matchLabels", {}).get("app") == "andyur-temporal":
            for rule in spec.get("ingress", []):
                if _covers_engine_port(rule):
                    peers = rule.get("from")
                    granted |= {_peer_app(p) for p in peers} if peers else {WILDCARD}
        if kind == "egress":
            app = spec["podSelector"].get("matchLabels", {}).get("app") or WILDCARD
            for rule in spec.get("egress", []):
                targets = rule.get("to")
                reaches = (not targets) or any(
                    _peer_app(t) in ("andyur-temporal", WILDCARD) for t in targets)
                if reaches and _covers_engine_port(rule):
                    granted.add(app)
    return granted


def test_the_run_launching_daemon_has_no_route_to_the_engine():
    """THE ATTACK THAT LANDED.

    `app: andyur-worker` held both ingress on the engine's policy and egress on
    its own, verified live with a connect from `andyur-worker-0`. It is the
    run-LAUNCHING daemon and never constructs a workflow provider; the comment
    granting it said "the workflow worker", which is a container in the
    andyur-server Pod. With the engine authorizing nobody, that route plus the
    daemon's SVID was full engine administration, handed to the component the
    agent's runtime is nearest to.
    """
    ingress = _engine_routes(KUBE / "temporal.yaml", "ingress")
    egress = _engine_routes(KUBE / "control-plane.yaml", "egress")

    assert "andyur-worker" not in ingress, (
        "the engine admits the run-launching daemon on 7233")
    assert WILDCARD not in ingress, (
        "a rule admits more than named apps to the engine's port -- an empty "
        "selector, a missing `from`, an ipBlock or a missing `ports`")
    assert "andyur-worker" not in egress, (
        "the run-launching daemon may dial the engine on 7233")


def test_positive_control_the_control_plane_still_reaches_the_engine():
    """The route must still exist where it IS used, or the test above passes
    because the scan found no routes at all."""
    ingress = _engine_routes(KUBE / "temporal.yaml", "ingress")
    egress = _engine_routes(KUBE / "control-plane.yaml", "egress")

    assert "andyur-server" in ingress and "andyur-server" in egress, (
        "the control plane, which hosts the workflow worker, lost its route to "
        "the engine -- or the scan is not reading the policies")


# --------------------------------------------------------------------------
# held: an agent's run namespace has no route to the engine
# --------------------------------------------------------------------------

def test_held_the_run_namespace_is_not_admitted_to_the_engine():
    """HELD, and kept so it stays held.

    The reviewers first claimed a run proxy could administer the engine, since
    it holds an SVID from the same trust bundle the frontend accepts. Verified
    live, it cannot: the engine's ingress admits only Pods in `andyur-system`,
    and connections from the run namespace are refused. When this was found it
    was the ONLY thing between an agent and the engine; the SPIFFE-ID
    authorizer below is now a second, and this stays so that losing one of the
    two is still a failing test rather than a silent halving.
    """
    for doc in yaml.safe_load_all((KUBE / "temporal.yaml").read_text()):
        if not doc or doc.get("kind") != "NetworkPolicy":
            continue
        if doc["spec"]["podSelector"].get("matchLabels", {}).get("app") != "andyur-temporal":
            continue
        for rule in doc["spec"].get("ingress", []):
            for peer in rule.get("from", []):
                ns = peer.get("namespaceSelector")
                assert ns is None, (
                    f"the engine admits a peer selected by namespace ({ns}); "
                    "any namespace selector widens ingress beyond this one, and "
                    "andyur-runs is where agents run")


# --------------------------------------------------------------------------
# LANDED: every SVID in the trust domain administered the engine
# --------------------------------------------------------------------------
#
# The behaviour is proved live in `tests/test_engine_authorizer.py` (the shipped
# Envoy config in front of a real Temporal, one certificate per identity). What
# is here is what that test cannot see: that the allowlist names the identities
# the cluster ACTUALLY issues, and that nothing in the engine Pod listens on the
# pod network except through the authorizer.

def _docs(name):
    return [d for d in yaml.safe_load_all((KUBE / name).read_text()) if d]


def _authz_config():
    cm = next(d for d in _docs("temporal.yaml") if d["kind"] == "ConfigMap"
              and d["metadata"]["name"] == "andyur-temporal-authz")
    return yaml.safe_load(cm["data"]["envoy.yaml"])


def _engine_pod():
    dep = next(d for d in _docs("temporal.yaml") if d["kind"] == "Deployment"
               and d["metadata"]["name"] == "andyur-temporal")
    return dep["spec"]["template"]["spec"]


def _issued_id(doc_name, pod_app):
    """The SPIFFE ID the cluster issues to Pods labelled `app: pod_app`."""
    for name in ("control-plane.yaml", "temporal.yaml"):
        for d in _docs(name):
            if (d["kind"] == "ClusterSPIFFEID"
                    and d["spec"]["podSelector"]["matchLabels"].get("app") == pod_app):
                return d["spec"]["spiffeIDTemplate"]
    raise AssertionError(f"no ClusterSPIFFEID selects app={pod_app} ({doc_name})")


def _allowlist():
    """(matcher kind, value) for every principal the authorizer admits, plus
    the filter order on the one listener."""
    listeners = _authz_config()["static_resources"]["listeners"]
    assert len(listeners) == 1, "the authorizer has more than one listener"
    chains = listeners[0]["filter_chains"]
    assert len(chains) == 1, "a second filter chain is a second way in"
    filters = chains[0]["filters"]
    order = [f["name"] for f in filters]
    rbac = next(f for f in filters if f["name"] == "envoy.filters.network.rbac")
    rules = rbac["typed_config"]["rules"]
    principals = []
    for policy in rules["policies"].values():
        for principal in policy["principals"]:
            matcher = principal.get("authenticated", {}).get("principal_name")
            assert matcher, f"a principal that is not an authenticated name: {principal}"
            (kind, value), = matcher.items()
            principals.append((kind, value))
    return rules["action"], order, principals, chains[0]


def test_the_engine_admits_exactly_the_identities_that_use_it():
    """THE ATTACK THAT LANDED.

    The frontend required a client certificate and accepted any that chained to
    the trust bundle, with no authorizer. So `spiffe://andyur.local/worker`, the
    operator, the run proxy in `andyur-runs` -- every SVID the cluster issues --
    was full engine administration from anywhere with a route. Temporal OSS
    cannot authorize on a certificate's URI SAN; the Envoy in front of it does.

    The expected set is DERIVED from the ClusterSPIFFEIDs, not written out: if
    the control plane's identity is renamed, the allowlist has to follow it or
    the provider is locked out, and if something is added to the allowlist it
    has to be an identity the cluster issues to a Pod that needs the engine.
    """
    action, order, principals, _chain = _allowlist()
    expected = {_issued_id("control plane", "andyur-server"),
                _issued_id("registration Job", "andyur-temporal-namespace"),
                # Architecture B+: the execution worker polls the engine's
                # execution queue under its OWN identity (ADR-014 D11).
                _issued_id("execution worker", "andyur-temporal-execution-worker")}

    assert action == "ALLOW", f"the authorizer's rules are a {action}-list"
    assert order.index("envoy.filters.network.rbac") < order.index(
        "envoy.filters.network.http_connection_manager"), (
        "the RBAC filter runs after the proxy, so connections are forwarded "
        "before anything is checked")
    loose = [(k, v) for k, v in principals if k != "exact"]
    assert not loose, (
        f"{loose} -- a non-exact matcher on a SPIFFE ID; a prefix of an allowed "
        "ID admits every ID that starts with it")
    assert {v for _k, v in principals} == expected, (
        f"the authorizer admits {sorted(v for _k, v in principals)}, and the "
        f"identities that use the engine are {sorted(expected)}")


def _method_policies(chain):
    hcm = next(f for f in chain["filters"]
               if f["name"] == "envoy.filters.network.http_connection_manager")
    http = hcm["typed_config"]["http_filters"]
    names = [f["name"] for f in http]
    assert names.index("envoy.filters.http.rbac") < names.index("envoy.filters.http.router"), (
        "the per-method check runs after the router, so requests reach Temporal first")
    rbac = next(f for f in http if f["name"] == "envoy.filters.http.rbac")
    assert rbac["typed_config"]["rules"]["action"] == "ALLOW"
    return rbac["typed_config"]["rules"]["policies"]


def test_the_execution_worker_may_make_only_a_workers_calls():
    """B+ ADVERSARIAL REVIEW (identity, H6). Admitted at the handshake with the
    whole API, the execution worker's identity could start the control plane's
    own workflows -- `ScheduledAgentRun` for any agent. Per request it is now a
    WORKER: exact method paths, every one of them a poll, a response, a
    heartbeat, or what a worker reads to start up. Nothing that starts,
    signals, cancels, terminates, updates or schedules."""
    _action, _order, principals, chain = _allowlist()
    policies = _method_policies(chain)
    by_principal = {}
    for name, policy in policies.items():
        for principal in policy["principals"]:
            (kind, value), = principal["authenticated"]["principal_name"].items()
            assert kind == "exact", principal
            by_principal[value] = policy
    assert set(by_principal) == {v for _k, v in principals}, (
        "the per-method policies do not cover exactly the admitted identities")
    worker = by_principal["spiffe://andyur.local/temporal-execution-worker"]
    assert {"any": True} not in worker["permissions"], "the worker holds the whole API"
    service = "/temporal.api.workflowservice.v1.WorkflowService/"
    methods = set()
    for permission in worker["permissions"]:
        (kind, path), = permission["url_path"]["path"].items()
        assert kind == "exact" and path.startswith(service), permission
        methods.add(path[len(service):])
    # A worker's calls: poll for a task, report its own task's outcome (a
    # `Respond...Canceled` reports that ITS task ended cancelled; it cancels
    # nothing), heartbeat, and what it reads to start up.
    startup = {"DescribeNamespace", "GetSystemInfo", "GetWorkflowExecutionHistory",
               "ResetStickyTaskQueue", "ShutdownWorker"}
    for method in methods - startup:
        assert method.startswith(("Poll", "Respond", "Record")), method
    commanding = {"StartWorkflowExecution", "SignalWorkflowExecution",
                  "SignalWithStartWorkflowExecution", "RequestCancelWorkflowExecution",
                  "TerminateWorkflowExecution", "ResetWorkflowExecution",
                  "UpdateWorkflowExecution", "ExecuteMultiOperation", "CreateSchedule",
                  "UpdateSchedule", "PatchSchedule", "DeleteSchedule",
                  "StartBatchOperation", "DeleteWorkflowExecution", "UpdateNamespace",
                  "RegisterNamespace", "ListWorkflowExecutions"}
    assert not methods & commanding, sorted(methods & commanding)


def test_positive_control_the_allowlist_is_read_from_the_shipped_config():
    """The test above compares two sets; if both came back empty it would pass.
    The control plane MUST be admitted, or the durable provider is offline."""
    _action, _order, principals, chain = _allowlist()

    assert ("exact", "spiffe://andyur.local/control-plane") in principals, (
        "the control plane is not admitted -- or the allowlist was not read")
    ctx = chain["transport_socket"]["typed_config"]
    assert ctx.get("require_client_certificate") is True, (
        "the authorizer does not require a client certificate, so the peer it "
        "checks may not exist")


def test_nothing_in_the_engine_pod_listens_on_the_pod_network_but_the_authorizer():
    """LANDED, found while building the authorizer.

    The image binds every Temporal service to the POD IP unless told
    otherwise: the frontend, history (7234), matching (7235) and the internal
    frontend (7236), which is plaintext, unauthenticated and full
    administration. An authorizer on 7233 is decoration while any of those is
    one hop away; the NetworkPolicy port allowlist was all that kept them shut.
    `BIND_ON_IP=127.0.0.1` puts them where only the Pod can dial them.
    """
    pod = _engine_pod()
    temporal = next(c for c in pod["containers"] if c["name"] == "temporal")
    env = {e["name"]: e.get("value") for e in temporal["env"]}

    assert env.get("BIND_ON_IP") == "127.0.0.1", (
        f"Temporal binds {env.get('BIND_ON_IP')!r}, so its services are "
        "reachable on the pod network without passing the authorizer")
    frontend = next(c for c in _authz_config()["static_resources"]["clusters"]
                    if c["name"] == "frontend")
    upstream = (frontend["load_assignment"]["endpoints"][0]["lb_endpoints"][0]
                ["endpoint"]["address"]["socket_address"])
    assert int(env.get("FRONTEND_GRPC_PORT", 7233)) == upstream["port_value"], (
        "the authorizer proxies to a port the frontend does not listen on")
    # Temporal's own defaults for the listeners this Pod leaves unconfigured.
    # 7243 is the frontend's HTTP API: moving gRPC onto it crash-looped the
    # engine with the frontend colliding with itself.
    taken = {7233, 7234, 7235, 7236, 7239, 7243, 6933, 6934, 6935, 6936, 6939}
    assert upstream["port_value"] not in taken, (
        f"the frontend's gRPC port {upstream['port_value']} is one Temporal "
        "already binds by default in this Pod")

    exposed = {(c["name"], p["containerPort"])
               for c in pod["containers"] for p in c.get("ports", [])}
    assert exposed == {("authz", 7233), ("temporal", 9090)}, (
        f"the engine Pod declares {sorted(exposed)}; only the authorizer and "
        "the metrics endpoint belong on the pod network")


def test_positive_control_the_service_reaches_the_authorizer_not_temporal():
    """The Service's `grpc` target must resolve to the authorizer's port. Were
    it to name a Temporal container port, clients would bypass the check --
    and the test above would still pass on the Pod alone."""
    pod = _engine_pod()
    owners = [c["name"] for c in pod["containers"]
              for p in c.get("ports", []) if p.get("name") == "grpc"]
    svc = next(d for d in _docs("temporal.yaml") if d["kind"] == "Service"
               and d["metadata"]["name"] == "andyur-temporal")
    targets = {p["port"]: p["targetPort"] for p in svc["spec"]["ports"]}

    assert owners == ["authz"], f"the `grpc` port belongs to {owners}"
    assert targets.get(7233) == "grpc", f"the Service sends 7233 to {targets.get(7233)!r}"


# --------------------------------------------------------------------------
# ROUND 2 (same day, over the round-1 fixes): what the live harness cannot see
# --------------------------------------------------------------------------
#
# tests/test_engine_authorizer.py swaps SDS for files, so these properties of
# the shipped config are pinned statically.

def test_the_authorizer_waits_for_its_certificate_rather_than_opening_without_one():
    """LANDED (round 2). With SDS's default 15s fetch timeout the listener
    opened WITHOUT a certificate -- measured with the SPIRE socket absent -- so
    the TCP readiness probe passed while every handshake failed with "Secret is
    not supplied by SDS". `0s` waits indefinitely."""
    tls = (_authz_config()["static_resources"]["listeners"][0]["filter_chains"][0]
           ["transport_socket"]["typed_config"]["common_tls_context"])
    sources = [c["sds_config"] for c in tls["tls_certificate_sds_secret_configs"]]
    sources.append(tls["validation_context_sds_secret_config"]["sds_config"])

    assert sources, "no SDS secret was found to check"
    for source in sources:
        assert source.get("initial_fetch_timeout") == "0s", (
            f"an SDS secret gives up after the default 15s ({source}); the "
            "listener then serves no certificate while readiness says Ready")


def test_the_authorizer_bounds_handshakes_and_speaks_tls13_only():
    chain = _authz_config()["static_resources"]["listeners"][0]["filter_chains"][0]
    tls = chain["transport_socket"]["typed_config"]["common_tls_context"]

    assert chain.get("transport_socket_connect_timeout"), (
        "no handshake timeout: a peer that never finishes its handshake holds "
        "the connection indefinitely")
    assert tls.get("tls_params", {}).get("tls_minimum_protocol_version") == "TLSv1_3"


def test_the_engine_runs_as_exactly_one_pod():
    """LANDED (round 2), as a constraint the loopback bind created. Every
    service advertises 127.0.0.1 to the membership ring, so a second replica
    would see every peer as itself and both would claim every shard. Nothing
    enforced the single replica the comment relied on."""
    dep = next(d for d in _docs("temporal.yaml") if d["kind"] == "Deployment"
               and d["metadata"]["name"] == "andyur-temporal")

    assert dep["spec"]["replicas"] == 1
    assert dep["spec"]["strategy"]["type"] == "Recreate", (
        "a rolling update runs two engine Pods at once, each claiming every shard")



def test_the_execution_worker_has_its_own_route_and_the_daemon_still_has_none():
    """Architecture B+ gives the engine a new caller, and the obvious shortcut
    is to run it as the worker daemon, which can already launch runs. That
    would re-open exactly the route LANDED above closed. The execution worker
    has a route of its own, and the daemon's absence is re-asserted beside it
    so the two cannot be merged without a failing test."""
    ingress = _engine_routes(KUBE / "temporal.yaml", "ingress")
    egress = _engine_routes(KUBE / "control-plane.yaml", "egress")

    assert "andyur-temporal-execution-worker" in ingress
    assert "andyur-temporal-execution-worker" in egress
    assert "andyur-worker" not in ingress and "andyur-worker" not in egress


def test_the_execution_worker_is_not_the_daemon_and_holds_no_minting_key():
    """Its identity is its own, and its container carries no run-token
    signing key: run credentials come from the server per run."""
    docs = _docs("control-plane.yaml")
    deploy = next(d for d in docs if d["kind"] == "Deployment"
                  and d["metadata"]["name"] == "andyur-temporal-execution-worker")
    pod = deploy["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for c in pod["containers"] for e in c.get("env", [])}

    assert _issued_id("execution worker", "andyur-temporal-execution-worker") == \
        "spiffe://andyur.local/temporal-execution-worker"
    assert pod["serviceAccountName"] == "andyur-temporal-execution-worker"
    assert "ANDYUR_RUN_TOKEN_SECRET" not in env, (
        "the execution worker carries the key that signs run tokens")
    assert env.get("ANDYUR_SPIFFE_ID") == "spiffe://andyur.local/temporal-execution-worker"
