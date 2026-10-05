"""The agent Pod must not run while its egress is still open.

MEASURED, not theorised. Against this platform's own run group, with the
NetworkPolicies already in place for minutes before the Pod was created:

    t(s)     internet   k8s-api   dns
    0.000    OPEN       OPEN      OPEN
    0.218    OPEN       OPEN      OPEN
    0.279    OPEN       deny      deny
    0.430    deny       deny      deny

and a second run held the internet open for 0.87s across 13 successful
connections. The window is a property of the POD -- the CNI programs its rules
after the network is already usable -- not of the policy's age, which is why
`kubernetes_controller.launch`'s "Policies, Service and proxy exist before
untrusted code" is correct and does not close it.

An exec/v1 agent is a third-party image holding the run's MCP bearer in its
environment. An entrypoint that opens a socket in its first 100ms is not luck.
"""

from __future__ import annotations

import uuid

import pytest

from andyur.daemon import kubernetes_manifests as km


def _agent_pod(**overrides):
    """The real agent Pod for a minimal exec/v1 run group."""
    from andyur.registry.models import RUNTIME_PROTOCOL_EXEC_V1, ConfigurationSpec

    spec = km.RunGroupSpec(
        namespace="andyur-runs", run_id=uuid.uuid4().hex, generation="test",
        agent_id="stock", registry_agent_id="agt_stock",
        proxy_image="reg/andyur-runner@sha256:" + "b" * 64,
        agent_image="ghcr.io/third/party@sha256:" + "c" * 64,
        proxy_port=8765, mcp_port=8766,
        proxy_args=("python", "-c", "pass"), agent_args=("sh", "-c", "true"),
        agent_runtime="container", agent_interface=RUNTIME_PROTOCOL_EXEC_V1,
        exec_input_mode="", exec_input=b"", exec_input_max_bytes=0,
        exec_model_name="none", otel_mode="off", otel_endpoint="",
        proxy_egress=(), run_ttl_seconds=600,
        **{"exec_configuration": ConfigurationSpec(env=(), files=()), **overrides})
    return next(r for r in km.build_run_group(spec)
                if r["kind"] == "Pod"
                and r["metadata"]["labels"]["app.kubernetes.io/component"] == "agent")


def test_the_agent_pod_carries_a_containment_barrier():
    pod = _agent_pod()
    inits = pod["spec"]["initContainers"]
    assert inits, "the agent Pod has no initContainer, so it starts immediately"
    assert inits[0]["name"] == "await-containment"


def test_the_barrier_runs_before_every_other_init_container():
    """kubelet runs initContainers in order. Anything ahead of the barrier runs
    in the open window -- including `materialize-config`, which renders the
    run's MCP bearer onto disk."""
    from andyur.registry.models import ConfigFile, ConfigurationSpec

    pod = _agent_pod(exec_configuration=ConfigurationSpec(
        env=(), files=(ConfigFile(path="${workspace.home}/c.yaml", template="x\n"),)))
    names = [c["name"] for c in pod["spec"]["initContainers"]]
    assert names[0] == "await-containment"
    assert "materialize-config" in names, "this test needs the second one to exist"


def test_the_barrier_runs_the_platforms_image_not_the_workloads():
    """The barrier is exactly the thing a workload image must not influence."""
    pod = _agent_pod()
    barrier = pod["spec"]["initContainers"][0]
    assert barrier["image"] == "reg/andyur-runner@sha256:" + "b" * 64
    assert barrier["image"] != pod["spec"]["containers"][0]["image"]


def test_the_barrier_needs_nothing_injected_to_find_the_api_server():
    """kubelet puts KUBERNETES_SERVICE_HOST in every Pod, so the barrier has a
    forbidden destination to probe without the controller resolving one."""
    assert "KUBERNETES_SERVICE_HOST" in km._CONTAINMENT_BARRIER


def test_the_barrier_probes_two_independent_things():
    """Either could be denied for a reason that is not enforcement. Both at
    once, from a Pod whose policy forbids both, is the signal -- and DNS is the
    exfiltration channel `agent_policy` removes on purpose."""
    assert "getaddrinfo" in km._CONTAINMENT_BARRIER
    assert "create_connection" in km._CONTAINMENT_BARRIER


# --- the program's own behaviour, run here rather than described -------------

def _run_barrier(monkeypatch, sequence, timeout="2"):
    """Execute the real barrier with socket calls faked from `sequence`, a list
    of (connect_ok, resolve_ok) per iteration."""
    import socket as socket_module

    steps = list(sequence)
    state = {"i": 0}

    def step():
        i = min(state["i"], len(steps) - 1)
        return steps[i]

    def fake_connect(address, timeout=None):
        ok = step()[0]
        state["i"] += 1
        if not ok:
            raise OSError("refused")
        class S:
            def close(self): pass
        return S()

    def fake_getaddrinfo(*a, **kw):
        if not step()[1]:
            raise OSError("no dns")
        return [("x",)]

    monkeypatch.setattr(socket_module, "create_connection", fake_connect)
    monkeypatch.setattr(socket_module, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.43.0.1")
    monkeypatch.setenv("ANDYUR_BARRIER_TIMEOUT", timeout)
    code = compile(km._CONTAINMENT_BARRIER, "barrier", "exec")
    with pytest.raises(SystemExit) as exit_info:
        exec(code, {"__name__": "__main__"})
    return exit_info.value.code


def test_it_waits_while_egress_is_open_and_exits_when_it_closes(monkeypatch, capsys):
    """The window, as measured: open for a while, then shut."""
    status = _run_barrier(monkeypatch, [(True, True)] * 6 + [(False, False)])
    assert status == 0
    out = capsys.readouterr().out
    assert "containment in force" in out
    assert "window observed: yes" in out


def test_it_starts_the_workload_immediately_when_already_enforced(monkeypatch, capsys):
    """Enforcement can land before the barrier's first probe. That is the good
    case and must not cost the run a timeout."""
    assert _run_barrier(monkeypatch, [(False, False)]) == 0
    assert "already enforced at start" in capsys.readouterr().out


def test_egress_that_never_closes_refuses_to_start_the_workload(monkeypatch, capsys):
    """FAIL CLOSED. A Pod whose policy is missing, or whose CNI is not
    enforcing, must not run third-party code at all -- and must say which of
    those two it looked like."""
    assert _run_barrier(monkeypatch, [(True, True)]) == 1
    out = capsys.readouterr().out
    assert "REFUSING TO START THE WORKLOAD" in out
    assert "policy was not applied or the CNI is not enforcing" in out


def test_one_channel_closing_is_not_enough(monkeypatch):
    """DNS down while the API is still reachable is not containment."""
    assert _run_barrier(monkeypatch, [(True, False)]) == 1
    assert _run_barrier(monkeypatch, [(False, True)]) == 1


def test_nothing_the_platform_adds_later_can_precede_the_barrier():
    """The barrier only works because kubelet will not start ANY app container
    until every initContainer has exited 0 -- and because it is first, so no
    other initContainer runs in the open window either. `materialize-config`
    renders the run's MCP bearer onto disk and would otherwise do that while
    the Pod could still reach the internet.

    Pinned as a property of the list rather than of today's two entries, so a
    third init container added by someone who has not read this cannot quietly
    take the front."""
    from andyur.registry.models import ConfigFile, ConfigurationSpec

    for configuration in (ConfigurationSpec(env=(), files=()),
                          ConfigurationSpec(env=(), files=(
                              ConfigFile(path="${workspace.home}/c.yaml",
                                         template="x\n"),))):
        pod = _agent_pod(exec_configuration=configuration)
        inits = pod["spec"]["initContainers"]
        assert inits[0]["name"] == "await-containment", (
            f"{inits[0]['name']} runs before containment is in force")
