"""The per-run tool sidecar: the sole tool egress (ADR-003).

Tested through `runner._start_tool_egress`, where the dispatch, the identity
assembly and the withholding live; a suite that stubbed one layer down would go
green with the hot path unwired. The sidecar's own proxy behaviour is covered by
the proxy tests. The questions here are (1) the egress builds the sidecar with
the run's real identity/scope/pin/exchange material, and (2) every failure mode
withholds fail-closed rather than handing the agent an unauthenticated URL. The
retired ANDYUR_TOOL_EGRESS switch (agentgateway is gone) is proven to refuse its
dead value rather than silently ignore it.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

from andyur import config
from andyur.runner import gateway, runner, toolsidecar

RUN_TOKEN = "run-token-that-must-never-reach-the-agent"
SERVER = "127.0.0.1:8642"
TLS = {"cert": "/tls/runner/cert.pem", "key": "/tls/runner/key.pem",
       "bundle": "/tls/runner/bundle.pem"}


def _managed(names=("ci",), audience=None):
    return {name: {"url": f"http://127.0.0.1:87{i:02d}/mcp",
                   "audience": audience or f"resource:{name}",
                   "scheme": "http",
                   "host": "127.0.0.1", "port": 8700 + i, "path": "/mcp"}
            for i, name in enumerate(names)}


PASSTHROUGH = {"notes": {"type": "stdio", "command": "notes"}}


class FakeSidecar:
    """Records what the runner hands the sidecar; started/stopped are the
    lifecycle facts the teardown tests assert."""
    built = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.stopped = False
        FakeSidecar.built = self

    def start(self):
        return "http://127.0.0.1:5001"

    def stop(self):
        self.stopped = True


@pytest.fixture
def sidecar_env(monkeypatch):
    """The runner's collaborators, faked at the runner seam. The fakes mirror
    the real helpers' gating (subject only under an external AS, no SVID for an
    empty audience) so no test asserts a configuration the real code cannot
    produce."""
    FakeSidecar.built = None
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "")
    monkeypatch.setattr(config, "AS_ISSUER", "")
    monkeypatch.setattr(runner.identity, "run_token_header",
                        lambda: {runner.identity.RUN_TOKEN_HEADER: RUN_TOKEN})
    monkeypatch.setattr(runner.identity, "export_tls_pems", lambda role: TLS)
    monkeypatch.setattr(gateway, "preflight", lambda managed: (dict(managed), {}))
    monkeypatch.setattr(gateway, "_server_host_port", lambda: SERVER)
    monkeypatch.setattr(
        runner, "_claim_of",
        lambda token, key: {"r": "run-7", "sc": ["mcp:call"],
                            "pn": {"team": "checkout"}}[key])
    monkeypatch.setattr(
        runner, "_fetch_subject_token",
        lambda token, actor=None, **kw: (("SUBJECT", "alice", "spiffe://andyur.local/agent/agent/run/run-7")
                                        if config.AS_TOKEN_ENDPOINT else None))
    monkeypatch.setattr(
        runner, "_fetch_actor_token",
        lambda audience: f"svid-for-{audience}" if audience else None)
    calls = {"factories": [], "minted": []}

    def local_exchange(run_token, server, timeout=10.0, actor_token=None):
        assert run_token == RUN_TOKEN and server == SERVER
        calls["factories"].append({"timeout": timeout,
                                   "actor_token": actor_token})

        def _mint(*, audience, scope=None, **_ignored):
            calls["minted"].append(audience)
            return {"access_token": "T", "expires_in": 60}
        _mint.is_local = True
        return _mint

    monkeypatch.setattr(gateway, "local_exchange", local_exchange)
    monkeypatch.setattr(toolsidecar, "ToolSidecar", FakeSidecar)
    return calls


def test_sidecar_egress_serves_managed_tools_through_the_sidecar(sidecar_env):
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    # the agent is pointed at the sidecar's loopback path, with NO credential
    assert view["ci"] == {"type": "http",
                          "url": "http://127.0.0.1:5001/tools/ci/mcp"}
    assert view["notes"] == PASSTHROUGH["notes"]
    # the stoppable handed back is the sidecar, so the run paths' existing
    # `tool_gateway.stop()` teardown applies unchanged
    assert instance is FakeSidecar.built and not instance.stopped


def test_sidecar_receives_the_runs_identity_scope_and_pin(sidecar_env):
    runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), {}))
    got = FakeSidecar.built.kwargs
    ident = got["identity"]
    # local mint: no external AS means no subject token exists to present, and
    # the empty string fails closed downstream (asclient refuses it; the local
    # mint never reads it)
    assert ident.subject_token == ""
    # no external AS: the actor SVID's relying party is Andyur itself
    assert ident.actor_token() == f"svid-for-{runner.identity.SERVER_AUDIENCE}"
    # the mTLS leg: the sidecar's tool client presents the run's X509-SVID
    assert ident.mtls_material() == TLS
    assert got["scope"] == ["mcp:call"]
    # the pin travels as the RFC 9396 detail, not Andyur's internal dict
    assert got["pin"] == runner._pin_as_rar({"team": "checkout"})
    # tool leg only this increment: the model leg is deliberately unwired
    assert got["gateway_url"] == "" and got["llm_master_key"] == ""
    assert got["enforced_model"] is None


def test_local_mint_selected_and_preflighted_without_an_external_as(
        sidecar_env, monkeypatch):
    # a budget below the runtime callable's fixed 10s timeout, so a probe that
    # ignored the remaining budget is DISTINGUISHABLE from a clamped one
    monkeypatch.setattr(gateway, "MINT_BUDGET", 5.0)
    runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(("ci", "obs")), {}))
    fn = FakeSidecar.built.kwargs["exchange_fn"]
    assert getattr(fn, "is_local", False)
    # the positive control asked the mint once PER AUDIENCE before promising
    assert sorted(sidecar_env["minted"]) == ["resource:ci", "resource:obs"]
    # every exchange carries the run's SVID as the Authorization leg -- without
    # it the mint refuses under ANDYUR_REQUIRE_RUN_SVID and the whole egress is
    # dead in exactly the hardened configuration
    andyur_svid = f"svid-for-{runner.identity.SERVER_AUDIENCE}"
    assert all(f["actor_token"] == andyur_svid
               for f in sidecar_env["factories"])
    # the runtime callable keeps its own timeout; each preflight probe is
    # clamped to the REMAINING budget, so the loop cannot overshoot it by a
    # whole fixed timeout
    runtime, *probes = sidecar_env["factories"]
    assert runtime["timeout"] == 10.0
    assert probes and all(0 < p["timeout"] <= gateway.MINT_BUDGET
                          for p in probes)


def test_spent_mint_budget_fails_closed_not_open(sidecar_env, monkeypatch):
    # with no budget left, every audience is "not checked" -- and unchecked
    # must mean withheld, never granted with its positive control skipped
    monkeypatch.setattr(gateway, "MINT_BUDGET", 0.0)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert sidecar_env["minted"] == []


def test_a_shared_audience_is_probed_once(sidecar_env):
    managed = _managed(("ci", "obs"), audience="resource:shared")
    view, _ = runner._start_tool_egress(
        "agent", {}, partitioned=(managed, {}))
    assert sidecar_env["minted"] == ["resource:shared"]
    assert "ci" in view and "obs" in view


def test_external_as_uses_the_apps_default_exchange(sidecar_env, monkeypatch):
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    runner._start_tool_egress("agent", {}, partitioned=(_managed(), {}))
    got = FakeSidecar.built.kwargs
    # None -> build_app defaults to asclient.exchange, the external-AS leg;
    # Andyur's local mint is never touched
    assert got["exchange_fn"] is None
    assert sidecar_env["minted"] == []
    # the subject is the user's token, and the actor SVID's relying party is
    # the ADOPTER's AS, never Andyur's own audience
    assert got["identity"].subject_token == "SUBJECT"
    assert got["identity"].expected_subject == "alice"
    assert got["identity"].expected_actor == "spiffe://andyur.local/agent/agent/run/run-7"
    assert got["identity"].actor_token() == "svid-for-https://as.example"


def test_external_as_without_an_issuer_withholds_not_leaks(sidecar_env, monkeypatch):
    # AS_ISSUER unset with an endpoint set: the actor audience must NOT fall
    # back to Andyur's own -- that would present an Andyur-audience SVID to the
    # adopter's AS. The run gets no managed tools instead.
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert FakeSidecar.built is None


def test_external_as_without_a_subject_withholds_at_start(sidecar_env, monkeypatch):
    # the gateway path refuses this before starting; promised tools that 502
    # per call are the same fact discovered later and less clearly
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(runner, "_fetch_subject_token", lambda *a: None)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert FakeSidecar.built is None


def test_external_as_without_server_sealed_actor_withholds_at_start(sidecar_env, monkeypatch):
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(
        runner, "_fetch_subject_token", lambda *a, **kw: ("SUBJECT", "alice", None))
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert FakeSidecar.built is None


def test_no_run_token_withholds_before_any_identity_fetch(sidecar_env, monkeypatch):
    monkeypatch.setattr(runner.identity, "run_token_header", lambda: {})

    def no_fetch(*a, **kw):
        raise AssertionError("identity fetched before the run-token check")
    monkeypatch.setattr(runner, "_fetch_actor_token", no_fetch)
    monkeypatch.setattr(runner, "_fetch_subject_token", no_fetch)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert FakeSidecar.built is None


def test_no_x509_svid_withholds_with_a_named_reason(sidecar_env, monkeypatch, capsys):
    # the sidecar's most likely field failure: no SPIRE Workload API. It must
    # be a named withhold, not an `unexpected ...` from inside construction.
    def no_svid(role):
        raise FileNotFoundError("no SPIRE workload socket")
    monkeypatch.setattr(runner.identity, "export_tls_pems", no_svid)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert FakeSidecar.built is None
    out = capsys.readouterr().out
    assert "X509-SVID" in out and "SPIRE" in out


def test_mint_refusal_withholds_that_audience_and_keeps_the_rest(
        sidecar_env, monkeypatch):
    def local_exchange(run_token, server, timeout=10.0, actor_token=None):
        def _mint(*, audience, scope=None, **_ignored):
            if audience == "resource:obs":
                raise gateway.GatewayUnavailable("refused")
            return {"access_token": "T"}
        return _mint
    monkeypatch.setattr(gateway, "local_exchange", local_exchange)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(("ci", "obs")), {}))
    # the survivor is served through the sidecar (not its real URL), the
    # refused audience's tool is absent entirely
    assert view["ci"] == {"type": "http",
                          "url": "http://127.0.0.1:5001/tools/ci/mcp"}
    assert "obs" not in view
    assert instance is FakeSidecar.built


def test_every_mint_refused_means_no_sidecar_at_all(sidecar_env, monkeypatch):
    def local_exchange(run_token, server, timeout=10.0, actor_token=None):
        def _mint(**_kw):
            raise gateway.GatewayUnavailable("refused")
        return _mint
    monkeypatch.setattr(gateway, "local_exchange", local_exchange)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    assert FakeSidecar.built is None


def test_unaddressable_local_mint_withholds(sidecar_env, monkeypatch):
    # SERVER_URL is https (ANDYUR_MTLS): the run token must not cross in clear
    monkeypatch.setattr(gateway, "_server_host_port", lambda: None)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)


def test_unreachable_tools_are_withheld_before_being_promised(
        sidecar_env, monkeypatch):
    managed = _managed(("ci", "obs"))
    monkeypatch.setattr(
        gateway, "preflight",
        lambda m: ({"ci": m["ci"]}, {"obs": "connection refused"}))
    view, _ = runner._start_tool_egress(
        "agent", {}, partitioned=(managed, {}))
    assert "ci" in view and "obs" not in view


def test_start_failure_stops_the_sidecar_and_withholds(sidecar_env, monkeypatch):
    class ExplodingSidecar(FakeSidecar):
        def start(self):
            raise OSError("no more sockets")
    monkeypatch.setattr(toolsidecar, "ToolSidecar", ExplodingSidecar)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)
    # a half-started sidecar still owns a listener and the run's material
    assert FakeSidecar.built.stopped


def test_construction_failure_withholds(sidecar_env, monkeypatch):
    # build_app creates the mTLS client eagerly, so a failure can raise in
    # __init__ before there is anything to stop -- the withhold must cover that
    def explodes(**kwargs):
        raise RuntimeError("uvicorn config refused")
    monkeypatch.setattr(toolsidecar, "ToolSidecar", explodes)
    view, instance = runner._start_tool_egress(
        "agent", {}, partitioned=(_managed(), dict(PASSTHROUGH)))
    assert (view, instance) == (PASSTHROUGH, None)


def _import_config(value):
    """Import andyur.config in a fresh interpreter with ANDYUR_TOOL_EGRESS set to
    `value` -- or genuinely UNSET for None. Fresh interpreter because the refusal
    is at import time; returns the CompletedProcess."""
    root = pathlib.Path(__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(root)}
    env.pop("ANDYUR_TOOL_EGRESS", None)
    if value is not None:
        env["ANDYUR_TOOL_EGRESS"] = value
    return subprocess.run(
        [sys.executable, "-c", "from andyur import config; print('ok')"],
        capture_output=True, text=True, env=env, cwd=root, timeout=60)


def test_retired_egress_flag_refuses_its_dead_value_but_config_still_imports():
    # agentgateway was deleted (ADR-003). A deployment still pinned to it must
    # get a LOUD refusal at import, not a silently-ignored setting that runs a
    # topology that no longer exists.
    dead = _import_config("agentgateway")
    assert dead.returncode != 0
    assert "ANDYUR_TOOL_EGRESS" in dead.stderr and "agentgateway" in dead.stderr
    # positive control: the refusal is specific to the dead value, not "config
    # always raises" -- unset, empty, and the explicit sidecar name all import.
    for value in (None, "", "sidecar", "SIDECAR"):
        got = _import_config(value)
        assert got.returncode == 0, got.stderr
        assert got.stdout.strip() == "ok"
