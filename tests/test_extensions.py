"""Extensions: what loads, what it may plug into, and that an authorization
policy can only ever narrow.

The loader half is tested against a fake entry-point table so each refusal is
reached on purpose. The policy half runs over the real HTTP surface with the
same user fixtures the admin and cross-user tests use, because the claim worth
proving is about the SERVER: that a policy is asked about every request that
presents a user token, on every route and before any of them looks anything
up; that its refusal is a 403; that its allow changes nothing the platform
would have refused anyway; and that a policy which hangs costs the requests
waiting on it and nothing else.
"""

import asyncio
import logging
import re
import threading
import time

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode
from starlette.requests import Request

from andyur import config, extensions, observability, otel
from andyur.orchestration import registry
from andyur.server import app as app_module, oidc

from conftest import NO_AUTH, OPERATOR_SVID, RUNNER_SVID, svid_header

client = TestClient(app_module.app)


# -- the loader ------------------------------------------------------------------

class _Dist:
    def __init__(self, name):
        self.name, self.version = name, "1.2.3"


class _EP:
    def __init__(self, name, register, dist="acme-ext"):
        self.name, self._register, self.dist = name, register, _Dist(dist)
        self.loaded = False

    def load(self):
        self.loaded = True
        return self._register


def _table(*eps):
    def entry_points(*, group, name):
        assert group == extensions.ENTRY_POINT_GROUP
        return [ep for ep in eps if ep.name == name]
    return entry_points


def _noop(_registrar):
    pass


def test_nothing_named_means_nothing_is_even_looked_up():
    def exploding(**_):
        raise AssertionError("scanned entry points with no extension named")
    assert extensions.load((), entry_points=exploding) == extensions.Loaded()


def test_an_installed_extension_nobody_named_is_never_imported():
    named, unnamed = _EP("named", _noop), _EP("unnamed", _noop)
    result = extensions.load(("named",), entry_points=_table(named, unnamed))
    assert named.loaded and not unnamed.loaded
    assert result.extensions == (extensions.LoadedExtension("named", "acme-ext", "1.2.3"),)


def test_a_named_extension_that_is_not_installed_stops_the_process():
    with pytest.raises(extensions.ExtensionError, match="no installed distribution"):
        extensions.load(("missing",), entry_points=_table())


def test_an_extension_declared_twice_is_refused_rather_than_picked_by_install_order():
    eps = _table(_EP("dup", _noop, "one"), _EP("dup", _noop, "two"))
    with pytest.raises(extensions.ExtensionError, match="more than one installed"):
        extensions.load(("dup",), entry_points=eps)


def test_naming_an_extension_twice_is_refused(monkeypatch):
    monkeypatch.setenv(extensions.ENV_VAR, "a, b ,a")
    with pytest.raises(extensions.ExtensionError, match="twice"):
        extensions.configured_names()


def test_an_extension_that_raises_while_registering_stops_the_process():
    def broken(_registrar):
        raise RuntimeError("boom")
    with pytest.raises(extensions.ExtensionError, match="failed while registering: boom"):
        extensions.load(("broken",), entry_points=_table(_EP("broken", broken)))


def test_an_extension_cannot_take_a_built_in_provider_name():
    def hijack(r):
        r.workflow_provider("Temporal", lambda: None)
    with pytest.raises(extensions.ExtensionError, match="built in"):
        extensions.load(("hijack",), entry_points=_table(_EP("hijack", hijack)),
                        reserved_providers=frozenset(registry.BUILDERS))


def test_two_extensions_cannot_offer_the_same_provider():
    def offer(r):
        r.workflow_provider("cadence", lambda: None)
    eps = _table(_EP("a", offer), _EP("b", offer))
    with pytest.raises(extensions.ExtensionError, match="offered by both 'a' and 'b'"):
        extensions.load(("a", "b"), entry_points=eps)


class _Allow:
    def refuse(self, request):
        return None


def test_at_most_one_authorization_policy():
    def policy(r):
        r.authorization_policy(_Allow())
    eps = _table(_EP("a", policy), _EP("b", policy))
    with pytest.raises(extensions.ExtensionError, match="at most one"):
        extensions.load(("a", "b"), entry_points=eps)


def test_a_policy_without_refuse_is_refused():
    def bad(r):
        r.authorization_policy(object())
    with pytest.raises(extensions.ExtensionError, match="refuse"):
        extensions.load(("bad",), entry_points=_table(_EP("bad", bad)))


# -- loader edges ----------------------------------------------------------------

def test_names_are_trimmed_and_empty_items_dropped(monkeypatch):
    monkeypatch.setenv(extensions.ENV_VAR, " a , ,b,")
    assert extensions.configured_names() == ("a", "b")


def test_an_extension_that_fails_to_import_stops_the_process():
    class _Broken(_EP):
        def load(self):
            raise ImportError("no module named acme")
    with pytest.raises(extensions.ExtensionError, match="'gone' failed to import"):
        extensions.load(("gone",), entry_points=_table(_Broken("gone", _noop)))


@pytest.mark.parametrize("name, builder, said", [
    ("  ", lambda: None, "empty name"),
    ("cadence", "not callable", "without a callable builder"),
])
def test_a_provider_must_have_a_name_and_a_builder(name, builder, said):
    def offer(r):
        r.workflow_provider(name, builder)
    with pytest.raises(extensions.ExtensionError, match=said):
        extensions.load(("x",), entry_points=_table(_EP("x", offer)))


def test_an_async_policy_is_refused_at_registration():
    """It would return a coroutine, which is neither None nor a reason, and
    every request would be refused with nothing saying why."""
    class _Async:
        async def refuse(self, request):
            return None

    def register(r):
        r.authorization_policy(_Async())
    with pytest.raises(extensions.ExtensionError, match="refuse\\(\\) is async"):
        extensions.load(("a",), entry_points=_table(_EP("a", register)))


@pytest.mark.parametrize("env, value", [
    (extensions.POLICY_TIMEOUT_ENV, "soon"), (extensions.POLICY_TIMEOUT_ENV, "0"),
    (extensions.POLICY_CONCURRENCY_ENV, "-1"), (extensions.POLICY_CONCURRENCY_ENV, "1.5"),
])
def test_a_policy_bound_that_does_not_parse_stops_the_process(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    with pytest.raises(extensions.ExtensionError, match="must be a positive number"):
        extensions.policy_limits()


def test_the_policy_bounds_come_from_the_environment(monkeypatch):
    monkeypatch.setenv(extensions.POLICY_TIMEOUT_ENV, "0.5")
    monkeypatch.setenv(extensions.POLICY_CONCURRENCY_ENV, "3")

    def register(r):
        r.authorization_policy(_Allow())
    result = extensions.load(("a",), entry_points=_table(_EP("a", register)))
    gate = result.authorization_gate
    assert (gate.timeout, gate.concurrency) == (0.5, 3)
    assert result.authorization_gate is gate, "one gate per load, shared by every request"


def test_the_real_loader_reserves_the_built_in_names_and_says_what_it_enabled(
        monkeypatch, caplog):
    """`load` refusing a built-in name proves nothing if `loaded` hands it an
    empty reserved set. This goes through the function the server calls."""
    def hijack(r):
        r.workflow_provider("temporal", lambda: None)
    monkeypatch.setenv(extensions.ENV_VAR, "hijack")
    monkeypatch.setattr(extensions.metadata, "entry_points",
                        _table(_EP("hijack", hijack)))
    extensions.reset()
    try:
        with pytest.raises(extensions.ExtensionError, match="built in"):
            extensions.loaded()
        monkeypatch.setenv(extensions.ENV_VAR, "fine")
        monkeypatch.setattr(extensions.metadata, "entry_points",
                            _table(_EP("fine", _noop, "acme-ext")))
        extensions.reset()
        with caplog.at_level(logging.WARNING, logger="andyur.extensions"):
            assert [e.name for e in extensions.loaded().extensions] == ["fine"]
        assert "extension enabled: fine (acme-ext 1.2.3)" in caplog.text
    finally:
        extensions.reset()


# -- the workflow-provider seam ----------------------------------------------------

class _Provider:
    def __init__(self, name):
        self.name = name


def _loaded_with(monkeypatch, **fields):
    """Install ONE loaded set. A fresh one per call would be a fresh gate per
    request, and no two requests would ever share its slots."""
    loaded = extensions.Loaded(**fields)
    monkeypatch.setattr(extensions, "loaded", lambda: loaded)
    return loaded


def test_an_enabled_extension_provider_is_selectable_and_built_ins_are_unchanged(monkeypatch):
    cadence = _Provider("cadence")
    _loaded_with(monkeypatch, workflow_providers={"cadence": lambda: cadence})
    assert registry.build_workflow_provider("cadence") is cadence
    assert set(registry.BUILDERS) == {"local", "temporal"}
    assert registry.build_workflow_provider("local").name == "local"


def test_a_provider_cannot_report_a_name_other_than_the_one_it_was_selected_under(monkeypatch):
    """Runs are bound and claimed by the name a provider REPORTS. Registered as
    `cadence` and reporting `local`, it would be handed the built-in's runs."""
    _loaded_with(monkeypatch, workflow_providers={"cadence": lambda: _Provider("local")})
    with pytest.raises(registry.UnknownProvider, match="reports its name as 'local'"):
        registry.build_workflow_provider("cadence")


def test_an_unknown_provider_lists_the_extension_ones_too(monkeypatch):
    _loaded_with(monkeypatch, workflow_providers={"cadence": lambda: None})
    with pytest.raises(registry.UnknownProvider, match="cadence, local, temporal"):
        registry.build_workflow_provider("temporel")


# -- the gate: somebody else's code, bounded ---------------------------------------

class _Recording:
    """Refuses whatever `deny` matches, and records every question it is asked."""

    def __init__(self, deny=lambda req: None):
        self.deny, self.asked = deny, []

    def refuse(self, request):
        self.asked.append(request)
        return self.deny(request)


def _request(**over):
    return extensions.UserRequest.of(**{
        "subject": "alice", "is_admin": False, "claims": {"sub": "alice"},
        "action": "GET /x", "params": {}, **over})


def _consult(gate, request=None):
    return asyncio.run(gate.consult(request or _request()))


def test_the_gate_names_each_thing_a_consultation_can_come_to():
    def gate(deny):
        return extensions.PolicyGate(_Recording(deny), timeout=5, concurrency=2)

    assert _consult(gate(lambda r: None)).outcome == extensions.ALLOW
    refused = _consult(gate(lambda r: "not today"))
    assert (refused.outcome, refused.reason) == (extensions.REFUSE, "not today")
    # An empty reason is still a reason: the policy answered with a string.
    assert _consult(gate(lambda r: "")).outcome == extensions.REFUSE


@pytest.mark.parametrize("verdict", [False, 0, True, [], {"allow": True}])
def test_anything_that_is_neither_none_nor_a_reason_refuses_as_the_policys_fault(verdict):
    """A policy written as a predicate returns False to mean "do not refuse".
    Read as a reason it is a refusal nobody meant; read as falsy it is an allow
    nobody checked. It is neither, and the request does not go through."""
    decision = _consult(extensions.PolicyGate(
        _Recording(lambda r: verdict), timeout=5, concurrency=1))
    assert decision.outcome == extensions.ERROR
    assert isinstance(decision.error, TypeError)


@pytest.mark.parametrize("raised", [RuntimeError("bug"), SystemExit(0), KeyboardInterrupt()])
def test_nothing_a_policy_raises_allows(raised):
    def boom(_r):
        raise raised
    decision = _consult(extensions.PolicyGate(_Recording(boom), timeout=5, concurrency=1))
    assert decision.outcome == extensions.ERROR and decision.error is raised


def test_a_policy_cannot_edit_what_it_is_handed():
    claims = {"sub": "alice", "realm_access": {"roles": ["ops"]}}

    def tamper(req):
        try:
            req.claims["sub"] = "carol"
        except TypeError:
            req.claims["realm_access"]["roles"].append("andyur-admin")
        return None
    request = _request(claims=claims)
    decision = _consult(extensions.PolicyGate(_Recording(tamper), timeout=5, concurrency=1),
                        request)
    assert decision.outcome == extensions.ALLOW
    assert claims == {"sub": "alice", "realm_access": {"roles": ["ops"]}}, (
        "the policy changed the claims the platform holds")
    with pytest.raises(TypeError):
        request.params["name"] = "other"
    with pytest.raises(TypeError):
        request.claims["sub"] = "carol"


def test_a_policy_that_hangs_is_timed_out_then_refused_at_once_until_it_returns():
    """The bound. Two slots, a policy that does not return: the first two
    callers wait out the deadline, and every caller after them is answered
    immediately. When the policy returns, the slots come back."""
    release, entered = threading.Event(), threading.Semaphore(0)

    def hang(_r):
        entered.release()
        release.wait(30)
        return None
    gate = extensions.PolicyGate(_Recording(hang), timeout=0.2, concurrency=2)
    try:
        for _ in range(2):
            decision = _consult(gate)
            assert decision.outcome == extensions.TIMEOUT
            assert 0.2 <= decision.seconds < 2
        assert entered.acquire(timeout=5) and entered.acquire(timeout=5)

        started = time.monotonic()
        assert _consult(gate).outcome == extensions.SATURATED
        assert time.monotonic() - started < 0.15, "saturated must not wait for the deadline"
    finally:
        release.set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and gate._slots._value < 2:
        time.sleep(0.01)
    gate._policy = _Recording()
    assert _consult(gate).outcome == extensions.ALLOW, "the slots never came back"


def test_a_call_that_cannot_start_gives_its_slot_back(monkeypatch):
    gate = extensions.PolicyGate(_Recording(), timeout=5, concurrency=1)

    def cannot_start(self):
        raise RuntimeError("can't start new thread")
    with monkeypatch.context() as patched:
        patched.setattr(threading.Thread, "start", cannot_start)
        with pytest.raises(RuntimeError, match="can't start"):
            _consult(gate)
    assert _consult(gate).outcome == extensions.ALLOW, "the slot was not returned"


@pytest.mark.parametrize("raised", [asyncio.CancelledError(), StopIteration("done")])
def test_an_exception_the_event_loop_treats_specially_is_still_the_policys_fault(raised):
    """Left on a future, CancelledError reads as the request being cancelled
    and StopIteration cannot be set at all. Both are the policy failing, and
    both are answered at once rather than a deadline later."""
    def boom(_r):
        raise raised
    decision = _consult(extensions.PolicyGate(_Recording(boom), timeout=5, concurrency=1))
    assert decision.outcome == extensions.ERROR and decision.error is raised
    assert decision.seconds < 1


def test_the_time_a_consultation_took_is_the_time_it_took():
    def slow(_r):
        time.sleep(0.05)
    decision = _consult(extensions.PolicyGate(_Recording(slow), timeout=5, concurrency=1))
    assert 0.05 <= decision.seconds < 2


def test_a_hung_policy_does_not_keep_the_process_alive():
    """Its thread is a daemon. A pool's workers are joined at exit, and one
    hung call then makes the server unable to stop without SIGKILL."""
    release = threading.Event()
    gate = extensions.PolicyGate(_Recording(lambda r: release.wait(30)),
                                 timeout=0.05, concurrency=1)
    try:
        assert _consult(gate).outcome == extensions.TIMEOUT
        (thread,) = [t for t in threading.enumerate()
                     if t.name == "andyur-extension-policy"]
        assert thread.daemon
    finally:
        release.set()


def test_the_documented_bounds_are_the_defaults():
    assert (extensions.DEFAULT_POLICY_TIMEOUT, extensions.DEFAULT_POLICY_CONCURRENCY) == (2.0, 8)
    documented = (app_module.config.PROJECT_ROOT / "docs" / "extensions.md").read_text()
    assert "| `ANDYUR_EXTENSION_POLICY_TIMEOUT` | `2.0` |" in documented
    assert "| `ANDYUR_EXTENSION_POLICY_CONCURRENCY` | `8` |" in documented


# -- the authorization seam, over HTTP ---------------------------------------------

ADMIN_ROLE = "andyur-admin"
_CLAIMS = {
    "alice-tok": {"sub": "alice"},
    "bob-tok": {"sub": "bob", "realm_access": {"roles": ["ops"]}},
    "carol-tok": {"sub": "carol", "realm_access": {"roles": [ADMIN_ROLE]}},
}


def _raise():
    raise oidc.InvalidUserToken("bad token")


@pytest.fixture
def users(monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "ADMIN_ROLE", ADMIN_ROLE)
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: _CLAIMS.get(t) or _raise())


@pytest.fixture
def policy(monkeypatch):
    def install(p, **bounds):
        loaded = _loaded_with(monkeypatch, authorization_policy=p,
                              authorization_policy_from="test-policy", **bounds)
        return p
    return install


def _hdr(tok):
    return {"X-Andyur-User-Token": tok}


def _mk(name, tok):
    r = client.post("/agents", json={"name": name}, headers=_hdr(tok))
    assert r.status_code == 201, r.text


def test_the_policy_sees_the_declared_route_its_parameters_and_the_caller(env, users, policy):
    _mk("pview", "alice-tok")
    p = policy(_Recording())
    assert client.get("/agents/pview", headers=_hdr("alice-tok")).status_code == 200
    req = p.asked[-1]
    assert req.action == "GET /agents/{name}"
    assert dict(req.params) == {"name": "pview"}
    assert (req.subject, req.is_admin) == ("alice", False)
    assert dict(req.claims) == {"sub": "alice"}

    client.get("/workers", headers=_hdr("carol-tok"))
    req = p.asked[-1]
    assert (req.subject, req.is_admin) == ("carol", True)
    assert req.claims["realm_access"]["roles"] == [ADMIN_ROLE]


def test_a_policy_refusal_is_a_403_carrying_the_reason(env, users, policy):
    _mk("pdeny", "alice-tok")
    policy(_Recording(lambda req: "read-only session"
                      if req.action.startswith("POST") else None))
    r = client.post("/agents/pdeny/trigger", json={"reason": "x"}, headers=_hdr("alice-tok"))
    assert r.status_code == 403
    assert r.json()["detail"] == "refused by authorization policy: read-only session"
    assert client.get("/agents/pdeny", headers=_hdr("alice-tok")).status_code == 200


def _api_routes():
    """Every operation the application serves, from its own description of
    itself. Walking `app.routes` for APIRoute misses a router that was
    included, which is one object there -- and the routes this left out were
    the registry reads, the ones the policy had never been asked about."""
    def plain(path):       # the schema writes {relpath:path} as {relpath}
        return re.sub(r":\w+}", "}", path)

    declared = {(method, route.path) for route in app_module.app.routes
                if isinstance(route, APIRoute) for method in route.methods}
    described = {(method.upper(), path)
                 for path, operations in app_module.app.openapi()["paths"].items()
                 for method in operations}
    known = {(method, plain(path)) for method, path in declared}
    assert known <= described, (
        f"routes hidden from the schema are not in this loop: {known - described}")
    included = described - known
    assert ("GET", "/v1/registry/agents") in included

    # Everything else in the table has to be accounted for. A route added with
    # add_route, or a mounted application, is not reached by an application
    # dependency at all: it would be ungoverned, and absent from this loop.
    documentation = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
    for route in app_module.app.routes:
        if isinstance(route, APIRoute):
            continue
        router = getattr(route, "original_router", None)
        if router is not None:
            for inner in router.routes:
                assert isinstance(inner, APIRoute), f"ungoverned route in a router: {inner!r}"
                for method in inner.methods:
                    assert any(m == method and path.endswith(plain(inner.path))
                               for m, path in described), (
                        f"{method} {inner.path} is hidden from the schema and "
                        "is not in this loop")
            continue
        assert getattr(route, "path", None) in documentation, (
            f"{route!r} is not an API route, so no policy governs it")
    return sorted(declared | included)


def test_the_route_table_check_refuses_a_route_no_policy_would_govern(monkeypatch):
    """The loop above is only as good as its enumeration. A route added outside
    the decorators is one the application dependency never runs for."""
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    extra = Route("/sidedoor", lambda request: PlainTextResponse("open"))
    monkeypatch.setattr(app_module.app.router, "routes",
                        [*app_module.app.router.routes, extra])
    with pytest.raises(AssertionError, match="no policy governs it"):
        _api_routes()


def test_every_route_is_governed_and_none_can_forget(env, users, policy):
    """THE coverage claim, made about the route table and not about a sample.

    A refuse-everything policy and a user token, against every method of every
    declared route: each answers with the policy's 403, having asked it once,
    about that route. A route added tomorrow is in this loop without anyone
    remembering to add it."""
    p = policy(_Recording(lambda req: "everything refused"))
    routes = _api_routes()
    assert len(routes) > 50, "the route table was not enumerated"
    for method, path in routes:
        before = len(p.asked)
        r = client.request(method, re.sub(r"[{}]|:\w+}", "", path),
                           headers=_hdr("bob-tok"))
        assert r.status_code == 403 and "everything refused" in r.text, (
            f"{method} {path} answered {r.status_code} to a refused user: {r.text[:120]}")
        assert [q.action for q in p.asked[before:]] == [f"{method} {path}"], (
            f"{method} {path} did not ask the policy exactly once about itself")


def test_a_refusal_does_not_say_whether_the_thing_exists(env, users, policy):
    """The policy answers before the route looks anything up, so a refused
    caller gets the same answer for another owner's agent and for no agent."""
    _mk("alice-secret", "alice-tok")
    policy(_Recording(lambda req: "auditors are read-only"
                      if req.subject == "bob" and req.action.startswith("POST") else None))
    answers = {name: client.post(f"/agents/{name}/trigger", json={"reason": "x"},
                                 headers=_hdr("bob-tok")) for name in
               ("alice-secret", "does-not-exist")}
    assert {r.status_code for r in answers.values()} == {403}
    assert answers["alice-secret"].text == answers["does-not-exist"].text
    # And with the policy allowing, the platform's own answer is unchanged.
    policy(_Recording())
    assert {client.post(f"/agents/{n}/trigger", json={"reason": "x"},
                        headers=_hdr("bob-tok")).status_code
            for n in answers} == {404}


def test_the_policy_is_asked_only_about_a_caller_the_platform_identified(env, users, policy):
    """A token that does not validate is a 401 and the policy is never shown
    it -- including on a route that would otherwise ignore the header."""
    p = policy(_Recording(lambda req: "everything refused"))
    for path in ("/agents", "/v1/registry/agents"):
        assert client.get(path, headers=_hdr("forged")).status_code == 401, path
    assert p.asked == []


def test_a_caller_with_no_workload_identity_reaches_neither_the_idp_nor_the_policy(
        env, users, policy, monkeypatch):
    """A user token means nothing here without the SVID of whatever forwarded
    it. Validated first, a forged token forced a key fetch per request from
    anyone who could connect, and a refusal told the holder of a stolen token
    what its user was barred from."""
    validated = []
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: validated.append(t) or _CLAIMS[t])
    p = policy(_Recording(lambda req: "everything refused"))
    for token in ("alice-tok", "forged"):
        r = client.get("/agents", headers={**_hdr(token), **NO_AUTH})
        assert r.status_code == 401 and "JWT-SVID" in r.text, r.text
        r = client.get("/agents", headers={**_hdr(token), "Authorization": "Bearer junk"})
        assert r.status_code == 401 and "invalid JWT-SVID" in r.text, r.text
    assert validated == [] and p.asked == []


def test_only_the_operator_can_put_a_user_to_the_policy(env, users, policy, monkeypatch):
    """A run holds a runner SVID and can hold its user's token. It is the
    component the platform does not trust, and it must not be able to read the
    policy's verdict on that user or take the policy's slots."""
    validated = []
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: validated.append(t) or _CLAIMS[t])
    p = policy(_Recording(lambda req: "alice barred: tier=gold only"))
    as_runner = {**_hdr("alice-tok"), **svid_header(RUNNER_SVID)}
    as_run = {**_hdr("alice-tok"), "X-Andyur-Run-Token": "anything"}
    for headers in (as_runner, as_run):
        r = client.post("/agents/x/trigger", json={"reason": "x"}, headers=headers)
        assert r.status_code == 403
        assert r.json()["detail"] == "a user token is accepted only from the operator workload"
    assert validated == [] and p.asked == []
    # The control: the operator, with the same token, does reach the policy.
    r = client.post("/agents/x/trigger", json={"reason": "x"}, headers=_hdr("alice-tok"))
    assert "alice barred" in r.text and len(p.asked) == 1


def test_identifying_the_caller_never_runs_on_the_event_loop(env, users, policy, monkeypatch):
    """Both checks can wait on something outside the process: the workload API,
    the identity provider's keys. On the loop, one slow answer is every
    request's delay."""
    on_loop = []

    def validate(token):
        try:
            asyncio.get_running_loop()
            on_loop.append(token)
        except RuntimeError:
            pass
        return _CLAIMS[token]
    monkeypatch.setattr(oidc, "validate_user_claims", validate)
    policy(_Recording())
    assert client.get("/agents", headers=_hdr("alice-tok")).status_code == 200
    assert on_loop == []


def test_with_user_auth_off_a_policy_is_never_asked(env, policy, monkeypatch):
    """Startup refuses this configuration. If it is reached anyway, a header
    nobody validated is not shown to the policy as a user."""
    monkeypatch.setattr(config, "USER_AUTH", False)
    p = policy(_Recording(lambda req: "everything refused"))
    assert client.get("/workers", headers=_hdr("anything")).status_code == 200
    assert p.asked == []


def test_a_refusal_with_nothing_to_say_still_says_who_refused(env, users, policy):
    policy(_Recording(lambda req: "  \n "))
    r = client.get("/agents", headers=_hdr("alice-tok"))
    assert r.status_code == 403
    assert r.json()["detail"] == "refused by authorization policy"


def test_a_policy_that_allows_cannot_widen_ownership(env, users, policy):
    """THE invariant. The policy says yes to everything; bob still cannot see
    alice's agent, and gets the platform's 404, not a view."""
    _mk("pmine", "alice-tok")
    p = policy(_Recording())
    assert client.get("/agents/pmine", headers=_hdr("bob-tok")).status_code == 404
    assert p.asked, "the policy was never consulted, so this proves nothing"


def test_a_policy_that_allows_cannot_widen_the_admin_role(env, users, policy):
    p = policy(_Recording())
    assert client.get("/workers", headers=_hdr("bob-tok")).status_code == 403
    assert client.get("/workers", headers=_hdr("carol-tok")).status_code == 200
    assert len(p.asked) == 2


def test_a_policy_can_narrow_an_admin(env, users, policy):
    policy(_Recording(lambda req: "no ops views" if req.action == "GET /workers" else None))
    r = client.get("/workers", headers=_hdr("carol-tok"))
    assert r.status_code == 403 and "no ops views" in r.text


@pytest.mark.parametrize("verdict", [RuntimeError("policy bug"), False])
def test_a_policy_that_fails_refuses_without_echoing_what_it_did(env, users, policy, verdict):
    def broken(_req):
        if isinstance(verdict, Exception):
            raise verdict
        return verdict
    policy(_Recording(broken))
    r = client.get("/agents", headers=_hdr("alice-tok"))
    assert r.status_code == 403
    assert r.json()["detail"] == "the authorization policy failed to evaluate this request"


def test_the_raw_operator_seam_is_not_policy_governed(env, users, policy):
    """No user token under user-auth is the host operator's SVID, kept reachable
    so the kill switch cannot become browser-only. A policy refusing everything
    must not take that away."""
    p = policy(_Recording(lambda req: "everything refused"))
    assert client.get("/workers").status_code == 200
    assert p.asked == []


def test_a_hung_policy_costs_its_own_callers_and_nobody_else(env, users, policy):
    """The policy never returns. Users are told the service is unavailable --
    within the deadline, then at once -- and the operator's path and the
    liveness check answer as if the policy were not there."""
    release = threading.Event()
    policy(_Recording(lambda req: release.wait(30) and None),
           policy_timeout=0.2, policy_concurrency=2)
    try:
        for _ in range(2):
            r = client.get("/agents", headers=_hdr("alice-tok"))
            assert r.status_code == 503 and "did not answer in time" in r.text
            assert r.headers["retry-after"] == "1"
        started = time.monotonic()
        r = client.get("/agents", headers=_hdr("alice-tok"))
        assert r.status_code == 503 and "too many calls outstanding" in r.text
        assert r.headers["retry-after"] == "1"
        assert time.monotonic() - started < 0.15

        for path in ("/workers", "/health"):
            started = time.monotonic()
            assert client.get(path).status_code == 200, path
            assert time.monotonic() - started < 0.15, f"{path} waited on the policy"
    finally:
        release.set()


# -- what the trace, the metrics and the log say -----------------------------------

@pytest.fixture
def telemetry(monkeypatch, caplog):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(app_module, "_tracer", provider.get_tracer("test"))
    metrics = []

    def record(service, name, value=1, **attributes):
        # The real validator, so a dimension outside the declared vocabulary
        # fails here instead of being swallowed by try_record_metric.
        clean = observability.metric_attributes(**attributes)
        observability.validate_record(name, value, clean)
        metrics.append((service, name, value, clean))
        return True
    monkeypatch.setattr(otel, "try_record_metric", record)
    caplog.set_level(logging.INFO)

    class Seen:
        def spans(self):
            return [s for s in exporter.get_finished_spans() if s.name == "authz.policy"]

        def span(self):
            (span,) = self.spans()
            return span

        def metrics(self):
            return {name: (value, attrs) for _svc, name, value, attrs in metrics}

        def events(self):
            return [(r.event_fields["outcome"], r.event_fields["reason"])
                    for r in caplog.records
                    if getattr(r, "event_name", "") == "extension_policy.decision"]

        def log_text(self):
            return "\n".join(r.getMessage() for r in caplog.records)
    return Seen()


def test_an_allow_is_on_the_trace_the_metric_and_the_log(env, users, policy, telemetry):
    policy(_Recording())
    assert client.get("/agents", headers=_hdr("alice-tok")).status_code == 200
    span = telemetry.span()
    assert dict(span.attributes) == {
        "andyur.authz.policy": "test-policy", "andyur.authz.action": "GET /agents",
        "andyur.user": "alice", "andyur.authz.decision": "allow"}
    assert span.status.status_code != StatusCode.ERROR and not span.events
    seen = telemetry.metrics()
    assert seen["andyur.extension_policy.decisions"] == (
        1, {"andyur.outcome": "success", "andyur.reason": "unknown"})
    value, attrs = seen["andyur.extension_policy.duration"]
    assert 0 < value < 5 and attrs == {"andyur.outcome": "success"}
    assert telemetry.events() == [("success", "unknown")]


def test_a_refusal_is_recorded_with_its_reason_redacted_and_bounded(env, users, policy,
                                                                    telemetry):
    """The reason is the policy's string. A token in it must not reach the
    trace, the log or the caller, and a megabyte of it must not either."""
    secret = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
    policy(_Recording(lambda req: secret + " " + "x" * 1_000_000))
    r = client.get("/agents", headers=_hdr("alice-tok"))
    assert r.status_code == 403
    span = telemetry.span()
    assert span.attributes["andyur.authz.decision"] == "refuse"
    assert span.status.status_code != StatusCode.ERROR, "a refusal is a decision, not a fault"
    (event,) = span.events
    reason = event.attributes["andyur.authz.reason"]
    assert event.name == "andyur.authz.refused"
    assert len(reason) <= otel.ATTRIBUTE_MAX_CHARS
    assert "refused GET /agents for 'alice'" in telemetry.log_text()
    for where in (reason, r.text, telemetry.log_text()):
        assert "eyJhbGciOiJSUzI1NiJ9" not in where
    assert len(r.text) < 1000
    assert telemetry.metrics()["andyur.extension_policy.decisions"][1] == {
        "andyur.outcome": "denied", "andyur.reason": "refused"}
    assert telemetry.events() == [("denied", "refused")]


def test_a_failing_policy_is_a_fault_on_the_trace_with_its_cause(env, users, policy,
                                                                 telemetry):
    def boom(_req):
        raise RuntimeError("policy bug")
    policy(_Recording(boom))
    assert client.get("/agents", headers=_hdr("alice-tok")).status_code == 403
    span = telemetry.span()
    assert span.attributes["andyur.authz.decision"] == "error"
    assert span.status.status_code == StatusCode.ERROR
    (event,) = span.events
    assert event.name == "exception"
    assert dict(event.attributes) == {
        "exception.type": "RuntimeError", "exception.message": "policy bug"}
    assert "failed on GET /agents for 'alice' (RuntimeError: policy bug)" in telemetry.log_text()
    assert telemetry.metrics()["andyur.extension_policy.decisions"][1] == {
        "andyur.outcome": "failure", "andyur.reason": "invalid"}
    assert telemetry.events() == [("failure", "invalid")]


def test_a_timeout_and_a_saturation_are_each_named(env, users, policy, telemetry):
    release = threading.Event()
    policy(_Recording(lambda req: release.wait(30) and None),
           policy_timeout=0.1, policy_concurrency=1)
    try:
        assert client.get("/agents", headers=_hdr("alice-tok")).status_code == 503
        assert client.get("/agents", headers=_hdr("alice-tok")).status_code == 503
        timed_out, saturated = telemetry.spans()
        assert timed_out.attributes["andyur.authz.decision"] == "timeout"
        assert saturated.attributes["andyur.authz.decision"] == "saturated"
        assert {timed_out.status.status_code, saturated.status.status_code} == {StatusCode.ERROR}
    finally:
        release.set()
    assert telemetry.events() == [("timeout", "timeout"), ("failure", "exhausted")]
    assert "did not answer GET /agents within 0.1s" in telemetry.log_text()
    assert "has all 1 calls outstanding" in telemetry.log_text()


def test_what_a_failing_policy_says_is_as_untrusted_as_what_it_returns(env, users, policy,
                                                                       telemetry):
    """The exception's message and its traceback carry whatever the policy put
    there. Recorded whole, a token in it reached the trace at full length."""
    secret = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"

    def boom(_req):
        raise RuntimeError(f"upstream said Authorization: Bearer {secret}\n" + "x" * 1_000_000)
    policy(_Recording(boom))
    r = client.get("/agents", headers=_hdr("alice-tok"))
    assert r.status_code == 403
    (event,) = telemetry.span().events
    assert set(event.attributes) == {"exception.type", "exception.message"}
    assert len(event.attributes["exception.message"]) <= otel.ATTRIBUTE_MAX_CHARS
    for where in (str(dict(event.attributes)), r.text, telemetry.log_text()):
        assert secret not in where
    assert len(telemetry.log_text()) < 5000


class _Unprintable(RuntimeError):
    def __str__(self):
        raise ValueError("Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl")


def test_nothing_about_a_failure_reaches_the_trace_except_through_the_redactor(
        env, users, policy, telemetry):
    """Three ways round it that a reviewer walked: an exception that cannot be
    printed, an exception CLASS named like a secret and a megabyte long, and a
    reason whose own methods raise. Each used to end as a 500 with the text
    recorded whole by the tracer."""
    secret = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
    loud = type("sk-ant-api03-" + "k" * 1_000_000, (RuntimeError,), {})

    class _Reason(str):
        def split(self, *a, **k):
            raise ValueError(f"password=hunter2 Bearer {secret}")

    def unprintable(_req):
        raise _Unprintable()

    def named(_req):
        raise loud(f"Bearer {secret}")

    for broken, decision in ((unprintable, "error"), (named, "error"),
                             (lambda req: _Reason("no"), "refuse")):
        policy(_Recording(broken))
        r = client.get("/agents", headers=_hdr("alice-tok"))
        assert r.status_code == 403, r.text
        span = telemetry.spans()[-1]
        assert span.attributes["andyur.authz.decision"] == decision
        recorded = str([dict(e.attributes) for e in span.events])
        assert len(recorded) < 2000 and "stacktrace" not in recorded
        for where in (recorded, r.text):
            assert secret not in where and "hunter2" not in where
    assert secret not in telemetry.log_text() and len(telemetry.log_text()) < 20000
    assert len(telemetry.events()) == 3, "a failure went unrecorded"


def test_the_span_records_nothing_the_code_did_not_put_there(env, users, policy,
                                                            telemetry, monkeypatch):
    """Whatever escapes inside the consultation -- here the gate itself failing
    -- must not be written to the trace by the tracer's own exception
    recording, which takes the message and the traceback whole."""
    policy(_Recording())
    gate = extensions.loaded().authorization_gate

    async def broken(_request):
        raise RuntimeError("Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl")
    monkeypatch.setattr(gate, "consult", broken)
    with pytest.raises(RuntimeError):
        client.get("/agents", headers=_hdr("alice-tok"))
    span = telemetry.span()
    assert not span.events and span.status.status_code != StatusCode.ERROR
    assert "andyur.authz.decision" not in span.attributes


def test_the_caller_on_the_span_goes_through_the_redactor(env, monkeypatch, policy, telemetry):
    """The subject is whatever the identity provider put in the claim."""
    monkeypatch.setattr(config, "USER_AUTH", True)
    secret = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
    monkeypatch.setattr(oidc, "validate_user_claims", lambda t: {"sub": f"Bearer {secret}"})
    policy(_Recording())
    client.get("/health", headers=_hdr("odd-tok"))
    assert secret not in telemetry.span().attributes["andyur.user"]


def test_the_policy_runs_inside_the_consultations_span(env, users, policy, telemetry):
    """So a decision service it calls is a child of this consultation, not a
    trace of its own that nobody can join to the request."""
    from opentelemetry import trace
    seen = []
    policy(_Recording(lambda req: seen.append(
        trace.get_current_span().get_span_context().span_id) and None))
    assert client.get("/agents", headers=_hdr("alice-tok")).status_code == 200
    assert seen == [telemetry.span().context.span_id]


def test_the_two_policy_metrics_are_the_kinds_the_runbook_says():
    assert observability.instrument_kind("andyur.extension_policy.decisions") == "counter"
    assert observability.instrument_kind("andyur.extension_policy.duration") == "histogram"


def test_a_request_with_no_declared_route_is_refused_and_says_so(users, policy, telemetry):
    """Not reachable over HTTP, where a request that matches no route never
    runs a dependency. If it ever is reached, the answer is a refusal that is
    on the trace, not a pass."""
    p = policy(_Recording())
    request = Request({"type": "http", "method": "GET", "path": "/nowhere",
                       "query_string": b"", "path_params": {},
                       "headers": [(b"x-andyur-user-token", b"alice-tok"),
                                   (b"authorization",
                                    svid_header(OPERATOR_SVID)["Authorization"].encode())]})
    with pytest.raises(HTTPException) as refused:
        asyncio.run(app_module._govern_user_request(request))
    assert refused.value.status_code == 403
    assert p.asked == []
    span = telemetry.span()
    assert span.attributes["andyur.authz.decision"] == "error"
    assert span.status.status_code == StatusCode.ERROR


# -- startup -----------------------------------------------------------------------

def test_a_policy_with_user_auth_off_refuses_to_start(monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", False)
    _loaded_with(monkeypatch, authorization_policy=_Allow(),
                 authorization_policy_from="test-policy")
    with pytest.raises(extensions.ExtensionError, match="ANDYUR_USER_AUTH is off"):
        app_module._assert_extensions()


def test_the_server_checks_its_extensions_before_it_serves(monkeypatch):
    """The check above is only worth something if startup runs it. This starts
    the real application."""
    monkeypatch.setattr(config, "USER_AUTH", False)
    _loaded_with(monkeypatch, authorization_policy=_Allow(),
                 authorization_policy_from="test-policy")
    with pytest.raises(extensions.ExtensionError, match="ANDYUR_USER_AUTH is off"):
        with TestClient(app_module.app):
            pass


def test_no_extensions_configured_starts_normally(monkeypatch):
    monkeypatch.delenv(extensions.ENV_VAR, raising=False)
    extensions.reset()
    try:
        app_module._assert_extensions()
        assert extensions.loaded() == extensions.Loaded()
    finally:
        extensions.reset()
