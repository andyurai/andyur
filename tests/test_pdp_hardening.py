"""Slice 4: the enforcement point must never mistake a non-answer for a permit.

These tests are about the seam between "the policy said no" and "nothing said
anything". Every layer that touches an authorization response has to collapse
the second case into a denial, because the failure is silent otherwise: a
misspelled rule, an unloaded bundle, a truncated batch and a genuine refusal
all look alike on the wire, and the only safe reading of all four is no.

The live engine is covered by infra/opa/verify-opa-hardening.sh (which attacks
it). These run with no Docker, so the parsing rules stay pinned in CI.
"""

import importlib.util
import pathlib

import httpx
import pytest

from andyur import config
from andyur.server import pdp

# The shim is deployment infrastructure, not part of the andyur package (it can
# be run beside a PDP that is not OPA at all), so load it by path.
_SHIM_PATH = pathlib.Path(__file__).resolve().parent.parent / "infra" / "opa" / "authzen_shim.py"
_spec = importlib.util.spec_from_file_location("authzen_shim", _SHIM_PATH)
shim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shim)


def test_live_tampered_bundle_gate_waits_for_the_observable_refusal():
    """Do not restore the fixed sleep that raced OPA and Docker log delivery.

    The live mutation proves the bounded waiter turns red with a one-second
    budget and green with the production budget. This source pin keeps CI from
    silently replacing that waiter with the historical fixed delay.
    """
    gate = (_SHIM_PATH.parent / "verify-opa-hardening.sh").read_text()
    assert "wait_for_bundle_refusal_signal" in gate
    assert "if wait_for_bundle_refusal_signal; then" in gate
    assert "OPA_REFUSAL_SIGNAL_TIMEOUT_SECONDS:-30" in gate
    assert 'sleep 12' not in gate


# --- the shim's reading of OPA's answer ------------------------------------

@pytest.mark.parametrize("result, expected", [
    # the shapes a working policy produces
    ({"decision": True, "reason_admin": "permitted: operator"}, True),
    ({"decision": False, "reason_admin": "denied: nothing permits this"}, False),
    (True, True),    # a deployment querying a bare boolean rule
    (False, False),
    # every shape that is NOT an answer must deny
    (None, False),          # undefined: unloaded, misnamed, or simply unmatched
    ({}, False),            # a package document with no decision rule
    ({"decision": "true"}, False),   # a string, not a boolean
    ({"decision": 1}, False),        # truthy but not a boolean
    ({"decision": None}, False),
    ("permit", False),      # a policy returning prose
    (1, False),
    ([True], False),
])
def test_only_a_real_boolean_permits(result, expected):
    decision, reason = shim._decide(result)
    assert decision is expected
    assert reason  # a decision always carries an explanation for the audit log


def test_undefined_is_distinguishable_in_the_reason():
    """Undefined and refused are both denials, but an operator needs to tell
    them apart: one is a broken deployment, the other is the policy working."""
    _, undefined = shim._decide(None)
    _, refused = shim._decide({"decision": False, "reason_admin": "denied: no rule permits"})
    assert "undefined" in undefined
    assert undefined != refused


def test_truthy_int_does_not_permit():
    """Guards the classic Python bug: `if result.get("decision")` would permit
    on 1, "yes", or a non-empty list. Identity against True is what stops it."""
    assert shim._decide({"decision": 1})[0] is False


# --- the enforcement point's reading of the PDP's answer -------------------

class _Resp:
    """What the PDP said, as `boundedhttp.post_json` would hand it back.

    A non-2xx status is raised rather than returned, because that is where the
    bound client raises it -- these tests assert how the ENFORCEMENT POINT reads
    an answer, so the transport's own error handling belongs behind the seam and
    not in the assertions.
    """

    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def result(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)
        return self._payload


def _patch_post(monkeypatch, resp):
    """Patch the SEAM the enforcement point actually calls.

    It used to patch `httpx.Client`, which stopped existing when PDP calls moved
    behind `andyur.boundedhttp` to get a total wall-clock bound. That the whole
    file went red on the move is the correct outcome -- a mock of a transport the
    code no longer uses would otherwise have kept passing while testing nothing.
    """
    def _post_json(url, payload, **kw):
        if isinstance(resp, Exception):
            raise resp
        return resp.result()

    monkeypatch.setattr(pdp.boundedhttp, "post_json", _post_json)
    monkeypatch.setattr(config, "PDP", "authzen")


def test_missing_decision_key_denies(monkeypatch):
    _patch_post(monkeypatch, _Resp({"context": {"reason_admin": {"en": "x"}}}))
    assert pdp.evaluate(pdp.Subject(type="run", is_operator=True), "files:read") is False


def test_non_boolean_decision_denies(monkeypatch):
    _patch_post(monkeypatch, _Resp({"decision": "true"}))
    assert pdp.evaluate(pdp.Subject(type="run", is_operator=True), "files:read") is False


def test_transport_failure_denies(monkeypatch):
    _patch_post(monkeypatch, httpx.ConnectError("no route"))
    assert pdp.evaluate(pdp.Subject(type="run", is_operator=True), "files:read") is False


def test_pdp_error_status_denies(monkeypatch):
    """The shim answers 503 when the engine is unreachable rather than inventing
    a decision. The enforcement point must treat that as a denial, not as an
    empty permit."""
    _patch_post(monkeypatch, _Resp({"detail": "policy engine unavailable"}, status=503))
    assert pdp.evaluate(pdp.Subject(type="run", is_operator=True), "files:read") is False


def test_short_batch_denies_everything(monkeypatch):
    """A batch with fewer decisions than actions cannot be aligned. Guessing
    would apply one action's permit to a different action, so the whole batch
    fails rather than silently mismatching."""
    _patch_post(monkeypatch, _Resp({"evaluations": [{"decision": True}]}))
    got = pdp.evaluate_all(pdp.Subject(type="user", entitlements=["*"]),
                           ["files:read", "files:write"])
    assert got == [False, False]


def test_long_batch_denies_everything(monkeypatch):
    _patch_post(monkeypatch, _Resp(
        {"evaluations": [{"decision": True}, {"decision": True}, {"decision": True}]}))
    got = pdp.evaluate_all(pdp.Subject(type="user", entitlements=["*"]),
                           ["files:read", "files:write"])
    assert got == [False, False]


def test_batch_order_is_preserved(monkeypatch):
    _patch_post(monkeypatch, _Resp(
        {"evaluations": [{"decision": True}, {"decision": False}]}))
    got = pdp.evaluate_all(pdp.Subject(type="user", entitlements=["files:read"]),
                           ["files:read", "files:write"])
    assert got == [True, False]


def test_denial_reason_is_logged_not_returned(monkeypatch, caplog):
    """The decider's reason belongs in the operator's log. Returning it to the
    caller would turn every refusal into a hint about what would have worked,
    which is an oracle for walking the policy."""
    _patch_post(monkeypatch, _Resp(
        {"decision": False,
         "context": {"reason_admin": {"en": "denied: outside business hours"}}}))
    with caplog.at_level("INFO"):
        assert pdp.evaluate(pdp.Subject(type="run", scope=["files:write"]),
                            "files:write") is False
    assert "outside business hours" in caplog.text


def test_reason_absent_is_not_an_error(monkeypatch):
    """reason_admin is OPTIONAL in AuthZEN. A conformant PDP that omits it must
    still produce a usable decision, not an exception."""
    assert pdp._reason({"decision": False}) == "(no reason given)"
    assert pdp._reason({"decision": False, "context": {}}) == "(no reason given)"
    assert pdp._reason({"context": {"reason_admin": {"fr": "refuse"}}}) == "refuse"
