"""Workload identity selection contracts."""

import sys
from types import SimpleNamespace

import pytest

from andyur import identity


def test_configured_spiffe_subject_is_explicit(monkeypatch):
    monkeypatch.setenv("ANDYUR_SPIFFE_ID", "spiffe://andyur.local/worker")

    assert str(identity._requested_subject()) == "spiffe://andyur.local/worker"


def test_single_identity_compatibility_uses_no_subject(monkeypatch):
    monkeypatch.delenv("ANDYUR_SPIFFE_ID", raising=False)

    assert identity._requested_subject() is None


def test_live_x509_readiness_fetches_exact_identity_and_bundle(monkeypatch):
    state = {"closed": False}

    class Source:
        def __init__(self, **kwargs):
            assert kwargs["timeout_in_seconds"] == identity.SVID_TIMEOUT

        def get_x509_context(self):
            return SimpleNamespace(default_svid=SimpleNamespace(
                spiffe_id="spiffe://andyur.local/control-plane"))

        def get_bundle_for_trust_domain(self, domain):
            assert domain == identity.TRUST_DOMAIN
            return object()

        def close(self):
            state["closed"] = True

    monkeypatch.setitem(sys.modules, "spiffe", SimpleNamespace(
        X509Source=Source, TrustDomain=lambda value: value))
    identity.assert_live_x509_identity("spiffe://andyur.local/control-plane")
    assert state["closed"] is True


def test_live_x509_readiness_refuses_wrong_identity_and_closes(monkeypatch):
    state = {"closed": False}

    class Source:
        def __init__(self, **_kwargs):
            pass

        def get_x509_context(self):
            return SimpleNamespace(default_svid=SimpleNamespace(
                spiffe_id="spiffe://andyur.local/worker"))

        def close(self):
            state["closed"] = True

    monkeypatch.setitem(sys.modules, "spiffe", SimpleNamespace(
        X509Source=Source, TrustDomain=lambda value: value))
    with pytest.raises(ValueError, match="identity mismatch"):
        identity.assert_live_x509_identity("spiffe://andyur.local/control-plane")
    assert state["closed"] is True
