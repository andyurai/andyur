"""The governed registry refuses everything it cannot prove, and stamps what
it serves.

The verify/pull seams are faked here so each refusal is tested in isolation;
the real cosign/oras path is exercised end to end by
infra/verify-registry-governance.sh against a live local OCI registry.
"""

import json
from pathlib import Path

import pytest

from andyur.registry.governed import GovernedAgentRegistry
from andyur.registry.models import RegistryUnavailable

DIGEST = "sha256:" + "ab" * 32
REF = f"registry.local/andyur/agents@{DIGEST}"

VALID_MANIFEST = {
    "schema_version": "andyur.agent-resolution/v1",
    "agent_id": "agt_governed_probe",
    "name": "governed-probe",
    "instructions": "exists so the governed read path has something to serve",
    "model": None,
    "tools": [],
    "ceiling": {"actions": [], "resources": []},
}


@pytest.fixture()
def key(tmp_path: Path) -> str:
    key = tmp_path / "cosign.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n")
    return str(key)


def _pull_valid(ref: str, dest: str) -> None:
    (Path(dest) / "probe.json").write_text(json.dumps(VALID_MANIFEST))


def _verify_ok(ref: str, key_path: str) -> None:
    return None


def test_a_tag_reference_is_refused_before_any_external_call(key):
    """A tag is a moving target: whoever can push the tag chooses what agents
    exist. Refusal must happen before verify/pull touch the network."""
    calls = []
    with pytest.raises(RegistryUnavailable, match="digest"):
        GovernedAgentRegistry(
            "registry.local/andyur/agents:latest", key,
            verify=lambda r, k: calls.append("verify"),
            pull=lambda r, d: calls.append("pull"))
    assert calls == []


def test_a_deny_listed_digest_is_refused_even_with_a_valid_signature(key):
    calls = []
    with pytest.raises(RegistryUnavailable, match="deny-listed"):
        GovernedAgentRegistry(
            REF, key, deny_digests=frozenset({DIGEST}),
            verify=lambda r, k: calls.append("verify"),
            pull=lambda r, d: calls.append("pull"))
    assert calls == []


def test_a_failed_signature_stops_the_pull(key):
    calls = []

    def verify_fails(ref, key_path):
        raise RegistryUnavailable("cosign verify failed (rc=1): bad signature")

    with pytest.raises(RegistryUnavailable, match="bad signature"):
        GovernedAgentRegistry(
            REF, key, verify=verify_fails,
            pull=lambda r, d: calls.append("pull"))
    assert calls == []


def test_a_missing_public_key_is_refused(tmp_path):
    with pytest.raises(RegistryUnavailable, match="public key"):
        GovernedAgentRegistry(
            REF, str(tmp_path / "absent.pub"),
            verify=_verify_ok, pull=_pull_valid)


def test_the_positive_control_serves_and_stamps_the_digest(key):
    """Refusals prove nothing unless the same machinery serves when everything
    checks out -- and what it serves must carry the snapshot digest."""
    reg = GovernedAgentRegistry(REF, key, verify=_verify_ok, pull=_pull_valid)
    resolution = reg.resolve("agt_governed_probe")
    assert resolution.registry_digest == DIGEST
    assert [r.registry_digest for r in reg.list_agents()] == [DIGEST]
    assert reg.digest == DIGEST


def test_manifest_mode_resolutions_carry_no_digest(tmp_path):
    """The ungoverned path must say so: None, not an invented value."""
    from andyur.registry.manifest_registry import ManifestAgentRegistry
    (tmp_path / "probe.json").write_text(json.dumps(VALID_MANIFEST))
    reg = ManifestAgentRegistry(tmp_path)
    assert reg.resolve("agt_governed_probe").registry_digest is None


def test_an_invalid_pulled_snapshot_fails_and_removes_the_workdir(key):
    """A verified signature on garbage is still garbage: manifest validation
    runs unchanged on the pulled content, and the half-made workdir must not
    survive to be mistaken for a good snapshot."""
    seen = {}

    def pull_garbage(ref, dest):
        seen["dest"] = dest
        (Path(dest) / "broken.json").write_text("{not json")

    with pytest.raises(Exception, match="not valid JSON"):
        GovernedAgentRegistry(REF, key, verify=_verify_ok, pull=pull_garbage)
    assert not Path(seen["dest"]).exists()


def test_a_ref_that_could_reach_the_tool_as_a_flag_is_refused(key):
    """A digest anywhere in the string is not a pin: "--flag@sha256:…" would
    pass a search() and reach cosign/oras argv as an option. The pin check
    must anchor the whole reference and reject a leading dash."""
    calls = []
    with pytest.raises(RegistryUnavailable, match="OCI reference"):
        GovernedAgentRegistry(
            f"--output=/tmp/x@{DIGEST}", key,
            verify=lambda r, k: calls.append("verify"),
            pull=lambda r, d: calls.append("pull"))
    assert calls == []


def test_a_non_integer_tool_timeout_is_a_clean_refusal_not_a_crash(key, monkeypatch):
    """A bad ANDYUR_REGISTRY_TOOL_TIMEOUT must surface as RegistryUnavailable
    (a clean 503) like every other misconfig, not an uncaught ValueError from
    int() reaching the caller as a 500. The parse happens inside _run_tool, so
    it only fires when verify/pull actually shell out -- use the real default
    verify to reach it."""
    monkeypatch.setenv("ANDYUR_REGISTRY_TOOL_TIMEOUT", "30s")
    with pytest.raises(RegistryUnavailable, match="must be an integer"):
        # real _default_verify -> _run_tool -> _tool_timeout_seconds(); cosign
        # need not exist, the timeout parse raises first.
        GovernedAgentRegistry(REF, key, pull=_pull_valid)


def test_a_malformed_deny_entry_is_refused_not_silently_ignored(key):
    """A typo'd deny digest that can never match is a revocation that does
    nothing -- fail open. Refuse the config instead."""
    with pytest.raises(RegistryUnavailable, match="not a"):
        GovernedAgentRegistry(
            REF, key, deny_digests=frozenset({"sha256:oops"}),
            verify=_verify_ok, pull=_pull_valid)


def test_the_workdir_does_not_leak_on_the_success_path(key):
    seen = {}

    def pull_capturing(ref, dest):
        seen["dest"] = dest
        _pull_valid(ref, dest)

    reg = GovernedAgentRegistry(REF, key, verify=_verify_ok, pull=pull_capturing)
    assert reg.resolve("agt_governed_probe").registry_digest == DIGEST
    assert not Path(seen["dest"]).exists(), "pulled snapshot workdir leaked"


def test_env_factory_requires_ref_and_key(monkeypatch, key):
    from andyur.registry.governed import governed_registry_from_env
    monkeypatch.delenv("ANDYUR_REGISTRY_REF", raising=False)
    with pytest.raises(RegistryUnavailable, match="ANDYUR_REGISTRY_REF"):
        governed_registry_from_env()
    monkeypatch.setenv("ANDYUR_REGISTRY_REF", REF)
    monkeypatch.delenv("ANDYUR_REGISTRY_COSIGN_KEY", raising=False)
    with pytest.raises(RegistryUnavailable, match="COSIGN_KEY"):
        governed_registry_from_env()
