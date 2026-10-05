import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra/curity/token-exchange.js"
README = ROOT / "infra/curity/README.md"
GATE = ROOT / "infra/curity/verify-rfc7523.py"
SINGLE_GATE = ROOT / "infra/curity/verify-single-exchange.py"
RESULT = ROOT / "infra/curity/result-rfc7523-live-2026-08-20-macos-arm64.json"


def test_curity_procedure_uses_only_introspected_tokens_and_emits_exact_actor():
    source = SCRIPT.read_text()
    assert "getPresentedSubjectToken()" in source
    assert "getPresentedActorToken(null)" in source
    assert 'accessTokenData.act = {sub: actorToken.get("sub")}' in source
    assert "getSubjectTokenValue" not in source
    assert "decode" not in source.lower()


def test_curity_assets_do_not_claim_certification_or_contain_demo_secret():
    text = SCRIPT.read_text() + README.read_text() + GATE.read_text()
    assert "admin123" not in text
    assert "not yet production certification" in text
    assert "sender-binding-spike/" in text
    assert "must not be imported" in text


def test_live_gate_has_positive_negative_source_binding_and_teardown():
    source = GATE.read_text()
    for required in (
        '"subject_status": 200', '"actor_status": 200',
        '"exchange_status": 200', '"attacker_signature"',
        '"wrong_audience"', '"source_sha256"', 'cleanup(subject, broker)',
        '"semantic_assertion_red": True', 'set_token_procedure(procedure_source)',
        '"resource_enforcement"', 'live_resource_gate(',
    ):
        assert required in source
    assert "admin123" not in source


def test_live_curity_evidence_is_bound_to_current_source():
    result = json.loads(RESULT.read_text())
    assert result["result"] == "pass"
    assert result["source_sha256"] == {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in result["source_sha256"]
    }


def test_single_exchange_cleanup_never_rewrites_an_unconfigured_tenant():
    source = SINGLE_GATE.read_text()
    assert "finally:\n        if configured:\n            try:\n                plugin_cleanup()" in source
