import importlib.util
from pathlib import Path
import sys


PATH = Path(__file__).parents[1] / "infra" / "oauth-client-bakeoff" / "bakeoff.py"
SPEC = importlib.util.spec_from_file_location("oauth_bakeoff", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _result():
    load = {"server_started": 8, "server_issued": 8,
            "server_max_active": 2, "errors": {}}
    redirect = {"started": 1, "methods": {"POST": 1}}
    return {"configuration": {"operations": 8, "concurrency": 2},
            "authlib_load": dict(load), "requests_load": dict(load),
            "authlib_redirect": dict(redirect),
            "requests_redirect": dict(redirect),
            "request_shape": {"authlib_invalid": 0, "requests_invalid": 0}}


def test_validator_accepts_exact_bounded_wire_result():
    assert MODULE.validate_results(_result()) == (True, [])


def test_validator_rejects_extra_attempt_result():
    result = _result()
    result["requests_load"]["server_started"] += 1
    passed, failures = MODULE.validate_results(result)
    assert not passed
    assert "wire attempt/issuance count mismatch" in failures[0]


def test_validator_rejects_redirect_follow_result():
    result = _result()
    result["requests_redirect"]["started"] = 2
    result["requests_redirect"]["methods"]["GET"] = 1
    passed, failures = MODULE.validate_results(result)
    assert not passed
    assert "redirect was followed" in failures[0]


def test_validator_rejects_concurrency_overshoot_result():
    result = _result()
    result["authlib_load"]["server_max_active"] = 3
    passed, failures = MODULE.validate_results(result)
    assert not passed
    assert "concurrency limit exceeded" in failures[0]
