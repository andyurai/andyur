"""Framework-level observability defaults, isolated from the test escape hatch."""

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _otel_default(value=None):
    env = dict(os.environ)
    if value is None:
        env.pop("ANDYUR_OTEL", None)
    else:
        env["ANDYUR_OTEL"] = value
    result = subprocess.run(
        [sys.executable, "-c", "from andyur import otel; print(otel.OTEL_ON)"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def test_framework_tracing_is_on_when_the_client_says_nothing():
    assert _otel_default() == "True"


def test_development_can_explicitly_turn_tracing_off():
    assert _otel_default("off") == "False"


def test_invalid_telemetry_value_fails_instead_of_silently_disabling():
    env = {**os.environ, "ANDYUR_OTEL": "tru"}
    result = subprocess.run(
        [sys.executable, "-c", "from andyur import otel"], cwd=ROOT, env=env,
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "ANDYUR_OTEL='tru' is invalid" in result.stderr


def _e2e_harness_otel(value=None, endpoint=None):
    env = {**os.environ, "ANDYUR_E2E_ENV_PROBE": "1"}
    if value is None:
        env.pop("ANDYUR_OTEL", None)
    else:
        env["ANDYUR_OTEL"] = value
    if endpoint is None:
        env.pop("ANDYUR_OTEL_ENDPOINT", None)
    else:
        env["ANDYUR_OTEL_ENDPOINT"] = endpoint
    result = subprocess.run(
        ["bash", "infra/verify-e2e.sh"], cwd=ROOT, env=env,
        capture_output=True, text=True, check=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def test_e2e_harness_defaults_telemetry_off_without_overriding_the_caller():
    assert _e2e_harness_otel() == {
        "ANDYUR_OTEL": "off", "ANDYUR_OTEL_ENDPOINT": "",
    }
    assert _e2e_harness_otel("on", "http://collector:4318") == {
        "ANDYUR_OTEL": "on", "ANDYUR_OTEL_ENDPOINT": "http://collector:4318",
    }
    assert _e2e_harness_otel("off") == {
        "ANDYUR_OTEL": "off", "ANDYUR_OTEL_ENDPOINT": "",
    }
