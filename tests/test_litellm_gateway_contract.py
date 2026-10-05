"""Freeze the intentionally small Andyur <-> shared LLM gateway boundary."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text())
CONFIG = yaml.safe_load((ROOT / "infra/litellm/config.yaml").read_text())


def test_shared_gateway_is_pinned_and_is_llm_only():
    service = COMPOSE["services"]["litellm"]
    assert service["profiles"] == ["llm"]
    assert service["image"] == (
        "docker.litellm.ai/berriai/litellm@"
        "sha256:af806882b7a6ced41658db5b6a7e98ed7b9b51d03b935e0417bf1c8552d688af"
    )
    serialized = yaml.safe_dump(service).lower()
    assert service["ports"] == ["127.0.0.1:${ANDYUR_LITELLM_PORT:-4000}:4000"]
    assert "mcp" not in serialized
    assert "agentgateway" not in serialized


def test_manifest_model_name_is_the_public_gateway_model():
    [deployment] = CONFIG["model_list"]
    assert deployment["model_name"] == "claude-haiku-4-5"
    assert deployment["litellm_params"]["model"] == "anthropic/claude-haiku-4-5"
    assert deployment["litellm_params"]["api_base"] == "os.environ/ANTHROPIC_API_BASE"
    assert deployment["litellm_params"]["api_key"] == "os.environ/ANTHROPIC_API_KEY"


def test_provider_key_and_telemetry_are_gateway_owned():
    service = COMPOSE["services"]["litellm"]
    env = service["environment"]
    assert env["ANTHROPIC_API_KEY"] == "${ANTHROPIC_API_KEY:-}"
    assert env["ANTHROPIC_API_BASE"] == "${ANTHROPIC_API_BASE:-https://api.anthropic.com}"
    assert env["OTEL_SERVICE_NAME"] == "andyur-litellm"
    command = service["command"][0]
    assert "ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY" in command
    assert "LITELLM_MASTER_KEY:?set LITELLM_MASTER_KEY" in command
    assert CONFIG["general_settings"]["master_key"] == "os.environ/LITELLM_MASTER_KEY"
    settings = CONFIG["litellm_settings"]
    assert settings["callbacks"] == ["otel"]
    assert settings["turn_off_message_logging"] is True


def test_native_anthropic_messages_route_exists_in_the_pinned_image_contract():
    readme = (ROOT / "infra/litellm/README.md").read_text()
    assert "Anthropic Messages/SSE" in readme
    assert "`/v1/messages`" in readme
    assert "There are no LiteLLM imports" in readme
    verifier = (ROOT / "infra/litellm/verify.sh").read_text()
    assert "ANTHROPIC_BASE_URL=\"http://127.0.0.1:$ANDYUR_LITELLM_PORT\"" in verifier
    assert 'ps -q litellm' in verifier
    assert 'docker port "$container_id" 4000/tcp' in verifier
    assert 'down --remove-orphans --volumes' in verifier
    assert 'up -d --no-deps litellm' in verifier
    assert "--model \"$MODEL\"" in verifier
    assert "ANDYUR_LITELLM_OK" in verifier
