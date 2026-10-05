import pytest

from andyur.daemon.daemon import broker_profile_for_orchestrator


@pytest.mark.parametrize("name", ["host", "container", "pod"])
def test_legacy_orchestrators_preserve_existing_broker_token(name):
    assert broker_profile_for_orchestrator(name, "off", "legacy") == (
        False, "legacy")


def test_kubernetes_profile_is_explicit_and_token_is_staged_only_when_enabled():
    assert broker_profile_for_orchestrator("kubernetes", "off", "assigned") == (
        False, None)
    assert broker_profile_for_orchestrator("kubernetes", "on", "assigned") == (
        True, "assigned")


@pytest.mark.parametrize("setting", ["", "ON", "true", "unexpected"])
def test_kubernetes_profile_rejects_unknown_values(setting):
    with pytest.raises(ValueError, match="exactly"):
        broker_profile_for_orchestrator("kubernetes", setting, "assigned")
