"""How ANDYUR_AGENT_SPLIT is read.

This variable selects the isolation shape a run gets, so misreading it is a
silent downgrade: the platform starts, runs agents perfectly, and provides less
containment than the operator asked for. It follows ANDYUR_PROFILE's rule --
refuse to guess rather than fall back to the least isolated shape.
"""

import importlib

import pytest


def _reload(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("ANDYUR_AGENT_SPLIT", raising=False)
    else:
        monkeypatch.setenv("ANDYUR_AGENT_SPLIT", value)
    import andyur.config as cfg
    return importlib.reload(cfg)


def test_unset_means_the_single_process_shape(monkeypatch):
    cfg = _reload(monkeypatch, None)
    assert cfg.AGENT_SPLIT_MODE == "off"
    assert cfg.AGENT_SPLIT is False and cfg.AGENT_SPLIT_POD is False


@pytest.mark.parametrize("value", ["on", "1", "true", "process", "ProCess", " on "])
def test_the_truthy_spellings_all_mean_two_processes(monkeypatch, value):
    cfg = _reload(monkeypatch, value)
    assert cfg.AGENT_SPLIT_MODE == "process"
    assert cfg.AGENT_SPLIT is True and cfg.AGENT_SPLIT_POD is False


@pytest.mark.parametrize("value", ["pod", "POD", " pod "])
def test_pod_means_two_containers(monkeypatch, value):
    cfg = _reload(monkeypatch, value)
    assert cfg.AGENT_SPLIT_MODE == "pod"
    assert cfg.AGENT_SPLIT is True and cfg.AGENT_SPLIT_POD is True


@pytest.mark.parametrize("value", ["yes", "container", "pods", "2", "on-ish"])
def test_an_unrecognised_value_is_refused_not_guessed(monkeypatch, value):
    """Falling back to "off" here would silently select the LEAST isolated shape
    -- which is the one an operator setting this variable was trying to leave."""
    with pytest.raises(RuntimeError, match="not a split mode"):
        _reload(monkeypatch, value)
    _reload(monkeypatch, None)   # leave the module in a sane state for the suite


def test_off_spellings_stay_off(monkeypatch):
    for value in ("off", "0", "false", ""):
        cfg = _reload(monkeypatch, value)
        assert cfg.AGENT_SPLIT is False, value
