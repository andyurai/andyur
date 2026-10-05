"""exec/v1 completion: D3 exit mapping and bounded output capture."""
from __future__ import annotations

import pytest

from andyur import execlifecycle as el
from andyur.execlifecycle import TRUNCATION_MARKER


# ---- D3: exit status -> run state (never task success) --------------------

def test_exit_zero_is_a_clean_completion_no_error():
    # None error -> the SERVER derives state 'done'. exit_error never returns a
    # state itself, so done/failed lives in one place (finish_run).
    assert el.exit_error(0) is None


@pytest.mark.parametrize("code", [1, 2, 3, 137, 255])
def test_nonzero_exit_yields_an_error_with_the_code(code):
    error = el.exit_error(code)
    assert error and str(code) in error


def test_a_vanished_process_yields_an_error_not_none():
    error = el.exit_error(None)
    assert error and "vanished" in error


# ---- bounded, redacted capture --------------------------------------------

def test_capture_combines_stdout_and_labels_stderr():
    out = el.capture_output("the result", "a warning",
                            emission_max_bytes=10_000, retention_max_bytes=10_000)
    assert "the result" in out
    assert "[stderr]" in out and "a warning" in out


def test_capture_takes_the_smaller_of_the_two_bounds():
    big = "x" * 500
    # emission is the smaller bound -> that is the effective one (100 leaves
    # room for the marker, so a truncation is legible)
    out = el.capture_output(big, None, emission_max_bytes=100, retention_max_bytes=10_000)
    assert len(out.encode("utf-8")) <= 100
    assert out.endswith(TRUNCATION_MARKER)
    # retention is the smaller bound
    out = el.capture_output(big, None, emission_max_bytes=10_000, retention_max_bytes=90)
    assert len(out.encode("utf-8")) <= 90
    assert out.endswith(TRUNCATION_MARKER)


def test_capture_never_exceeds_the_bound_even_below_the_marker_length():
    out = el.capture_output("x" * 100, None, emission_max_bytes=5, retention_max_bytes=5)
    assert len(out.encode("utf-8")) <= 5
    assert TRUNCATION_MARKER not in out          # no marker that would overflow


def test_capture_does_not_split_a_multibyte_character():
    out = el.capture_output("é" * 100, None, emission_max_bytes=21, retention_max_bytes=21)
    assert len(out.encode("utf-8")) <= 21
    out.encode("utf-8")                          # must be valid UTF-8, no partial


def test_capture_redacts_before_truncating():
    # A JWT-shaped secret must be redacted, and redaction runs before the cut so
    # a secret straddling the boundary cannot survive half-included.
    secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aGVsbG8"
    out = el.capture_output(f"before {secret} after", None,
                            emission_max_bytes=10_000, retention_max_bytes=10_000)
    assert secret not in out


def test_capture_of_nothing_is_empty():
    assert el.capture_output(None, None, emission_max_bytes=100, retention_max_bytes=100) == ""
    assert el.capture_output("", "", emission_max_bytes=100, retention_max_bytes=100) == ""


# ---- the API adapter reads the exact terminated exit code -----------------

def test_read_container_exit_returns_the_terminated_code():
    from types import SimpleNamespace as NS
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)

    class _ApiExc(Exception):
        status = 404

    def make(status_obj):
        api._api_exception = _ApiExc
        api._core = NS(read_namespaced_pod=lambda name, namespace, _request_timeout: NS(status=status_obj))
        return api

    # terminated with a code
    make(NS(init_container_statuses=None, container_statuses=[
        NS(name="agent", state=NS(terminated=NS(exit_code=3)))]))
    assert api.read_container_exit("ns", "pod", "agent") == 3
    # still running -> None (not knowable yet)
    make(NS(init_container_statuses=None, container_statuses=[
        NS(name="agent", state=NS(terminated=None, running=NS()))]))
    assert api.read_container_exit("ns", "pod", "agent") is None
    # terminated but no code (evicted/OOM before status) -> None -> fails closed
    make(NS(init_container_statuses=None, container_statuses=[
        NS(name="agent", state=NS(terminated=NS(exit_code=None)))]))
    assert api.read_container_exit("ns", "pod", "agent") is None
    # container absent -> None
    make(NS(init_container_statuses=None, container_statuses=[]))
    assert api.read_container_exit("ns", "pod", "agent") is None


def test_read_container_exit_of_a_gone_pod_is_none():
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)

    class _ApiExc(Exception):
        def __init__(self): self.status = 404
    api._api_exception = _ApiExc
    def gone(name, namespace, _request_timeout): raise _ApiExc()
    from types import SimpleNamespace as NS
    api._core = NS(read_namespaced_pod=gone)
    assert api.read_container_exit("ns", "pod", "agent") is None
