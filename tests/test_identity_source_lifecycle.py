"""The cached JwtSource self-heals and is built exactly once under a race.

Red-team findings, 2026-08-13:
  - a py-spiffe source latches _closed permanently on an unretryable Workload
    API error; a bare is-None cache never rebuilds it, so one SPIRE blip 401s
    all token validation until process restart.
  - the lazy init was an unsynchronized check-then-act on a module global, so a
    cold-start burst built N sources (N-1 orphaned gRPC streams + threads).

Both are exercised through the real identity._get_jwt_source / fetch_token
paths with a fake JwtSource injected at spiffe.JwtSource, so no SPIRE agent is
needed.
"""

import threading
import time

import pytest

from andyur import identity


class FakeSource:
    built = 0
    _lock = threading.Lock()

    def __init__(self, socket_path=None, timeout_in_seconds=None):
        with FakeSource._lock:
            FakeSource.built += 1
        self._closed = False
        # Widen the construction window so an unsynchronized caller would race.
        time.sleep(0.02)

    def is_closed(self):
        return self._closed

    def close(self):
        self._closed = True

    # fetch_token calls .fetch_svid on the client source; give it a stub.
    def fetch_svid(self, **kwargs):
        raise AssertionError("not exercised by these lifecycle tests")


@pytest.fixture(autouse=True)
def _fake_spiffe(monkeypatch):
    monkeypatch.setattr("spiffe.JwtSource", FakeSource)
    monkeypatch.setattr(identity, "_jwt_source", None)
    monkeypatch.setattr(identity, "_client_jwt_source", None)
    FakeSource.built = 0
    yield


def test_a_live_source_is_reused_not_rebuilt():
    s1 = identity._get_jwt_source()
    s2 = identity._get_jwt_source()
    assert s1 is s2
    assert FakeSource.built == 1


def test_a_dead_source_is_rebuilt_rather_than_serving_the_corpse():
    """The permanent-latch fix: once the cached source reports is_closed(), the
    next call must construct a fresh one instead of returning the dead object
    forever."""
    s1 = identity._get_jwt_source()
    s1._closed = True                      # simulate the unretryable-error latch
    s2 = identity._get_jwt_source()
    assert s2 is not s1
    assert not s2.is_closed()
    assert FakeSource.built == 2


def test_a_concurrent_cold_start_burst_builds_exactly_one_source():
    """The init-race fix: N threads hitting the cold cache together must yield
    one shared source, not N orphaned ones."""
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(identity._get_jwt_source())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert FakeSource.built == 1
    assert len({id(r) for r in results}) == 1
