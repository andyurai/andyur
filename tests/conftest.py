"""Test harness for Andyur's server-side logic.

Andyur reads its data directory (and thus the SQLite DB path) from the
ANDYUR_DATA_DIR env var at import time, so we point it at a throwaway temp dir
BEFORE importing any andyur module, and force the sqlite backend (no
ANDYUR_DB_URL). Each test gets a fresh, empty schema via the `env` fixture.

`env` also seeds agents and exposes small read helpers, so a test reads like the
behaviour it checks rather than raw SQL.

ONE TRAP THAT COSTS AN HOUR EVERY TIME, written here because this is the file
anyone writing a test already opens. `test_profile.py` and
`test_console_client.py` call ``importlib.reload(config)``. Reloading a module
REBINDS ITS CLASSES: after the reload, ``config.InsecureProfile`` is a NEW class
object, while source modules that read ``config.InsecureProfile`` per call raise
the new one. So a test that captures that class AT MODULE IMPORT TIME --

    _REFUSALS = (InvalidAgentManifest, config.InsecureProfile)   # WRONG

-- holds the pre-reload class, and ``pytest.raises`` stops matching. The test
PASSES ALONE AND FAILS IN THE FULL SUITE, with a traceback showing the right
exception and the right message, which is what makes it confusing. Resolve the
class inside the test body instead::

    def _refusals():
        return (InvalidAgentManifest, config.InsecureProfile)    # RIGHT

This bites precisely when someone does the right thing and tightens a broad
``pytest.raises(Exception, ...)`` into named types.
"""

import os
import tempfile

os.environ["ANDYUR_DATA_DIR"] = tempfile.mkdtemp(prefix="andyur-tests-")
os.environ.pop("ANDYUR_DB_URL", None)  # force the local sqlite backend
os.environ["ANDYUR_PROFILE"] = "dev"    # the suite is a dev deployment, stated not assumed
os.environ["ANDYUR_AGENT_AUTH"] = "on"  # exercise R1 agent-scoped auth in tests
os.environ["ANDYUR_OTEL"] = "off"       # explicit test escape hatch; no collector

import pytest

from andyur import db, identity
from andyur.config import DB_PATH

# ---------------------------------------------------------------------------
# SPIRE, stubbed at ONE seam: the cryptography, and nothing else.
#
# This file used to set ANDYUR_TRUST_LOCAL=on with the comment "identity is off
# in tests: trust no-token = operator". That is what let the entire suite pass
# while every caller was unauthenticated, and it is why the authority path was
# never once executed with an identity behind it.
#
# So the replacement deliberately does NOT restore a bypass. Every request now
# carries a bearer, and `auth.require` runs in full: the header check, the role
# lookup, the allowed-set comparison, the run-token binding. The only thing
# replaced is `validate_token`, which is the call that would otherwise need a
# live SPIRE agent. A test that wants a different identity sends its own header.
# ---------------------------------------------------------------------------

_SVID = "test-svid:"
OPERATOR_SVID = f"spiffe://{identity.TRUST_DOMAIN}/operator"
RUNNER_SVID = f"spiffe://{identity.TRUST_DOMAIN}/runner"
WORKER_SVID = f"spiffe://{identity.TRUST_DOMAIN}/worker"


# Marker header a test sends to suppress the default identity entirely.
NO_AUTH_HEADER = "x-test-no-auth"
NO_AUTH = {NO_AUTH_HEADER: "1"}


def svid_header(spiffe_id: str) -> dict[str, str]:
    """An Authorization header proving `spiffe_id`, for tests that need to be
    someone other than the operator."""
    return {"Authorization": f"Bearer {_SVID}{spiffe_id}"}


def _validate_token(token: str) -> str:
    # Mirrors the real contract: return the SPIFFE ID, raise on anything else.
    # A malformed or absent token must still be rejected, or tests would pass
    # against a server that accepts garbage.
    if not token.startswith(_SVID):
        raise ValueError(f"not a valid JWT-SVID: {token[:16]!r}")
    return token[len(_SVID):]


@pytest.fixture(autouse=True)
def _engine_breaker_closed():
    """The engine breaker is process-wide state. A test that trips it would
    otherwise leave every later test's drain and schedules paused for 30s+,
    so results would depend on test order."""
    from andyur.server import engine_breaker
    engine_breaker.ENGINE.reset()
    yield
    engine_breaker.ENGINE.reset()


@pytest.fixture(autouse=True)
def spire(monkeypatch):
    monkeypatch.setattr(identity, "validate_token", _validate_token)
    monkeypatch.setattr(identity, "fetch_token", lambda *a, **k: _SVID + RUNNER_SVID)


def _default_operator_header(cls):
    """Give every TestClient request the operator's SVID unless it sets its own.

    Patched onto the class rather than each client because the suite constructs
    `TestClient(app)` at module scope in ~40 files."""
    original = cls.request

    def request(self, method, url, *args, **kw):
        headers = dict(kw.get("headers") or {})
        # A test asserting the UNAUTHENTICATED case must be able to opt out, or
        # the default quietly makes "no token is refused" untestable.
        if headers.pop(NO_AUTH_HEADER, None) is not None:
            kw["headers"] = headers
            return original(self, method, url, *args, **kw)
        if not any(k.lower() == "authorization" for k in headers):
            headers["Authorization"] = f"Bearer {_SVID}{OPERATOR_SVID}"
            kw["headers"] = headers
        return original(self, method, url, *args, **kw)

    cls.request = request


from starlette.testclient import TestClient as _TestClient  # noqa: E402

_default_operator_header(_TestClient)


class World:
    """A freshly-initialised Andyur DB plus helpers to drive and inspect it."""

    def agent(self, name: str) -> str:
        """Create an idle agent so it can be woken for a run."""
        with db.connect() as c:
            c.execute(
                "INSERT INTO agents (name, description, paused, created_at) "
                "VALUES (?, '', 0, ?)",
                (name, db.utcnow()),
            )
        return name   # idle is the absence of a live run, so nothing else to seed

    def set_idle(self, name: str) -> None:
        """Return an agent to idle so it can be woken again.

        Idle means "has no live run", so this finishes whatever it is on rather
        than writing a status row: there is no status row to write."""
        with db.connect() as c:
            c.execute(
                "UPDATE runs SET state = 'cancelled', finished_at = ? "
                "WHERE agent = ? AND state IN ('pending', 'running')",
                (db.utcnow(), name),
            )

    def run_workflow(self, run_id: str) -> str | None:
        with db.connect() as c:
            return c.execute(
                "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)
            ).fetchone()["workflow_id"]

    def latest_run_workflow(self, agent: str) -> str | None:
        with db.connect() as c:
            row = c.execute(
                "SELECT workflow_id FROM runs WHERE agent = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (agent,),
            ).fetchone()
        return row["workflow_id"] if row else None

    def task_workflow(self, task_id: str) -> str | None:
        with db.connect() as c:
            return c.execute(
                "SELECT workflow_id FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()["workflow_id"]

    def run_state(self, run_id: str) -> str | None:
        with db.connect() as c:
            row = c.execute(
                "SELECT state FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        return row["state"] if row else None


@pytest.fixture
def env():
    """A clean database for each test. Also removes the SQLite WAL sidecars, or a
    prior test's committed rows can survive deleting only the main db file."""
    for suffix in ("", "-wal", "-shm"):
        p = str(DB_PATH) + suffix
        if os.path.exists(p):
            os.remove(p)
    db.init_db()
    return World()


@pytest.fixture(autouse=True)
def _telemetry_is_reopened_after_each_test():
    """otel.shutdown_bounded() marks the module's providers CLOSED -- correct
    for a process that is about to exit (the serve-only sidecar), wrong across
    a test session: a later test's setup_tracing() would raise "telemetry
    providers are shut down" (found by the suite-order red on PR #25: the
    serve-only bearer refusal runs the real bounded shutdown). Reopen after
    every test; registries are left alone."""
    from andyur import otel
    yield
    otel._closed = False
