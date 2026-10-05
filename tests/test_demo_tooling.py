"""The operator tooling: the authority demo and reset.

These are shell scripts, and until this file existed nothing ran them. That is
not a small gap, because tooling is exactly where hand-verification rots: the
prefix change alone shipped three bugs that a few lines here would have caught
(two of six agents still hardcoded to a literal prefix, an explicit empty prefix
silently replaced by the saved one, and `up` failing the second time because the
agents already held live runs).

The tests drive the REAL script against a REAL server. Nothing is stubbed, since
what is under test is precisely whether the script and the product agree.

They are slower than the rest of the suite -- a server start each, a few seconds
total -- which is the price of testing a thing that only exists as a process.
"""

import json
import os
import shutil
import socket
import subprocess
import sysconfig
import time
from pathlib import Path

import pytest

from andyur import identity

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "infra" / "authority-demo.sh"
RESET = ROOT / "infra" / "reset.sh"
VENV_PY = ROOT / ".venv" / "bin" / "python"
ROLE_BIN = ROOT / "infra" / "roles" / "bin"
# Derived from their owners, not duplicated: identity.socket_path() honours
# SPIFFE_ENDPOINT_SOCKET (a nonstandard socket must not skip a module that
# could run), and this interpreter IS the venv, so it knows its own
# site-packages without a python version hardcoded anywhere.
SPIRE_SOCKET = Path(identity.socket_path().removeprefix("unix:"))
SITE = sysconfig.get_paths()["purelib"]

# Identity is not optional, so neither is SPIRE here: these tests drive the real
# script against a real server, and both sides need the Workload API. A skip is
# NOT a pass -- CI must provision SPIRE so this module actually runs there.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not shutil.which("sqlite3") or not VENV_PY.exists()
        or not (ROLE_BIN / "andyur-server").exists()
        or not (ROLE_BIN / "andyur-operator").exists()
        or not SPIRE_SOCKET.exists(),
        reason="the demo tooling needs sqlite3, the project venv, and local SPIRE "
               "(./run.sh spire-setup, then spire-server + spire-agent + spire-roles)",
    ),
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _env(data_dir: Path, port: int) -> dict:
    """The configuration the demo documents. Agent-auth ON is not incidental:
    with it off there is no caller identity for the ceiling to apply to, so the
    script would come up and demonstrate nothing.

    ANDYUR_ASSERTED_USER is the same kind of requirement. The demo names the user
    its runs act for without an identity provider, and Andyur refuses to sign a
    token for a subject nobody authenticated unless an operator has said so. The
    demo turns it on in its own server; this fixture starts the server itself, so
    it must turn it on here or the demo cannot start a single run."""
    return {
        **os.environ,
        "ANDYUR_ASSERTED_USER": "on",
        "ANDYUR_DATA_DIR": str(data_dir),
        "ANDYUR_PORT": str(port),
        "ANDYUR_PROFILE": "dev",
        "ANDYUR_AGENT_AUTH": "on",
        "ANDYUR_GRAPH": "none",
        "ANDYUR_OTEL": "off",
        "ANDYUR_RUN_TOKEN_SECRET": "demo-tooling-test-secret",
    }


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """One Andyur, shared by the module, standing in for the operator's own. The
    demo runs against it in --real mode, which is the mode worth testing: it is
    the one that touches a database somebody cares about."""
    import httpx

    data = tmp_path_factory.mktemp("demo-tooling")
    port = _free_port()
    env = _env(data, port)
    # Under the server ROLE binary, not the venv python: validating a caller's
    # JWT-SVID needs the trust bundle from the Workload API, and SPIRE serves
    # only an attested workload. The role binaries are bare interpreters, so
    # the venv rides in on PYTHONPATH.
    proc = subprocess.Popen(
        [str(ROLE_BIN / "andyur-server"), "-m", "uvicorn", "andyur.server.app:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env={**env, "PYTHONPATH": f"{SITE}:{ROOT}"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.fail("the test server never became healthy")
    yield {"base": base, "env": env, "data": data}
    proc.terminate()
    proc.wait(timeout=10)


def _demo(server, *args, expect_ok=True) -> subprocess.CompletedProcess:
    r = subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=ROOT, env=server["env"], capture_output=True, text=True, timeout=180,
    )
    if expect_ok and r.returncode != 0:
        pytest.fail(f"{' '.join(args)} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r


def _demo_with_env(server, extra_env: dict, *args,
                   expect_ok=True) -> subprocess.CompletedProcess:
    scoped = {**server, "env": {**server["env"], **extra_env}}
    return _demo(scoped, *args, expect_ok=expect_ok)


def _op_header() -> dict:
    """A fresh operator bearer, fetched through the operator ROLE binary. The
    test process itself is not attested as anything, so it cannot fetch its own
    SVID -- but a bearer is a bearer, and the server checks the token, not the
    transport. Fetched per call: the SVID lives 300s and a module of server
    starts can outlive it."""
    out = subprocess.run(
        [str(ROLE_BIN / "andyur-operator"), "-c",
         "from andyur import identity; print(identity.fetch_token())"],
        capture_output=True, text=True, timeout=60, cwd=ROOT, check=True,
        env={**os.environ, "PYTHONPATH": f"{SITE}:{ROOT}"},
    )
    return {"Authorization": f"Bearer {out.stdout.strip()}"}


def _agents(server) -> set:
    import httpx
    r = httpx.get(f"{server['base']}/agents", headers=_op_header(), timeout=10)
    return {a["name"] for a in r.json()}


def _agent(server, name: str) -> dict:
    import httpx
    r = httpx.get(f"{server['base']}/agents/{name}",
                  headers=_op_header(), timeout=10)
    assert r.status_code == 200, r.text
    return r.json()


def _tokens(server) -> dict:
    """The exports the script writes, as a dict."""
    out = {}
    for line in (server["data"] / "tokens.env").read_text().splitlines():
        if line.startswith("export "):
            k, _, v = line[len("export "):].partition("=")
            out[k] = v
    return out


# --- up creates what it says it creates ---------------------------------------

def test_up_creates_the_six_agents_and_writes_usable_tokens(server):
    _demo(server, "up", "--real", "--prefix", "t1-")
    names = _agents(server)
    ids = {"classifier": "agt_classifier", "specialist": "agt_specialist",
           "roamer": "agt_9c2e_roaming", "bystander": "agt_bystander",
           "teller": "agt_teller", "muzzled": "agt_muzzled"}
    for role, registry_id in ids.items():
        assert f"t1-{role}" in names, f"t1-{role} was not created"
        assert _agent(server, f"t1-{role}")["registry_agent_id"] == registry_id

    tok = _tokens(server)
    assert tok["ANDYUR_DEMO_PREFIX"] == "t1-"
    # every token the runbook tells you to use must actually be present; an empty
    # value here is the failure mode where `up` "succeeded" and handed you nothing
    for key in ("TOK_CLASSIFIER", "TOK_SPECIALIST", "TOK_ROAMER", "TOK_BYSTANDER",
                "GRANT_SPECIALIST", "GRANT_ROAMER"):
        assert tok.get(key), f"{key} is missing or empty in tokens.env"


def test_the_demo_actually_demonstrates_the_ceiling(server):
    """The point of the whole script. If the ceilings were not applied, or the
    runs were not pinned, `up` would still exit 0 and the tour would show
    nothing -- so assert the narrowing the runbook promises, not just that the
    agents exist."""
    import httpx
    _demo(server, "up", "--real", "--prefix", "t2-")
    tok = _tokens(server)
    r = httpx.post(
        f"{server['base']}/oauth/token",
        headers={"X-Andyur-Run-Token": tok["TOK_CLASSIFIER"]},
        json={"audience": "tool:fs", "actor": "t2-specialist",
              "scope": ["files:read", "files:write"]},
        timeout=10,
    )
    assert r.status_code == 200
    # write dropped by the read-only CALLER's ceiling, and reported because the
    # grant came back smaller than the request
    assert r.json()["scope"] == "files:read"


def test_demo_materializes_registry_policy_and_instructions_exactly(server):
    """Assert every security-significant tri-state plus the live definition
    overlay. A shell mutation swapping actions/resources or reverting to a
    caller-authored ceiling/instruction must fail here."""
    import httpx
    _demo(server, "up", "--real", "--prefix", "registry-")
    headers = _op_header()

    def ceiling(role):
        r = httpx.get(f"{server['base']}/agents/registry-{role}/ceiling",
                      headers=headers, timeout=10)
        assert r.status_code == 200, r.text
        return {k: r.json()[k] for k in ("actions", "audiences")}

    assert ceiling("classifier") == {"actions": ["files:read"], "audiences": None}
    assert ceiling("teller") == {"actions": None, "audiences": ["tool:bank"]}
    assert ceiling("muzzled") == {"actions": [], "audiences": None}
    assert ceiling("specialist") == {"actions": None, "audiences": None}

    resolved = httpx.get(
        f"{server['base']}/v1/registry/agents/agt_classifier/resolve",
        headers=headers, timeout=10,
    )
    context = httpx.get(
        f"{server['base']}/agents/registry-classifier/context",
        headers=headers, timeout=10,
    )
    assert resolved.status_code == context.status_code == 200
    assert context.json()["instructions"] == resolved.json()["instructions"]
    assert context.json()["registry_agent_id"] == "agt_classifier"


def test_harness_reads_registry_and_never_writes_a_ceiling(server, tmp_path):
    """Prove the shell's source-of-truth behavior, not merely final DB state."""
    trace = tmp_path / "api.trace"
    _demo_with_env(
        server, {"ANDYUR_DEMO_API_TRACE": str(trace)},
        "up", "--real", "--prefix", "trace-",
    )
    calls = trace.read_text().splitlines()
    assert "GET /v1/registry/agents" in calls
    ids = ("agt_classifier", "agt_specialist", "agt_9c2e_roaming",
           "agt_bystander", "agt_teller", "agt_muzzled")
    for registry_id in ids:
        assert f"GET /v1/registry/agents/{registry_id}/resolve" in calls
    assert not any(call.startswith("PUT /agents/") and call.endswith("/ceiling")
                   for call in calls)


def test_late_registry_failure_removes_all_partial_instances(server, tmp_path):
    """ERR propagation cleans earlier roles while preserving unrelated data."""
    import httpx
    headers = _op_header()
    r = httpx.post(
        f"{server['base']}/agents", headers=headers,
        json={"name": "fail-notes", "description": "unrelated"}, timeout=10,
    )
    assert r.status_code in (201, 409), r.text

    trace = tmp_path / "failure.trace"
    failed = _demo_with_env(
        server,
        {"ANDYUR_DEMO_TEST_FAIL_PATH":
         "/v1/registry/agents/agt_specialist/resolve",
         "ANDYUR_DEMO_API_TRACE": str(trace)},
        "up", "--real", "--prefix", "fail-", expect_ok=False,
    )
    assert failed.returncode != 0
    names = _agents(server)
    assert "fail-notes" in names
    roles = ("classifier", "specialist", "roamer", "bystander", "teller",
             "muzzled")
    assert not ({f"fail-{role}" for role in roles} & names)
    calls = trace.read_text().splitlines()
    # One initial idempotent pre-clean for every role, then exactly one rollback
    # delete for the successfully-created classifier. An inherited subshell trap
    # used to add a third destructive sweep for classifier.
    assert calls.count("DELETE /agents/fail-classifier?force=true") == 2
    for role in roles[1:]:
        assert calls.count(f"DELETE /agents/fail-{role}?force=true") == 1


def test_scratch_failure_stops_server_and_removes_only_owned_state(server,
                                                                   tmp_path):
    data = tmp_path / "scratch-demo"
    port = _free_port()
    failed = _demo_with_env(
        server,
        {"ANDYUR_DATA_DIR": str(data), "ANDYUR_PORT": str(port),
         "ANDYUR_DEMO_TEST_FAIL_PATH":
         "/v1/registry/agents/agt_specialist/resolve"},
        "up", "--prefix", "scratch-", expect_ok=False,
    )
    assert failed.returncode != 0
    for _ in range(40):
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                break
        time.sleep(0.1)
    else:
        pytest.fail("failed scratch up left its server listening")
    assert not data.exists(), "failed scratch up left its owned data directory"


def test_scratch_repeat_up_and_down_wait_for_exact_server_exit(server, tmp_path):
    data = tmp_path / "repeat-scratch"
    port = _free_port()
    env = {"ANDYUR_DATA_DIR": str(data), "ANDYUR_PORT": str(port)}
    _demo_with_env(server, env, "up", "--prefix", "repeat-")
    _demo_with_env(server, env, "up", "--prefix", "repeat-")
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", port)) == 0
    _demo_with_env(server, env, "down", "--prefix", "repeat-")
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", port)) != 0
    assert not data.exists()


@pytest.mark.parametrize("command", ["up", "down"])
def test_scratch_refuses_unowned_directory_and_pid(server, tmp_path, command):
    data = tmp_path / "not-a-demo"
    data.mkdir()
    marker = data / "keep-me"
    marker.write_text("unrelated")
    sleeper = subprocess.Popen(["sleep", "60"])
    try:
        (data / "demo-server.pid").write_text(str(sleeper.pid))
        result = _demo_with_env(
            server, {"ANDYUR_DATA_DIR": str(data),
                     "ANDYUR_PORT": str(_free_port())},
            command, "--prefix", "safe-", expect_ok=False,
        )
        assert result.returncode != 0
        assert marker.read_text() == "unrelated"
        assert sleeper.poll() is None, "unowned PID file killed another process"
    finally:
        sleeper.terminate()
        sleeper.wait(timeout=10)


def test_scratch_refuses_same_command_pid_without_its_start_fingerprint(server,
                                                                        tmp_path):
    data = tmp_path / "marked-but-stale"
    data.mkdir()
    (data / ".andyur-authority-demo").touch()
    marker = data / "keep-me"
    marker.write_text("unrelated")
    # Make ps show the same identifying text as the real uvicorn command. A
    # command-substring check alone would kill this unrelated process.
    sleeper = subprocess.Popen(
        ["andyur.server.app:app", "60"], executable="/bin/sleep",
    )
    try:
        (data / "demo-server.pid").write_text(str(sleeper.pid))
        (data / "demo-server.started").write_text("definitely not its start time")
        result = _demo_with_env(
            server, {"ANDYUR_DATA_DIR": str(data)},
            "down", "--prefix", "safe-", expect_ok=False,
        )
        assert result.returncode != 0
        assert marker.read_text() == "unrelated"
        assert sleeper.poll() is None
    finally:
        sleeper.terminate()
        sleeper.wait(timeout=10)


def test_scratch_repairs_owned_permissions_and_clears_stale_state(server,
                                                                  tmp_path):
    data = tmp_path / "unclearable"
    data.mkdir()
    (data / ".andyur-authority-demo").touch()
    marker = data / "stale.db"
    marker.write_text("stale")
    data.chmod(0o300)
    try:
        env = {"ANDYUR_DATA_DIR": str(data), "ANDYUR_PORT": str(_free_port())}
        _demo_with_env(
            server, {"ANDYUR_DATA_DIR": str(data),
                     "ANDYUR_PORT": env["ANDYUR_PORT"]},
            "up", "--prefix", "safe-",
        )
        assert not marker.exists(), "stale state survived permission repair"
        _demo_with_env(server, env, "down", "--prefix", "safe-")
    finally:
        if data.exists():
            data.chmod(0o700)


@pytest.mark.parametrize(
    "fault",
    ["ANDYUR_DEMO_TEST_EMPTY_RUN_TOKEN", "ANDYUR_DEMO_TEST_EMPTY_ACCESS_TOKEN"],
)
def test_missing_minted_token_fails_and_rolls_back(server, tmp_path, fault):
    data = tmp_path / fault.lower()
    prefix = "bad-run-" if fault.endswith("RUN_TOKEN") else "bad-grant-"
    result = _demo_with_env(
        server, {"ANDYUR_DATA_DIR": str(data), fault: "1"},
        "up", "--real", "--prefix", prefix, expect_ok=False,
    )
    assert result.returncode != 0
    output = result.stdout + result.stderr
    if fault.endswith("RUN_TOKEN"):
        assert "could not mint a run token" in output
    else:
        assert "non-empty access_token" in output
    assert not (data / "tokens.env").exists()
    roles = ("classifier", "specialist", "roamer", "bystander", "teller",
             "muzzled")
    assert not ({f"{prefix}{role}" for role in roles} & _agents(server))


def test_up_twice_with_the_same_prefix_succeeds(server):
    """It failed the second time: the agents already held live runs and an agent
    may only have one. Scratch mode never hit this because it deletes its whole
    database, so the bug only existed on the path that touches real data."""
    _demo(server, "up", "--real", "--prefix", "t3-")
    _demo(server, "up", "--real", "--prefix", "t3-")
    assert "t3-classifier" in _agents(server)


# --- down removes exactly its own ----------------------------------------------

def test_down_removes_its_own_prefix_and_leaves_another_alone(server):
    """The isolation that makes --real safe. Teardown deletes PREFIX + the six
    known roles, never a scan for names starting with the prefix, so an agent of
    yours that merely sorts under it survives."""
    _demo(server, "up", "--real", "--prefix", "keep-")
    _demo(server, "up", "--real", "--prefix", "drop-")
    assert {"keep-classifier", "drop-classifier"} <= _agents(server)

    _demo(server, "down", "--real", "--prefix", "drop-")
    names = _agents(server)
    assert not any(n.startswith("drop-") for n in names), "drop- survived teardown"
    assert "keep-classifier" in names, "teardown took another prefix's agents"


def test_down_does_not_delete_an_unrelated_agent_that_sorts_under_the_prefix(server):
    """The exact hazard the prefix exists for, from the other direction: an agent
    called `mine-notes` must survive `down --prefix mine-`, because it is not one
    of the six roles."""
    import httpx
    httpx.post(f"{server['base']}/agents", headers=_op_header(),
               json={"name": "mine-notes", "description": "yours"}, timeout=10)
    _demo(server, "up", "--real", "--prefix", "mine-")
    _demo(server, "down", "--real", "--prefix", "mine-")
    assert "mine-notes" in _agents(server)
    assert "mine-classifier" not in _agents(server)


def test_down_is_idempotent(server):
    _demo(server, "up", "--real", "--prefix", "t4-")
    _demo(server, "down", "--real", "--prefix", "t4-")
    _demo(server, "down", "--real", "--prefix", "t4-")   # nothing left; still fine


# --- a bad prefix is refused BEFORE anything is created ------------------------

@pytest.mark.parametrize("bad", ["", "Bad-", "9x-", "has space", "a" * 50])
def test_a_bad_prefix_is_refused_and_creates_nothing(server, bad):
    """Refused before creating, not after: a prefix that fails validation halfway
    through would leave agents nobody can name to clean up."""
    before = _agents(server)
    r = _demo(server, "up", "--real", "--prefix", bad, expect_ok=False)
    assert r.returncode != 0, f"prefix {bad!r} was accepted"
    assert _agents(server) == before, f"prefix {bad!r} created agents before failing"


def test_an_explicitly_empty_prefix_is_not_silently_replaced(server):
    """It was. The saved prefix was read whenever the value was empty, so
    `--prefix ""` became the remembered one and the guard never fired -- which
    matters because empty means teardown deletes unprefixed agents."""
    _demo(server, "up", "--real", "--prefix", "t5-")      # leaves t5- in tokens.env
    r = _demo(server, "up", "--real", "--prefix", "", expect_ok=False)
    assert r.returncode != 0
    assert "empty" in (r.stdout + r.stderr).lower()


# --- decode reads a real token -------------------------------------------------

def test_decode_prints_the_claims_of_a_minted_token(server):
    _demo(server, "up", "--real", "--prefix", "t6-")
    grant = _tokens(server)["GRANT_SPECIALIST"]
    r = _demo(server, "decode", grant)
    claims = json.loads(r.stdout)
    assert claims["sub"] == "alice"
    assert claims["act"]["sub"] == "t6-specialist"
    assert claims["authorization_details"][0]["resources"] == {"account": "447"}


# --- reset ----------------------------------------------------------------------

def _reset(data_dir: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(RESET), *args],
        cwd=ROOT, env={**os.environ, "ANDYUR_DATA_DIR": str(data_dir)},
        capture_output=True, text=True, timeout=60,
    )


def _populate(d: Path) -> None:
    (d / "logs").mkdir(parents=True, exist_ok=True)
    (d / "spire").mkdir(parents=True, exist_ok=True)
    (d / "tls").mkdir(parents=True, exist_ok=True)
    (d / "andyur.db").write_text("x")
    (d / "logs" / "a.log").write_text("x")
    (d / "spire" / "key").write_text("secret")


def test_reset_clears_state_but_keeps_identity_material(tmp_path):
    """Identity material is slow to regenerate and unrelated to the agents being
    cleared, and losing it silently breaks every identity-on target afterwards."""
    _populate(tmp_path)
    r = _reset(tmp_path, "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "andyur.db").exists()
    assert not (tmp_path / "logs").exists()
    assert (tmp_path / "spire" / "key").exists(), "reset destroyed identity material"


def test_reset_all_removes_identity_material_too(tmp_path):
    _populate(tmp_path)
    assert _reset(tmp_path, "--all", "--yes").returncode == 0
    assert not (tmp_path / "spire").exists()


def test_reset_without_confirmation_deletes_nothing(tmp_path):
    """The prompt is the only thing between a typo and an unrecoverable wipe, so
    a refused confirmation must leave everything in place."""
    _populate(tmp_path)
    r = subprocess.run(
        ["bash", str(RESET)],
        cwd=ROOT, env={**os.environ, "ANDYUR_DATA_DIR": str(tmp_path)},
        input="no\n", capture_output=True, text=True, timeout=60,
    )
    assert r.returncode != 0
    assert (tmp_path / "andyur.db").exists(), "aborting the prompt still deleted"


def test_reset_on_a_clean_directory_is_not_an_error(tmp_path):
    r = _reset(tmp_path, "--yes")
    assert r.returncode == 0
    assert "already clean" in r.stdout


def test_a_sandboxed_reset_leaves_a_running_stack_alone(tmp_path):
    """A UNIT TEST MUST NOT STOP THE DEVELOPER'S CONTROL PLANE.

    `reset.sh` stopped the stack unconditionally, and `run.sh down` reads its
    pids from the CHECKOUT's data/run whatever ANDYUR_DATA_DIR says -- so every
    sandboxed reset above (four of them) killed whatever server and daemon the
    developer had running. It is how a full RC-gate run reported its console
    line as "control plane not up", eleven lines and forty minutes after the
    suite had silently taken the stack down.

    Asserted with a real process and a real pid file, because the property is
    "the process is still alive afterwards" and nothing weaker distinguishes a
    fixed script from one that happened to find no pid file.
    """
    run_dir = ROOT / "data" / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    pid_file = run_dir / "server.pid"
    if pid_file.exists():
        pytest.skip("a real stack is running here; this test must not touch its pid file")
    # POPULATED, or the reset exits at "(nothing; already clean)" before it
    # ever reaches the stop -- which is how the first version of this test
    # passed against the very defect it was written for.
    _populate(tmp_path)
    sentinel = subprocess.Popen(["sleep", "60"])
    try:
        pid_file.write_text(str(sentinel.pid))
        result = _reset(tmp_path, "--yes")
        assert not (tmp_path / "andyur.db").exists(), "the reset did not run"
        assert result.returncode == 0, result.stdout + result.stderr
        assert sentinel.poll() is None, (
            "a reset pointed at a scratch directory stopped a process the "
            "checkout's stack owns")
        assert pid_file.exists(), "the reset removed another stack's pid file"
    finally:
        pid_file.unlink(missing_ok=True)
        sentinel.terminate()
        sentinel.wait(timeout=10)
