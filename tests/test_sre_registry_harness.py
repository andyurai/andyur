"""Mutation-sensitive contracts for the canonical real SRE verifier."""

import os
from pathlib import Path
import subprocess
import time


HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "infra/spire/docker/verify-sre-registry.sh"


def test_stable_harness_lease_admits_exactly_one_concurrent_owner(tmp_path):
    env = {**os.environ, "TMPDIR": str(tmp_path),
           "ANDYUR_SRE_LOCK_HOLD_SECONDS": "3",
           "ANDYUR_SRE_LOCK_PUBLISH_DELAY": "1"}
    first = subprocess.Popen(["bash", str(SCRIPT)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True)
    state = tmp_path / f"andyur-sre-registry-{os.getuid()}"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if (state / "active").exists():
            break
        time.sleep(0.02)
    assert (state / "active").exists(), "first process never acquired lease"

    second = subprocess.run(["bash", str(SCRIPT)], env=env,
                            capture_output=True, text=True, timeout=5)
    assert second.returncode != 0
    assert "ownership is still being published; refusing to steal" in second.stderr
    assert first.poll() is None, "loser cleanup disturbed the active owner"

    assert first.wait(timeout=6) == 0


def test_real_demo_exports_and_retains_its_observability_contract():
    source = SCRIPT.read_text()
    assert "-e ANDYUR_OTEL=on" not in source, (
        "telemetry is a framework default, not a demo-authored policy")
    assert source.count(
        "ANDYUR_OTEL_ENDPOINT=http://host.docker.internal:4318") == 2
    assert 'api/traces/$TRACE_ID' in source
    for artifact in (
        "registry-resolution.json", "materialized-ceiling.json",
        "authority-probes.log", "run-record.json", "runner.log", "obs.log",
        "tix.log", "jaeger-trace.json", "README.txt",
        "litellm.log",
    ):
        assert artifact in source
    assert "scan_artifacts" in source
    # The gate declares an exact pass count and enforces it, and the api edition
    # (external AS + vault + model run) declares MORE than the base. Assert that
    # contract by PRESENCE + CONSISTENCY, not a magic literal: hardcoding the
    # number re-broke this guard on every phase that added a check (HIGH-1). What
    # must hold is that the count exists, the api edition is strictly higher, and
    # the run is actually gated on matching it.
    import re
    base = re.search(r'^EXPECTED_PASS=(\d+)', source, re.M)
    api = re.search(
        r'\[ "\$\{ANDYUR_LLM:-ollama\}" = api \] && EXPECTED_PASS=(\d+)', source)
    assert base and api, "the gate must declare a base and an api EXPECTED_PASS"
    assert int(api.group(1)) > int(base.group(1)), (
        "the api edition runs more checks than the base and must expect more")
    assert '[ "$PASS" -eq "$EXPECTED_PASS" ]' in source, (
        "the gate must FAIL unless the observed pass count equals the expected one")
    assert "validate_sre_trace.py" in source


def test_anthropic_sre_uses_shared_litellm_through_the_per_run_sidecar():
    source = SCRIPT.read_text()
    runner_start = source.index("runner_model_args=()")
    runner_end = source.index('runner_rc=${PIPESTATUS[0]}', runner_start)
    runner = source[runner_start:runner_end]

    # LiteLLM holds the model credential; the runner never sees it. Phase 2 makes
    # that credential VAULT-SOURCED (read from the sealed OpenBao under the
    # model-broker policy into $VAULT_KEY) AND keeps it off the docker argv: it is
    # FORWARDED (`-e ANTHROPIC_API_KEY`, no value) from the shell env, never
    # `-e KEY=value` which any host `ps` would read.
    assert 'VAULT_KEY="$(bash "$OBGATE" read)"' in source, (
        "the model credential must be read from the vault, not injected raw")
    assert 'ANTHROPIC_API_KEY="$VAULT_KEY"' in source[:runner_start], (
        "the vault key must be placed in the env for forwarding")
    assert "\n    -e ANTHROPIC_API_KEY \\" in source[:runner_start], (
        "the key must be forwarded (-e NAME), not passed as -e NAME=value on argv")
    assert '-e "ANTHROPIC_API_KEY=' not in source, (
        "no model credential value may appear on the docker command line")
    assert "ANTHROPIC_API_KEY" not in runner
    assert 'ANDYUR_LITELLM_URL=http://$LITELLM:4000' in runner
    assert 'LITELLM_MASTER_KEY=$LITELLM_MASTER_KEY' in runner
    assert "ANDYUR_BROKER_TOKEN" not in runner
    assert "ANDYUR_BROKER_URL" not in runner
    assert "ANDYUR_AGENT_MODEL" not in runner
    assert '"/worker/heartbeat"' in source
    assert "from andyur.server import runtoken" not in source
    assert "purpose=runtoken.PURPOSE_BROKER" not in source
    assert 'LITELLM_KEY_VALUE="${LITELLM_MASTER_KEY:-}"' in source
    assert 'required.add("litellm.log")' in source
    assert 'POST /v1/messages' in source
    assert "python -m andyur.broker" not in source
    assert 'REGISTRY_ID="agt_oncall_ollama"' in source
    # macOS still ships Bash 3.2: under `set -u`, an empty `array[@]` is an
    # unbound variable unless the expansion uses the `+` guard.
    assert '${runner_model_args[@]+"${runner_model_args[@]}"}' in runner
    assert 'REGISTRY_ID="agt_oncall"' in source
    assert '"$TRACE_ID" "$resolved_model"' in source


def test_retained_telemetry_is_private_and_bounded(tmp_path):
    root = tmp_path / "artifacts"
    env = {**os.environ, "ANDYUR_SRE_ARTIFACT_TEST_ONLY": "1",
           "ANDYUR_SRE_ARTIFACT_DIR": str(root),
           "ANDYUR_SRE_ARTIFACT_KEEP": "2"}
    subprocess.run(["bash", str(SCRIPT)], env=env, check=True)
    assert root.stat().st_mode & 0o077 == 0

    for index, name in enumerate(("000000000001", "000000000002", "000000000003")):
        run = root / name
        run.mkdir()
        artifact = run / "trace.json"
        artifact.write_text(name)
        timestamp = 100 + index
        os.utime(run, (timestamp, timestamp))

    subprocess.run(["bash", str(SCRIPT)], env=env, check=True)
    assert not (root / "000000000001").exists()
    assert (root / "000000000002").exists()
    assert (root / "000000000003").exists()
    for path in root.rglob("*"):
        assert path.stat().st_mode & 0o077 == 0, path


def test_early_failure_never_writes_through_an_unvalidated_artifact_root(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    canary = target / "canary"
    canary.write_text("unchanged")
    link = tmp_path / "artifacts-link"
    link.symlink_to(target, target_is_directory=True)
    env = {**os.environ, "ANDYUR_SRE_ARTIFACT_DIR": str(link),
           "ANDYUR_SRE_FAIL_BEFORE_ARTIFACTS": "1"}
    result = subprocess.run(["bash", str(SCRIPT)], env=env,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert canary.read_text() == "unchanged"
    assert list(target.iterdir()) == [canary]


def test_production_artifact_scanner_rejects_a_retained_jwt(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name in ("runner.log", "server.log", "obs.log", "tix.log",
                 "jaeger-trace.json", "run-record.json"):
        (bundle / name).write_text("expected evidence\n")
    planted = "eyJ" + "a" * 20 + "." + "b" * 12 + "." + "c" * 12
    (bundle / "runner.log").write_text(f"leaked={planted}\n")
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env={**os.environ, "ANDYUR_SRE_SCAN_TEST_DIR": str(bundle)},
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "JWT-shaped material retained" in result.stderr


def _record_process(state, process, started=None):
    state.mkdir(parents=True, exist_ok=True)
    (state / "test.pid").write_text(f"{process.pid}\n")
    actual = subprocess.run(
        ["ps", "-p", str(process.pid), "-o", "lstart="],
        capture_output=True, text=True, check=True,
    ).stdout
    (state / "test.started").write_text(actual if started is None else started)


def test_normal_cleanup_stops_only_the_recorded_process_generation(tmp_path):
    source = SCRIPT.read_text()
    cleanup = source[source.index("cleanup() {"):source.index("trap cleanup EXIT")]
    assert "stop_recorded_process obs 'demos/sre-triage/observability.py'" in cleanup
    assert "stop_recorded_process tix 'demos/sre-triage/tickets.py'" in cleanup
    state = tmp_path / f"andyur-sre-registry-{os.getuid()}"
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env={**os.environ, "TMPDIR": str(tmp_path),
             "ANDYUR_SRE_PROCESS_CLEANUP_TEST_SPAWN": "1"},
        capture_output=True, text=True, timeout=8,
    )
    assert result.returncode == 0, result.stderr

    replacement = subprocess.Popen(["sleep", "60"])
    try:
        _record_process(state, replacement, started="not this generation\n")
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env={**os.environ, "TMPDIR": str(tmp_path),
                 "ANDYUR_SRE_PROCESS_CLEANUP_TEST_PID": str(replacement.pid),
                 "ANDYUR_SRE_PROCESS_CLEANUP_TEST_NEEDLE": "sleep"},
            capture_output=True, text=True, timeout=8,
        )
        assert result.returncode != 0
        assert "ownership fingerprint does not match" in result.stderr
        assert replacement.poll() is None
    finally:
        replacement.kill()
        replacement.wait()


def test_opa_traversal_check_cannot_false_negative_under_pipefail(tmp_path):
    """The phase-3 assertion must not read the decision log through a pipeline.

    `docker logs X | grep -q PATTERN` looks correct and is not: grep -q exits at
    the first match, docker is killed by SIGPIPE (141) while still writing, and
    under `set -o pipefail` the pipeline reports FAILURE even though the pattern
    was present. The gate then says "the external OPA engine logged no decision
    -- the run did not use it" about a run that did use it. It only misbehaves
    once the log is large enough, which is why it read as a flake.

    Two assertions: the trap is real (behavioural), and the gate does not use
    the trapped form for this check (source-pinned, so a revert reddens here).
    """
    big = tmp_path / "big.log"
    big.write_text('{"decision_id":"x"}\n' + "filler line\n" * 200_000)

    piped = subprocess.run(
        ["bash", "-c", f'set -euo pipefail; cat {big} | grep -q decision_id'],
        capture_output=True)
    assert piped.returncode != 0, (
        "expected the pipeline form to false-negative under pipefail; if this "
        "stops being true the guidance in the gate can be simplified")

    captured = subprocess.run(
        ["bash", "-c",
         f'set -euo pipefail; logs="$(cat {big})"; '
         'case "$logs" in *decision_id*) exit 0 ;; esac; exit 1'],
        capture_output=True)
    assert captured.returncode == 0, "the capture-then-match form must survive"

    source = (Path(__file__).resolve().parents[1]
              / "infra/spire/docker/verify-sre-registry.sh").read_text()
    check = source[source.index("opa_decided=0"):source.index('[ "$opa_decided"')]
    piped_only = check.replace("||", "")
    assert "|" not in piped_only, (
        "the OPA traversal check reads the decision log through a pipeline "
        "again; under pipefail that reports no decision for a run that made "
        "one. Capture into a variable and match with case.")
    assert 'case "$opa_logs"' in check


def test_delete_direct_probe_can_only_pass_on_an_answer_from_the_as():
    """The red-team result must be attributable to the authorization server.

    The check exists to prove the AS REFUSES to issue a scope above the
    registry ceiling. It used to catch bare `Exception` and print
    "DELETE-DIRECT REFUSED-BY-AS: {type}", so any purely local failure
    satisfied it with the AS never contacted -- and `reference_scope_mapping`
    runs outside asclient's try/except, so dropping "tickets:close" from the
    scope map (the natural cleanup, since the registry never grants close)
    would have turned this permanently green while proving nothing. It also
    inverted one real case: response verification runs only after a 200, so an
    AS that ISSUED an over-ceiling token surfaced as a refusal by that AS.

    ASError carries the discriminator: only the AS-answered raise site sets
    `status`. So the probe must require a status, and the gate must require
    the emitted evidence to carry it.
    """
    probe = (Path(__file__).resolve().parents[1] / "infra/sre_probe.py").read_text()
    block = probe[probe.index("RED TEAM:"):]
    assert "except ASError" in block, (
        "the over-ceiling mint must catch ASError specifically; a bare "
        "`except Exception` lets a local error read as a refusal by the AS")
    assert "exc.status is None" in block and "raise" in block, (
        "an ASError without a status did not come from the AS (local raise, or "
        "a post-200 verification failure); it must propagate, not be reported "
        "as REFUSED-BY-AS")
    assert "{exc.status}" in block, "the evidence line must name the AS's status"

    gate = SCRIPT.read_text()
    matcher = gate[gate.index('*"DELETE-DIRECT REFUSED-BY-AS: "'):]
    matcher = matcher[:matcher.index("esac")]
    assert "[0-9][0-9][0-9]" in matcher, (
        "the gate must require the AS's three-digit status, otherwise a local "
        "failure's message still satisfies the check")


def test_the_delete_direct_matcher_rejects_a_local_failures_message():
    """Behavioural: the exact string a local failure produced must not pass."""
    import subprocess

    gate = SCRIPT.read_text()
    matcher = gate[gate.index('case "$probe" in\n  *"DELETE-DIRECT'):]
    matcher = matcher[:matcher.index("esac") + len("esac")]
    for line, expected in [
            ("DELETE-DIRECT REFUSED-BY-AS: 400 invalid_scope", "ok"),
            ("DELETE-DIRECT REFUSED-BY-AS: ProviderConfigurationError", "bad"),
            ("DELETE-DIRECT REFUSED-BY-AS", "bad")]:
        script = ('set -euo pipefail\nok(){ echo ok; }\nbad(){ echo bad; }\n'
                  f'probe={line!r}\n' + matcher)
        out = subprocess.run(["bash", "-c", script],
                             capture_output=True, text=True).stdout.strip()
        assert out == expected, f"{line!r} -> {out!r}, expected {expected!r}"
