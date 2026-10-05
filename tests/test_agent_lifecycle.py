"""Per-agent lifecycle: declared in the manifest, granted by policy, consumed once.

The defect these cover: ANDYUR_RUN_TTL_SECONDS was a platform-global constant
read independently by four modules, and no agent could ask for anything else
because the manifest schema is closed. Raising it to run one long agent gave
every agent a long run, minted a run token as long as the run, doubled the
SPIRE entry TTL by derivation, and stopped the reaper reclaiming dead runs.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest

from andyur.agentspec.compiler import compile_resolution
from andyur.agentspec.models import (
    InvalidManifest,
    ManifestDenied,
    PlatformPolicy,
)
from andyur.agentspec.parser import parse_manifest
from andyur.registry.models import (
    AuthorityCeiling,
    ConfigFile,
    ConfigurationSpec,
    EnvVar,
    LifecycleSpec,
    ProcessSpec,
    RuntimeResolution,
    granted_lifetime_seconds,
    lifecycle_from_assignment,
)
from andyur.registry.runtime_overlay import _parse_runtime
from andyur.registry.runtime_wire import encode_runtime

DIGEST = "sha256:" + "ab" * 32

MANIFEST = {
    "apiVersion": "andyur.ai/v1",
    "kind": "Agent",
    "metadata": {"id": "agt_opensre", "name": "opensre-sre", "version": "0.1.0"},
    "runtime": {
        "type": "container",
        "image": {"ref": "ghcr.io/andyur-demo/opensre", "digest": DIGEST},
        "command": ["/app/andyur-opensre"],
        "interface": {"protocol": "andyur-agent-runtime/v1"},
    },
    "instructions": "Investigate the assigned incident.",
}


def manifest_with(lifecycle: dict | None) -> dict:
    doc = copy.deepcopy(MANIFEST)
    if lifecycle is not None:
        doc["runtime"]["lifecycle"] = lifecycle
    return doc


def policy(**kw) -> PlatformPolicy:
    base = dict(
        tool_catalog={},
        ceiling=AuthorityCeiling(actions=None, resources=None),
        approved_models=None,
        revision="rev-1",
    )
    base.update(kw)
    return PlatformPolicy(**base)


# --------------------------------------------------------------------------
# The policy intersection. Duration narrows, mode is denied.
# --------------------------------------------------------------------------

def test_an_over_long_request_narrows_to_the_policy_ceiling():
    manifest = parse_manifest(manifest_with(
        {"mode": "task", "max_seconds": 86400}))
    granted = compile_resolution(
        manifest, policy(max_lifetime_seconds=3600)).resolution
    assert granted.runtime.lifecycle.max_seconds == 3600


def test_a_request_under_the_ceiling_is_granted_unchanged():
    """The narrowing must not become a floor: asking for less gets less."""
    manifest = parse_manifest(manifest_with(
        {"mode": "task", "max_seconds": 120}))
    granted = compile_resolution(
        manifest, policy(max_lifetime_seconds=3600)).resolution
    assert granted.runtime.lifecycle.max_seconds == 120


def test_service_mode_is_refused_because_the_runtime_cannot_deliver_one():
    """The registry can EXPRESS a resident agent; nothing may REQUEST one until
    turn polling, stream windows and supervised restart exist. A granted
    'service' today would be a long task wearing the name of a service, and a
    manifest is a document a reviewer is entitled to believe."""
    with pytest.raises(InvalidManifest, match="not implemented"):
        parse_manifest(manifest_with({"mode": "service", "max_seconds": 3600}))


def test_the_compiler_refuses_service_even_when_the_parser_is_bypassed():
    """Second gate. A manifest object built in code rather than parsed from a
    document must reach the same answer, and no policy may enable it."""
    import dataclasses

    from andyur.agentspec.models import LifecycleRequest
    manifest = parse_manifest(manifest_with({"mode": "task", "max_seconds": 3600}))
    smuggled = dataclasses.replace(
        manifest,
        runtime=dataclasses.replace(
            manifest.runtime,
            lifecycle=LifecycleRequest(mode="service", max_seconds=3600)))
    with pytest.raises(ManifestDenied, match="cannot be granted"):
        compile_resolution(smuggled, policy(max_lifetime_seconds=3600))


def test_no_policy_can_enable_service_mode():
    """The switch is deleted, not defaulted off. A dormant flag enabling a
    capability that does not exist is a promise nothing keeps."""
    import dataclasses

    from andyur.agentspec.models import PlatformPolicy as P
    assert "allow_service_mode" not in {f.name for f in dataclasses.fields(P)}


def test_a_platform_with_no_ceiling_refuses_every_lifecycle_declaration():
    manifest = parse_manifest(manifest_with({"mode": "task", "max_seconds": 120}))
    with pytest.raises(ManifestDenied, match="no lifetime ceiling"):
        compile_resolution(manifest, policy())


def test_an_agent_declaring_nothing_still_compiles_and_grants_nothing():
    manifest = parse_manifest(manifest_with(None))
    granted = compile_resolution(manifest, policy()).resolution
    assert granted.runtime.lifecycle is None


# --------------------------------------------------------------------------
# Parse-time refusals: combinations that cannot mean anything.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("lifecycle,expected", [
    ({"mode": "task", "max_seconds": 900, "idle_seconds": 120}, "meaningless"),
    ({"mode": "task", "max_seconds": 900, "on_exit": "restart"}, "refused for a task"),
    ({"mode": "task", "max_seconds": 30}, "between"),
    ({"mode": "task", "max_seconds": 99_999_999}, "between"),
    ({"mode": "task", "max_seconds": True}, "must be an integer"),
    ({"mode": "task"}, "max_seconds is required"),
    ({"mode": "forever", "max_seconds": 900}, "mode must be one of"),
    ({"mode": "task", "max_seconds": 900, "unbounded": True}, "unknown field"),
])
def test_nonsense_lifecycles_are_refused_at_parse_time(lifecycle, expected):
    with pytest.raises(InvalidManifest, match=expected):
        parse_manifest(manifest_with(lifecycle))


def test_builtin_claude_may_not_declare_a_lifecycle():
    doc = copy.deepcopy(MANIFEST)
    doc["runtime"] = {"type": "builtin-claude",
                      "lifecycle": {"mode": "task", "max_seconds": 900}}
    with pytest.raises(InvalidManifest, match="not applicable to builtin-claude"):
        parse_manifest(doc)


# --------------------------------------------------------------------------
# The overlay is the registry boundary. It must fail CLOSED on a newer field.
# --------------------------------------------------------------------------

def overlay_doc(**over) -> dict:
    doc = {
        "runtime_type": "container",
        "interface_version": "andyur-agent-runtime/v1",
        "manifest_digest": DIGEST,
        "image_ref": "ghcr.io/andyur-demo/opensre",
        "image_digest": DIGEST,
        "command": ["/app/andyur-opensre"],
        "resources": None,
        "policy_revision": "rev-1",
    }
    doc.update(over)
    return doc


def test_overlay_round_trips_a_granted_lifecycle():
    parsed = _parse_runtime("agt_x", overlay_doc(lifecycle={
        "mode": "service", "max_seconds": 7200,
        "idle_seconds": 600, "on_exit": "restart"}))
    assert parsed.lifecycle == LifecycleSpec("service", 7200, 600, "restart")


def test_an_older_reader_refuses_a_newer_artifact_rather_than_dropping_the_field():
    """The property that makes this safe to add. If the overlay parser ignored
    unknown keys, an older platform handed a newer snapshot would silently run
    a 24-hour service as a 900-second task."""
    # Positive control: the reader that refuses an unknown key must still
    # ACCEPT the key this feature added, or the refusal below proves nothing
    # except that the parser refuses things.
    assert _parse_runtime("agt_x", overlay_doc(
        lifecycle={"mode": "task", "max_seconds": 3600})).lifecycle is not None
    with pytest.raises(Exception, match="unknown fields"):
        _parse_runtime("agt_x", overlay_doc(lifetime_forever=True))


@pytest.mark.parametrize("lifecycle,expected", [
    ({"mode": "task", "max_seconds": 900, "idle_seconds": 60}, "meaningless"),
    ({"mode": "task", "max_seconds": 900, "on_exit": "restart"}, "refused for a task"),
    ({"mode": "task", "max_seconds": 10}, "between"),
    ({"mode": "task", "max_seconds": True}, "must be an integer"),
    ({"mode": "task", "max_seconds": 900, "extra": 1}, "unknown fields"),
])
def test_the_overlay_refuses_the_same_nonsense_the_parser_does(lifecycle, expected):
    """Two independent validators, deliberately. The overlay is fed by the
    compiler, not by a manifest, so it cannot assume the parser ran."""
    with pytest.raises(Exception, match=expected):
        _parse_runtime("agt_x", overlay_doc(lifecycle=lifecycle))


# --------------------------------------------------------------------------
# One dataclass, one codec. What is left to assert here is the DURABLE seal:
# the omit-when-unset rule that keeps existing run rows readable.
# --------------------------------------------------------------------------

def test_every_runtime_resolution_field_reaches_the_per_run_assignment():
    """End-to-end check that the codec's omit rule drops only what it should.

    The structural guarantee lives in runtime_wire: it will not import unless
    every field has a wire rule. What that CANNOT catch is a field wrongly
    marked additive, which would then vanish from the assignment whenever it
    is unset. Here every field is populated, so every field must appear.
    """
    runtime = RuntimeResolution(
        runtime_type="container",
        interface_version="andyur-agent-runtime/v1",
        manifest_digest=DIGEST,
        image_ref="ghcr.io/x/y",
        image_digest=DIGEST,
        command=("/app/agent",),
        resources=None,
        policy_revision="rev-1",
        lifecycle=LifecycleSpec("service", 7200, 600, "restart"),
        # Hand-listed, and it has to stay that way: this fixture's whole job is
        # to populate EVERY field, so a field added to the dataclass and not
        # added here reddens this test. That is the intended failure -- it is
        # how these two arrived.
        process=ProcessSpec(input_mode="stdin", input_max_bytes=1024),
        configuration=ConfigurationSpec(
            env=(EnvVar(name="HOME", reference="workspace.home"),),
            files=(ConfigFile(path="/tmp/c.yaml", template="k: v"),)),
    )
    # Through the COORDINATOR's durable seal, not the codec directly. The
    # codec is covered in test_runtime_wire; what this file owns is that the
    # per-run assignment path actually carries what the codec produced, so
    # post-processing introduced there cannot go unnoticed.
    from andyur.server.coordinator import _canonical_runtime_resolution
    assignment = json.loads(_canonical_runtime_resolution(runtime))
    declared = {f.name for f in dataclasses.fields(RuntimeResolution)}
    assert declared - set(assignment) == set(), (
        "a RuntimeResolution field is missing from the per-run assignment"
    )


def test_the_assignment_carries_the_lifetime_the_reaper_will_read():
    runtime = RuntimeResolution(
        runtime_type="container", interface_version="andyur-agent-runtime/v1",
        manifest_digest=DIGEST, image_ref="ghcr.io/x/y", image_digest=DIGEST,
        command=("/app/agent",),
        lifecycle=LifecycleSpec("service", 7200, 600, "restart"),
    )
    raw = json.loads(json.dumps(encode_runtime(runtime)))
    assert lifecycle_from_assignment(raw) == runtime.lifecycle


# --------------------------------------------------------------------------
# The single resolver, and its fail-closed behaviour.
# --------------------------------------------------------------------------

def test_an_agent_that_declared_nothing_gets_the_platform_default():
    assert granted_lifetime_seconds(None, 900) == 900


def test_a_granted_lifetime_beats_the_platform_default():
    assert granted_lifetime_seconds(LifecycleSpec("service", 86400), 900) == 86400


@pytest.mark.parametrize("raw", [{}, {"lifecycle": None}])
def test_an_absent_lifecycle_means_no_grant_and_takes_the_default(raw):
    """The agent declared no lifetime, so the platform default IS the right
    answer. This is the only case that may widen to it."""
    assert lifecycle_from_assignment(raw) is None
    assert granted_lifetime_seconds(None, 900) == 900


@pytest.mark.parametrize("raw", [
    None,
    "not-a-dict",
    {"lifecycle": "nope"},
    {"lifecycle": {"mode": "eternal", "max_seconds": 900}},
    {"lifecycle": {"mode": "task", "max_seconds": True}},
    {"lifecycle": {"mode": "task", "max_seconds": "900"}},
    {"lifecycle": {"mode": "task", "max_seconds": 10 ** 9}},
    {"lifecycle": {"mode": "task"}},
])
def test_a_lost_grant_is_distinguished_from_no_grant(raw):
    """PRESENT-BUT-UNREADABLE must not read as ABSENT.

    Collapsing both to None widened a run granted 120s to the 900s platform
    default -- "not immortal" is not the same as fail-closed, which is what two
    reviews independently said. Callers now catch this and use the floor.
    """
    from andyur.registry.models import MalformedLifecycle
    with pytest.raises(MalformedLifecycle):
        lifecycle_from_assignment(raw)


# --------------------------------------------------------------------------
# The reaper. This is the behaviour change: a long agent is no longer killed
# at the platform default just because that default is what the server reads.
# --------------------------------------------------------------------------

def _seal_lifetime(run_id, max_seconds, mode="task"):
    """Put a granted lifetime on the run row the way run creation does."""
    from andyur import db
    from andyur.server.coordinator import _canonical_runtime_resolution
    runtime = RuntimeResolution(
        runtime_type="container", interface_version="andyur-agent-runtime/v1",
        manifest_digest=DIGEST, image_ref="ghcr.io/x/y", image_digest=DIGEST,
        command=("/app/agent",),
        lifecycle=LifecycleSpec(mode, max_seconds, None, "fail"),
    )
    with db.connect() as c:
        c.execute("UPDATE runs SET runtime_resolution = ? WHERE id = ?",
                  (_canonical_runtime_resolution(runtime), run_id))


def _age_run(run_id, seconds):
    from andyur import db
    from andyur.server import heartbeat
    with db.connect() as c:
        c.execute("UPDATE runs SET started_at = ? WHERE id = ?",
                  (heartbeat._cutoff(seconds), run_id))


def _state(run_id):
    from andyur import db
    with db.connect() as c:
        return c.execute("SELECT state FROM runs WHERE id = ?",
                         (run_id,)).fetchone()["state"]


def test_a_long_lived_agent_survives_past_the_platform_default(env):
    """THE defect. Before this, a run granted 24 hours was reaped at 900s
    because the server read one global constant for every agent."""
    from andyur.server import coordinator, heartbeat
    env.agent("longrunner")
    run = coordinator.maybe_wakeup("longrunner", "work")
    coordinator.start_run(run)
    _seal_lifetime(run, 24 * 3600)
    _age_run(run, heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 600)

    heartbeat.recover_stuck_runs()
    assert _state(run) == "running", (
        "a run granted 24h was reaped at the platform default")


def test_a_long_lived_agent_is_still_reaped_past_its_own_deadline(env):
    """The positive control. A longer lifetime is not an exemption from
    being reaped, only a different deadline."""
    from andyur.server import coordinator, heartbeat
    env.agent("overrunner")
    run = coordinator.maybe_wakeup("overrunner", "work")
    coordinator.start_run(run)
    _seal_lifetime(run, 3600)
    _age_run(run, 3600 + heartbeat.RUN_GRACE_SECONDS + 600)

    heartbeat.recover_stuck_runs()
    assert _state(run) == "failed"


def test_an_agent_declaring_nothing_is_still_reaped_at_the_platform_default(env):
    """No regression for every agent that predates this feature."""
    from andyur.server import coordinator, heartbeat
    env.agent("plain")
    run = coordinator.maybe_wakeup("plain", "work")
    coordinator.start_run(run)
    _age_run(run, heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 600)

    heartbeat.recover_stuck_runs()
    assert _state(run) == "failed"


@pytest.mark.parametrize("sealed,reaches_parser", [
    # unreadable bytes: json.loads raises, handled before the parser
    ("{not json at all", False),
    # VALID json whose lifecycle is nonsense: this is the case that actually
    # reaches lifecycle_from_assignment. Without it the parser's fail-closed
    # behaviour is asserted by a test that never executes it -- the first
    # version of this test was exactly that, and a mutation proved it.
    ('{"lifecycle": {"mode": "eternal", "max_seconds": 1}}', True),
    ('{"lifecycle": {"mode": "service", "max_seconds": 999999999}}', True),
    ('{"lifecycle": "not-an-object"}', True),
    # VALID json that is not an object at all. A separate branch from the
    # cases above, and the only one that reaches the non-dict guard.
    ('[1, 2, 3]', True),
    ('42', True),
])
def test_a_run_with_corrupt_sealed_state_is_reaped_not_immortal(
        env, sealed, reaches_parser):
    """Fail closed. The dangerous failure is not a short run, it is one no
    reaper will ever collect."""
    from andyur import db
    from andyur.registry.models import lifecycle_from_assignment
    from andyur.server import coordinator, heartbeat

    if reaches_parser:
        # Assert the case genuinely exercises the parser, so this test cannot
        # quietly stop covering it the way its first version did. A recorded
        # grant that cannot be read now RAISES rather than reading as absent.
        from andyur.registry.models import MalformedLifecycle
        with pytest.raises(MalformedLifecycle):
            lifecycle_from_assignment(json.loads(sealed))

    env.agent(f"corrupt{abs(hash(sealed)) % 10000}")
    agent = f"corrupt{abs(hash(sealed)) % 10000}"
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    with db.connect() as c:
        c.execute("UPDATE runs SET runtime_resolution = ? WHERE id = ?",
                  (sealed, run))
    _age_run(run, heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 600)

    heartbeat.recover_stuck_runs()
    assert _state(run) == "failed"


def test_a_fresh_long_run_is_not_reaped_before_its_deadline(env):
    """Positive control on the other side: the reaper must not be reaping
    everything, or the first test above would pass on a broken reaper."""
    from andyur.server import coordinator, heartbeat
    env.agent("fresh")
    run = coordinator.maybe_wakeup("fresh", "work")
    coordinator.start_run(run)
    _seal_lifetime(run, 24 * 3600)
    _age_run(run, 60)

    heartbeat.recover_stuck_runs()
    assert _state(run) == "running"


# --------------------------------------------------------------------------
# The run token covers the grant. No rotation endpoint, by design: a credential
# is minted to cover its run, and run LIVENESS -- not expiry -- is what
# revocation turns on.
# --------------------------------------------------------------------------

def _sealed(max_seconds, mode="task") -> str:
    from andyur.server.coordinator import _canonical_runtime_resolution
    return _canonical_runtime_resolution(RuntimeResolution(
        runtime_type="container", interface_version="andyur-agent-runtime/v1",
        manifest_digest=DIGEST, image_ref="ghcr.io/x/y", image_digest=DIGEST,
        command=("/app/agent",),
        lifecycle=LifecycleSpec(mode, max_seconds, None, "fail"),
    ))


def test_a_granted_agents_token_outlives_its_whole_grant():
    """THE defect this closes. RUN_TOKEN_TTL is clamped against the PLATFORM
    default, so without this a 24h agent's credential died at 1800s and every
    call after that 401'd while the run was still healthy."""
    from andyur.server.app import _RUN_TOKEN_GRACE, _run_token_ttl
    ttl = _run_token_ttl("work", _sealed(24 * 3600))
    assert ttl == 24 * 3600 + _RUN_TOKEN_GRACE


def test_the_token_outlives_the_reaper_grace_so_a_reaped_run_can_report():
    """A run being collected must still be able to make the call that reports
    its own failure, so the credential has to outlast the reaper's window."""
    from andyur.server.app import _RUN_TOKEN_GRACE
    from andyur.server.heartbeat import RUN_GRACE_SECONDS
    assert _RUN_TOKEN_GRACE > RUN_GRACE_SECONDS


def test_an_agent_declaring_nothing_still_gets_the_platform_default():
    from andyur.server.app import _run_token_ttl
    assert _run_token_ttl("work", None) is None
    assert _run_token_ttl("work", _sealed_without_lifecycle()) is None


def _sealed_without_lifecycle() -> str:
    from andyur.server.coordinator import _canonical_runtime_resolution
    return _canonical_runtime_resolution(RuntimeResolution(
        runtime_type="container", interface_version="andyur-agent-runtime/v1",
        manifest_digest=DIGEST, image_ref="ghcr.io/x/y", image_digest=DIGEST,
        command=("/app/agent",),
    ))


def test_a_conversation_is_still_bounded_by_its_own_ceiling():
    """The conversation branch predates this and must not be disturbed by it."""
    from andyur import config
    from andyur.server.app import _RUN_TOKEN_GRACE, _run_token_ttl
    assert _run_token_ttl("conversation", _sealed(24 * 3600)) == (
        config.CONVERSATION_MAX_SECONDS + _RUN_TOKEN_GRACE)


def test_unreadable_bytes_take_the_platform_default_token():
    """Not JSON at all: nothing was recorded that we can even call a grant."""
    from andyur.server.app import _run_token_ttl
    assert _run_token_ttl("work", "{not json") is None


@pytest.mark.parametrize("sealed", [
    "[1,2,3]", '{"lifecycle": {"mode": "eternal", "max_seconds": 1}}',
    '{"lifecycle": {"mode": "task", "max_seconds": 999999999}}',
])
def test_a_lost_grant_mints_the_shortest_defensible_token(sealed):
    """A grant EXISTED and cannot be read. The platform default would be WIDER
    than what may have been granted, so the floor is used: a lost grant must
    never buy a run more time than it was given."""
    from andyur.registry.models import LIFETIME_FLOOR_SECONDS
    from andyur.server.app import _RUN_TOKEN_GRACE, _run_token_ttl
    assert _run_token_ttl("work", sealed) == (
        LIFETIME_FLOOR_SECONDS + _RUN_TOKEN_GRACE)


def test_the_assignment_carries_the_sealed_runtime_to_the_mint_site(env):
    """The token TTL and the reaper must read the SAME sealed value, or they
    disagree about when the run ends."""
    from andyur import db
    from andyur.server import coordinator
    env.agent("assigned")
    run = coordinator.maybe_wakeup("assigned", "work")
    with db.connect() as c:
        c.execute("UPDATE runs SET runtime_resolution = ? WHERE id = ?",
                  (_sealed(7200), run))
    coordinator.record_heartbeat("w1", 1)
    assignments = coordinator.assign_runs("w1", 1)
    mine = [a for a in assignments if a["id"] == run]
    assert mine, "the run was not assigned"
    assert mine[0]["runtime_resolution"] == _sealed(7200)


def test_run_liveness_not_expiry_is_what_revocation_turns_on():
    """Why there is no rotation endpoint. Documented here because the absence
    of a feature is invisible, and the next person to want one should find the
    reason rather than the gap."""
    import inspect
    from andyur.server import auth
    source = inspect.getsource(auth.require_run)
    assert "_run_liveness" in source
    assert "finished/unknown run" in source


def test_the_granted_wall_clock_reaches_the_runner_environment():
    """The runner arms its OWN asyncio timeout from ANDYUR_RUN_TTL_SECONDS.
    Without this the server, the token and the reaper all honour a 24h grant
    while the runner still kills the agent at the platform default."""
    import dataclasses
    import inspect

    from andyur.daemon import orchestrator
    from andyur.daemon.orchestrator import RunSpec

    assert "server_run_ttl" in {f.name for f in dataclasses.fields(RunSpec)}
    # and the orchestrator actually turns it into the variable the runner reads
    source = inspect.getsource(orchestrator)
    assert 'ANDYUR_RUN_TTL_SECONDS' in source
    assert 'spec.server_run_ttl' in source


def test_the_server_resolves_the_per_run_wall_clock_itself():
    """Resolved server-side so the number the runner enforces, the number the
    token covers and the number the reaper collects by are one computation."""
    from andyur.server.app import _granted_run_seconds
    assert _granted_run_seconds(_sealed(24 * 3600)) == 24 * 3600
    assert _granted_run_seconds(_sealed_without_lifecycle()) is None
    assert _granted_run_seconds(None) is None
    assert _granted_run_seconds("{not json") is None


def test_a_daemon_given_no_grant_keeps_the_platform_wide_value():
    """No regression for every agent that predates this."""
    import inspect
    from andyur.daemon import daemon
    source = inspect.getsource(daemon.Daemon.launch)
    assert "run_ttl or SERVER_RUN_TTL" in source


def test_an_agent_without_a_lifecycle_produces_the_pre_feature_bytes():
    """F8. The per-run assignment is compared BYTE FOR BYTE against the value
    sealed on the run row at creation, so emitting `"lifecycle": null` for an
    agent that declared none makes every row sealed before the deploy mismatch
    forever -- skipped with "governed runtime resolution no longer matches its
    admitted provenance", which reads as tampering, until the 24h queue
    backstop fails it.

    Both the overlay document and the durable seal now go through one codec,
    where the rule is declared per field rather than remembered per site. This
    asserts the rule from the seal's side, which is the side that breaks
    in-flight runs when it is wrong.
    """
    from andyur.server.coordinator import _canonical_runtime_resolution
    plain = RuntimeResolution(
        runtime_type="container", interface_version="andyur-agent-runtime/v1",
        manifest_digest=DIGEST, image_ref="ghcr.io/x/y", image_digest=DIGEST,
        command=("/app/agent",))
    canonical = _canonical_runtime_resolution(plain)
    assert "lifecycle" not in canonical, (
        "an agent that declared no lifecycle must canonicalize exactly as it "
        "did before the field existed, or every in-flight run breaks at upgrade")
    assert "lifecycle" in _canonical_runtime_resolution(
        dataclasses.replace(plain, lifecycle=LifecycleSpec("task", 3600)))


def test_a_run_with_an_unreadable_started_at_is_actually_reached_and_reaped(env):
    """The fix for this was UNREACHABLE, which a peer review caught.

    `started_at` is TEXT compared as a string, so the query's `started_at < ?`
    predicate excluded any row whose timestamp was unparseable -- the very rows
    the Python branch was written to collect. The row sat in 'running' forever
    while a test asserting the branch's logic passed.
    """
    from andyur import db
    from andyur.server import coordinator, heartbeat
    env.agent("badstamp")
    run = coordinator.maybe_wakeup("badstamp", "work")
    coordinator.start_run(run)
    with db.connect() as c:
        c.execute("UPDATE runs SET started_at = ? WHERE id = ?",
                  ("not-a-timestamp", run))
    heartbeat.recover_stuck_runs()
    assert _state(run) == "failed"
