"""The policy stack belongs to ONE invocation, so concurrent gates cannot maul it.

Four scripts source `infra/opa/opa-stack.sh` -- verify-opa.sh,
verify-opa-hardening.sh, verify-sre-registry.sh and demo-no-redeploy.sh -- and on
a developer machine several run at once in different sessions against one Docker
daemon. The helper used to hard-assign `OPA_CONTAINER="andyur-opa"` and then
`docker rm -f` that name on the way up, so whichever gate started LAST destroyed
the engine of every gate already running. The victim never failed as "someone
deleted my container": it failed as a missing decision or an unreachable PDP,
which reads like a policy defect and is not one.

These drive the REAL shell function with a stubbed `docker` on PATH, so they pin
the behaviour rather than the wording of the source, and they need no daemon.
The live engine is still covered by infra/opa/verify-opa-hardening.sh.
"""

import pathlib
import subprocess
import tempfile

import pytest

STACK = pathlib.Path(__file__).resolve().parent.parent / "infra" / "opa" / "opa-stack.sh"


def _bash(script: str, path_prefix: pathlib.Path | None = None) -> str:
    """Run `script` with opa-stack.sh sourced, returning stdout.

    A failing shell is surfaced with its stderr, because a silently empty stdout
    here would let one of these assertions pass for the wrong reason.
    """
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}:{env['PATH']}"
    done = subprocess.run(
        ["bash", "-c", f'set -uo pipefail; source "{STACK}"\n{script}'],
        capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, f"shell failed: {done.stderr}"
    return done.stdout


@pytest.fixture
def docker_stub(tmp_path):
    """A fake `docker` whose behaviour each test sets through files in tmp_path.

    `exists` present  -> `docker container inspect` succeeds (the name is taken).
    Every invocation is appended to `calls`, so a test can assert what the helper
    did AND, just as importantly, what it did not do.
    """
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "docker"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{tmp_path}/calls"\n'
        'case "$1 $2" in\n'
        f'  "container inspect") [ -e "{tmp_path}/exists" ] && exit 0 || exit 1;;\n'
        'esac\n'
        'exit 0\n')
    stub.chmod(0o755)
    return stub_dir, tmp_path


def test_two_invocations_get_different_container_names():
    """The name is the whole defence: same name, and one run deletes the other."""
    first = _bash('echo "$OPA_CONTAINER"').strip()
    second = _bash('echo "$OPA_CONTAINER"').strip()
    assert first and second
    assert first != second, (
        "two sourcings produced the same container name, so two concurrent "
        "gates would fight over one container")
    assert first.startswith("andyur-opa-") and second.startswith("andyur-opa-")


def test_an_explicit_container_name_still_wins():
    """An operator pinning the name must keep working; the default is what changed."""
    out = subprocess.run(
        ["bash", "-c", f'source "{STACK}"; echo "$OPA_CONTAINER"'],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin",
                                             "OPA_CONTAINER": "andyur-opa-pinned"},
        timeout=60)
    assert out.stdout.strip() == "andyur-opa-pinned", out.stderr


def test_no_fixed_default_ports_remain():
    """8181/8282/8383 in two shells at once is a collision, not a configuration."""
    source = STACK.read_text()
    for literal in ("OPA_PORT:-8181", "SHIM_PORT:-8282", "BUNDLE_PORT:-8383"):
        assert literal not in source, (
            f"{literal} is back: a fixed default port collides between gates")


def test_the_three_ports_are_allocated_distinct_in_one_shot():
    """Distinctness must come from the kernel, not from the OS happening to cycle.

    Allocating one port at a time returns three ports that are *usually*
    different because ephemeral ranges advance -- an assumption of the host, not
    a guarantee. Holding all three sockets open at once makes it a guarantee.
    Two of this file's scars (the in-container build uid, the loopback bundle
    bind) came from exactly this shape of assumption holding on macOS.
    """
    out = _bash('opa_stack_paths\n_opa_free_ports 127.0.0.1').split()
    assert len(out) == 3 and all(p.isdigit() for p in out), out
    assert len(set(out)) == 3, f"the allocator handed out a duplicate port: {out}"


def test_repeated_allocation_returns_usable_distinct_triples():
    """Positive control for the allocator: 40 triples, all well-formed and distinct.

    Read what this does NOT prove. It cannot detect a one-at-a-time allocator:
    both implementations pass, because every OS tested cycles its ephemeral range
    rather than immediately re-handing a just-closed port. That was measured, not
    assumed -- reintroducing the per-call allocator left this module fully green.
    The held-sockets guarantee is therefore pinned structurally below, and this
    test's job is only to prove the allocator actually works.
    """
    out = _bash(
        'opa_stack_paths\n'
        'for _ in $(seq 1 40); do _opa_free_ports 127.0.0.1; done')
    triples = [line.split() for line in out.strip().splitlines()]
    assert len(triples) == 40
    for triple in triples:
        assert len(set(triple)) == 3, f"duplicate port within one stack: {triple}"


def test_the_allocator_holds_every_socket_open_until_the_last_is_bound():
    """The one property here that no behavioural test on a cycling OS can catch.

    Distinctness must be the kernel's guarantee, not a side effect of the host
    advancing its ephemeral range. A per-call allocator (bind, read, close, next)
    is free to hand the same port back twice and would sail through every
    behavioural assertion in this file -- verified by injecting exactly that
    mutation and watching the module stay green. So the structure is pinned
    directly: sockets accumulate and are closed only after all three are read.
    """
    source = STACK.read_text()
    body = source.split("_opa_free_ports()", 1)[1].split("\n}", 1)[0]
    assert "held.append(s)" in body, (
        "the allocator no longer accumulates sockets: it is binding and closing "
        "one at a time, so two of this stack's ports can be identical")
    close_at = body.index("s.close()")
    read_at = body.index('print(" ".join(')
    assert read_at < close_at, (
        "a socket is closed before all three ports have been read, which "
        "reopens the duplicate-port window this design exists to shut")


def test_a_caller_that_pinned_only_some_ports_keeps_them(docker_stub):
    """verify-sre-registry.sh exports its own ports; a partial pin must survive.

    This drives the REAL opa_stack_up. An earlier version of this test pasted a
    copy of the resolution logic into the shell instead, which meant it asserted
    on a reimplementation and would have stayed green no matter what the shipped
    function did.
    """
    stub_dir, work = docker_stub
    # `docker run` fails, so opa_stack_up unwinds and returns right after it has
    # resolved the ports. That keeps this fast and spawns no real OPA or shim,
    # while still driving the shipped resolution code rather than a copy of it.
    (stub_dir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{work}/calls"\n'
        'case "$1 $2" in\n'
        '  "container inspect") exit 1;;\n'
        '  "run -d") exit 125;;\n'
        'esac\n'
        'exit 0\n')
    (stub_dir / "docker").chmod(0o755)
    out = subprocess.run(
        ["bash", "-c",
         f'source "{STACK}"\n'
         'opa_stack_up >/dev/null 2>&1\n'
         'echo "$OPA_PORT $SHIM_PORT $BUNDLE_PORT"'],
        capture_output=True, text=True, timeout=120,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "OPA_PORT": "8191",
             "OPA_CONTAINER": "andyur-opa-pinports"})
    assert out.returncode == 0, out.stderr
    opa_port, shim_port, bundle_port = out.stdout.split()
    assert opa_port == "8191", "an explicitly pinned port was overwritten"
    assert shim_port != "8191" and bundle_port != "8191"
    assert shim_port.isdigit() and bundle_port.isdigit()


def test_startup_refuses_a_container_it_did_not_create(docker_stub):
    """The core regression: refuse, never `docker rm -f` someone else's engine."""
    stub_dir, work = docker_stub
    (work / "exists").touch()          # the name is already taken
    done = subprocess.run(
        ["bash", "-c",
         f'source "{STACK}"\n'
         'opa_stack_up >/dev/null 2>&1; echo "rc=$?"'],
        capture_output=True, text=True, timeout=60,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "OPA_CONTAINER": "andyur-opa-victim"})
    assert "rc=1" in done.stdout, "startup must FAIL when the name is occupied"
    calls = (work / "calls").read_text()
    assert "container inspect andyur-opa-victim" in calls
    assert "rm -f" not in calls, (
        "startup force-deleted a container it did not create -- this is the "
        "exact bug: one gate starting destroys another gate's running engine")


def test_teardown_removes_nothing_it_did_not_create(docker_stub):
    """A gate that failed before `docker run` must not reap a healthy peer."""
    stub_dir, work = docker_stub
    subprocess.run(
        ["bash", "-c", f'source "{STACK}"\nopa_stack_down >/dev/null 2>&1'],
        capture_output=True, text=True, timeout=60,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "OPA_CONTAINER": "andyur-opa-peer"})
    calls = (work / "calls").read_text() if (work / "calls").exists() else ""
    assert "rm -f" not in calls, (
        "teardown removed a container this invocation never created")


def test_teardown_does_remove_what_it_did_create(docker_stub):
    """The positive control: ownership must not be an excuse to leak.

    Without this, the refusal tests above would pass against a teardown that
    removes nothing at all, ever. Ownership is proven by the label, so the stub
    reports a container carrying this invocation's id and teardown must remove
    exactly that one.
    """
    stub_dir, work = docker_stub
    (stub_dir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{work}/calls"\n'
        'case "$*" in\n'
        '  *"label=andyur.opa-stack=mineonly"*) echo deadbeefcafe; exit 0;;\n'
        'esac\n'
        'exit 0\n')
    (stub_dir / "docker").chmod(0o755)
    subprocess.run(
        ["bash", "-c", f'source "{STACK}"\nopa_stack_down >/dev/null 2>&1'],
        capture_output=True, text=True, timeout=60,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "OPA_STACK_ID": "mineonly"})
    calls = (work / "calls").read_text()
    assert "rm -f deadbeefcafe" in calls, (
        f"teardown leaked the container this invocation owned. calls:\n{calls}")


def test_the_container_really_carries_this_invocations_label(docker_stub):
    """Behavioural, not a grep: the label is what teardown proves ownership with.

    Asserting the label's spelling in the source would pass with the label on
    the wrong container or with a stale id, and ownership is now decided by it.
    """
    stub_dir, work = docker_stub
    # Fail the run: the label is on the `run -d` argv, which is recorded before
    # the failure, so this asserts the same property without sitting through the
    # 30-second readiness wait for an OPA that will never answer.
    (stub_dir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{work}/calls"\n'
        'case "$1 $2" in\n'
        '  "container inspect") exit 1;;\n'
        '  "run -d") exit 125;;\n'
        'esac\n'
        'exit 0\n')
    (stub_dir / "docker").chmod(0o755)
    subprocess.run(
        ["bash", "-c", f'source "{STACK}"\nopa_stack_up >/dev/null 2>&1'],
        capture_output=True, text=True, timeout=120,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin",
             "OPA_STACK_ID": "labeltest", "OPA_CONTAINER": "andyur-opa-labeltest"})
    calls = (work / "calls").read_text()
    run_line = [c for c in calls.splitlines() if c.startswith("run -d")]
    assert run_line, f"docker run was never invoked: {calls}"
    assert "--label andyur.opa-stack=labeltest" in run_line[0], (
        "the container does not carry this invocation's label, so teardown "
        f"cannot prove it owns it: {run_line[0]}")
    assert "--name andyur-opa-labeltest" in run_line[0]


def test_reaping_targets_one_stack_id_never_a_blanket_sweep(docker_stub):
    """An unfiltered sweep is the destructive behaviour this change removed."""
    stub_dir, work = docker_stub
    subprocess.run(
        ["bash", "-c", f'source "{STACK}"\nopa_stack_reap onlythisone >/dev/null 2>&1'],
        capture_output=True, text=True, timeout=60,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin"})
    calls = (work / "calls").read_text()
    assert "label=andyur.opa-stack=onlythisone" in calls, calls
    assert "--filter label=andyur.opa-stack " not in calls, (
        "reap filtered on the label KEY, which sweeps every session's stacks")


def test_a_container_that_was_created_but_failed_to_start_is_cleaned_up(docker_stub):
    """`docker run -d` can fail AFTER creating the container; that must not leak.

    A taken host port exits 125 with the container sitting in Created. The
    previous design recorded ownership in a flag set only on success, so exactly
    this case orphaned a container that teardown then refused to touch.
    """
    stub_dir, work = docker_stub
    # A stub whose `run` fails (as docker does when the port is taken) while
    # `container inspect` reports the name free, so startup proceeds to run.
    (stub_dir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{work}/calls"\n'
        'case "$1 $2" in\n'
        '  "container inspect") exit 1;;\n'
        '  "run -d") exit 125;;\n'
        'esac\n'
        'exit 0\n')
    (stub_dir / "docker").chmod(0o755)
    done = subprocess.run(
        ["bash", "-c",
         f'source "{STACK}"\nopa_stack_up >/dev/null 2>&1; echo "rc=$?"'],
        capture_output=True, text=True, timeout=120,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "OPA_STACK_ID": "failstart"})
    assert "rc=1" in done.stdout, "a failed docker run must fail the stack"
    calls = (work / "calls").read_text()
    assert "label=andyur.opa-stack=failstart" in calls, (
        "startup failed after creating the container and never tried to reap "
        f"it -- that container is orphaned forever. calls:\n{calls}")


def test_a_refused_start_creates_no_signing_key_and_no_listener(docker_stub, tmp_path):
    """Refusing must happen BEFORE any resource exists, not after.

    The check used to sit beside `docker run`, so every refusal had already
    written an RSA signing key to a temp dir and started an all-interfaces HTTP
    server that nothing then stopped.
    """
    stub_dir, work = docker_stub
    (work / "exists").touch()          # the name is taken -> refuse
    before = set(pathlib.Path(tempfile.gettempdir()).glob("tmp.*"))
    done = subprocess.run(
        ["bash", "-c",
         f'source "{STACK}"\nopa_stack_up >/dev/null 2>&1; echo "rc=$?"'],
        capture_output=True, text=True, timeout=120,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "OPA_CONTAINER": "andyur-opa-taken",
             "TMPDIR": tempfile.gettempdir()})
    assert "rc=1" in done.stdout
    calls = (work / "calls").read_text()
    assert "run -d" not in calls, "refusal happened after starting the container"
    leaked = set(pathlib.Path(tempfile.gettempdir()).glob("tmp.*")) - before
    keys = [d for d in leaked if (d / "bundle-signing-private.pem").exists()]
    assert not keys, f"a refused start left a signing key on disk: {keys}"
