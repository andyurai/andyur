"""Seccomp profile rendering, role differences, and launch wiring.

The property under test is NOT "a flag appears in argv" -- docker silently
takes the last `--security-opt seccomp=` it is given, so argv presence is not
enforcement. These tests cover what argv cannot: that the rendered profile
actually denies what we claim, that the two roles differ where they should,
and that the whole thing fails closed. The in-container proof that the filter
is loaded lives in infra/verify-seccomp.sh, which reads Seccomp_filters from
/proc.
"""

import json

import pytest

from andyur import config
from andyur.daemon import seccomp


def _allowed(profile: dict) -> set[str]:
    """Every syscall name the profile still allows anywhere."""
    return {
        name
        for group in profile["syscalls"]
        if group["action"] == "SCMP_ACT_ALLOW"
        for name in group["names"]
    }


def test_base_is_deny_by_default():
    # If the base ever became allow-by-default, every subtraction below would
    # be a no-op while the profile still looked like a profile.
    base = json.loads((seccomp._BASE_PATH).read_text())
    assert base["defaultAction"] == "SCMP_ACT_ERRNO"


def test_base_keeps_the_argument_level_rules_a_handwritten_profile_would_lose():
    # The reason we vendor the runtime's profile instead of writing one. If a
    # future edit flattens these, the profile gets narrower in names and weaker
    # in arguments, which is a regression that no name-level test would catch.
    base = json.loads((seccomp._BASE_PATH).read_text())
    clone = [g for g in base["syscalls"] if "clone" in g.get("names", [])]
    assert any(g.get("args") for g in clone), "clone namespace-flag mask is gone"
    clone3 = [g for g in base["syscalls"] if "clone3" in g.get("names", [])]
    assert any(g["action"] == "SCMP_ACT_ERRNO" and g.get("errnoRet") == 38
               for g in clone3), "clone3 must answer ENOSYS so glibc falls back"


@pytest.mark.parametrize("role", [seccomp.AGENT, seccomp.RUNNER])
def test_process_inspection_is_denied_in_both_roles(role):
    allowed = _allowed(seccomp.render(role))
    for call in ("ptrace", "process_vm_readv", "process_vm_writev", "kcmp"):
        assert call not in allowed, f"{call} still allowed for {role}"


def test_agent_denies_the_uid_family_and_the_sidecar_keeps_it():
    # The role difference IS the feature: the agent container is unprivileged
    # from PID 1 and never changes uid; the sidecar runs setpriv.
    agent = _allowed(seccomp.render(seccomp.AGENT))
    runner = _allowed(seccomp.render(seccomp.RUNNER))
    for call in ("setuid", "setgid", "setresuid", "setgroups"):
        assert call not in agent, f"{call} still allowed for the agent"
        assert call in runner, f"{call} must stay for the sidecar's setpriv"


def test_ordinary_syscalls_survive_both_profiles():
    # Positive control. A profile that denied everything would pass every
    # assertion above and break every run.
    for role in (seccomp.AGENT, seccomp.RUNNER):
        allowed = _allowed(seccomp.render(role))
        for call in ("read", "write", "openat", "execve", "clone", "futex"):
            assert call in allowed, f"{call} must stay allowed for {role}"


def test_no_group_is_left_with_an_empty_name_list():
    # A group stripped to zero names is meaningless and some parsers reject it.
    for role in (seccomp.AGENT, seccomp.RUNNER):
        for group in seccomp.render(role)["syscalls"]:
            assert group["names"], f"empty syscall group in {role} profile"


def test_profile_is_written_and_hashed_stably():
    path_a, digest_a = seccomp.profile_path(seccomp.AGENT)
    seccomp._cache.clear()
    path_b, digest_b = seccomp.profile_path(seccomp.AGENT)
    assert (path_a, digest_a) == (path_b, digest_b)
    assert json.loads(open(path_a).read())["defaultAction"] == "SCMP_ACT_ERRNO"
    # The two roles must not collide on one file.
    assert seccomp.profile_path(seccomp.RUNNER)[1] != digest_a


def test_missing_base_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(seccomp, "_BASE_PATH", tmp_path / "absent.json")
    with pytest.raises(seccomp.SeccompUnavailable):
        seccomp.render(seccomp.AGENT)


def test_allow_by_default_base_is_refused(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}))
    monkeypatch.setattr(seccomp, "_BASE_PATH", bad)
    with pytest.raises(seccomp.SeccompUnavailable):
        seccomp.render(seccomp.RUNNER)


def test_unknown_role_is_refused():
    with pytest.raises(seccomp.SeccompUnavailable):
        seccomp.render("supervisor")


def test_off_applies_nothing_and_says_so(monkeypatch):
    monkeypatch.setattr(config, "SECCOMP_MODE", "off")
    assert seccomp.docker_args(seccomp.AGENT) == []
    assert seccomp.describe(seccomp.AGENT)["profile_sha256"] is None


@pytest.mark.parametrize("mode", ["auto", "require"])
def test_on_modes_apply_exactly_one_profile_flag(monkeypatch, mode):
    monkeypatch.setattr(config, "SECCOMP_MODE", mode)
    args = seccomp.docker_args(seccomp.RUNNER)
    assert args[0] == "--security-opt"
    assert args[1].startswith("seccomp=/")
    assert seccomp.describe(seccomp.RUNNER)["profile_sha256"]


def test_launch_argv_carries_the_right_role_for_each_container(monkeypatch):
    # Built from the orchestrator's own functions, so this cannot drift from
    # what actually launches.
    from andyur.daemon import orchestrator
    monkeypatch.setattr(config, "SECCOMP_MODE", "auto")
    agent_path, _ = seccomp.profile_path(seccomp.AGENT)
    runner_path, _ = seccomp.profile_path(seccomp.RUNNER)

    sidecar = orchestrator._sandbox_argv("scout", "r-1", pod=True)
    agent = orchestrator._agent_argv("scout", "r-1")

    assert f"seccomp={runner_path}" in sidecar
    assert f"seccomp={agent_path}" in agent
    # Exactly one seccomp flag per container: docker silently honours the LAST
    # one, so a second would disable the first with no error.
    for argv in (sidecar, agent):
        assert sum(a.startswith("seccomp=") for a in argv) == 1


def test_single_container_mode_gets_the_runner_profile(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(config, "SECCOMP_MODE", "auto")
    runner_path, _ = seccomp.profile_path(seccomp.RUNNER)
    argv = orchestrator._sandbox_argv("scout", "r-2", pod=False)
    assert f"seccomp={runner_path}" in argv


def test_require_without_a_container_to_apply_it_to_is_refused(monkeypatch):
    """`require` plus no sandbox is a belief about a control, not a control."""
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "DEPLOYMENT", "docker")
    monkeypatch.setattr(config, "SECCOMP_MODE", "require")
    monkeypatch.setattr(config, "SANDBOX", False)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_SANDBOX=on" in str(exc.value)
    assert "no effect" in str(exc.value)


@pytest.mark.parametrize("raw, expected", [
    ("off", "off"), ("false", "off"),
    ("auto", "auto"), ("on", "auto"), ("", "auto"),
    ("require", "require"), ("REQUIRE", "require"), (" require ", "require"),
])
def test_flag_aliases_resolve(raw, expected):
    assert config._SECCOMP_ALIASES.get(raw.strip().lower()) == expected


@pytest.mark.parametrize("raw", ["enforce", "yes", "strict", "2", "onn"])
def test_an_unrecognised_flag_value_is_refused_not_guessed(raw):
    """Guessing would select the least protected branch, which is the opposite
    of what someone setting this variable intended."""
    assert config._SECCOMP_ALIASES.get(raw.strip().lower()) is None


def test_off_leaves_no_seccomp_flag_in_either_container(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(config, "SECCOMP_MODE", "off")
    for argv in (orchestrator._sandbox_argv("scout", "r-3", pod=True),
                 orchestrator._agent_argv("scout", "r-3")):
        assert not any(a.startswith("seccomp=") for a in argv)
