"""Resolution of the exec/v1 configuration surface (ADR-011 D4).

The parser proved a manifest may only NAME these references. This module proves
what they BECOME, which is where two new failure modes live: a reference that
resolves to nothing, and a path whose containment could only be promised at
parse time because the value it depends on did not exist yet.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib

import pytest

from andyur import execconfig
from andyur.execconfig import RunFacts, UnresolvedReference
from andyur.registry.models import (
    CONFIG_REFERENCE_PREFIXES,
    CONFIG_REFERENCES,
    ConfigFile,
    ConfigurationSpec,
    EnvVar,
)

FACTS = RunFacts(
    run_id="run_abc",
    deadline_epoch=1787550000,
    model_base_url="http://127.0.0.1:8765",
    model_openai_base_url="http://127.0.0.1:8765/v1",
    model_name="claude-opus-5",
    mcp_url="http://10.42.0.7:8766/mcp",
    workspace_home="/home/agent",
    workspace_tmp="/tmp",
    input_path=execconfig.INPUT_PATH,
)
WITH_BEARER = dataclasses.replace(FACTS, mcp_bearer="opaque-run-bearer")


# --------------------------------------------------------------------------
# The vocabulary resolves, completely
# --------------------------------------------------------------------------

@pytest.mark.parametrize("reference", sorted(CONFIG_REFERENCES))
def test_every_public_reference_resolves_to_a_value(reference):
    """The structural guard. A reference added to the vocabulary without a value
    here would parse, validate, cross the wire, and then hand a stock workload a
    literal ${...} -- which it would read as a hostname."""
    value = execconfig.resolve(reference, WITH_BEARER, where="probe")
    assert value and isinstance(value, str)


def test_the_header_family_resolves_to_the_runs_bearer():
    for name in ("Authorization", "X-Andyur-Run"):
        ref = CONFIG_REFERENCE_PREFIXES[0] + name
        assert execconfig.resolve(ref, WITH_BEARER, where="probe") \
            == "opaque-run-bearer"


def test_a_reference_outside_the_vocabulary_is_refused():
    with pytest.raises(UnresolvedReference):
        execconfig.resolve("services.model.api_key", WITH_BEARER, where="probe")


def test_a_bearer_reference_without_a_bearer_refuses_rather_than_empties():
    """Resolving to "" would write a config file with an empty Authorization
    header, and the workload would report an auth failure against its own
    governed endpoint -- a diagnosis pointing at the wrong component."""
    with pytest.raises(UnresolvedReference):
        execconfig.resolve(CONFIG_REFERENCE_PREFIXES[0] + "Authorization",
                           FACTS, where="probe")


# --------------------------------------------------------------------------
# Substitution leaves nothing behind
# --------------------------------------------------------------------------

def test_substitution_refuses_to_leave_a_reference_behind(monkeypatch):
    """A partially rendered template is the failure that looks like success."""
    monkeypatch.setattr(execconfig, "resolve",
                        lambda ref, facts, where: "${still.a.reference}")
    with pytest.raises(UnresolvedReference):
        execconfig.substitute("url: ${services.tools.mcp_url}", WITH_BEARER,
                              where="probe")


# --------------------------------------------------------------------------
# The environment split: the bearer never becomes a literal
# --------------------------------------------------------------------------

def test_a_bearer_backed_variable_is_returned_as_a_name_not_a_value():
    configuration = ConfigurationSpec(env=(
        EnvVar(name="LLM_PROVIDER", literal="openai"),
        EnvVar(name="OPENAI_BASE_URL",
               reference="services.model.openai_base_url"),
        EnvVar(name="MCP_TOKEN",
               reference=CONFIG_REFERENCE_PREFIXES[0] + "Authorization"),
    ))
    plain, secret = execconfig.plan_environment(configuration, WITH_BEARER)
    assert dict(plain) == {
        "LLM_PROVIDER": "openai",
        "OPENAI_BASE_URL": "http://127.0.0.1:8765/v1",
    }
    assert secret == ("MCP_TOKEN",)
    # The value is absent from what a launcher can put in a Pod spec, even
    # though this call had the bearer available to it.
    assert "opaque-run-bearer" not in json.dumps(plain)


def test_planning_needs_no_bearer_at_all():
    """A launcher builds a Pod spec without ever holding the credential."""
    configuration = ConfigurationSpec(env=(
        EnvVar(name="MCP_TOKEN",
               reference=CONFIG_REFERENCE_PREFIXES[0] + "Authorization"),))
    plain, secret = execconfig.plan_environment(configuration, FACTS)
    assert plain == () and secret == ("MCP_TOKEN",)


# --------------------------------------------------------------------------
# Containment, re-established on the RESOLVED path
# --------------------------------------------------------------------------

def test_a_resolved_path_outside_the_scratch_is_refused():
    """The parse-time rule was about the unresolved form. If workspace.home ever
    resolves somewhere unexpected, this is the check that notices."""
    hostile = dataclasses.replace(FACTS, workspace_home="/etc")
    configuration = ConfigurationSpec(files=(
        ConfigFile(path="${workspace.home}/passwd", template="x"),))
    with pytest.raises(UnresolvedReference):
        execconfig.render_files(configuration, hostile)


def test_files_render_with_their_references_substituted():
    configuration = ConfigurationSpec(files=(
        ConfigFile(path="${workspace.home}/.config/w/config.yaml",
                   template="mcp_url: ${services.tools.mcp_url}\n"
                            "auth: ${services.tools.mcp_headers.Authorization}\n"),))
    (path, content), = execconfig.render_files(configuration, WITH_BEARER)
    assert path == "/home/agent/.config/w/config.yaml"
    assert "mcp_url: http://10.42.0.7:8766/mcp" in content
    assert "auth: opaque-run-bearer" in content
    assert "${" not in content


# --------------------------------------------------------------------------
# The init container's own boundary
# --------------------------------------------------------------------------

def test_facts_survive_the_environment_round_trip(monkeypatch):
    monkeypatch.setenv(execconfig.FACTS_ENV, json.dumps(FACTS.public()))
    monkeypatch.setenv(execconfig.BEARER_ENV, "opaque-run-bearer")
    rebuilt = execconfig.facts_from_environment()
    assert rebuilt == WITH_BEARER


def test_an_absent_bearer_stays_absent_rather_than_becoming_empty(monkeypatch):
    monkeypatch.setenv(execconfig.FACTS_ENV, json.dumps(FACTS.public()))
    monkeypatch.delenv(execconfig.BEARER_ENV, raising=False)
    assert execconfig.facts_from_environment().mcp_bearer is None


def test_materialized_files_are_private_to_the_workload(tmp_path):
    """A rendered file may hold the run's bearer. The emptyDir is world-writable
    because kubelet makes it so; the file inside it need not be."""
    target = tmp_path / "nested" / "config.yaml"
    execconfig.materialize(((str(target), "secret: value\n"),))
    assert target.read_text() == "secret: value\n"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_an_empty_value_fails_closed():
    """An empty model name is not a smaller configuration; it is a broken one
    the workload will report as its own fault."""
    blank = dataclasses.replace(FACTS, model_name="")
    with pytest.raises(UnresolvedReference):
        execconfig.resolve("services.model.name", blank, where="probe")


def test_render_files_refuses_a_resolved_path_inside_the_input_directory():
    """M-B: a file whose path resolves under /tmp/andyur (e.g. via
    ${workspace.tmp}) passes the parser but must be refused at render, or it
    collides with the run input. The parser cannot see the resolved form."""
    from andyur.execconfig import render_files, UnresolvedReference, INPUT_PATH
    from andyur.registry.models import ConfigurationSpec, ConfigFile
    # A double-slash form so the check must NORMALISE the resolved path, not
    # raw-string prefix it (R M-A/M-B): raw "/tmp//andyur/input" does not
    # startswith "/tmp/andyur/" but normalises onto the input.
    for raw in ("${workspace.tmp}/andyur/input", "${workspace.tmp}//andyur/input",
                "${workspace.tmp}/andyur"):
        cfg = ConfigurationSpec(files=(ConfigFile(path=raw, template="x"),))
        with pytest.raises(UnresolvedReference, match="run input"):
            render_files(cfg, FACTS)
    # a sibling under /tmp resolves fine
    ok = ConfigurationSpec(files=(
        ConfigFile(path="${workspace.tmp}/other", template="y"),))
    assert render_files(ok, FACTS)
