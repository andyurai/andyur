"""The shipped SOC bundle, asserted as a thing somebody else will install.

test_agent_bundles.py covers the registry mechanism. These pin the CONTENT:
what the three agents may do, and that two of them can do nothing at all to the
outside world.

THE TOOL NAMES ARE THE POINT OF HALF THIS FILE. An earlier version of this
bundle invented them -- `search_alerts`, `detonate`, `create_case` -- and every
one validated cleanly, because the registry checks a grant against the agent's
ceiling and cannot know whether a remote server has a tool by that name. It
would have failed on its first tool call. So each name below is asserted
against the server's own published inventory, and a test that pins a name is
cheap insurance against the same mistake being made again by someone reading
the neighbouring files for the pattern.
"""

import json
import pathlib

import pytest

from andyur.registry.manifest_registry import ManifestAgentRegistry

BUNDLES = pathlib.Path(__file__).resolve().parents[1] / "demos" / "bundles"

# The one action in this bundle that changes anything outside Andyur. It is a
# PLATFORM action, served by the run's own tool service, not by any MCP server
# named here -- which is why it appears in a ceiling with no tool binding.
CONSEQUENTIAL = "deployments:rollback:with-approval"

# Read off each server's own documentation, not guessed.
PUBLISHED = {
    "osv": {"query_vulnerability", "query_vulnerabilities_batch",
            "get_vulnerability"},
    "cases": {"get_thehive_alerts", "get_thehive_alert_by_id",
              "get_thehive_cases", "get_thehive_case_by_id",
              "create_thehive_case", "promote_alert_to_case"},
}

# Wazuh's inventory is not typed out here. It is READ FROM THE RECORDING, which
# captured `tools/list` from the running server -- so the bundle is checked
# against evidence rather than against my transcription of a README. That
# transcription is precisely how a `get_wazuh_running_agents` that does not
# exist got into this bundle; the real tool is `get_wazuh_agents`.
RECORDING = json.loads(
    (BUNDLES / "soc" / "fixtures" / "wazuh.recorded.json").read_text())
PUBLISHED["wazuh"] = set(RECORDING["published_tools"])


@pytest.fixture(scope="module")
def soc():
    registry = ManifestAgentRegistry(BUNDLES)
    return {a.name: a for a in registry.list_agents() if a.bundle == "soc"}


def test_the_bundle_ships_the_three_agents_with_a_working_server(soc):
    """Three, not six. Hunt, search and malware were dropped: no Sigma or
    ATT&CK MCP server exists, and Cortex's MCP analyses OBSERVABLES only -- no
    file analysis, no detonation -- so the malware agent had no backing at all.
    Shipping them would have been shipping four agents that cannot run."""
    assert set(soc) == {"soc-triage", "soc-response", "soc-exposure"}


def test_every_granted_tool_is_one_its_server_actually_publishes(soc):
    """The mistake this bundle already made once. The registry cannot catch it:
    it validates a grant against the ceiling, never against the remote server."""
    for name, agent in soc.items():
        for binding in agent.tools:
            published = PUBLISHED[binding.name]
            granted = {grant.name for grant in binding.mcp_tools or ()}
            assert granted <= published, (
                f"{name} grants {sorted(granted - published)} on "
                f"{binding.name!r}, which that server does not publish")


def test_exactly_one_agent_can_change_anything(soc):
    """Five-sixths of the earlier bundle, two-thirds of this one, hold no
    authority to act. If an edit hands another agent a consequential action,
    this names it."""
    holders = sorted(name for name, a in soc.items()
                     if CONSEQUENTIAL in (a.ceiling.actions or ()))
    assert holders == ["soc-response"]


def test_the_rollback_is_a_platform_action_with_no_tool_binding(soc):
    """It is served by the run's own tool service, so it reaches no server in
    this bundle. An agent needs the ACTION, never a binding -- and a ceiling
    resource for it would name a resource nothing here declares."""
    response = soc["soc-response"]
    assert CONSEQUENTIAL in response.ceiling.actions
    assert {t.name for t in response.tools} == {"cases"}
    assert set(response.ceiling.resources) == {"resource:cases"}


def test_the_read_only_agents_hold_only_read_shaped_actions(soc):
    expected = {
        "soc-triage": {"cases:read", "alerts:read"},
        "soc-exposure": {"vulns:read"},
    }
    for name, actions in expected.items():
        assert set(soc[name].ceiling.actions) == actions, name


def test_no_agent_holds_an_unrestricted_ceiling(soc):
    for name, agent in soc.items():
        assert agent.ceiling.actions is not None, f"{name} has an open ceiling"
        assert "*" not in agent.ceiling.actions, f"{name} holds a wildcard"


def test_every_agent_states_its_prerequisites(soc):
    """A bundle is installed by somebody who did not write it. Two of these
    three servers speak stdio and need a bridge, and the OSV one needs a
    non-default transport -- none of which is guessable from a port number."""
    for name, agent in soc.items():
        assert agent.card is not None, f"{name} ships without a card"
        assert agent.card.summary and agent.card.category, name
        assert agent.card.requires, f"{name} states no prerequisites"


def test_the_exposure_agent_does_not_promise_exploitation_ranking(soc):
    """OSV records advisories and affected ranges. It carries no KEV membership
    and no EPSS score, and an earlier version of these instructions told the
    agent to rank by real-world exploitation anyway -- asking for a judgement
    its only tool cannot supply. The instructions now say so out loud, and this
    keeps them saying it."""
    instructions = soc["soc-exposure"].instructions.lower()
    assert "does not tell you whether anything is being exploited" in instructions
    assert "do not rank by real-world risk" in instructions


def test_each_ceiling_is_covered_by_the_agents_own_tools(soc):
    """A ceiling RESOURCE nothing reaches is authority that can never be used
    and reads to a reviewer as though it can. Actions are exempt: a platform
    action legitimately has no binding."""
    for name, agent in soc.items():
        reachable = {tool.resource_id for tool in agent.tools}
        assert set(agent.ceiling.resources or ()) <= reachable, name


def test_no_agent_pins_a_model(soc):
    for name, agent in soc.items():
        assert agent.model is None, f"{name} pins a model"


def test_the_bundle_states_the_deployment_shape_it_needs(soc):
    """A bundle is installed by somebody who did not write it, and `managed`
    tools do not work under just any control plane. What they need is the shape
    the other registry agents already run under and `./run.sh sre-demo` builds:
    dev profile, agent-auth on, containerised runs."""
    for name, agent in soc.items():
        stated = " ".join(agent.card.requires).lower()
        assert "andyur_agent_auth=on" in stated, f"{name} omits the agent-auth need"
        assert "dev-profile" in stated, f"{name} omits the profile it needs"


def test_reach_urls_follow_the_convention_the_shipped_agents_use(soc):
    """`http://host.docker.internal:<port>/mcp`, the same as
    demos/agent-registry/oncall-ollama.json.

    This churned three times before landing back here, and the reason it is
    right is worth keeping: under the dev profile the runner rewrites host-local
    URLs to the host gateway, and the tool servers run on the operator's
    machine. https and a run-network name are what a PRODUCTION profile needs
    (see tls_front.py) -- not this path, and shipping them here made the bundle
    unrunnable under the deployment it is actually meant for.
    """
    for name, agent in soc.items():
        for tool in agent.tools:
            assert tool.reach_url.startswith("http://host.docker.internal:"), (
                f"{name} tool {tool.name!r} is {tool.reach_url}, not the "
                "convention demos/agent-registry uses")
