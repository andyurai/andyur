"""Keep the accepted egress architecture from reversing again."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _doc(rel: str) -> str:
    """Published copy, else the internal one, else skip. Same rule as the
    governance docs test: these pointers are still enforced where the documents
    exist, and absent documents are a skip with a reason, not a failure."""
    published = ROOT / rel
    if published.is_file():
        return published.read_text()
    internal = ROOT.parent / "docs-internal" / Path(rel).name
    if internal.is_file():
        return internal.read_text()
    pytest.skip(f"{rel} is an internal document and is absent here")


def test_accepted_topology_has_distinct_tool_and_model_paths():
    adr = (ROOT / "docs/adr-003-egress-topology.md").read_text()
    assert "per-run Andyur sidecar" in adr
    assert "shared LiteLLM" in adr
    assert "audience = manifest resource_id" in adr
    assert "route = manifest reach_url" in adr
    assert "agentgateway is not on either target data path" in adr
    assert "No Andyur protocol adapter sits in front of LiteLLM" in adr


def test_public_entrypoints_link_to_the_accepted_topology():
    readme = (ROOT / "README.md").read_text()
    components = (ROOT / "docs/replaceable-components.md").read_text()
    historical = _doc("infra/agentgateway/README.md")
    assert "ADR 003" in readme
    assert "Shared LLM gateway" in components
    assert "pinned LiteLLM 1.95.0" in components
    assert "Historical measurement, not the current architecture" in historical
    for path in (
        "docs/container-split-plan.md",
        "docs/sre-demo-complete-plan.md",
        "docs/authority-architecture.md",
    ):
        assert "ADR 003" in _doc(path), path
