"""The managed-tool scheme rules on the two tool-partition paths.

F-01's fix carries the reach_url scheme end to end and refuses a plaintext
managed tool in production (the delegated token may not ride plaintext). These
tests pin that on the mcp.json path (`gateway.split_tools`), which had no
coverage of its own -- the registry path is covered in
`test_registry_consumption.py`. Both paths must agree on the scheme rule even
though they differ in loudness (manifest withholds one tool; a registry
resolution is unlaunchable), so a regression on either is caught.
"""
from __future__ import annotations

import pytest

from andyur import config
from andyur.runner import gateway


def _mcp(url: str) -> dict:
    return {"tool": {"type": "http", "url": url, "andyur": {"authority": True}}}


def test_split_tools_carries_the_scheme():
    managed, _ = gateway.split_tools(_mcp("https://tool.internal/mcp"))
    assert managed["tool"]["scheme"] == "https"
    assert managed["tool"]["port"] == 443
    managed, _ = gateway.split_tools(_mcp("http://tool.internal:8080/mcp"))
    assert managed["tool"]["scheme"] == "http"


def test_split_tools_withholds_a_plaintext_managed_tool_in_prod(monkeypatch):
    """The manifest path's counterpart to the registry PROD-http refusal. It
    WITHHOLDS the single tool (log + drop) rather than aborting the launch,
    matching split_tools' contract for every other unusable tool; the run then
    proceeds without it rather than calling it with a token over plaintext."""
    monkeypatch.setattr(config, "PROD", True)
    managed, passthrough = gateway.split_tools(_mcp("http://tool.internal/mcp"))
    assert managed == {}
    assert "tool" not in passthrough  # withheld, NOT downgraded to passthrough


def test_split_tools_accepts_an_https_managed_tool_in_prod(monkeypatch):
    """Positive control: PROD + https is honoured, so the refusal above is the
    scheme rule firing, not the check refusing everything."""
    monkeypatch.setattr(config, "PROD", True)
    managed, _ = gateway.split_tools(_mcp("https://tool.internal/mcp"))
    assert managed["tool"]["scheme"] == "https"


def test_split_url_refuses_an_ipv6_literal():
    """An IPv6-literal host rebuilds to a malformed `scheme://::1:port/path`;
    it is refused as a named withhold rather than emitted and failed deep in
    httpx. Positive control: the same host as a name is accepted."""
    assert gateway._split_url("http://[::1]:8080/mcp") is None
    assert gateway._split_url("http://ipv6-host:8080/mcp") == (
        "http", "ipv6-host", 8080, "/mcp")
