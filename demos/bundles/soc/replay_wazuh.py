#!/usr/bin/env python3
"""Replay recorded Wazuh MCP responses, so soc-triage runs without a SIEM.

WHY A RECORDING AND NOT A SIMULATOR. The responses in
`fixtures/wazuh.recorded.json` were captured from gbrigandi/mcp-server-wazuh
v0.3.0 driven over stdio against a real wazuh-docker single-node v4.14.0. That
provenance is the whole value. A fake whose payloads I had written by hand would
pass against agents I had also written and prove nothing -- which is exactly the
failure that put an invented `get_wazuh_running_agents` into this bundle in the
first place, from a README summary rather than the server.

WHAT THIS IS HONEST ABOUT:

  * It serves ONLY the tools it has recordings for. Advertising the other nine
    the real server publishes and then erroring would be worse than not
    advertising them.
  * It IGNORES arguments. There is one recorded response per tool, and it is
    returned whatever you pass. The tool descriptions say so, in the text the
    model actually reads, because an agent that believes it filtered by
    `agent_id` and did not would draw conclusions from the wrong host.
  * It says it is a fixture, in every description, for the same reason.

Run it:  python demos/bundles/soc/replay_wazuh.py [--port 8811]
"""
from __future__ import annotations

import argparse
import json
import pathlib

from mcp.server.fastmcp import FastMCP

HERE = pathlib.Path(__file__).resolve().parent
RECORDING = HERE / "fixtures" / "wazuh.recorded.json"


def load_recording(path: pathlib.Path = RECORDING) -> dict:
    data = json.loads(path.read_text())
    if data.get("schema") != "andyur.recorded-mcp/v1":
        raise SystemExit(f"{path}: not an andyur.recorded-mcp/v1 recording")
    if not data.get("responses"):
        raise SystemExit(f"{path}: recording contains no responses")
    return data


def response_text(recording: dict, tool: str) -> str:
    """The recorded text for one tool, joined as the server returned it."""
    entry = recording["responses"][tool]
    return "\n".join(block["text"] for block in entry["content"])


def describe(recording: dict, tool: str) -> str:
    """What the model is told. It must know this is a fixture and that its
    arguments are not honoured -- otherwise it reasons about a filter it did
    not actually apply."""
    src = recording["recorded_from"]
    args = recording["responses"][tool]["arguments"]
    return (
        f"[RECORDED FIXTURE - not live data] {tool} as captured from "
        f"{src['server']} {src['server_version']} against {src['backend']} "
        f"{src['wazuh_version']}. The recording was taken with arguments "
        f"{json.dumps(args, sort_keys=True)}. Arguments you pass are IGNORED: "
        "this returns that one recorded response every time. Do not describe "
        "the result as filtered by anything you asked for."
    )


_PY_TYPE = {"integer": int, "number": float, "boolean": bool, "string": str}


def _handler(text: str, schema: dict | None):
    """A tool that takes the REAL tool's parameters and ignores them.

    Taking no parameters at all would be simpler and wrong: `soc-triage` calls
    `get_wazuh_agent_ports` with the agent_id, protocol and state its schema
    requires, and a fixture that rejected those would fail for a reason that has
    nothing to do with what is being demonstrated. So the signature is rebuilt
    from the recorded schema — the arguments are accepted, and discarded.
    """
    import inspect

    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or ())

    def handler(**_ignored) -> str:
        return text

    params = []
    for name, spec in props.items():
        annotation = _PY_TYPE.get(spec.get("type"), str)
        if name in required:
            params.append(inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY, annotation=annotation))
        else:
            params.append(inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY,
                annotation=annotation | None, default=None))
    # Required first: a Signature refuses a defaulted parameter before a bare one.
    params.sort(key=lambda p: p.default is not inspect.Parameter.empty)
    handler.__signature__ = inspect.Signature(params, return_annotation=str)
    return handler


def build(recording: dict, port: int) -> FastMCP:
    mcp = FastMCP("wazuh-replay", host="127.0.0.1", port=port)
    schemas = recording.get("input_schemas") or {}

    # Registered from the recording rather than declared here, so the served
    # inventory can never drift from what was actually captured.
    for tool in sorted(recording["responses"]):
        handler = _handler(response_text(recording, tool), schemas.get(tool))
        handler.__name__ = tool
        mcp.add_tool(handler, name=tool, description=describe(recording, tool))
    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8811)
    parser.add_argument("--recording", type=pathlib.Path, default=RECORDING)
    args = parser.parse_args()

    recording = load_recording(args.recording)
    src = recording["recorded_from"]
    served = sorted(recording["responses"])
    print(f"replaying {len(served)} of the {len(recording['published_tools'])} "
          f"tools {src['server']} publishes")
    for tool in served:
        print(f"  {tool}")
    print(f"captured from {src['backend']} {src['wazuh_version']}")
    print(f"serving streamable HTTP on http://127.0.0.1:{args.port}/mcp")
    build(recording, args.port).run(transport="streamable-http")


if __name__ == "__main__":
    main()
