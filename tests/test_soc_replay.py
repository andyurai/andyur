"""The recorded Wazuh fixture, and the server that replays it.

The fixture exists so `soc-triage` can be run without standing up a SIEM. Its
value is entirely in its PROVENANCE: the payloads were captured from
gbrigandi/mcp-server-wazuh v0.3.0, driven over stdio against a real
wazuh-docker single-node v4.14.0, with alerts produced by Wazuh's own ruleset.

A fixture I had written by hand would pass against agents I had also written
and prove nothing -- which is exactly how an invented `get_wazuh_running_agents`
reached this bundle, transcribed from a README summary rather than read off the
server. So these tests are mostly about the recording remaining honest: that it
says where it came from, that it is not quietly editable into fiction, and that
the replay tells the model it is a fixture.
"""

import json
import pathlib

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1] / "demos" / "bundles" / "soc"
RECORDING_PATH = BUNDLE / "fixtures" / "wazuh.recorded.json"

# Imported by path: demos/ is not a package on the import path.
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "soc_replay_wazuh", BUNDLE / "replay_wazuh.py")
replay_wazuh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay_wazuh)


@pytest.fixture(scope="module")
def recording():
    return json.loads(RECORDING_PATH.read_text())


def test_the_recording_says_exactly_what_produced_it(recording):
    """Provenance is the whole value. A fixture that cannot name its source is
    indistinguishable from an invented one the moment anybody doubts it."""
    src = recording["recorded_from"]
    assert recording["schema"] == "andyur.recorded-mcp/v1"
    assert src["server"] == "gbrigandi/mcp-server-wazuh"
    assert src["server_version"].startswith("v")
    assert src["wazuh_version"].startswith("v")
    assert src["backend"] and src["transport_recorded_over"]


def test_it_records_the_whole_published_inventory_not_just_what_was_called(recording):
    """`published_tools` is a capture of tools/list, and it is what
    test_soc_bundle checks the bundle's grants against. If it only listed the
    tools that were called, the bundle could grant a name nobody tried and the
    check would pass by omission."""
    assert len(recording["published_tools"]) > len(recording["responses"])
    assert "get_wazuh_agents" in recording["published_tools"]
    # The name that never existed, asserted absent so its return is loud.
    assert "get_wazuh_running_agents" not in recording["published_tools"]


def test_the_responses_carry_real_wazuh_output(recording):
    """Real means: Wazuh's own rule descriptions, from Wazuh's own ruleset.
    Text that could have been typed from imagination would not carry a rule
    description and an alert id in the format the server emits."""
    alerts = recording["responses"]["get_wazuh_alert_summary"]
    assert alerts["isError"] is False
    text = "\n".join(b["text"] for b in alerts["content"])
    assert "Alert ID:" in text and "Level:" in text and "Description:" in text
    # rule 5710, from Wazuh's shipped ruleset, fired on the injected sequence
    assert "non-existent user" in text


def test_every_recorded_call_names_the_arguments_it_was_taken_with(recording):
    """The replay ignores arguments, so the caller has to be able to find out
    which ones produced the payload it is being handed."""
    for name, entry in recording["responses"].items():
        assert "arguments" in entry, name
        assert isinstance(entry["arguments"], dict), name


def test_the_replay_serves_only_what_it_actually_has(recording):
    """Advertising the other nine and erroring would be worse than not
    advertising them: an agent would plan around a tool that cannot answer."""
    served = replay_wazuh.build(recording, port=0)
    names = {t.name for t in served._tool_manager.list_tools()}
    assert names == set(recording["responses"])
    assert names < set(recording["published_tools"])


def test_the_replay_accepts_the_arguments_the_real_schema_requires(recording):
    """`get_wazuh_agent_ports` requires agent_id, protocol and state. A fixture
    taking no parameters would reject soc-triage's real call and fail for a
    reason that has nothing to do with what is being demonstrated."""
    served = replay_wazuh.build(recording, port=0)
    tool = next(t for t in served._tool_manager.list_tools()
                if t.name == "get_wazuh_agent_ports")
    required = set(tool.parameters.get("required", ()))
    assert {"agent_id", "protocol", "state"} <= required


def test_the_model_is_told_it_is_a_fixture_and_that_arguments_are_ignored(recording):
    """In the description, because that is the text the model reads. An agent
    that believes it filtered by agent_id and did not would draw conclusions
    about the wrong host and have no way to notice."""
    for tool in replay_wazuh.build(recording, port=0)._tool_manager.list_tools():
        assert "RECORDED FIXTURE" in tool.description
        assert "IGNORED" in tool.description
        assert "gbrigandi/mcp-server-wazuh" in tool.description


def test_a_recording_of_the_wrong_schema_is_refused(tmp_path):
    """It is a file on disk that decides what an agent is told. Loading one that
    is not a recording at all should stop, not improvise."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "something-else", "responses": {"a": 1}}))
    with pytest.raises(SystemExit):
        replay_wazuh.load_recording(bad)


def test_an_empty_recording_is_refused(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps(
        {"schema": "andyur.recorded-mcp/v1", "responses": {}}))
    with pytest.raises(SystemExit):
        replay_wazuh.load_recording(empty)


def test_the_bundle_grants_only_tools_the_recording_can_answer():
    """The join between the two halves: every wazuh tool soc-triage is granted
    has a recorded response, so `andyur bundle install` + the replay server is a
    combination that actually runs rather than one that merely validates."""
    recording = json.loads(RECORDING_PATH.read_text())
    triage = json.loads((BUNDLE / "triage.json").read_text())
    granted = {g["name"] for t in triage["tools"] if t["name"] == "wazuh"
               for g in t["mcp_tools"]}
    assert granted <= set(recording["responses"]), (
        f"no recorded response for {sorted(granted - set(recording['responses']))}")
