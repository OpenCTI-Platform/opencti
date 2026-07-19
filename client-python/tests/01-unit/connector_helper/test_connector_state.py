import json

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


def _helper_with_state(state):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.connector_state = state
    return helper


def test_connector_state_returns_isolated_snapshots():
    helper = _helper_with_state(None)
    original = {"start_from": "1-0", "cursor": {"sequence": 1}}

    helper.set_state(original)
    original["cursor"]["sequence"] = 99
    first_read = helper.get_state()
    first_read["cursor"]["sequence"] = 42

    assert helper.get_state() == {"start_from": "1-0", "cursor": {"sequence": 1}}


def test_connector_state_normalizes_remote_json_strings():
    helper = _helper_with_state(json.dumps({"start_from": "2-0"}))

    assert helper.get_state() == {"start_from": "2-0"}

    helper.set_state(json.dumps({"start_from": "3-0"}))
    assert helper.get_state() == {"start_from": "3-0"}
