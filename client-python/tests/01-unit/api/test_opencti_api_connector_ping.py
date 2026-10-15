from unittest.mock import MagicMock

import pytest
import requests

from pycti import OpenCTIApiConnector

PING_RESULT = {
    "data": {"pingConnector": {"id": "connector-id", "connector_state": None}}
}
CONNECTOR_INFO = {"run_and_terminate": False, "buffering": False}
CONNECTOR_INFO_WITH_ERRORS = {
    **CONNECTOR_INFO,
    "errors": [{"code": "API_UNREACHABLE", "message": "", "criticity": "HIGH"}],
}


def sent_connector_info(api, call_index):
    return api.query.call_args_list[call_index].args[1]["connectorInfo"]


def test_ping_does_not_select_errors_in_response():
    api = MagicMock()
    api.query.return_value = PING_RESULT
    OpenCTIApiConnector(api).ping("connector-id", {}, CONNECTOR_INFO)
    query = api.query.call_args.args[0]
    assert "errors" not in query


def test_ping_retries_without_errors_when_platform_rejects_them():
    api = MagicMock()
    api.query.side_effect = [ValueError("Field errors is not defined"), PING_RESULT]

    result = OpenCTIApiConnector(api).ping(
        "connector-id", {}, CONNECTOR_INFO_WITH_ERRORS
    )

    assert result == PING_RESULT["data"]["pingConnector"]
    assert api.query.call_count == 2
    assert sent_connector_info(api, 0) == CONNECTOR_INFO_WITH_ERRORS
    assert sent_connector_info(api, 1) == CONNECTOR_INFO
    api.app_logger.warning.assert_called_once()


def test_ping_raises_when_retry_without_errors_also_fails():
    api = MagicMock()
    api.query.side_effect = [ValueError("rejected"), ValueError("still rejected")]

    with pytest.raises(ValueError, match="still rejected"):
        OpenCTIApiConnector(api).ping("connector-id", {}, CONNECTOR_INFO_WITH_ERRORS)
    assert api.query.call_count == 2


@pytest.mark.parametrize("connector_info", [CONNECTOR_INFO, None])
def test_ping_does_not_retry_without_errors_to_remove(connector_info):
    api = MagicMock()
    api.query.side_effect = ValueError("rejected")

    with pytest.raises(ValueError):
        OpenCTIApiConnector(api).ping("connector-id", {}, connector_info)
    assert api.query.call_count == 1


def test_ping_does_not_retry_on_network_error():
    api = MagicMock()
    api.query.side_effect = requests.exceptions.ConnectionError("unreachable")

    with pytest.raises(requests.exceptions.ConnectionError):
        OpenCTIApiConnector(api).ping("connector-id", {}, CONNECTOR_INFO_WITH_ERRORS)
    assert api.query.call_count == 1
