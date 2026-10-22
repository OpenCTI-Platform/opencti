import json
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
    "errors": [{"code": "API_UNREACHABLE", "message": "", "criticity": 2}],
}


GRAPHQL_16_REJECTION = (
    'Variable "$connectorInfo" got invalid value { errors: [] }; '
    'Field "errors" is not defined by type "ConnectorInfoInput".'
)
GRAPHQL_17_REJECTION = (
    'Variable "$connectorInfo" has invalid value: Expected value of type '
    '"ConnectorInfoInput" not to include unknown field "errors", found: { errors: [] }.'
)


def graphql_error(message):
    # As raised by OpenCTIApiClient.query on a 200 response carrying GraphQL errors
    return ValueError({"name": "BAD_USER_INPUT", "error_message": message})


def http_error(message):
    # As raised by OpenCTIApiClient.query on any other status: the raw JSON body
    return ValueError(json.dumps({"errors": [{"message": message}]}))


def sent_connector_info(api, call_index):
    return api.query.call_args_list[call_index].args[1]["connectorInfo"]


def test_ping_does_not_select_errors_in_response():
    api = MagicMock()
    api.query.return_value = PING_RESULT
    OpenCTIApiConnector(api).ping("connector-id", {}, CONNECTOR_INFO)
    query = api.query.call_args.args[0]
    assert "errors" not in query


@pytest.mark.parametrize(
    "rejection",
    [
        graphql_error(GRAPHQL_16_REJECTION),
        graphql_error(GRAPHQL_17_REJECTION),
        http_error(GRAPHQL_16_REJECTION),
        http_error(GRAPHQL_17_REJECTION),
    ],
    ids=["graphql16", "graphql17", "graphql16-http-body", "graphql17-http-body"],
)
def test_ping_retries_without_errors_when_platform_rejects_them(rejection):
    api = MagicMock()
    api.query.side_effect = [rejection, PING_RESULT]

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
    api.query.side_effect = [
        graphql_error(GRAPHQL_16_REJECTION),
        ValueError("still rejected"),
    ]

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


@pytest.mark.parametrize(
    "failure",
    [
        http_error("Bad gateway"),
        ValueError("<html><body>502 Bad Gateway</body></html>"),
        graphql_error("No connector found with the specified ID"),
        graphql_error(
            'Variable "$connectorInfo" got invalid value { }; '
            'Field "buffering" of required type "Boolean!" was not provided.'
        ),
    ],
    ids=["http-error", "html-error-page", "graphql-error", "other-input-field"],
)
def test_ping_does_not_drop_errors_on_unrelated_failure(failure):
    api = MagicMock()
    api.query.side_effect = [failure, PING_RESULT]

    with pytest.raises(ValueError):
        OpenCTIApiConnector(api).ping("connector-id", {}, CONNECTOR_INFO_WITH_ERRORS)
    assert api.query.call_count == 1
    api.app_logger.warning.assert_not_called()
