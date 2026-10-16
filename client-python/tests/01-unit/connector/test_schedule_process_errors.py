from unittest.mock import MagicMock

import pytest

from pycti.connector.opencti_connector_helper import (
    ConnectorInfo,
    OpenCTIConnectorHelper,
)

API_ERROR = {
    "code": "API_UNREACHABLE",
    "message": "Source API returned 503",
    "criticity": 3,
}
RATE_ERROR = {"code": "RATE_LIMITED", "message": "Too many requests", "criticity": 1}
PREVIOUS_RUN_ERROR = {
    "code": "PREVIOUS",
    "message": "From previous run",
    "criticity": 2,
}


def _build_helper() -> OpenCTIConnectorHelper:
    """Build a helper with only what schedule_process needs, without connecting to the platform."""
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connect_run_and_terminate = False
    helper.connector_info = ConnectorInfo(errors=[PREVIOUS_RUN_ERROR])
    helper.connector_logger = MagicMock()
    helper.metric = MagicMock()
    helper.scheduler = MagicMock()
    helper.check_connector_buffering = MagicMock(return_value=False)
    helper.last_run_datetime = MagicMock()
    helper.next_run_datetime = MagicMock()
    return helper


def _run(callback_result) -> OpenCTIConnectorHelper:
    helper = _build_helper()
    helper.schedule_process(lambda: callback_result, duration_period=60)
    # The run must never end in the generic "unexpected error" path
    helper.metric.inc.assert_not_called()
    return helper


def _stored_errors(helper: OpenCTIConnectorHelper) -> list:
    return [error.model_dump() for error in helper.connector_info.errors]


def test_none_result_clears_errors():
    helper = _run(None)
    assert helper.connector_info.errors == []
    helper.connector_logger.error.assert_not_called()


@pytest.mark.parametrize(
    "callback_result",
    [
        "something went wrong",
        b"something went wrong",
        42,
        3.14,
        True,
        API_ERROR,
        object(),
    ],
    ids=["str", "bytes", "int", "float", "bool", "single-dict", "object"],
)
def test_non_list_result_is_handled_like_none(callback_result):
    helper = _run(callback_result)
    assert helper.connector_info.errors == []
    helper.connector_logger.error.assert_not_called()


@pytest.mark.parametrize(
    "malformed_error",
    [
        "something went wrong",
        42,
        None,
        [API_ERROR],
        {},
        {"code": "MISSING_FIELDS"},
        {**API_ERROR, "criticity": "3"},
        {**API_ERROR, "code": 404},
        {**API_ERROR, "criticity": "HIGH"},
        {**API_ERROR, "code": None},
        {**API_ERROR, "message": None},
        {**API_ERROR, "extra": "not allowed"},
    ],
    ids=[
        "str",
        "int",
        "none",
        "nested-list",
        "empty-dict",
        "missing-fields",
        "criticity-as-str",
        "code-as-int",
        "criticity-as-label",
        "code-as-none",
        "message-as-none",
        "extra-field",
    ],
)
def test_list_of_malformed_errors_is_dropped_and_logged(malformed_error):
    helper = _run([malformed_error, malformed_error])
    assert helper.connector_info.errors == []
    assert helper.connector_logger.error.call_count == 2
    message, meta = helper.connector_logger.error.call_args.args
    assert message == "Malformed error response from the connector"
    assert meta["received"] == repr(malformed_error)
    assert meta["reason"]


@pytest.mark.parametrize(
    "callback_result",
    [[], [API_ERROR], [API_ERROR, RATE_ERROR], (API_ERROR, RATE_ERROR)],
    ids=["empty-list", "one-error", "two-errors", "tuple"],
)
def test_list_of_valid_errors_is_stored(callback_result):
    helper = _run(callback_result)
    assert _stored_errors(helper) == list(callback_result)
    helper.connector_logger.error.assert_not_called()


def test_mixed_list_keeps_valid_errors_and_logs_malformed_ones():
    helper = _run([API_ERROR, "oops", RATE_ERROR])
    assert _stored_errors(helper) == [API_ERROR, RATE_ERROR]
    helper.connector_logger.error.assert_called_once()
    assert helper.connector_logger.error.call_args.args[1]["received"] == "'oops'"
