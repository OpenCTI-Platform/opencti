"""Errors of listen() callbacks: run through the CallbackExecutor, reported with the ping."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from pycti.connector import opencti_connector_helper
from pycti.connector.opencti_connector_helper import (
    ConnectorInfo,
    ListenQueue,
    OpenCTIConnectorHelper,
)

QUOTA_ERROR = {
    "code": "QUOTA_EXCEEDED",
    "message": "QuotaError: daily quota exhausted",
    "criticity": 30,
}


class QuotaError(Exception):
    code = "QUOTA_EXCEEDED"
    criticity = 30


def _helper(connect_type="EXTERNAL_IMPORT"):
    helper = MagicMock()
    helper.connect_type = connect_type
    helper.connector_info = ConnectorInfo()
    helper.connector_info.clear_errors_once_sent = True
    return helper


def _listen_queue(helper, callback):
    listen_queue = ListenQueue.__new__(ListenQueue)
    listen_queue.helper = helper
    listen_queue.callback = callback
    listen_queue.connector_applicant_id = "connector-applicant"
    return listen_queue


def _message(work_id="work-1", **event):
    return {
        "event": {"entity_id": "report--1", "entity_type": "Report", **event},
        "internal": {"work_id": work_id, "draft_id": "", "applicant_id": None},
    }


def _process(helper, callback, message=None):
    _listen_queue(helper, callback)._data_handler(message or _message())


def test_a_returned_message_closes_the_work_and_reports_no_error():
    helper = _helper()
    _process(helper, lambda data: "Enrichment done")
    helper.api.work.to_processed.assert_called_once_with("work-1", "Enrichment done")
    assert helper.connector_info.errors == []
    helper.metric.inc.assert_not_called()


@pytest.mark.parametrize("returned", [None, ["not", "errors"], {"code": "X"}])
def test_the_returned_value_is_still_the_work_message(returned):
    helper = _helper()
    _process(helper, lambda data: returned)
    helper.api.work.to_processed.assert_called_once_with("work-1", returned)
    assert helper.connector_info.errors == []
    helper.connector_logger.warning.assert_not_called()


def test_a_raised_exception_closes_the_work_in_error_and_is_reported():
    helper = _helper()

    def callback(data):
        raise ValueError("bad value")

    _process(helper, callback)

    helper.api.work.to_processed.assert_called_once_with("work-1", "bad value", True)
    assert helper.connector_info.errors == [
        {"code": "other.unknown", "message": "ValueError: bad value", "criticity": 50}
    ]
    # Counted once, by the listen handler
    helper.metric.inc.assert_called_once_with("error_count")
    helper.api.set_draft_id.assert_called_with("")


def test_an_exception_with_a_code_and_a_criticity_is_reported_with_them():
    helper = _helper()

    def callback(data):
        raise QuotaError("daily quota exhausted")

    _process(helper, callback)
    assert helper.connector_info.errors == [QUOTA_ERROR]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="ExceptionGroup is 3.11+")
def test_an_exception_group_is_reported_as_one_error_per_exception():
    helper = _helper()

    def callback(data):
        raise ExceptionGroup(  # noqa: F821
            "several failures",
            [QuotaError("daily quota exhausted"), KeyError("indicator")],
        )

    _process(helper, callback)
    assert helper.connector_info.errors == [
        QUOTA_ERROR,
        {"code": "other.unknown", "message": "KeyError: 'indicator'", "criticity": 50},
    ]


def test_errors_of_successive_messages_accumulate_until_a_ping_sends_them():
    helper = _helper()

    def failing(data):
        raise QuotaError("daily quota exhausted")

    def adding_an_error(data):
        helper.connector_info.add_error("PARTIAL", "2 observables skipped", 10)
        return "done with warnings"

    _process(helper, failing, _message("work-1"))
    _process(helper, adding_an_error, _message("work-2"))
    _process(helper, lambda data: "done", _message("work-3"))

    assert helper.connector_info.errors == [
        QUOTA_ERROR,
        {"code": "PARTIAL", "message": "2 observables skipped", "criticity": 10},
    ]


def test_a_repeated_error_takes_a_single_slot():
    helper = _helper()

    def failing(data):
        raise QuotaError("daily quota exhausted")

    for index in range(50):
        _process(helper, failing, _message(f"work-{index}"))
    assert helper.connector_info.errors == [QUOTA_ERROR]


def test_a_failure_before_the_callback_is_not_a_connector_error():
    helper = _helper(connect_type="INTERNAL_ENRICHMENT")
    callback = MagicMock()

    _process(helper, callback, _message(entity_id=None))

    callback.assert_not_called()
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Internal enrichment must be based on a specific id", True
    )
    assert helper.connector_info.errors == []
    helper.metric.inc.assert_called_once_with("error_count")


def test_a_failing_to_processed_after_a_raised_exception_keeps_the_error():
    helper = _helper()
    helper.api.work.to_processed.side_effect = ConnectionError("platform down")

    def callback(data):
        raise QuotaError("daily quota exhausted")

    _process(helper, callback)
    assert helper.connector_info.errors == [QUOTA_ERROR]


def test_listen_clears_the_errors_once_sent():
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connector_info = ConnectorInfo()
    for attribute in [
        "opencti_token",
        "config",
        "connector_config",
        "applicant_id",
        "listen_protocol",
        "listen_protocol_api_ssl",
        "listen_protocol_api_path",
        "listen_protocol_api_port",
    ]:
        setattr(helper, attribute, None)

    with patch.object(opencti_connector_helper, "ListenQueue"):
        helper.listen(lambda data: "done")

    assert helper.connector_info.clear_errors_once_sent is True
