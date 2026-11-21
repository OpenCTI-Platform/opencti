from unittest.mock import MagicMock, patch

import pytest

from pycti.connector.opencti_connector_helper import (
    ConnectorInfo,
    ListenQueue,
    OpenCTIConnectorHelper,
    _split_listen_callback_result,
)

API_ERROR = {
    "code": "QUOTA_EXCEEDED",
    "message": "Enrichment API quota exhausted",
    "criticity": 3,
}
WORK_ID = "work-123"
ENTITY_ID = "indicator--5a3e6a3d-7f1c-4b1e-9a43-1d0f3f3e6c11"


def _build_helper(connect_type="INTERNAL_IMPORT_FILE") -> OpenCTIConnectorHelper:
    """Build a helper with only what ListenQueue._data_handler needs, without connecting to the platform."""
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connector_info = ConnectorInfo()
    helper.connector_info._clear_errors_once_sent = True
    helper.connector_logger = MagicMock()
    helper.metric = MagicMock()
    helper.api = MagicMock()
    helper.api_impersonate = MagicMock()
    helper.connect_type = connect_type
    return helper


def _handle(helper, callback):
    """Run ListenQueue._data_handler on one message with the given callback."""
    listen_queue = ListenQueue.__new__(ListenQueue)
    listen_queue.helper = helper
    listen_queue.callback = callback
    listen_queue.connector_applicant_id = "connector-applicant"
    json_data = {
        "event": {"entity_id": ENTITY_ID, "entity_type": "Indicator"},
        "internal": {"work_id": WORK_ID, "draft_id": "", "applicant_id": None},
    }
    with patch.object(listen_queue, "_set_draft_id"):
        listen_queue._data_handler(json_data)


# region result split


@pytest.mark.parametrize(
    "result, expected",
    [
        ("done", ("done", None)),
        (None, (None, None)),
        (("done", [API_ERROR]), ("done", [API_ERROR])),
        (("done", None), ("done", None)),
        (["a", "b"], (["a", "b"], None)),
        (("a", "b", "c"), (("a", "b", "c"), None)),
    ],
    ids=["str", "none", "pair", "pair-without-errors", "list", "triple"],
)
def test_split_listen_callback_result(result, expected):
    assert _split_listen_callback_result(result) == expected


# endregion

# region work and errors


def test_reported_errors_close_the_work_in_error():
    helper = _build_helper()
    _handle(helper, lambda event: ("Quota exhausted", [API_ERROR]))
    helper.api.work.to_processed.assert_called_once_with(
        WORK_ID, "Quota exhausted", in_error=True
    )
    assert helper.connector_info.all_details["errors"] == [API_ERROR]


@pytest.mark.parametrize(
    "result", ["done", None, ("done", []), ("done", None)], ids=str
)
def test_no_error_returned_closes_the_work_and_reports_an_empty_list(result):
    helper = _build_helper()
    _handle(helper, lambda event: result)
    message = result[0] if isinstance(result, tuple) else result
    helper.api.work.to_processed.assert_called_once_with(
        WORK_ID, message, in_error=False
    )
    assert helper.connector_info.all_details["errors"] == []


def test_only_malformed_errors_do_not_close_the_work_in_error():
    helper = _build_helper()
    _handle(helper, lambda event: ("done", [{"code": "BAD", "criticity": "high"}]))
    helper.api.work.to_processed.assert_called_once_with(
        WORK_ID, "done", in_error=False
    )
    message, _ = helper.connector_logger.warning.call_args.args
    assert message == "Malformed error response from the connector"


def test_errors_build_up_across_messages():
    helper = _build_helper()
    other_error = {"code": "API_UNREACHABLE", "message": "503", "criticity": 2}
    _handle(helper, lambda event: ("first", [API_ERROR]))
    _handle(helper, lambda event: "second")
    _handle(helper, lambda event: ("third", [other_error]))
    assert helper.connector_info.all_details["errors"] == [API_ERROR, other_error]


def test_errors_are_kept_when_closing_the_work_fails():
    helper = _build_helper()
    helper.api.work.to_processed.side_effect = [ConnectionError("down"), None]
    _handle(helper, lambda event: ("Quota exhausted", [API_ERROR]))
    assert helper.connector_info.errors == [API_ERROR]


def test_raising_callback_still_closes_the_work_in_error_without_reporting():
    helper = _build_helper()

    def failing_callback(event):
        raise ValueError("boom")

    _handle(helper, failing_callback)
    helper.api.work.to_processed.assert_called_once_with(WORK_ID, "boom", True)
    assert "errors" not in helper.connector_info.all_details


def test_enrichment_callback_reports_errors():
    helper = _build_helper("INTERNAL_ENRICHMENT")
    opencti_entity = {"id": "internal-id", "standard_id": ENTITY_ID}
    helper.api.stix2.get_reader.return_value = lambda **kwargs: opencti_entity
    helper.api.stix2.prepare_export.return_value = [
        {"id": ENTITY_ID, "type": "indicator"}
    ]
    received = {}

    def enrichment_callback(event):
        received.update(event)
        return "Quota exhausted", [API_ERROR]

    _handle(helper, enrichment_callback)
    assert received["enrichment_entity"] == opencti_entity
    helper.api.work.to_processed.assert_called_once_with(
        WORK_ID, "Quota exhausted", in_error=True
    )
    assert helper.connector_info.all_details["errors"] == [API_ERROR]


# endregion


def test_listen_enables_clearing_errors_once_sent():
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connector_info = ConnectorInfo()
    for name in [
        "opencti_token",
        "config",
        "connector_config",
        "applicant_id",
        "listen_protocol",
        "listen_protocol_api_ssl",
        "listen_protocol_api_path",
        "listen_protocol_api_port",
    ]:
        setattr(helper, name, None)
    with patch("pycti.connector.opencti_connector_helper.ListenQueue"):
        helper.listen(lambda event: "done")
    assert helper.connector_info._clear_errors_once_sent is True
