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
    return helper.connector_info.errors


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


def _run_errors_logs(helper: OpenCTIConnectorHelper) -> list:
    return [
        call.args
        for call in helper.connector_logger.info.call_args_list
        if call.args[0] == "Errors reported by the connector run"
    ]


def test_valid_errors_are_logged_once_per_run():
    helper = _run([API_ERROR, RATE_ERROR])
    assert _run_errors_logs(helper) == [
        ("Errors reported by the connector run", {"errors": [API_ERROR, RATE_ERROR]})
    ]


@pytest.mark.parametrize(
    "callback_result",
    [None, [], ["oops"]],
    ids=["none", "empty-list", "only-malformed"],
)
def test_no_errors_log_without_valid_errors(callback_result):
    helper = _run(callback_result)
    assert _run_errors_logs(helper) == []


def _run_with_add_error(callback_result) -> OpenCTIConnectorHelper:
    helper = _build_helper()

    def process():
        helper.connector_info.add_error(**API_ERROR)
        return callback_result

    helper.schedule_process(process, duration_period=60)
    helper.metric.inc.assert_not_called()
    return helper


def test_errors_added_during_the_run_are_kept():
    helper = _run_with_add_error(None)
    assert helper.connector_info.errors == [API_ERROR]


def test_errors_added_during_the_run_are_kept_with_returned_ones():
    helper = _run_with_add_error([RATE_ERROR])
    assert helper.connector_info.errors == [API_ERROR, RATE_ERROR]


def test_errors_from_the_previous_run_are_dropped():
    helper = _run_with_add_error([RATE_ERROR])
    assert PREVIOUS_RUN_ERROR not in helper.connector_info.errors


def test_returned_errors_are_sent_on_ping():
    helper = _run([RATE_ERROR, API_ERROR])
    assert helper.connector_info.all_details["errors"] == [API_ERROR, RATE_ERROR]


def test_errors_added_during_the_run_are_logged_with_returned_ones():
    helper = _run_with_add_error([RATE_ERROR])
    assert _run_errors_logs(helper) == [
        ("Errors reported by the connector run", {"errors": [API_ERROR, RATE_ERROR]})
    ]


def _run_later(process) -> OpenCTIConnectorHelper:
    helper = _build_helper()
    helper._schedule_process(MagicMock(), process, 60)
    helper.metric.inc.assert_not_called()
    return helper


def test_later_runs_replace_errors_with_returned_ones():
    helper = _run_later(lambda: [RATE_ERROR])
    assert helper.connector_info.errors == [RATE_ERROR]
    assert _run_errors_logs(helper) == [
        ("Errors reported by the connector run", {"errors": [RATE_ERROR]})
    ]


def test_later_runs_without_errors_clear_previous_ones():
    helper = _run_later(lambda: None)
    assert helper.connector_info.errors == []
    assert _run_errors_logs(helper) == []


def test_later_runs_keep_errors_added_during_the_run():
    helper = _build_helper()

    def process():
        helper.connector_info.add_error(**API_ERROR)

    helper._schedule_process(MagicMock(), process, 60)
    assert helper.connector_info.errors == [API_ERROR]


def test_buffering_skips_the_run_and_keeps_previous_errors():
    helper = _build_helper()
    helper.check_connector_buffering.return_value = True
    process = MagicMock(return_value=[RATE_ERROR])
    helper._schedule_process(MagicMock(), process, 60)
    process.assert_not_called()
    assert helper.connector_info.errors == [PREVIOUS_RUN_ERROR]


def _run_and_terminate(process, run_and_terminate=True, duration_period=60):
    helper = _build_helper()
    helper.connect_run_and_terminate = run_and_terminate
    sent_on_force_ping = []
    helper.force_ping = MagicMock(
        side_effect=lambda: sent_on_force_ping.append(
            helper.connector_info.all_details.get("errors")
        )
    )
    # A zero duration without run_and_terminate swallows the SystemExit in schedule_process
    try:
        helper.schedule_process(process, duration_period=duration_period)
    except SystemExit:
        pass
    return helper, sent_on_force_ping


@pytest.mark.parametrize(
    "run_and_terminate, duration_period",
    [(True, 60), (False, 0)],
    ids=["run-and-terminate", "zero-duration"],
)
def test_run_and_terminate_sends_returned_errors_on_final_ping(
    run_and_terminate, duration_period
):
    helper, sent_on_force_ping = _run_and_terminate(
        lambda: [RATE_ERROR, API_ERROR], run_and_terminate, duration_period
    )
    assert helper.connector_info.errors == [RATE_ERROR, API_ERROR]
    assert sent_on_force_ping[0] == [API_ERROR, RATE_ERROR]
    assert _run_errors_logs(helper) == [
        ("Errors reported by the connector run", {"errors": [RATE_ERROR, API_ERROR]})
    ]


def test_run_and_terminate_keeps_errors_added_during_the_run():
    helper = _build_helper()

    def process():
        helper.connector_info.add_error(**API_ERROR)

    helper.connect_run_and_terminate = True
    helper.force_ping = MagicMock()
    with pytest.raises(SystemExit):
        helper.schedule_process(process, duration_period=60)
    assert helper.connector_info.errors == [API_ERROR]


def test_run_and_terminate_without_errors_sends_none():
    helper, sent_on_force_ping = _run_and_terminate(lambda: None)
    assert helper.connector_info.errors == []
    assert sent_on_force_ping[0] is None


def test_run_and_terminate_buffering_skips_the_run():
    helper = _build_helper()
    helper.connect_run_and_terminate = True
    helper.check_connector_buffering.return_value = True
    helper.force_ping = MagicMock()
    process = MagicMock(return_value=[RATE_ERROR])
    with pytest.raises(SystemExit):
        helper.schedule_process(process, duration_period=60)
    process.assert_not_called()
    assert helper.connector_info.errors == [PREVIOUS_RUN_ERROR]
