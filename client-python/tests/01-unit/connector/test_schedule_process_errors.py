import sys
from enum import Enum, IntEnum
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
    helper.connector_logger.warning.assert_not_called()


@pytest.mark.parametrize(
    "callback_result",
    [
        "something went wrong",
        b"something went wrong",
        42,
        3.14,
        True,
        object(),
    ],
    ids=["str", "bytes", "int", "float", "bool", "object"],
)
def test_non_list_result_is_handled_like_none(callback_result):
    helper = _run(callback_result)
    assert helper.connector_info.errors == []
    helper.connector_logger.warning.assert_not_called()


def test_single_error_dict_is_ignored_with_a_warning():
    helper = _run(API_ERROR)
    assert helper.connector_info.errors == []
    helper.connector_logger.warning.assert_called_once()
    message, meta = helper.connector_logger.warning.call_args.args
    assert message == "Connector run returned a single error instead of a list, ignored"
    assert meta["received"] == repr(API_ERROR)


def test_run_without_errors_sends_an_empty_list():
    helper = _run(None)
    assert helper.connector_info.all_details["errors"] == []


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
        {**API_ERROR, "criticity": 2**31},
        {**API_ERROR, "criticity": -(2**31) - 1},
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
        "criticity-above-graphql-int",
        "criticity-below-graphql-int",
    ],
)
def test_list_of_malformed_errors_is_dropped_and_logged(malformed_error):
    helper = _run([malformed_error, malformed_error])
    assert helper.connector_info.errors == []
    assert helper.connector_logger.warning.call_count == 2
    message, meta = helper.connector_logger.warning.call_args.args
    assert message == "Malformed error response from the connector"
    assert meta["received"] == repr(malformed_error)
    assert meta["reason"]
    helper.connector_logger.error.assert_not_called()


@pytest.mark.parametrize(
    "callback_result",
    [[], [API_ERROR], [API_ERROR, RATE_ERROR], (API_ERROR, RATE_ERROR)],
    ids=["empty-list", "one-error", "two-errors", "tuple"],
)
def test_list_of_valid_errors_is_stored(callback_result):
    helper = _run(callback_result)
    assert _stored_errors(helper) == list(callback_result)
    helper.connector_logger.warning.assert_not_called()


def test_mixed_list_keeps_valid_errors_and_logs_malformed_ones():
    helper = _run([API_ERROR, "oops", RATE_ERROR])
    assert _stored_errors(helper) == [API_ERROR, RATE_ERROR]
    helper.connector_logger.warning.assert_called_once()
    assert helper.connector_logger.warning.call_args.args[1]["received"] == "'oops'"


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


def test_run_and_terminate_without_errors_sends_an_empty_list():
    helper, sent_on_force_ping = _run_and_terminate(lambda: None)
    assert helper.connector_info.errors == []
    assert sent_on_force_ping[0] == []


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


class _DataConversionError(Exception):
    code = "data.conversion"
    criticity = 30


class _Criticity(IntEnum):
    CRITICAL = 50


class _StrCode(str, Enum):
    AUTH = "api.authentication"


def _raise(exc: BaseException):
    def process():
        raise exc

    return process


def _run_raising(process, helper=None) -> OpenCTIConnectorHelper:
    helper = helper or _build_helper()
    helper.schedule_process(process, duration_period=60)
    return helper


def test_unexpected_exception_is_reported_as_unknown_error():
    helper = _run_raising(_raise(ValueError("invalid literal for int(): 'twenty'")))
    assert helper.connector_info.errors == [
        {
            "code": "other.unknown",
            "message": "ValueError: invalid literal for int(): 'twenty'",
            "criticity": 50,
        }
    ]


def test_exception_code_and_criticity_are_used():
    helper = _run_raising(_raise(_DataConversionError("unable to convert IOC")))
    assert helper.connector_info.errors == [
        {
            "code": "data.conversion",
            "message": "_DataConversionError: unable to convert IOC",
            "criticity": 30,
        }
    ]


def test_enum_code_and_criticity_are_sent_as_plain_values():
    exc = Exception("rejected")
    exc.code = _StrCode.AUTH
    exc.criticity = _Criticity.CRITICAL
    helper = _run_raising(_raise(exc))
    [error] = helper.connector_info.errors
    assert error == {
        "code": "api.authentication",
        "message": "Exception: rejected",
        "criticity": 50,
    }
    assert type(error["code"]) is str
    assert type(error["criticity"]) is int


@pytest.mark.parametrize(
    "code, criticity, expected",
    [
        (404, 30, ("other.unknown", 30)),
        ("  ", 30, ("other.unknown", 30)),
        (None, 30, ("other.unknown", 30)),
        ("api.timeout", "HIGH", ("api.timeout", 50)),
        ("api.timeout", True, ("api.timeout", 50)),
        ("api.timeout", 2**31, ("api.timeout", 50)),
        ("api.timeout", 30.0, ("api.timeout", 50)),
    ],
    ids=[
        "code-as-int",
        "blank-code",
        "code-as-none",
        "criticity-as-str",
        "criticity-as-bool",
        "criticity-above-graphql-int",
        "criticity-as-float",
    ],
)
def test_invalid_code_or_criticity_falls_back_to_defaults(code, criticity, expected):
    exc = Exception("boom")
    exc.code = code
    exc.criticity = criticity
    helper = _run_raising(_raise(exc))
    [error] = helper.connector_info.errors
    assert (error["code"], error["criticity"]) == expected


def test_exception_without_message_is_reported_with_its_type():
    helper = _run_raising(_raise(KeyError()))
    assert helper.connector_info.errors[0]["message"] == "KeyError"


def test_exception_failing_to_render_is_still_reported():
    class _Unprintable(Exception):
        @property
        def code(self):
            raise RuntimeError("broken attribute")

        @property
        def criticity(self):
            raise RuntimeError("broken attribute")

        def __str__(self):
            raise RuntimeError("broken __str__")

    helper = _run_raising(_raise(_Unprintable()))
    assert helper.connector_info.errors == [
        {"code": "other.unknown", "message": "_Unprintable", "criticity": 50}
    ]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="ExceptionGroup is 3.11+")
def test_exception_group_reports_each_exception_flattened():
    group = ExceptionGroup(  # noqa: F821
        "run failed",
        [
            _DataConversionError("bad IOC"),
            ExceptionGroup("nested", [ValueError("bad value")]),  # noqa: F821
        ],
    )
    helper = _run_raising(_raise(group))
    assert helper.connector_info.errors == [
        {
            "code": "data.conversion",
            "message": "_DataConversionError: bad IOC",
            "criticity": 30,
        },
        {"code": "other.unknown", "message": "ValueError: bad value", "criticity": 50},
    ]


def test_exception_is_logged_and_counted():
    helper = _run_raising(_raise(ValueError("bad value")))
    helper.metric.inc.assert_called_once_with("error_count")
    helper.connector_logger.error.assert_called_once_with(
        "Connector run raised an exception", {"reason": "ValueError: bad value"}
    )
    assert _run_errors_logs(helper) == [
        (
            "Errors reported by the connector run",
            {"errors": helper.connector_info.errors},
        )
    ]


def test_exception_is_sent_on_ping():
    helper = _run_raising(_raise(ValueError("bad value")))
    assert helper.connector_info.all_details["errors"] == [
        {"code": "other.unknown", "message": "ValueError: bad value", "criticity": 50}
    ]


def test_exception_keeps_errors_added_before_it_and_drops_previous_run_ones():
    helper = _build_helper()

    def process():
        helper.connector_info.add_error(**API_ERROR)
        raise ValueError("bad value")

    _run_raising(process, helper)
    assert helper.connector_info.errors == [
        API_ERROR,
        {"code": "other.unknown", "message": "ValueError: bad value", "criticity": 50},
    ]


def test_exception_on_first_run_still_schedules_the_next_one():
    helper = _run_raising(_raise(ValueError("bad value")))
    helper.scheduler.enter.assert_called_once()
    helper.scheduler.run.assert_called_once()


def test_exception_on_later_run_is_reported_and_next_run_scheduled():
    helper = _build_helper()
    scheduler = MagicMock()
    helper._schedule_process(scheduler, _raise(ValueError("bad value")), 60)
    assert helper.connector_info.errors == [
        {"code": "other.unknown", "message": "ValueError: bad value", "criticity": 50}
    ]
    scheduler.enter.assert_called_once()


def test_run_and_terminate_sends_exception_on_final_ping():
    helper, sent_on_force_ping = _run_and_terminate(_raise(ValueError("bad value")))
    assert sent_on_force_ping[0] == [
        {"code": "other.unknown", "message": "ValueError: bad value", "criticity": 50}
    ]


def test_base_exceptions_are_not_caught():
    with pytest.raises(KeyboardInterrupt):
        _build_helper()._run_and_collect_errors(_raise(KeyboardInterrupt()))


BAD_VALUE_ERROR = {
    "code": "other.unknown",
    "message": "ValueError: bad value",
    "criticity": 50,
}


def test_generator_callback_errors_are_stored():
    def process():
        yield API_ERROR
        yield RATE_ERROR

    helper = _run(process())
    assert helper.connector_info.errors == [API_ERROR, RATE_ERROR]


def test_generator_raising_before_yielding_is_reported():
    def process():
        raise ValueError("bad value")
        yield API_ERROR  # pylint: disable=unreachable

    helper = _run_raising(process)
    assert helper.connector_info.errors == [BAD_VALUE_ERROR]
    helper.metric.inc.assert_called_once_with("error_count")


def test_generator_raising_after_yielding_keeps_yielded_errors():
    def process():
        yield API_ERROR
        yield "oops"
        raise ValueError("bad value")

    helper = _run_raising(process)
    assert helper.connector_info.errors == [API_ERROR, BAD_VALUE_ERROR]
    helper.connector_logger.warning.assert_called_once()


def test_run_and_terminate_sends_generator_exception_on_final_ping():
    def process():
        yield API_ERROR
        raise ValueError("bad value")

    helper, sent_on_force_ping = _run_and_terminate(process)
    assert sent_on_force_ping[0] == [BAD_VALUE_ERROR, API_ERROR]
