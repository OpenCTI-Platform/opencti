import logging
from unittest.mock import MagicMock

from pycti.connector.opencti_connector_helper import (
    CONNECTOR_ERROR_CODE_MAX_LENGTH,
    CONNECTOR_ERROR_MESSAGE_MAX_LENGTH,
    CONNECTOR_ERRORS_MAX_COUNT,
    ConnectorInfo,
    ConnectorRunError,
    PingAlive,
)

API_ERROR = {
    "code": "API_UNREACHABLE",
    "message": "Source API returned 503",
    "criticity": 2,
}
RATE_ERROR = {
    "code": "RATE_LIMITED",
    "message": "Too many requests",
    "criticity": 0,
}


def test_errors_default_to_empty_list_and_are_not_sent():
    info = ConnectorInfo()
    assert info.errors == []
    assert "errors" not in info.all_details


def test_errors_from_constructor_are_copied():
    source = [API_ERROR]
    info = ConnectorInfo(errors=source)
    source.append(RATE_ERROR)
    assert info.errors == [API_ERROR]


def test_sent_errors_coerce_field_types():
    info = ConnectorInfo()
    info.add_error(404, None, 1)
    assert info.all_details["errors"] == [
        {"code": "404", "message": "", "criticity": 1}
    ]


def test_sent_errors_trim_and_truncate_strings():
    info = ConnectorInfo()
    info.add_error("  " + "C" * 300 + "  ", "  " + "M" * 2000 + "  ", 0)
    [sent_error] = info.all_details["errors"]
    assert sent_error["code"] == "C" * CONNECTOR_ERROR_CODE_MAX_LENGTH
    assert sent_error["message"] == "M" * CONNECTOR_ERROR_MESSAGE_MAX_LENGTH


def test_sent_errors_drop_invalid_entries():
    info = ConnectorInfo(
        errors=[
            API_ERROR,
            {"code": None, "message": "no code", "criticity": 0},
            {"code": "   ", "message": "blank code", "criticity": 0},
            {"code": "STRING", "message": "string criticity", "criticity": "HIGH"},
            {"code": "DECIMAL", "message": "decimal criticity", "criticity": 1.5},
            {"code": "BOOLEAN", "message": "boolean criticity", "criticity": True},
            {"code": "OVERFLOW", "message": "too big criticity", "criticity": 2**31},
            {"code": "NO_CRITICITY", "message": "missing criticity"},
            "not a dict",
            None,
        ]
    )
    assert info.all_details["errors"] == [API_ERROR]


def test_sent_errors_are_sorted_from_most_to_least_critical():
    info = ConnectorInfo()
    for criticity in [1, 3, 0, 2]:
        info.add_error(f"CRITICITY_{criticity}", "", criticity)
    assert [error["criticity"] for error in info.all_details["errors"]] == [3, 2, 1, 0]


def test_sent_errors_keep_most_critical_up_to_the_limit():
    info = ConnectorInfo()
    for index in range(CONNECTOR_ERRORS_MAX_COUNT):
        info.add_error(f"LOW_{index}", "", 0)
    info.add_error("CRITICAL", "", 3)
    sent_errors = info.all_details["errors"]
    assert len(sent_errors) == CONNECTOR_ERRORS_MAX_COUNT
    assert sent_errors[0]["code"] == "CRITICAL"
    assert sent_errors[-1]["code"] == f"LOW_{CONNECTOR_ERRORS_MAX_COUNT - 2}"


def test_non_iterable_errors_are_not_sent():
    info = ConnectorInfo()
    info.errors = [API_ERROR]
    info._errors = 42
    assert "errors" not in info.all_details


def test_errors_setter_replaces_and_accepts_none():
    info = ConnectorInfo(errors=[API_ERROR])
    info.errors = [RATE_ERROR]
    assert info.errors == [RATE_ERROR]
    info.errors = None
    assert info.errors == []


def test_clear_errors():
    info = ConnectorInfo(errors=[API_ERROR, RATE_ERROR])
    info.clear_errors()
    assert info.errors == []
    assert "errors" not in info.all_details


def test_all_details_errors_is_a_snapshot():
    info = ConnectorInfo(errors=[API_ERROR])
    details = info.all_details
    info.add_error("RATE_LIMITED", "Too many requests", 0)
    assert details["errors"] == [API_ERROR]


def test_ping_alive_sends_errors_to_platform():
    connector_info = ConnectorInfo()
    connector_info.add_error("API_UNREACHABLE", "Source API returned 503", 2)
    fake_api = MagicMock()

    def fake_ping(connector_id, state, info):
        ping_alive.exit_event.set()
        return {"connector_state": None}

    fake_api.connector.ping.side_effect = fake_ping
    ping_alive = PingAlive(
        connector_logger=logging.getLogger("test-ping-alive-errors"),
        connector_id="test-connector-id",
        api=fake_api,
        get_state=lambda: None,
        set_state=lambda state: None,
        metric=MagicMock(),
        connector_info=connector_info,
    )
    ping_alive.ping()

    sent_connector_info = fake_api.connector.ping.call_args.args[2]
    assert sent_connector_info["errors"] == [API_ERROR]


def test_ping_alive_does_not_log_errors_on_each_ping():
    connector_info = ConnectorInfo()
    connector_info.add_error("API_UNREACHABLE", "Source API returned 503", 2)
    connector_logger = MagicMock()
    fake_api = MagicMock()

    def fake_ping(connector_id, state, info):
        ping_alive.exit_event.set()
        return {"connector_state": None}

    fake_api.connector.ping.side_effect = fake_ping
    ping_alive = PingAlive(
        connector_logger=connector_logger,
        connector_id="test-connector-id",
        api=fake_api,
        get_state=lambda: None,
        set_state=lambda state: None,
        metric=MagicMock(),
        connector_info=connector_info,
    )
    ping_alive.ping()

    connector_logger.info.assert_not_called()
    connector_logger.error.assert_not_called()


def test_connector_run_error_objects_are_sent():
    info = ConnectorInfo(errors=[ConnectorRunError.model_validate(API_ERROR)])
    assert info.all_details["errors"] == [API_ERROR]


def test_sent_errors_keep_the_last_report_of_a_repeated_code():
    info = ConnectorInfo()
    info.add_error("API_UNREACHABLE", "old", 1)
    info.add_error("RATE_LIMITED", "", 2)
    info.add_error("  API_UNREACHABLE  ", "latest", 3)
    assert info.all_details["errors"] == [
        {"code": "API_UNREACHABLE", "message": "latest", "criticity": 3},
        {"code": "RATE_LIMITED", "message": "", "criticity": 2},
    ]


def test_sent_errors_count_a_repeated_code_once_against_the_limit():
    info = ConnectorInfo()
    for _ in range(CONNECTOR_ERRORS_MAX_COUNT):
        info.add_error("REPEATED", "", 3)
    info.add_error("DISTINCT", "", 2)
    assert [error["code"] for error in info.all_details["errors"]] == [
        "REPEATED",
        "DISTINCT",
    ]
