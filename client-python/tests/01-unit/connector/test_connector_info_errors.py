import logging
from unittest.mock import MagicMock

from pycti.connector.opencti_connector_helper import (
    CONNECTOR_ERROR_CODE_MAX_LENGTH,
    CONNECTOR_ERROR_MESSAGE_MAX_LENGTH,
    CONNECTOR_ERRORS_MAX_COUNT,
    ConnectorInfo,
    ConnectorInfoErrorCriticity,
    PingAlive,
)

API_ERROR = {
    "code": "API_UNREACHABLE",
    "message": "Source API returned 503",
    "criticity": "HIGH",
}
RATE_ERROR = {
    "code": "RATE_LIMITED",
    "message": "Too many requests",
    "criticity": "LOW",
}


def test_errors_default_to_empty_list():
    info = ConnectorInfo()
    assert info.errors == []
    assert info.all_details["errors"] == []


def test_errors_from_constructor_are_copied():
    source = [API_ERROR]
    info = ConnectorInfo(errors=source)
    source.append(RATE_ERROR)
    assert info.errors == [API_ERROR]


def test_sent_errors_coerce_field_types():
    info = ConnectorInfo()
    info.add_error(404, None, ConnectorInfoErrorCriticity.MEDIUM)
    assert info.all_details["errors"] == [
        {"code": "404", "message": "", "criticity": "MEDIUM"}
    ]


def test_sent_errors_accept_criticity_name_in_any_case():
    info = ConnectorInfo()
    info.add_error("API_UNREACHABLE", "Source API returned 503", " high ")
    assert info.all_details["errors"] == [API_ERROR]


def test_sent_errors_trim_and_truncate_strings():
    info = ConnectorInfo()
    info.add_error("  " + "C" * 300 + "  ", "  " + "M" * 2000 + "  ", "LOW")
    [sent_error] = info.all_details["errors"]
    assert sent_error["code"] == "C" * CONNECTOR_ERROR_CODE_MAX_LENGTH
    assert sent_error["message"] == "M" * CONNECTOR_ERROR_MESSAGE_MAX_LENGTH


def test_sent_errors_drop_invalid_entries():
    info = ConnectorInfo(
        errors=[
            API_ERROR,
            {"code": None, "message": "no code", "criticity": "LOW"},
            {"code": "   ", "message": "blank code", "criticity": "LOW"},
            {"code": "UNKNOWN", "message": "unknown criticity", "criticity": "SEVERE"},
            {"code": "NUMERIC", "message": "numeric criticity", "criticity": 3},
            {"code": "NO_CRITICITY", "message": "missing criticity"},
            "not a dict",
            None,
        ]
    )
    assert info.all_details["errors"] == [API_ERROR]


def test_sent_errors_are_sorted_from_most_to_least_critical():
    info = ConnectorInfo()
    for criticity in ["MEDIUM", "CRITICAL", "LOW", "HIGH"]:
        info.add_error(criticity, "", criticity)
    assert [error["criticity"] for error in info.all_details["errors"]] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]


def test_sent_errors_keep_most_critical_up_to_the_limit():
    info = ConnectorInfo()
    for index in range(CONNECTOR_ERRORS_MAX_COUNT):
        info.add_error(f"LOW_{index}", "", ConnectorInfoErrorCriticity.LOW)
    info.add_error("CRITICAL", "", ConnectorInfoErrorCriticity.CRITICAL)
    sent_errors = info.all_details["errors"]
    assert len(sent_errors) == CONNECTOR_ERRORS_MAX_COUNT
    assert sent_errors[0]["code"] == "CRITICAL"
    assert sent_errors[-1]["code"] == f"LOW_{CONNECTOR_ERRORS_MAX_COUNT - 2}"


def test_non_iterable_errors_are_sent_as_empty_list():
    info = ConnectorInfo()
    info.errors = [API_ERROR]
    info._errors = 42
    assert info.all_details["errors"] == []


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
    assert info.all_details["errors"] == []


def test_all_details_errors_is_a_snapshot():
    info = ConnectorInfo(errors=[API_ERROR])
    details = info.all_details
    info.add_error("RATE_LIMITED", "Too many requests", "LOW")
    assert details["errors"] == [API_ERROR]


def test_ping_alive_sends_errors_to_platform():
    connector_info = ConnectorInfo()
    connector_info.add_error(
        "API_UNREACHABLE", "Source API returned 503", ConnectorInfoErrorCriticity.HIGH
    )
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
