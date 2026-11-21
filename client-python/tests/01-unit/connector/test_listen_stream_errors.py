import logging
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pycti.connector.opencti_connector_helper import (
    BatchCallbackWrapper,
    ConnectorInfo,
    ListenStream,
    OpenCTIConnectorHelper,
    PingAlive,
)

API_ERROR = {
    "code": "API_UNREACHABLE",
    "message": "SIEM returned 503",
    "criticity": 3,
}
RATE_ERROR = {"code": "RATE_LIMITED", "message": "Too many requests", "criticity": 1}


def _build_helper() -> OpenCTIConnectorHelper:
    """Build a helper with only what stream errors reporting needs, without connecting to the platform."""
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connector_info = ConnectorInfo()
    helper.connector_info._clear_errors_once_sent = True
    helper.connector_logger = MagicMock()
    return helper


def _ping_once(connector_info: ConnectorInfo, ping_side_effect=None) -> MagicMock:
    """Run exactly one PingAlive iteration and return the fake api."""
    fake_api = MagicMock()

    def fake_ping(connector_id, state, info):
        ping_alive.exit_event.set()
        if ping_side_effect is not None:
            ping_side_effect()
        return {"connector_state": None}

    fake_api.connector.ping.side_effect = fake_ping
    ping_alive = PingAlive(
        connector_logger=logging.getLogger("test-listen-stream-errors"),
        connector_id="test-connector-id",
        api=fake_api,
        get_state=lambda: None,
        set_state=lambda state: None,
        metric=MagicMock(),
        connector_info=connector_info,
    )
    ping_alive.ping()
    return fake_api


def _sent_errors(fake_api: MagicMock):
    return fake_api.connector.ping.call_args.args[2].get("errors")


# region reporting


def test_returned_errors_accumulate_across_events():
    helper = _build_helper()
    helper._report_callback_errors([API_ERROR], "Stream callback")
    helper._report_callback_errors(None, "Stream callback")
    helper._report_callback_errors([RATE_ERROR], "Stream callback")
    assert helper.connector_info.all_details["errors"] == [API_ERROR, RATE_ERROR]


def test_repeated_code_keeps_its_last_report_and_a_single_slot():
    helper = _build_helper()
    for index in range(1000):
        helper._report_callback_errors(
            [{**API_ERROR, "message": f"event {index}"}], "Stream callback"
        )
    assert helper.connector_info.errors == [{**API_ERROR, "message": "event 999"}]


@pytest.mark.parametrize("error_list", [None, []], ids=["none", "empty-list"])
def test_no_error_returned_reports_an_empty_list(error_list):
    helper = _build_helper()
    assert "errors" not in helper.connector_info.all_details
    helper._report_callback_errors(error_list, "Stream callback")
    assert helper.connector_info.all_details["errors"] == []


def test_malformed_returned_error_is_dropped_with_a_warning():
    helper = _build_helper()
    helper._report_callback_errors(
        [API_ERROR, {"code": "BAD", "criticity": "high"}], "Stream callback"
    )
    assert helper.connector_info.errors == [API_ERROR]
    message, _ = helper.connector_logger.warning.call_args.args
    assert message == "Malformed error response from the connector"


def test_single_error_dict_is_ignored_with_a_warning():
    helper = _build_helper()
    helper._report_callback_errors(API_ERROR, "Stream callback")
    assert helper.connector_info.errors == []
    message, _ = helper.connector_logger.warning.call_args.args
    assert (
        message == "Stream callback returned a single error instead of a list, ignored"
    )


def test_failing_error_list_never_raises():
    helper = _build_helper()

    def failing_errors():
        yield API_ERROR
        raise RuntimeError("broken generator")

    helper._report_callback_errors(failing_errors(), "Stream callback")
    message, _ = helper.connector_logger.warning.call_args.args
    assert message == "Unable to report the errors returned by the stream callback"


# endregion

# region ping


def test_ping_clears_the_errors_it_sent():
    helper = _build_helper()
    helper._report_callback_errors([API_ERROR], "Stream callback")

    first_ping = _ping_once(helper.connector_info)
    assert _sent_errors(first_ping) == [API_ERROR]

    second_ping = _ping_once(helper.connector_info)
    assert _sent_errors(second_ping) == []


def test_error_reported_during_the_ping_is_sent_by_the_next_one():
    helper = _build_helper()
    helper._report_callback_errors([API_ERROR], "Stream callback")

    first_ping = _ping_once(
        helper.connector_info,
        lambda: helper._report_callback_errors([RATE_ERROR], "Stream callback"),
    )
    assert _sent_errors(first_ping) == [API_ERROR]

    second_ping = _ping_once(helper.connector_info)
    assert _sent_errors(second_ping) == [RATE_ERROR]


def test_code_reported_again_during_the_ping_is_sent_by_the_next_one():
    helper = _build_helper()
    helper._report_callback_errors([API_ERROR], "Stream callback")
    reported_again = {**API_ERROR, "message": "still down"}

    _ping_once(
        helper.connector_info,
        lambda: helper._report_callback_errors([reported_again], "Stream callback"),
    )

    second_ping = _ping_once(helper.connector_info)
    assert _sent_errors(second_ping) == [reported_again]


def test_errors_are_kept_when_the_ping_fails():
    helper = _build_helper()
    helper._report_callback_errors([API_ERROR], "Stream callback")

    def platform_down():
        raise ConnectionError("platform down")

    _ping_once(helper.connector_info, platform_down)
    assert helper.connector_info.errors == [API_ERROR]


def test_errors_added_with_add_error_are_cleared_once_sent():
    helper = _build_helper()
    helper.connector_info.add_error("API_UNREACHABLE", "SIEM returned 503", 3)
    _ping_once(helper.connector_info)
    assert helper.connector_info.errors == []


def test_ping_keeps_the_errors_of_a_connector_that_is_not_a_stream():
    connector_info = ConnectorInfo()
    connector_info.add_error("API_UNREACHABLE", "SIEM returned 503", 3)
    _ping_once(connector_info)
    _ping_once(connector_info)
    assert connector_info.errors == [API_ERROR]


# endregion

# region callbacks


def _run_listen_stream(helper, callback, messages):
    """Run ListenStream over the given SSE messages, without connecting to the platform."""
    state = {"start_from": "0-0", "recover_until": False}
    helper.get_state = lambda: dict(state)
    helper.set_state = state.update
    with patch(
        "pycti.connector.opencti_connector_helper.SSEClient", return_value=messages
    ), patch("pycti.connector.opencti_connector_helper.StreamAlive"):
        ListenStream(
            helper,
            callback,
            "http://opencti/stream",
            "token",
            True,
            None,
            None,
            False,
            False,
            False,
            False,
        ).run()


def test_listen_stream_reports_the_errors_returned_by_the_callback():
    helper = _build_helper()
    returns = iter([[API_ERROR], None, [RATE_ERROR]])
    messages = [
        SimpleNamespace(id=f"{index}-0", event="update", data="{}")
        for index in range(3)
    ]
    _run_listen_stream(helper, lambda msg: next(returns), messages)
    assert helper.connector_info.all_details["errors"] == [API_ERROR, RATE_ERROR]


def test_listen_stream_does_not_report_errors_for_heartbeats():
    helper = _build_helper()
    callback = MagicMock()
    _run_listen_stream(
        helper, callback, [SimpleNamespace(id="1-0", event="heartbeat", data="")]
    )
    callback.assert_not_called()
    assert "errors" not in helper.connector_info.all_details


def test_listen_stream_enables_clearing_errors_once_sent():
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connector_info = ConnectorInfo()
    helper.opencti_url = "http://opencti"
    helper.opencti_token = "token"
    helper.opencti_ssl_verify = True
    for name in [
        "connect_live_stream_id",
        "connect_live_stream_listen_delete",
        "connect_live_stream_no_dependencies",
        "connect_live_stream_with_inferences",
        "connect_live_stream_start_timestamp",
        "connect_live_stream_recover_iso_date",
    ]:
        setattr(helper, name, None)
    with patch.object(ListenStream, "start"):
        helper.listen_stream(lambda msg: None)
    assert helper.connector_info._clear_errors_once_sent is True


def test_batch_callback_errors_are_reported():
    helper = _build_helper()
    helper.get_state = lambda: None
    helper.set_state = lambda state: None
    done = threading.Event()

    def batch_callback(batch_data):
        done.set()
        return [API_ERROR]

    original_interval = BatchCallbackWrapper._TIMER_CHECK_INTERVAL
    BatchCallbackWrapper._TIMER_CHECK_INTERVAL = 0.01
    try:
        wrapper = BatchCallbackWrapper(helper, batch_callback, batch_size=1)
        wrapper(SimpleNamespace(id="1-0"))
        assert done.wait(2)
        wrapper.stop()
    finally:
        BatchCallbackWrapper._TIMER_CHECK_INTERVAL = original_interval
    assert helper.connector_info.errors == [API_ERROR]


# endregion
