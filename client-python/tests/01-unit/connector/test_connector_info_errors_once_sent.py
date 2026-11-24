"""Errors of a connector that listens continuously: kept until a ping sends them."""

import logging
from unittest.mock import MagicMock

from pycti.connector.opencti_connector_helper import ConnectorInfo, PingAlive

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


def _ping_once(connector_info, on_ping=None, fail=False):
    """Run one PingAlive iteration, return the connector info it sent."""
    fake_api = MagicMock()

    def fake_ping(connector_id, state, info):
        ping_alive.exit_event.set()
        if on_ping is not None:
            on_ping()
        if fail:
            raise ConnectionError("platform unreachable")
        return {"connector_state": None}

    fake_api.connector.ping.side_effect = fake_ping
    ping_alive = PingAlive(
        connector_logger=logging.getLogger("test-ping-alive-errors-once-sent"),
        connector_id="test-connector-id",
        api=fake_api,
        get_state=lambda: None,
        set_state=lambda state: None,
        metric=MagicMock(),
        connector_info=connector_info,
    )
    ping_alive.ping()
    return fake_api.connector.ping.call_args.args[2]


def _listening_info():
    info = ConnectorInfo()
    info.clear_errors_once_sent = True
    return info


def test_add_errors_replaces_an_earlier_error_with_the_same_code():
    info = ConnectorInfo()
    info.add_errors([API_ERROR, RATE_ERROR])
    newer = {**API_ERROR, "message": "Source API returned 502"}
    info.add_errors([newer])
    assert info.errors == [RATE_ERROR, newer]
    assert info.all_details["errors"] == [newer, RATE_ERROR]


def test_add_error_replaces_an_earlier_error_with_the_same_code():
    info = ConnectorInfo()
    for _ in range(1000):
        info.add_error("API_UNREACHABLE", "Source API returned 503", 2)
    assert info.errors == [API_ERROR]


def test_a_scheduled_connector_keeps_its_errors_after_a_ping():
    info = ConnectorInfo()
    info.add_errors([API_ERROR])
    assert _ping_once(info)["errors"] == [API_ERROR]
    assert info.errors == [API_ERROR]
    assert _ping_once(info)["errors"] == [API_ERROR]


def test_a_listening_connector_clears_its_errors_once_sent():
    info = _listening_info()
    info.add_errors([API_ERROR])
    assert _ping_once(info)["errors"] == [API_ERROR]
    assert info.errors == []
    # The next ping sends an explicit empty list, which clears the platform's errors
    assert _ping_once(info)["errors"] == []


def test_a_listening_connector_keeps_its_errors_when_the_ping_fails():
    info = _listening_info()
    info.add_errors([API_ERROR])
    _ping_once(info, fail=True)
    assert info.errors == [API_ERROR]


def test_an_error_reported_during_the_ping_waits_for_the_next_one():
    info = _listening_info()
    info.add_errors([API_ERROR])
    newer = {**API_ERROR, "message": "Source API returned 502"}

    sent = _ping_once(info, on_ping=lambda: info.add_errors([newer, RATE_ERROR]))

    assert sent["errors"] == [API_ERROR]
    assert info.errors == [newer, RATE_ERROR]
    assert _ping_once(info)["errors"] == [newer, RATE_ERROR]
    assert info.errors == []


def test_clear_errors_once_sent_is_off_by_default():
    assert ConnectorInfo().clear_errors_once_sent is False
