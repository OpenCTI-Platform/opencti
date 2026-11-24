"""Errors of listen_stream() callbacks: run through the CallbackExecutor, reported with the ping."""

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pycti.connector import opencti_connector_helper
from pycti.connector.opencti_connector_helper import (
    BatchCallbackWrapper,
    ConnectorInfo,
    ListenStream,
    OpenCTIConnectorHelper,
)

SIEM_ERROR = {"code": "SIEM_UNREACHABLE", "message": "503", "criticity": 30}
QUOTA_ERROR = {
    "code": "QUOTA_EXCEEDED",
    "message": "QuotaError: daily quota exhausted",
    "criticity": 30,
}


class QuotaError(Exception):
    code = "QUOTA_EXCEEDED"
    criticity = 30


class StateHelper:
    """Helper with a real ConnectorInfo and an in-memory state."""

    def __init__(self):
        self.connector_logger = MagicMock()
        self.metric = MagicMock()
        self.connector_info = ConnectorInfo()
        self.connector_info.clear_errors_once_sent = True
        self.force_ping = MagicMock()
        self._state = {"start_from": "0-0", "recover_until": False}

    def get_state(self):
        return self._state

    def set_state(self, state):
        self._state = state

    def date_now_z(self):
        return "2026-01-01T00:00:00Z"


def _event(message_id):
    return SimpleNamespace(id=message_id, event="create", data="{}")


def _run_stream(helper, callback, events):
    """Run ListenStream over the given events, return the excepthook calls."""
    stream = ListenStream.__new__(ListenStream)
    stream.helper = helper
    stream.callback = callback
    stream.url = "http://opencti/stream"
    stream.token = "token"
    stream.verify_ssl = False
    stream.start_timestamp = None
    stream.live_stream_id = None
    stream.listen_delete = True
    stream.no_dependencies = True
    stream.recover_iso_date = None
    stream.with_inferences = False
    stream.exit_event = threading.Event()
    excepthook = MagicMock()
    with patch.object(
        opencti_connector_helper, "SSEClient", return_value=iter(events)
    ), patch.object(opencti_connector_helper, "StreamAlive"), patch.object(
        opencti_connector_helper.sys, "excepthook", excepthook
    ):
        stream.run()
    return excepthook


def test_returned_errors_are_reported_and_accumulate_across_events():
    helper = StateHelper()
    returns = {
        "1-0": [SIEM_ERROR],
        "2-0": None,
        "3-0": [{"code": "BAD_EVENT", "message": "skipped", "criticity": 10}],
    }

    excepthook = _run_stream(
        helper, lambda msg: returns[msg.id], [_event(i) for i in returns]
    )

    excepthook.assert_not_called()
    assert helper.connector_info.errors == [
        SIEM_ERROR,
        {"code": "BAD_EVENT", "message": "skipped", "criticity": 10},
    ]
    assert helper.get_state()["start_from"] == "3-0"


def test_a_malformed_returned_error_is_ignored_with_a_warning():
    helper = StateHelper()
    _run_stream(helper, lambda msg: [{"code": "NO_CRITICITY"}], [_event("1-0")])
    assert helper.connector_info.errors == []
    helper.connector_logger.warning.assert_called_once()


def test_a_raised_exception_is_sent_before_the_connector_stops():
    helper = StateHelper()
    processed = []

    def callback(msg):
        processed.append(msg.id)
        if msg.id == "2-0":
            raise QuotaError("daily quota exhausted")

    def force_ping():
        # The error is stored before the ping that sends it
        assert helper.connector_info.errors == [QUOTA_ERROR]

    helper.force_ping.side_effect = force_ping

    excepthook = _run_stream(
        helper, callback, [_event(i) for i in ["1-0", "2-0", "3-0"]]
    )

    assert processed == ["1-0", "2-0"]
    helper.force_ping.assert_called_once_with()
    # As before, the failing event is not acknowledged and the connector stops
    assert helper.get_state()["start_from"] == "1-0"
    excepthook.assert_called_once()
    assert isinstance(excepthook.call_args.args[1], QuotaError)
    # As before, the ListenStream loop logs it and does not count it
    helper.metric.inc.assert_not_called()


def test_listen_stream_clears_the_errors_once_sent():
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connector_info = ConnectorInfo()
    helper.opencti_url = "http://opencti"
    helper.opencti_token = "token"
    helper.opencti_ssl_verify = False
    for attribute in [
        "connect_live_stream_id",
        "connect_live_stream_listen_delete",
        "connect_live_stream_no_dependencies",
        "connect_live_stream_with_inferences",
        "connect_live_stream_recover_iso_date",
        "connect_live_stream_start_timestamp",
    ]:
        setattr(helper, attribute, None)

    with patch.object(opencti_connector_helper, "ListenStream"):
        helper.listen_stream(lambda msg: None)

    assert helper.connector_info.clear_errors_once_sent is True


def _batch_data(*message_ids):
    return {
        "events": [_event(i) for i in message_ids],
        "batch_metadata": {
            "batch_size": len(message_ids),
            "trigger_reason": "size_limit",
            "elapsed_time": 0.0,
            "timestamp": time.time(),
        },
    }


def test_errors_returned_by_a_batch_callback_are_reported():
    helper = StateHelper()
    wrapper = BatchCallbackWrapper(
        helper, lambda batch: [SIEM_ERROR], batch_size=10, batch_timeout=10.0
    )
    try:
        wrapper._execute_batch_callback(_batch_data("1-0", "2-0"))
    finally:
        wrapper.stop()
    assert helper.connector_info.errors == [SIEM_ERROR]
    assert helper.get_state()["start_from"] == "2-0"


def test_an_exception_of_a_batch_callback_is_reported_and_still_raised():
    helper = StateHelper()

    def batch_callback(batch):
        raise QuotaError("daily quota exhausted")

    wrapper = BatchCallbackWrapper(
        helper, batch_callback, batch_size=10, batch_timeout=10.0
    )
    raised = None
    try:
        wrapper._execute_batch_callback(_batch_data("1-0"))
    except QuotaError as err:
        raised = err
    finally:
        wrapper.stop()
    assert raised is not None
    assert helper.connector_info.errors == [QUOTA_ERROR]
    # Not acknowledged: the batch is processed again on restart
    assert helper.get_state()["start_from"] == "0-0"
