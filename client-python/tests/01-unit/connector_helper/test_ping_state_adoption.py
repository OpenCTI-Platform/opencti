import datetime
from unittest import TestCase
from unittest.mock import MagicMock

from pycti.connector.opencti_connector_helper import PingAlive


class DummyLogger:
    def info(self, message, data=None):
        pass

    def debug(self, message, data=None):
        pass

    def error(self, message, data=None):
        pass


def _run_one_ping(local_state, last_write, ping_response):
    """Construct PingAlive with stubs, run exactly one loop iteration,
    and return the resulting local state."""
    holder = {"state": local_state}
    api = MagicMock()
    api.connector.ping.return_value = ping_response

    ping = PingAlive(
        DummyLogger(),
        "connector-test",
        api,
        lambda: holder["state"],
        lambda s: holder.__setitem__("state", s),
        MagicMock(),
        MagicMock(all_details={}),
        lambda: last_write,
    )
    # Stop the loop after a single iteration.
    ping.exit_event.wait = lambda *args, **kwargs: ping.exit_event.set()
    ping.ping()
    return holder["state"]


class TestPingStateAdoption(TestCase):
    def test_stale_value_echo_is_ignored(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        old = (now - datetime.timedelta(hours=1)).isoformat()
        result = _run_one_ping(
            {"last_run": 2},
            now,
            {
                "connector_state": '{"last_run": 1}',
                "connector_state_timestamp": old,
            },
        )
        # Local state must be preserved; the stale value echo is ignored.
        self.assertEqual(result, {"last_run": 2})

    def test_stale_empty_echo_is_ignored(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        old = (now - datetime.timedelta(hours=1)).isoformat()
        result = _run_one_ping(
            {"last_run": 2},
            now,
            {
                "connector_state": None,
                "connector_state_timestamp": old,
            },
        )
        # Empty echo with an old reset timestamp is not a genuine reset.
        self.assertEqual(result, {"last_run": 2})

    def test_genuine_reset_is_adopted(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        fresh = (now + datetime.timedelta(seconds=5)).isoformat()
        result = _run_one_ping(
            {"last_run": 2},
            now,
            {
                "connector_state": None,
                "connector_state_timestamp": fresh,
            },
        )
        # Empty state with a fresh reset timestamp is a genuine reset.
        self.assertIsNone(result)
