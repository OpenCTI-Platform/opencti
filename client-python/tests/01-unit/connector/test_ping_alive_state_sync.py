"""Regression tests for PingAlive.ping() connector_state handling.

Covers the bug described in OpenCTI-Platform/opencti#17472 (client-side part):
whenever the platform's echoed ``connector_state`` differs from the local
``initial_state``, ``PingAlive.ping()`` used to call ``set_state()`` with the
*raw JSON string* returned by the API instead of the already-parsed
``remote_state`` dict. Since ``set_state()`` only accepts a ``Dict`` (anything
else resolves the local state to ``None``), any mismatch - whatever its cause,
including a stale echo caused by ES read-after-write latency on the server
side - silently wiped the connector's local state to ``None``, forcing a full
re-import on the connector's next run.
"""

import logging
from unittest import TestCase
from unittest.mock import MagicMock

from pycti.connector.opencti_connector_helper import ConnectorInfo, PingAlive


class TestPingAliveStateSync(TestCase):
    """Verify PingAlive.ping() adopts the platform state without data loss."""

    def _run_single_ping(self, initial_state, remote_connector_state_json):
        """Run exactly one iteration of PingAlive.ping() and return the instance.

        :param initial_state: the dict returned by get_state() before pinging
        :param remote_connector_state_json: the raw `connector_state` string
            (JSON-encoded, or None/"") the fake API echoes back in the ping response
        """
        state_holder = {"state": initial_state}

        def fake_get_state():
            return state_holder["state"]

        def fake_set_state(state):
            # Mirrors the real OpenCTIConnectorHelper.set_state behavior:
            # only a Dict is kept, anything else (e.g. a raw JSON string) is dropped.
            if isinstance(state, dict):
                state_holder["state"] = state
            else:
                state_holder["state"] = None

        fake_api = MagicMock()

        def fake_ping(connector_id, state, connector_info):
            # Let exactly one loop iteration run, then stop the daemon loop.
            ping_alive.exit_event.set()
            return {"connector_state": remote_connector_state_json}

        fake_api.connector.ping.side_effect = fake_ping

        ping_alive = PingAlive(
            connector_logger=logging.getLogger("test-ping-alive"),
            connector_id="test-connector-id",
            api=fake_api,
            get_state=fake_get_state,
            set_state=fake_set_state,
            metric=MagicMock(),
            connector_info=ConnectorInfo(run_and_terminate=False),
        )
        ping_alive.ping()
        return state_holder

    def test_stale_echo_does_not_wipe_local_state(self):
        """A mismatch caused by a stale/different echoed state must be adopted
        as the parsed dict, never as None because of a raw-string type error."""
        initial_state = {"last_run": "2026-01-01T00:00:00Z"}
        remote_state_dict = {"last_run": "2025-12-31T23:59:00Z"}
        remote_state_json = '{"last_run": "2025-12-31T23:59:00Z"}'

        result_state = self._run_single_ping(initial_state, remote_state_json)

        self.assertEqual(
            result_state["state"],
            remote_state_dict,
            "connector_state must be adopted as the parsed remote dict, not wiped to None",
        )

    def test_actual_remote_reset_sets_state_to_none(self):
        """When the platform genuinely has no state (empty/None), local state
        should become None - this is the only legitimate case for a reset."""
        initial_state = {"last_run": "2026-01-01T00:00:00Z"}

        result_state = self._run_single_ping(initial_state, None)

        self.assertIsNone(result_state["state"])

    def test_matching_state_is_left_untouched(self):
        """No mismatch, no state churn."""
        initial_state = {"last_run": "2026-01-01T00:00:00Z"}
        remote_state_json = '{"last_run": "2026-01-01T00:00:00Z"}'

        result_state = self._run_single_ping(initial_state, remote_state_json)

        self.assertEqual(result_state["state"], initial_state)
