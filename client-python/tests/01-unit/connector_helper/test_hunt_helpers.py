"""Tests of the INTERNAL_HUNT helpers of the connector helper (OpenCTI Hunts)."""

from unittest import TestCase
from unittest.mock import MagicMock

from pycti.connector.opencti_connector import ConnectorType
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


def _helper(connect_type=ConnectorType.INTERNAL_HUNT.value):
    helper = OpenCTIConnectorHelper.__new__(OpenCTIConnectorHelper)
    helper.connect_type = connect_type
    helper.connect_id = "connector-1"
    helper.api = MagicMock()
    helper.connector_logger = MagicMock()
    # listen() runs the callback on each message: the tests drive it directly
    helper.listen = MagicMock()
    return helper


def _event(**overrides):
    event = {
        "event_type": "INTERNAL_HUNT",
        "mode": "execute",
        "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "manual"},
        "hunt": {"id": "hunt-1", "name": "Hunt"},
    }
    event.update(overrides)
    return event


def _hunt_callback(helper, message_callback):
    helper.listen_hunt(message_callback)
    return helper.listen.call_args.kwargs["message_callback"]


class TestHuntHelpers(TestCase):
    def test_connector_type_lists_internal_hunt(self):
        self.assertEqual(ConnectorType.INTERNAL_HUNT.value, "INTERNAL_HUNT")

    def test_register_hunt_platform_registers_the_connector_itself(self):
        helper = _helper()
        helper.api.hunt_run.register_connector.return_value = {"id": "connector-1"}
        result = helper.register_hunt_platform(
            "splunk", ["spl"], security_platform_name="Splunk prod"
        )
        self.assertEqual(result, {"id": "connector-1"})
        helper.api.hunt_run.register_connector.assert_called_once_with(
            connector_id="connector-1",
            platform="splunk",
            languages=["spl"],
            security_platform_name="Splunk prod",
            security_platform_type="SIEM",
            supports_preview=True,
            max_concurrent_runs=None,
        )

    def test_hunt_helpers_refuse_other_connector_types(self):
        helper = _helper(ConnectorType.INTERNAL_ENRICHMENT.value)
        with self.assertRaises(ValueError):
            helper.register_hunt_platform("splunk", ["spl"])
        with self.assertRaises(ValueError):
            helper.listen_hunt(MagicMock())

    def test_report_hunt_run_forwards_the_report(self):
        helper = _helper()
        helper.report_hunt_run(
            "run-1", "completed", hits_count=3, result_ids=["sighting--1"]
        )
        helper.api.hunt_run.report.assert_called_once_with(
            id="run-1",
            status="completed",
            hits_count=3,
            distinct_entities=None,
            evidence_sample=None,
            translated_query=None,
            query_language=None,
            cost_ms=None,
            result_ids=["sighting--1"],
            error=None,
        )

    def test_listen_hunt_reports_running_before_the_callback(self):
        helper = _helper()
        message_callback = MagicMock(return_value="done")
        callback = _hunt_callback(helper, message_callback)
        self.assertEqual(callback(_event()), "done")
        helper.api.hunt_run.report.assert_called_once()
        self.assertEqual(
            helper.api.hunt_run.report.call_args.kwargs["status"], "running"
        )
        message_callback.assert_called_once()

    def test_listen_hunt_reports_a_failure_and_raises_again(self):
        helper = _helper()
        callback = _hunt_callback(helper, MagicMock(side_effect=RuntimeError("down")))
        with self.assertRaises(RuntimeError):
            callback(_event())
        statuses = [
            call.kwargs["status"] for call in helper.api.hunt_run.report.call_args_list
        ]
        self.assertEqual(statuses, ["running", "failed"])
        self.assertEqual(helper.api.hunt_run.report.call_args.kwargs["error"], "down")

    def test_listen_hunt_tolerates_a_failure_already_reported(self):
        helper = _helper()
        helper.api.hunt_run.report.side_effect = [
            {"id": "run-1"},
            Exception("The hunt run is already terminated"),
        ]
        callback = _hunt_callback(helper, MagicMock(side_effect=RuntimeError("down")))
        with self.assertRaises(RuntimeError):
            callback(_event())
        helper.connector_logger.debug.assert_called_once()

    def test_listen_hunt_refuses_messages_that_are_not_hunt_runs(self):
        helper = _helper()
        callback = _hunt_callback(helper, MagicMock())
        with self.assertRaises(ValueError):
            callback(_event(event_type="INTERNAL_ENRICHMENT"))
        with self.assertRaises(ValueError):
            callback(_event(hunt_run={}))
        helper.api.hunt_run.report.assert_not_called()
