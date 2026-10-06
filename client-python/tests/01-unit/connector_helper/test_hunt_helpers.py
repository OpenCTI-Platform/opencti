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
    # The work of the message being processed, set by listen() for each message
    helper.work_id = "work-1"
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
            supports_indicators=False,
            max_concurrent_runs=None,
            required_permissions=None,
            documentation_url=None,
        )

    def test_register_hunt_platform_declares_its_required_permissions(self):
        helper = _helper()
        permissions = [{"name": "search", "purpose": "Run the hunt searches"}]
        helper.register_hunt_platform(
            "splunk",
            ["spl"],
            required_permissions=permissions,
            documentation_url="https://docs.example.com/splunk",
        )
        kwargs = helper.api.hunt_run.register_connector.call_args.kwargs
        self.assertEqual(kwargs["required_permissions"], permissions)
        self.assertEqual(kwargs["documentation_url"], "https://docs.example.com/splunk")

    def test_report_hunt_connection_check_forwards_the_checks(self):
        helper = _helper()
        checks = [{"name": "search", "ok": True, "message": "Allowed"}]
        helper.report_hunt_connection_check("check-1", checks)
        helper.api.hunt_run.report_connection_check.assert_called_once_with(
            connector_id="connector-1", check_id="check-1", checks=checks
        )

    def test_listen_hunt_answers_a_connection_test_without_a_run(self):
        helper = _helper()
        message_callback = MagicMock(return_value="checked")
        callback = _hunt_callback(helper, message_callback)
        event = _event(mode="check", hunt_run=None, connection_check={"id": "check-1"})
        self.assertEqual(callback(event), "checked")
        helper.api.hunt_run.report.assert_not_called()

    def test_listen_hunt_reports_a_failed_connection_test(self):
        helper = _helper()
        callback = _hunt_callback(helper, MagicMock(side_effect=RuntimeError("down")))
        event = _event(mode="check", hunt_run=None, connection_check={"id": "check-1"})
        with self.assertRaises(RuntimeError):
            callback(event)
        checks = helper.api.hunt_run.report_connection_check.call_args.kwargs["checks"]
        self.assertEqual(checks[0]["message"], "down")
        self.assertFalse(checks[0]["ok"])
        with self.assertRaises(ValueError):
            callback(_event(mode="check", connection_check={}))

    def test_register_hunt_platform_declares_indicator_lookups(self):
        helper = _helper()
        helper.register_hunt_platform(
            "splunk",
            ["spl"],
            security_platform_name="Splunk prod",
            supports_indicators=True,
        )
        self.assertTrue(
            helper.api.hunt_run.register_connector.call_args.kwargs[
                "supports_indicators"
            ]
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
            "run-1",
            "completed",
            hits_count=3,
            result_ids=["sighting--1"],
            truncated=True,
        )
        helper.api.hunt_run.report.assert_called_once_with(
            work_id="work-1",
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
            truncated=True,
            ioc_results=None,
            hits_sample=None,
            retryable=None,
            hit_keys=None,
        )

    def test_report_hunt_run_forwards_the_hit_keys(self):
        helper = _helper()
        keys = ["a" * 64, "b" * 64]
        helper.report_hunt_run("run-1", "completed", hits_count=2, hit_keys=keys)
        self.assertEqual(helper.api.hunt_run.report.call_args.kwargs["hit_keys"], keys)

    def test_report_hunt_run_forwards_the_results_per_value(self):
        helper = _helper()
        results = [{"key": "k-1", "seen": True, "hits_count": 2}]
        helper.report_hunt_run("run-1", "completed", ioc_results=results)
        self.assertEqual(
            helper.api.hunt_run.report.call_args.kwargs["ioc_results"], results
        )

    def test_report_hunt_run_forwards_the_hits_sample(self):
        helper = _helper()
        hits = [
            {
                "event_id": "evt-1",
                "timestamp": "2026-10-05T10:00:00Z",
                "detection": None,
                "matched": [
                    {
                        "field": "target.process.command_line",
                        "value_hash": "a" * 64,
                        "value_preview": "powershell -enc ",
                    }
                ],
                "host": "ws-042",
                "user": "jdoe",
                "process": "powershell.exe",
            }
        ]
        helper.report_hunt_run("run-1", "completed", hits_count=1, hits_sample=hits)
        self.assertEqual(
            helper.api.hunt_run.report.call_args.kwargs["hits_sample"], hits
        )

    def test_report_hunt_run_forwards_whether_the_failure_is_retryable(self):
        helper = _helper()
        helper.report_hunt_run(
            "run-1", "failed", error="HuntTranslationError: boom", retryable=False
        )
        self.assertIs(helper.api.hunt_run.report.call_args.kwargs["retryable"], False)

    def test_report_hunt_run_names_the_work_it_was_given(self):
        helper = _helper()
        helper.report_hunt_run("run-1", "failed", error="boom", work_id="work-2")
        self.assertEqual(
            helper.api.hunt_run.report.call_args.kwargs["work_id"], "work-2"
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

    def test_listen_hunt_does_not_report_again_a_failure_the_callback_reported(self):
        helper = _helper()
        error = TimeoutError("no answer within 30 seconds")
        error.hunt_run_reported = True
        callback = _hunt_callback(helper, MagicMock(side_effect=error))
        with self.assertRaises(TimeoutError):
            callback(_event())
        statuses = [
            call.kwargs["status"] for call in helper.api.hunt_run.report.call_args_list
        ]
        self.assertEqual(statuses, ["running"])

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
