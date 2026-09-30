from types import MethodType, SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class FakeWorkApi:
    def __init__(self, already_open=()):
        self.open = set(already_open)
        self.processed = []

    def open_work_ids(self):
        return set(self.open)

    def initiate(self, work_id):
        self.open.add(work_id)

    def to_processed(self, work_id, message, in_error=False):
        self.open.discard(work_id)
        self.processed.append((work_id, message, in_error))


def make_helper(work_api):
    helper = SimpleNamespace(
        api=SimpleNamespace(work=work_api), connector_logger=MagicMock()
    )
    helper._run_connector_process = MethodType(
        OpenCTIConnectorHelper._run_connector_process, helper
    )
    helper._close_run_works = MethodType(
        OpenCTIConnectorHelper._close_run_works, helper
    )
    return helper


class TestRunConnectorProcess(TestCase):
    def test_closes_the_works_the_run_left_open(self):
        work_api = FakeWorkApi(already_open={"work_before"})
        helper = make_helper(work_api)

        def run():
            work_api.initiate("work_a")
            work_api.initiate("work_b")
            work_api.to_processed("work_b", "closed by the connector")

        helper._run_connector_process(run)
        self.assertIn(("work_a", "Run finished", False), work_api.processed)
        self.assertEqual(work_api.open, {"work_before"})

    def test_closes_in_error_and_reraises_when_the_run_fails(self):
        work_api = FakeWorkApi()
        helper = make_helper(work_api)

        def run():
            work_api.initiate("work_a")
            raise ValueError("API unreachable")

        with self.assertRaises(ValueError):
            helper._run_connector_process(run)
        work_id, message, in_error = work_api.processed[0]
        self.assertEqual(work_id, "work_a")
        self.assertTrue(in_error)
        self.assertIn("API unreachable", message)

    def test_a_clean_exit_is_a_finished_run(self):
        work_api = FakeWorkApi()
        helper = make_helper(work_api)

        def run():
            work_api.initiate("work_a")
            raise SystemExit(0)

        with self.assertRaises(SystemExit):
            helper._run_connector_process(run)
        self.assertEqual(work_api.processed, [("work_a", "Run finished", False)])
