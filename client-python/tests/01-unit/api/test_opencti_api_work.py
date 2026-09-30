from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock

from pycti.api.opencti_api_work import OpenCTIApiWork


def make_work_api():
    api = SimpleNamespace(
        bundle_send_to_queue=True,
        app_logger=MagicMock(),
        query=MagicMock(return_value={"data": {"workAdd": {"id": "work_c_1"}}}),
    )
    return OpenCTIApiWork(api), api


class TestOpenCTIApiWork(TestCase):
    def test_initiate_work_is_multipart_by_default(self):
        work, api = make_work_api()
        work.initiate_work("connector-id", "run")
        variables = api.query.call_args[0][1]
        self.assertTrue(variables["isMultiPartWork"])

    def test_initiate_work_keeps_an_explicit_single_part(self):
        work, api = make_work_api()
        work.initiate_work("connector-id", "run", is_multipart=False)
        self.assertFalse(api.query.call_args[0][1]["isMultiPartWork"])

    def test_open_works_are_tracked_until_processed(self):
        work, _ = make_work_api()
        work_id = work.initiate_work("connector-id", "run")
        self.assertEqual(work.open_work_ids(), {work_id})
        work.to_processed(work_id, "done")
        self.assertEqual(work.open_work_ids(), set())

    def test_auto_close_false_is_not_tracked(self):
        work, _ = make_work_api()
        work.initiate_work("connector-id", "run", auto_close=False)
        self.assertEqual(work.open_work_ids(), set())
