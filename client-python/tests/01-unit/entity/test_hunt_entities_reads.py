"""Tests of the reads, pagination and guards of the Hunt and HuntRun entities."""

from unittest import TestCase
from unittest.mock import MagicMock

from pycti.entities.opencti_hunt import Hunt
from pycti.entities.opencti_hunt_run import HuntRun


def _opencti(*pages):
    opencti = MagicMock()
    opencti.query.side_effect = [{"data": page} for page in pages]
    opencti.process_multiple_fields.side_effect = lambda value: value
    opencti.process_multiple.side_effect = lambda value, *_: [
        edge["node"] for edge in value["edges"]
    ]
    return opencti


def _page(key, ids, has_next, cursor=None):
    return {
        key: {
            "edges": [{"node": {"id": value}} for value in ids],
            "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
        }
    }


class TestHuntReads(TestCase):
    def test_list_get_all_follows_every_page(self):
        opencti = _opencti(
            _page("hunts", ["hunt-1"], True, "cursor-1"),
            _page("hunts", ["hunt-2"], False),
        )
        hunts = Hunt(opencti).list(getAll=True)
        self.assertEqual(hunts, [{"id": "hunt-1"}, {"id": "hunt-2"}])
        self.assertEqual(opencti.query.call_count, 2)
        self.assertEqual(opencti.query.call_args.args[1]["after"], "cursor-1")

    def test_read_by_id_returns_the_hunt(self):
        opencti = _opencti({"hunt": {"id": "hunt-1", "name": "Encoded PowerShell"}})
        hunt = Hunt(opencti).read(id="hunt-1")
        self.assertEqual(hunt["name"], "Encoded PowerShell")
        self.assertEqual(opencti.query.call_args.args[1], {"id": "hunt-1"})

    def test_read_without_id_or_filters_returns_none(self):
        opencti = _opencti()
        self.assertIsNone(Hunt(opencti).read())
        opencti.query.assert_not_called()

    def test_mutations_without_an_id_send_nothing(self):
        opencti = _opencti()
        hunt = Hunt(opencti)
        self.assertIsNone(hunt.start_runs())
        self.assertIsNone(hunt.preview())
        self.assertIsNone(hunt.delete())
        self.assertIsNone(hunt.import_from_stix2())
        opencti.query.assert_not_called()

    def test_delete_sends_the_id(self):
        opencti = _opencti({"huntDelete": "hunt-1"})
        self.assertIsNone(Hunt(opencti).delete(id="hunt-1"))
        self.assertEqual(opencti.query.call_args.args[1], {"id": "hunt-1"})


class TestHuntRunReads(TestCase):
    def test_list_get_all_follows_every_page(self):
        opencti = _opencti(
            _page("huntRuns", ["run-1"], True, "cursor-1"),
            _page("huntRuns", ["run-2"], False),
        )
        runs = HuntRun(opencti).list(getAll=True)
        self.assertEqual(runs, [{"id": "run-1"}, {"id": "run-2"}])
        self.assertEqual(opencti.query.call_args.args[1]["after"], "cursor-1")

    def test_read_requires_an_id(self):
        opencti = _opencti({"huntRun": {"id": "run-1"}})
        run = HuntRun(opencti)
        self.assertIsNone(run.read())
        self.assertEqual(run.read(id="run-1"), {"id": "run-1"})
        self.assertEqual(opencti.query.call_count, 1)

    def test_report_sends_truncation_and_ioc_results_only_when_known(self):
        opencti = _opencti({"huntRunReport": {"id": "run-1"}})
        ioc_results = [{"value": "1.2.3.4", "hits_count": 1}]
        HuntRun(opencti).report(
            id="run-1", status="completed", truncated=1, ioc_results=ioc_results
        )
        report_input = opencti.query.call_args.args[1]["input"]
        self.assertIs(report_input["truncated"], True)
        self.assertEqual(report_input["ioc_results"], ioc_results)

    def test_retry_requires_an_id(self):
        opencti = _opencti({"huntRunRetry": {"id": "run-2", "attempt": 2}})
        run = HuntRun(opencti)
        self.assertIsNone(run.retry())
        self.assertEqual(run.retry(id="run-1"), {"id": "run-2", "attempt": 2})
        self.assertEqual(opencti.query.call_args.args[1], {"id": "run-1"})

    def test_register_connector_sends_the_optional_declarations(self):
        opencti = _opencti({"huntConnectorRegister": {"id": "connector-1"}})
        permissions = [{"name": "search", "purpose": "run the hunt queries"}]
        HuntRun(opencti).register_connector(
            connector_id="connector-1",
            platform="splunk",
            languages=["spl"],
            required_permissions=permissions,
            documentation_url="https://docs.example.com/hunt",
        )
        registration = opencti.query.call_args.args[1]["input"]
        self.assertEqual(registration["required_permissions"], permissions)
        self.assertEqual(
            registration["documentation_url"], "https://docs.example.com/hunt"
        )

    def test_list_connectors_reads_the_alive_ones(self):
        opencti = _opencti({"huntConnectors": [{"id": "connector-1"}]})
        connectors = HuntRun(opencti).list_connectors(only_alive=True)
        self.assertEqual(connectors, [{"id": "connector-1"}])
        self.assertEqual(opencti.query.call_args.args[1], {"onlyAlive": True})
