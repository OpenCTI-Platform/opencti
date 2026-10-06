"""Tests of the Hunt and HuntRun entities (OpenCTI Hunts)."""

from unittest import TestCase
from unittest.mock import MagicMock

from pycti.entities.opencti_hunt import Hunt
from pycti.entities.opencti_hunt_run import HuntRun
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def _opencti(data):
    opencti = MagicMock()
    opencti.query.return_value = {"data": data}
    opencti.process_multiple_fields.side_effect = lambda value: value
    opencti.process_multiple.side_effect = lambda value, *_: [
        edge["node"] for edge in value["edges"]
    ]
    opencti.get_attribute_in_extension.return_value = None
    opencti.stix2.convert_markdown.side_effect = lambda value: value
    return opencti


def _variables(opencti):
    return opencti.query.call_args.args[1]


class TestHunt(TestCase):
    def test_generate_id_is_deterministic_and_case_insensitive(self):
        hunt_id = Hunt.generate_id("APT-X encoded PowerShell")
        self.assertTrue(hunt_id.startswith("hunt--"))
        self.assertEqual(hunt_id, Hunt.generate_id("  apt-x encoded powershell "))
        self.assertEqual(
            hunt_id, Hunt.generate_id_from_data({"name": "APT-X encoded PowerShell"})
        )

    def test_create_sends_the_hunt_definition(self):
        opencti = _opencti({"huntAdd": {"id": "hunt-1"}})
        result = Hunt(opencti).create(
            name="Hunt",
            hypothesis="If APT-X is active, PowerShell runs encoded commands",
            sigma_rule="title: t",
            native_queries=[
                {
                    "platform": "splunk",
                    "language": "spl",
                    "query": "index=main",
                    "pipeline": None,
                }
            ],
            hunt_schedule="0 * * * *",
            huntTechniques=["T1059.001"],
            objectMarking=["marking-1"],
        )
        self.assertEqual(result, {"id": "hunt-1"})
        hunt_input = _variables(opencti)["input"]
        self.assertEqual(hunt_input["name"], "Hunt")
        self.assertEqual(hunt_input["hunt_schedule"], "0 * * * *")
        self.assertEqual(hunt_input["huntTechniques"], ["T1059.001"])
        self.assertEqual(hunt_input["native_queries"][0]["platform"], "splunk")
        self.assertIsNone(hunt_input["hunt_type"])

    def test_create_sends_the_indicator_hunt_definition(self):
        opencti = _opencti({"huntAdd": {"id": "hunt-1"}})
        values = [{"observable_type": "IPv4-Addr", "value": "203.0.113.7"}]
        filters = '{"mode":"and","filters":[],"filterGroups":[]}'
        Hunt(opencti).create(
            name="Hunt",
            hunt_type="indicators",
            hunt_ioc_filters=filters,
            hunt_ioc_values=values,
        )
        hunt_input = _variables(opencti)["input"]
        self.assertEqual(hunt_input["hunt_type"], "indicators")
        self.assertEqual(hunt_input["hunt_ioc_filters"], filters)
        self.assertEqual(hunt_input["hunt_ioc_values"], values)

    def test_default_fields_read_the_indicator_hunt_definition(self):
        properties = Hunt(_opencti({})).properties
        self.assertIn("hunt_ioc_filters", properties)
        self.assertIn("hunt_ioc_values {", properties)
        self.assertIn("observable_type", properties)

    def test_default_fields_read_the_escalation_of_manual_runs(self):
        properties = Hunt(_opencti({})).properties
        self.assertIn("escalation_threshold", properties)
        self.assertIn("escalate_manual_runs", properties)

    def test_create_requires_a_name(self):
        opencti = _opencti({})
        self.assertIsNone(Hunt(opencti).create(hypothesis="h"))
        opencti.query.assert_not_called()

    def test_import_from_stix2_maps_the_refs_and_fields(self):
        opencti = _opencti({"huntAdd": {"id": "hunt-1"}})
        Hunt(opencti).import_from_stix2(
            stixObject={
                "id": "hunt--1",
                "type": "hunt",
                "name": "Hunt",
                "hunt_status": "draft",
                "hunt_source_kind": "hub",
                "sigma_rule": "title: t",
                "escalation_threshold": 5,
                "escalate_manual_runs": True,
                "target_refs": ["intrusion-set--1"],
                "technique_refs": ["attack-pattern--1"],
                "source_refs": ["indicator--1"],
            },
            extras={"created_by_id": "identity-1", "object_marking_ids": ["marking-1"]},
        )
        hunt_input = _variables(opencti)["input"]
        self.assertEqual(hunt_input["stix_id"], "hunt--1")
        self.assertEqual(hunt_input["hunt_status"], "draft")
        self.assertEqual(hunt_input["hunt_source_kind"], "hub")
        self.assertEqual(hunt_input["escalation_threshold"], 5)
        self.assertTrue(hunt_input["escalate_manual_runs"])
        self.assertEqual(hunt_input["huntTargets"], ["intrusion-set--1"])
        self.assertEqual(hunt_input["huntTechniques"], ["attack-pattern--1"])
        self.assertEqual(hunt_input["huntSources"], ["indicator--1"])
        self.assertEqual(hunt_input["createdBy"], "identity-1")
        self.assertEqual(hunt_input["objectMarking"], ["marking-1"])
        self.assertIsNone(hunt_input["hunt_ioc_filters"])

    def test_import_from_stix2_keeps_the_indicator_hunt_definition(self):
        opencti = _opencti({"huntAdd": {"id": "hunt-1"}})
        values = [{"observable_type": "Domain-Name", "value": "example.org"}]
        Hunt(opencti).import_from_stix2(
            stixObject={
                "id": "hunt--2",
                "type": "hunt",
                "name": "Indicator hunt",
                "hunt_type": "indicators",
                "hunt_ioc_filters": "",
                "hunt_ioc_values": values,
            },
        )
        hunt_input = _variables(opencti)["input"]
        self.assertEqual(hunt_input["hunt_type"], "indicators")
        self.assertEqual(hunt_input["hunt_ioc_values"], values)
        self.assertIsNone(hunt_input["hunt_ioc_filters"])

    def test_export_pack_returns_the_bundle(self):
        opencti = _opencti({"huntPackExport": '{"type": "bundle", "objects": []}'})
        self.assertEqual(Hunt(opencti).export_pack(ids=["hunt-1"])["type"], "bundle")
        self.assertIsNone(Hunt(opencti).export_pack(ids=[]))

    def test_start_runs_and_preview(self):
        opencti = _opencti(
            {"huntRunStart": [{"id": "run-1"}], "huntTestQuery": {"id": "preview-1"}}
        )
        hunt = Hunt(opencti)
        self.assertEqual(
            hunt.start_runs(id="hunt-1", time_window_hours=48), [{"id": "run-1"}]
        )
        self.assertEqual(_variables(opencti)["input"]["time_window_hours"], 48)
        self.assertEqual(
            hunt.preview(id="hunt-1", security_platform_id="sp-1"), {"id": "preview-1"}
        )
        self.assertEqual(_variables(opencti)["securityPlatformId"], "sp-1")

    def test_bundle_splitter_keeps_hunts(self):
        hunt = {
            "type": "hunt",
            "id": "hunt--8984f3bd-d90c-5c7b-8354-0309d9b78eaa",
            "name": "Encoded PowerShell",
        }
        bundle = {"type": "bundle", "id": "bundle--1", "objects": [hunt]}
        _, _, bundles = OpenCTIStix2Splitter().split_bundle_with_expectations(
            bundle, use_json=False
        )
        self.assertEqual(len(bundles), 1)
        self.assertEqual(bundles[0]["objects"][0]["id"], hunt["id"])


class TestHuntRun(TestCase):
    def test_report_refuses_statuses_a_connector_cannot_report(self):
        opencti = _opencti({})
        self.assertIsNone(HuntRun(opencti).report(id="run-1", status="queued"))
        opencti.query.assert_not_called()

    def test_report_sends_a_deadline_timeout(self):
        opencti = _opencti(
            {"huntRunReport": {"id": "run-1", "hunt_run_status": "timeout"}}
        )
        HuntRun(opencti).report(
            id="run-1", status="timeout", error="The run exceeded its deadline"
        )
        variables = opencti.query.call_args[0][1]
        self.assertEqual(variables["input"]["status"], "timeout")
        self.assertEqual(variables["input"]["error"], "The run exceeded its deadline")

    def test_report_sends_the_outcome(self):
        opencti = _opencti(
            {"huntRunReport": {"id": "run-1", "hunt_run_status": "completed"}}
        )
        HuntRun(opencti).report(
            id="run-1", status="completed", hits_count=4, translated_query="index=main"
        )
        variables = _variables(opencti)
        self.assertEqual(variables["id"], "run-1")
        self.assertEqual(variables["input"]["hits_count"], 4)
        self.assertEqual(variables["input"]["translated_query"], "index=main")
        self.assertNotIn("work_id", variables["input"])
        self.assertNotIn("hits_sample", variables["input"])

    def test_report_sends_the_hits_sample(self):
        opencti = _opencti(
            {"huntRunReport": {"id": "run-1", "hunt_run_status": "completed"}}
        )
        hits = [
            {
                "event_id": "evt-1",
                "timestamp": "2026-10-05T10:00:00Z",
                "matched": [
                    {
                        "field": "principal.ip",
                        "value_hash": "a" * 64,
                        "value_preview": "10.0.0.4",
                    }
                ],
                "host": "ws-042",
            }
        ]
        HuntRun(opencti).report(
            id="run-1", status="completed", hits_count=1, hits_sample=hits
        )
        self.assertEqual(_variables(opencti)["input"]["hits_sample"], hits)

    def test_report_sends_hit_keys_only_when_known(self):
        opencti = _opencti(
            {"huntRunReport": {"id": "run-1", "hunt_run_status": "completed"}}
        )
        keys = ("a" * 64, "b" * 64)
        HuntRun(opencti).report(
            id="run-1", status="completed", hits_count=2, hit_keys=keys
        )
        self.assertEqual(_variables(opencti)["input"]["hit_keys"], list(keys))
        HuntRun(opencti).report(id="run-1", status="completed", hits_count=2)
        self.assertNotIn("hit_keys", _variables(opencti)["input"])

    def test_report_sends_retryable_only_when_known(self):
        opencti = _opencti(
            {"huntRunReport": {"id": "run-1", "hunt_run_status": "failed"}}
        )
        HuntRun(opencti).report(
            id="run-1",
            status="failed",
            error="HuntTranslationError: boom",
            retryable=False,
        )
        self.assertIs(_variables(opencti)["input"]["retryable"], False)
        HuntRun(opencti).report(id="run-1", status="failed", error="boom")
        self.assertNotIn("retryable", _variables(opencti)["input"])

    def test_report_names_the_work_of_the_dispatch(self):
        opencti = _opencti(
            {"huntRunReport": {"id": "run-1", "hunt_run_status": "running"}}
        )
        HuntRun(opencti).report(id="run-1", status="running", work_id="work-1")
        self.assertEqual(_variables(opencti)["input"]["work_id"], "work-1")

    def test_set_verdict_validates_the_verdict(self):
        opencti = _opencti({"huntRunSetVerdict": {"id": "run-1", "verdict": "benign"}})
        run = HuntRun(opencti)
        self.assertIsNone(run.set_verdict(id="run-1", verdict="maybe"))
        # pending is the state of a run waiting for its verdict, never a verdict
        self.assertIsNone(run.set_verdict(id="run-1", verdict="pending"))
        self.assertEqual(opencti.query.call_count, 0)
        run.set_verdict(
            id="run-1",
            verdict="benign",
            hunt_analyst_feedback="admin tool",
            source="agent",
        )
        self.assertEqual(
            _variables(opencti)["input"],
            {
                "verdict": "benign",
                "hunt_analyst_feedback": "admin tool",
                "source": "agent",
            },
        )

    def test_add_evidence_requires_result_objects(self):
        opencti = _opencti({"huntRunEvidenceAdd": {"id": "run-1", "hits_count": 7}})
        run = HuntRun(opencti)
        self.assertIsNone(run.add_evidence(id="run-1", result_ids=[]))
        run.add_evidence(
            id="run-1",
            result_ids=["sighting--1"],
            hits_count=2,
            source="splunk-alert-action",
        )
        evidence_input = _variables(opencti)["input"]
        self.assertEqual(evidence_input["result_ids"], ["sighting--1"])
        self.assertEqual(evidence_input["source"], "splunk-alert-action")
        self.assertNotIn("hits_sample", evidence_input)
        hits = [{"event_id": "evt-2", "matched": [], "host": "ws-042"}]
        run.add_evidence(id="run-1", result_ids=["sighting--2"], hits_sample=hits)
        self.assertEqual(_variables(opencti)["input"]["hits_sample"], hits)
        self.assertNotIn("hit_keys", _variables(opencti)["input"])
        run.add_evidence(id="run-1", result_ids=["sighting--2"], hit_keys=["c" * 64])
        self.assertEqual(_variables(opencti)["input"]["hit_keys"], ["c" * 64])

    def test_register_connector_requires_the_platform_and_languages(self):
        opencti = _opencti({"huntConnectorRegister": {"id": "connector-1"}})
        run = HuntRun(opencti)
        self.assertIsNone(
            run.register_connector(
                connector_id="connector-1", platform="splunk", languages=[]
            )
        )
        run.register_connector(
            connector_id="connector-1", platform="internet", languages=["internet"]
        )
        registration = _variables(opencti)["input"]
        self.assertEqual(registration["platform"], "internet")
        self.assertTrue(registration["supports_preview"])

    def test_list_reads_the_runs(self):
        opencti = _opencti(
            {
                "huntRuns": {
                    "edges": [{"node": {"id": "run-1"}}],
                    "pageInfo": {"hasNextPage": False},
                }
            }
        )
        runs = HuntRun(opencti).list(
            filters={
                "mode": "and",
                "filters": [{"key": "hunt_id", "values": ["hunt-1"]}],
                "filterGroups": [],
            }
        )
        self.assertEqual(runs, [{"id": "run-1"}])

    def test_default_fields_tell_whether_the_hits_count_is_a_lower_bound(self):
        # The partial results flag is read with the counters it qualifies
        properties = HuntRun(_opencti({})).properties
        self.assertIn("hits_count", properties)
        self.assertIn("results_truncated", properties)
