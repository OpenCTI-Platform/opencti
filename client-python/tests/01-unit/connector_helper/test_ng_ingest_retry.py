"""Unit tests for OpenCTINGConnectorHelper client-side transient-error retry.

The helper's real ``__init__`` decodes a JWT and builds an HTTP session, so the
tests construct a bare instance via ``__new__`` and set only the attributes the
retry path touches. ``_submit_and_wait`` is monkeypatched to return canned job
results without any network access.
"""

import json
from unittest import TestCase
from unittest.mock import patch

from pycti.connector.opencti_ng_connector_helper import OpenCTINGConnectorHelper


def _bare_helper(max_retries=3):
    helper = OpenCTINGConnectorHelper.__new__(OpenCTINGConnectorHelper)
    helper.connector_id = "connector--test"
    helper._ingest_max_retries = max_retries
    helper._ingest_retry_backoff = 0.0  # no real backoff in tests
    # Silence logging.
    helper.log_info = lambda *a, **k: None
    helper.log_warning = lambda *a, **k: None
    helper.log_error = lambda *a, **k: None
    return helper


def _bundle(*ids):
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--root",
            "spec_version": "2.1",
            "objects": [{"id": i, "type": i.split("--", 1)[0]} for i in ids],
        }
    )


class TestCollectRetryableObjects(TestCase):
    def test_given_transient_group_when_collect_then_maps_back_to_objects(self):
        helper = _bare_helper()
        objects_by_id = {"software--a": {"id": "software--a"}}
        result = {
            "errors": [
                {
                    "error_type": "database_transient",
                    "ids": ["software--a/software"],
                }
            ]
        }
        out = helper._collect_retryable_objects(result, objects_by_id)
        self.assertEqual(out, [{"id": "software--a"}])

    def test_given_validation_and_dangling_dependency_when_collect_then_skipped(self):
        helper = _bare_helper()
        objects_by_id = {
            "relationship--r": {"id": "relationship--r"},
            "malware--b": {"id": "malware--b"},
        }
        result = {
            "errors": [
                # Dangling dependency: the missing referent is in no bundle, so
                # resending the dependent can never satisfy it -> skip.
                {
                    "error_type": "dependency",
                    "ids": ["relationship--r/relationship"],
                    "dependency_id": "vulnerability--not-in-bundle",
                },
                {"error_type": "validation", "ids": ["malware--b/malware"]},
            ]
        }
        self.assertEqual(helper._collect_retryable_objects(result, objects_by_id), [])

    def test_given_dependency_on_in_bundle_referent_when_collect_then_dependent_and_referent(self):
        """The cascade case: a transient failure on a referent poisons its
        dependents. Both the referent (transient) and the dependents (dependency,
        referent in-bundle) must be collected so the retry sub-bundle heals the
        whole subgraph."""
        helper = _bare_helper()
        vuln_id = "vulnerability--c8d2"
        objects_by_id = {
            vuln_id: {"id": vuln_id},
            "relationship--1": {"id": "relationship--1"},
            "relationship--2": {"id": "relationship--2"},
        }
        result = {
            "errors": [
                {
                    "error_type": "dependency",
                    "ids": ["relationship--1/relationship", "relationship--2/relationship"],
                    "dependency_id": vuln_id,
                },
                {"error_type": "database_transient", "ids": [f"{vuln_id}/vulnerability"]},
            ]
        }
        out = helper._collect_retryable_objects(result, objects_by_id)
        ids = sorted(o["id"] for o in out)
        self.assertEqual(ids, ["relationship--1", "relationship--2", vuln_id])

    def test_given_unknown_id_when_collect_then_dropped(self):
        helper = _bare_helper()
        result = {
            "errors": [
                {"error_type": "conflict", "ids": ["software--missing/software"]}
            ]
        }
        self.assertEqual(helper._collect_retryable_objects(result, {}), [])

    def test_given_duplicate_ids_when_collect_then_deduplicated(self):
        helper = _bare_helper()
        objects_by_id = {"x--1": {"id": "x--1"}}
        result = {
            "errors": [
                {"error_type": "database_transient", "ids": ["x--1/x", "x--1/x"]}
            ]
        }
        self.assertEqual(helper._collect_retryable_objects(result, objects_by_id), [{"id": "x--1"}])


class TestSendStix2BundleRetry(TestCase):
    @patch("pycti.connector.opencti_ng_connector_helper.time.sleep", lambda *_: None)
    def test_given_transient_then_clean_when_send_then_retries_failed_object(self):
        helper = _bare_helper()
        calls = []

        def fake_submit(bundle_obj, ingest_ids):
            calls.append([o["id"] for o in bundle_obj["objects"]])
            if len(calls) == 1:
                return {
                    "ingestion_id": "job-1",
                    "errors": [
                        {
                            "error_type": "database_transient",
                            "ids": ["malware--b/malware"],
                        }
                    ],
                }
            return {"ingestion_id": "job-2", "errors": []}

        helper._submit_and_wait = fake_submit
        helper._report_result = lambda *a, **k: None

        ids = helper.send_stix2_bundle(_bundle("identity--a", "malware--b"))

        self.assertEqual(ids, ["job-1", "job-2"])
        self.assertEqual(calls[0], ["identity--a", "malware--b"])
        self.assertEqual(calls[1], ["malware--b"])  # only the failed object retried

    @patch("pycti.connector.opencti_ng_connector_helper.time.sleep", lambda *_: None)
    def test_given_persistent_transient_when_send_then_stops_at_max_retries(self):
        helper = _bare_helper(max_retries=2)
        calls = []

        def fake_submit(bundle_obj, ingest_ids):
            calls.append([o["id"] for o in bundle_obj["objects"]])
            return {
                "ingestion_id": f"job-{len(calls)}",
                "errors": [
                    {"error_type": "database_transient", "ids": ["x--1/x"]}
                ],
            }

        helper._submit_and_wait = fake_submit
        helper._report_result = lambda *a, **k: None

        ids = helper.send_stix2_bundle(_bundle("x--1"))

        # 1 initial submit + 2 retries = 3 attempts.
        self.assertEqual(len(calls), 3)
        self.assertEqual(ids, ["job-1", "job-2", "job-3"])

    @patch("pycti.connector.opencti_ng_connector_helper.time.sleep", lambda *_: None)
    def test_given_no_errors_when_send_then_no_retry(self):
        helper = _bare_helper()
        calls = []

        def fake_submit(bundle_obj, ingest_ids):
            calls.append(1)
            return {"ingestion_id": "job-1", "errors": []}

        helper._submit_and_wait = fake_submit
        helper._report_result = lambda *a, **k: None

        ids = helper.send_stix2_bundle(_bundle("malware--a"))
        self.assertEqual(ids, ["job-1"])
        self.assertEqual(len(calls), 1)
