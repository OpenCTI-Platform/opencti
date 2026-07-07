import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class _NoopLogger:
    def info(self, *args, **kwargs):
        pass


class _NoopMetric:
    def inc(self, *args, **kwargs):
        pass


def _helper(directory: str):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.work_id = None
    helper.validation_mode = "workbench"
    helper.draft_id = None
    helper.force_validation = False
    helper.bundle_send_to_queue = False
    helper.bundle_send_to_directory = True
    helper.bundle_send_to_directory_path = directory
    helper.bundle_send_to_directory_retention = 7
    helper._directory_cleanup_lock = threading.Lock()
    helper._directory_cleanup_deadlines = {}
    helper.bundle_send_to_s3 = False
    helper.enrichment_shared_organizations = None
    helper.playbook = None
    helper.connect_validate_before_import = False
    helper.connect_name = "test"
    helper.connect_id = "test-id"
    helper.connect_type = "EXTERNAL_IMPORT"
    helper.connect_scope = "test"
    helper.connect_auto = False
    helper.applicant_id = "applicant"
    helper.connector_logger = _NoopLogger()
    helper.metric = _NoopMetric()
    helper.connector_info = SimpleNamespace(buffering=False)
    return helper


def test_send_stix2_bundle_scans_directory_retention_once_per_interval(
    monkeypatch, tmp_path
):
    retained_file = tmp_path / "retained.json"
    retained_file.write_text("{}", encoding="utf-8")
    helper = _helper(str(tmp_path))
    bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": []})
    listdir_calls = 0
    real_listdir = os.listdir

    def tracked_listdir(path):
        nonlocal listdir_calls
        listdir_calls += 1
        return real_listdir(path)

    monotonic_values = iter([0, 1])
    bundle_names = iter(["bundle-one.json", "bundle-two.json"])
    monkeypatch.setattr(os, "listdir", tracked_listdir)
    monkeypatch.setattr(
        "pycti.connector.opencti_connector_helper.time.monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(helper, "_generate_bundle_filename", lambda: next(bundle_names))

    helper.send_stix2_bundle(bundle, no_split=True)
    helper.send_stix2_bundle(bundle, no_split=True)

    assert listdir_calls == 1
    assert retained_file.exists()
    assert len(list(Path(tmp_path).glob("*.json"))) == 3


def test_generate_bundle_filename_is_unique_with_same_clock_tick(monkeypatch):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.connect_name = "Test Connector"
    monkeypatch.setattr(
        "pycti.connector.opencti_connector_helper.time.strftime",
        lambda _format: "20260707-093031-",
    )
    monkeypatch.setattr(
        "pycti.connector.opencti_connector_helper.time.time", lambda: 1783434631.0
    )

    first_name = helper._generate_bundle_filename()
    second_name = helper._generate_bundle_filename()

    assert first_name.startswith("test_connector-20260707-093031-")
    assert first_name != second_name


def test_send_stix2_bundle_removes_expired_directory_bundle(monkeypatch, tmp_path):
    expired_file = tmp_path / "expired.json"
    expired_file.write_text("{}", encoding="utf-8")
    os.utime(expired_file, (0, 0))
    helper = _helper(str(tmp_path))
    bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": []})
    monkeypatch.setattr(helper, "_generate_bundle_filename", lambda: "current.json")

    helper.send_stix2_bundle(bundle, no_split=True)

    assert expired_file.exists() is False
    assert (tmp_path / "current.json").exists() is True
