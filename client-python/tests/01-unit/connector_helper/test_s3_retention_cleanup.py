import datetime
import threading

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class _NoopLogger:
    def __init__(self):
        self.warning_calls = []

    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        self.warning_calls.append((args, kwargs))

    def error(self, *args, **kwargs):
        pass


class _FakePaginator:
    def __init__(self, client):
        self.client = client

    def paginate(self, **kwargs):
        self.client.list_calls += 1
        return [{"Contents": self.client.objects}]


class _FakeS3Client:
    def __init__(self):
        self.objects = [
            {
                "Key": "bundles/test-retained.json",
                "LastModified": datetime.datetime.now(datetime.timezone.utc),
            }
        ]
        self.list_calls = 0
        self.put_calls = 0
        self.deleted_keys = []
        self.delete_requests = 0
        self.delete_errors = []

    def put_object(self, **kwargs):
        self.put_calls += 1

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _FakePaginator(self)

    def delete_objects(self, **kwargs):
        self.delete_requests += 1
        self.deleted_keys.extend(item["Key"] for item in kwargs["Delete"]["Objects"])
        return {"Errors": self.delete_errors}


def _helper(client):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.bundle_send_to_s3_bucket = "test-bucket"
    helper.bundle_send_to_s3_folder = "bundles"
    helper.bundle_send_to_s3_retention = 7
    helper._s3_client = client
    helper._s3_cleanup_lock = threading.Lock()
    helper._next_s3_cleanup_at = 0
    helper.connect_name = "test"
    helper.connector_logger = _NoopLogger()
    return helper


def test_send_bundle_to_s3_scans_retention_once_per_interval(monkeypatch):
    client = _FakeS3Client()
    helper = _helper(client)
    monotonic_values = iter([0, 1])
    monkeypatch.setattr(
        "pycti.connector.opencti_connector_helper.time.monotonic",
        lambda: next(monotonic_values),
    )

    helper._send_bundle_to_s3("{}", "bundle-one.json")
    helper._send_bundle_to_s3("{}", "bundle-two.json")

    assert client.put_calls == 2
    assert client.list_calls == 1


def test_send_bundle_to_s3_resumes_retention_scan_after_interval(monkeypatch):
    client = _FakeS3Client()
    helper = _helper(client)
    monotonic_values = iter([0, 61])
    monkeypatch.setattr(
        "pycti.connector.opencti_connector_helper.time.monotonic",
        lambda: next(monotonic_values),
    )

    helper._send_bundle_to_s3("{}", "bundle-one.json")
    helper._send_bundle_to_s3("{}", "bundle-two.json")

    assert client.put_calls == 2
    assert client.list_calls == 2


def test_send_bundle_to_s3_deletes_expired_bundle_on_scan():
    client = _FakeS3Client()
    client.objects[0]["LastModified"] = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(days=8)
    helper = _helper(client)

    helper._send_bundle_to_s3("{}", "bundle.json")

    assert client.deleted_keys == ["bundles/test-retained.json"]


def test_send_bundle_to_s3_batches_expired_bundle_deletes():
    client = _FakeS3Client()
    client.objects = [
        {
            "Key": f"bundles/test-retained-{index}.json",
            "LastModified": datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=8),
        }
        for index in range(1001)
    ]
    helper = _helper(client)

    helper._send_bundle_to_s3("{}", "bundle.json")

    assert client.delete_requests == 2
    assert len(client.deleted_keys) == 1001


def test_send_bundle_to_s3_warns_on_partial_bulk_delete_failure():
    client = _FakeS3Client()
    client.objects[0]["LastModified"] = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(days=8)
    client.delete_errors = [
        {"Key": "bundles/test-retained.json", "Code": "AccessDenied"}
    ]
    helper = _helper(client)

    helper._send_bundle_to_s3("{}", "bundle.json")

    assert helper.connector_logger.warning_calls == [
        (
            (
                "Failed to delete some expired S3 bundles",
                {
                    "count": 1,
                    "errors": [
                        {"Key": "bundles/test-retained.json", "Code": "AccessDenied"}
                    ],
                },
            ),
            {},
        )
    ]
