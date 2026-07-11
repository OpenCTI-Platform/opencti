import base64
import json
import threading
from types import SimpleNamespace

import pika
from pika.exceptions import StreamLostError

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


class _NoopLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class _NoopMetric:
    def inc(self, *args, **kwargs):
        pass


class _FakeWork:
    def __init__(self):
        self.add_expectations_calls = []

    def add_expectations(self, work_id, expectations):
        self.add_expectations_calls.append((work_id, expectations))


class _FakeChannel:
    def __init__(self):
        self.is_closed = False
        self.confirm_delivery_calls = 0
        self.published = []

    def confirm_delivery(self):
        self.confirm_delivery_calls += 1

    def basic_publish(self, **kwargs):
        self.published.append(kwargs)

    def close(self):
        self.is_closed = True


class _FakeConnection:
    def __init__(self):
        self.is_closed = False
        self.channel_instance = _FakeChannel()
        self.channel_calls = 0
        self.process_data_events_calls = 0
        self.process_data_events_error = None

    def channel(self):
        self.channel_calls += 1
        return self.channel_instance

    def process_data_events(self, time_limit=0):
        assert time_limit == 0
        self.process_data_events_calls += 1
        if self.process_data_events_error is not None:
            raise self.process_data_events_error

    def close(self):
        self.is_closed = True


def _helper():
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.work_id = None
    helper.validation_mode = "workbench"
    helper.draft_id = None
    helper.force_validation = False
    helper.bundle_send_to_queue = True
    helper.bundle_send_to_directory = False
    helper.bundle_send_to_directory_path = None
    helper.bundle_send_to_directory_retention = 0
    helper.bundle_send_to_s3 = False
    helper.enrichment_shared_organizations = None
    helper.playbook = None
    helper.connect_validate_before_import = False
    helper.queue_protocol = "amqp"
    helper.connector_config = {
        "connection": {
            "host": "rabbitmq",
            "port": 5672,
            "vhost": "/",
            "user": "guest",
            "pass": "guest",
            "use_ssl": False,
        },
        "push_exchange": "exchange",
        "push_routing": "routing",
    }
    helper.config = {}
    helper.connector_logger = _NoopLogger()
    helper.connect_name = "test"
    helper.metric = _NoopMetric()
    helper.connector_info = SimpleNamespace(buffering=False)
    helper.applicant_id = "applicant"
    helper._publisher_lock = threading.RLock()
    helper._publisher_connection = None
    helper._publisher_channel = None
    helper._publisher_heartbeat = 10
    helper._publisher_last_used_at = None
    helper.bundle_split_max_bytes = 1000000
    return helper


def test_send_stix2_bundle_reuses_publisher_connection(monkeypatch):
    connections = []

    def create_connection(_parameters):
        connection = _FakeConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(pika, "BlockingConnection", create_connection)
    helper = _helper()
    bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": []})

    helper.send_stix2_bundle(bundle, no_split=True)
    helper.send_stix2_bundle(bundle, no_split=True)

    assert len(connections) == 1
    assert connections[0].channel_calls == 1
    assert connections[0].channel_instance.confirm_delivery_calls == 1
    assert connections[0].process_data_events_calls == 1
    assert len(connections[0].channel_instance.published) == 2

    helper._close_publisher_connection()
    assert connections[0].channel_instance.is_closed is True
    assert connections[0].is_closed is True


def test_send_stix2_bundle_reopens_closed_publisher_connection(monkeypatch):
    connections = []

    def create_connection(_parameters):
        connection = _FakeConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(pika, "BlockingConnection", create_connection)
    helper = _helper()
    bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": []})

    helper.send_stix2_bundle(bundle, no_split=True)
    connections[0].is_closed = True
    connections[0].channel_instance.is_closed = True
    helper.send_stix2_bundle(bundle, no_split=True)

    assert len(connections) == 2
    assert len(connections[1].channel_instance.published) == 1


def test_send_stix2_bundle_reopens_idle_publisher_connection(monkeypatch):
    connections = []
    monotonic_values = iter([0, 11, 11])

    def create_connection(_parameters):
        connection = _FakeConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(pika, "BlockingConnection", create_connection)
    monkeypatch.setattr(
        "pycti.connector.opencti_connector_helper.time.monotonic",
        lambda: next(monotonic_values),
    )
    helper = _helper()
    bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": []})

    helper.send_stix2_bundle(bundle, no_split=True)
    helper.send_stix2_bundle(bundle, no_split=True)

    assert len(connections) == 2
    assert connections[0].channel_instance.is_closed is True
    assert connections[0].is_closed is True
    assert len(connections[1].channel_instance.published) == 1


def test_send_stix2_bundle_reopens_failed_publisher_connection(monkeypatch):
    connections = []

    def create_connection(_parameters):
        connection = _FakeConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(pika, "BlockingConnection", create_connection)
    helper = _helper()
    bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": []})

    helper.send_stix2_bundle(bundle, no_split=True)
    connections[0].process_data_events_error = StreamLostError("stale connection")
    helper.send_stix2_bundle(bundle, no_split=True)

    assert len(connections) == 2
    assert connections[0].channel_instance.is_closed is True
    assert connections[0].is_closed is True
    assert len(connections[1].channel_instance.published) == 1


def test_send_stix2_bundle_publishes_bounded_chunks_with_item_expectations(monkeypatch):
    connections = []

    def create_connection(_parameters):
        connection = _FakeConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(pika, "BlockingConnection", create_connection)
    helper = _helper()
    helper.bundle_split_max_objects = 2
    helper.api = SimpleNamespace(work=_FakeWork())
    bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--chunked",
            "objects": [
                {"id": "indicator--1", "type": "indicator"},
                {"id": "indicator--2", "type": "indicator"},
                {"id": "indicator--3", "type": "indicator"},
            ],
        }
    )

    bundles = helper.send_stix2_bundle(bundle, work_id="work--1")

    messages = [
        json.loads(published["body"])
        for published in connections[0].channel_instance.published
    ]
    published_object_counts = [
        len(json.loads(base64.b64decode(message["content"]).decode("utf-8"))["objects"])
        for message in messages
    ]

    assert len(bundles) == 2
    assert helper.api.work.add_expectations_calls == [("work--1", 3)]
    assert published_object_counts == [2, 1]
    assert [message["no_split"] for message in messages] == [True, True]


def test_send_stix2_bundle_publishes_byte_bounded_chunks(monkeypatch):
    connections = []

    def create_connection(_parameters):
        connection = _FakeConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(pika, "BlockingConnection", create_connection)
    helper = _helper()
    helper.bundle_split_max_objects = 3
    objects = [
        {
            "id": f"indicator--{index}",
            "type": "indicator",
            "description": "x" * 128,
        }
        for index in range(3)
    ]
    sized_objects = [{**item, "nb_deps": 1} for item in objects]
    helper.bundle_split_max_bytes = (
        len(
            OpenCTIStix2Splitter.stix2_create_bundle(
                "bundle--byte-chunked",
                1,
                sized_objects,
                True,
            ).encode("utf-8")
        )
        - 1
    )
    bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--byte-chunked",
            "objects": objects,
        }
    )

    bundles = helper.send_stix2_bundle(bundle)

    messages = [
        json.loads(published["body"])
        for published in connections[0].channel_instance.published
    ]
    assert len(bundles) == 2
    assert all(
        len(split_bundle.encode("utf-8")) <= helper.bundle_split_max_bytes
        for split_bundle in bundles
    )
    assert [message["no_split"] for message in messages] == [True, True]
