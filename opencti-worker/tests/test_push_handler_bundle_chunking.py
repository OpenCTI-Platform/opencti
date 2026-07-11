from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

WORKER_SRC = Path(__file__).resolve().parents[1] / "src"
if str(WORKER_SRC) not in sys.path:
    sys.path.insert(0, str(WORKER_SRC))

import push_handler  # noqa: E402


class _NoopLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class _NoopMetric:
    def add(self, *args, **kwargs):
        pass

    def record(self, *args, **kwargs):
        pass


class _FakeWork:
    def __init__(self):
        self.add_expectations_calls = []

    def add_expectations(self, work_id, expectations):
        self.add_expectations_calls.append((work_id, expectations))
        return True


class _FakeApi:
    def __init__(self):
        self.work = _FakeWork()

    def set_applicant_id_header(self, *args, **kwargs):
        pass

    def set_playbook_id_header(self, *args, **kwargs):
        pass

    def set_event_id(self, *args, **kwargs):
        pass

    def set_draft_id(self, *args, **kwargs):
        pass

    def set_synchronized_upsert_header(self, *args, **kwargs):
        pass

    def set_previous_standard_header(self, *args, **kwargs):
        pass

    def set_work_id(self, *args, **kwargs):
        pass


class _FakeChannel:
    def __init__(self, published):
        self.published = published

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def confirm_delivery(self):
        pass

    def basic_publish(self, **kwargs):
        self.published.append(kwargs["body"])


class _FakeConnection:
    def __init__(self, published):
        self.channel_instance = _FakeChannel(published)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def channel(self):
        return self.channel_instance


def _build_handler(max_bundle_objects=2):
    handler = object.__new__(push_handler.PushHandler)
    handler.logger = _NoopLogger()
    handler.push_exchange = "exchange"
    handler.listen_exchange = "listen-exchange"
    handler.push_routing = "routing"
    handler.dead_letter_routing = "dead-letter"
    handler.pika_parameters = object()
    handler.bundles_global_counter = _NoopMetric()
    handler.bundles_processing_time_gauge = _NoopMetric()
    handler.objects_max_refs = 0
    handler.bundle_split_max_objects = max_bundle_objects
    handler.api = _FakeApi()
    return handler


def _build_body():
    bundle = {
        "type": "bundle",
        "id": "bundle--worker-chunking",
        "objects": [
            {"id": "indicator--1", "type": "indicator"},
            {"id": "indicator--2", "type": "indicator"},
            {"id": "indicator--3", "type": "indicator"},
        ],
    }
    return json.dumps(
        {
            "type": "bundle",
            "content": base64.b64encode(json.dumps(bundle).encode("utf-8")).decode(
                "utf-8"
            ),
            "work_id": "work--1",
            "update": True,
        }
    )


def _run_handler(monkeypatch, max_bundle_objects=2):
    published = []
    monkeypatch.setattr(
        push_handler.pika,
        "BlockingConnection",
        lambda _parameters: _FakeConnection(published),
    )
    handler = _build_handler(max_bundle_objects)

    result = handler.handle_message(_build_body())

    messages = [json.loads(body) for body in published]
    object_counts = [
        len(json.loads(base64.b64decode(message["content"]).decode("utf-8"))["objects"])
        for message in messages
    ]

    return handler, result, messages, object_counts


def test_handle_message_requeues_bounded_chunks_with_item_expectations(monkeypatch):
    handler, result, messages, object_counts = _run_handler(monkeypatch)

    assert result == "ack"
    assert handler.api.work.add_expectations_calls == [("work--1", 3)]
    assert object_counts == [2, 1]
    assert [message["no_split"] for message in messages] == [True, True]


def test_handle_message_preserves_one_object_handoff_when_chunking_is_disabled(
    monkeypatch,
):
    handler, result, messages, object_counts = _run_handler(monkeypatch, 1)

    assert result == "ack"
    assert handler.api.work.add_expectations_calls == [("work--1", 3)]
    assert object_counts == [1, 1, 1]
    assert all("no_split" not in message for message in messages)
