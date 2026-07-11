"""Microbenchmark for worker-side STIX bundle requeue fanout.

The benchmark isolates PushHandler.handle_message() with fake API and AMQP
objects so it captures splitter and serialization cost without broker latency.
It records the number of queue messages and total serialized body bytes emitted
when an unsplit platform-originated bundle reaches the worker.
"""

from __future__ import annotations

import argparse
import base64
import gc
import json
import statistics
import sys
import time
import tracemalloc
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
    def __init__(self):
        self.published = []

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
        self.channel_instance = _FakeChannel()
        self.published = published

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def channel(self):
        original_basic_publish = self.channel_instance.basic_publish

        def basic_publish(**kwargs):
            original_basic_publish(**kwargs)
            self.published.append(kwargs["body"])

        self.channel_instance.basic_publish = basic_publish
        return self.channel_instance


def _build_body(object_count: int) -> str:
    bundle = {
        "type": "bundle",
        "id": "bundle--worker-requeue-benchmark",
        "objects": [
            {
                "id": f"indicator--{index}",
                "type": "indicator",
                "name": f"benchmark-{index}",
            }
            for index in range(object_count)
        ],
    }
    return json.dumps(
        {
            "type": "bundle",
            "content": base64.b64encode(json.dumps(bundle).encode("utf-8")).decode(
                "utf-8"
            ),
            "work_id": "work--benchmark",
            "update": True,
        }
    )


def _build_handler(max_bundle_objects: int):
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


def _run_once(
    object_count: int, max_bundle_objects: int
) -> tuple[float, int, int, int, int, int]:
    published = []
    handler = _build_handler(max_bundle_objects)
    body = _build_body(object_count)
    original_blocking_connection = push_handler.pika.BlockingConnection
    push_handler.pika.BlockingConnection = lambda _parameters: _FakeConnection(
        published
    )
    try:
        gc.collect()
        tracemalloc.start()
        started_at = time.perf_counter()
        result = handler.handle_message(body)
        elapsed_seconds = time.perf_counter() - started_at
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        push_handler.pika.BlockingConnection = original_blocking_connection

    if result != "ack":
        raise AssertionError(f"worker returned {result!r} instead of 'ack'")
    if handler.api.work.add_expectations_calls != [("work--benchmark", object_count)]:
        raise AssertionError("worker did not preserve per-item work expectations")

    requeued_object_count = 0
    no_split_count = 0
    for message_body in published:
        message = json.loads(message_body)
        requeued_bundle = json.loads(
            base64.b64decode(message["content"]).decode("utf-8")
        )
        requeued_object_count += len(requeued_bundle["objects"])
        no_split_count += int(bool(message.get("no_split", False)))

    if requeued_object_count != object_count:
        raise AssertionError("worker requeue did not preserve object count")

    return (
        elapsed_seconds,
        peak_bytes,
        len(published),
        sum(len(message.encode("utf-8")) for message in published),
        requeued_object_count,
        no_split_count,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--max-bundle-objects", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100), args.max_bundle_objects)
    samples = [
        _run_once(args.objects, args.max_bundle_objects) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    publish_samples = [sample[2] for sample in samples]
    body_byte_samples = [sample[3] for sample in samples]
    object_samples = [sample[4] for sample in samples]
    no_split_samples = [sample[5] for sample in samples]

    result = {
        "objects": args.objects,
        "max_bundle_objects": args.max_bundle_objects,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_publish_count": int(statistics.median(publish_samples)),
        "median_body_bytes": int(statistics.median(body_byte_samples)),
        "median_requeued_object_count": int(statistics.median(object_samples)),
        "median_no_split_count": int(statistics.median(no_split_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
