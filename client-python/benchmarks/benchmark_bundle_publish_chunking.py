"""Microbenchmark for connector bundle publish fanout.

The benchmark isolates OpenCTIConnectorHelper.send_stix2_bundle() with a fake
AMQP channel so it captures splitter and serialization cost without broker
latency. It records the number of queue messages and total serialized body
bytes emitted for a large independent-object bundle.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import threading
import time
import tracemalloc
from types import SimpleNamespace

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


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


class _FakeChannel:
    def __init__(self):
        self.publish_count = 0
        self.body_bytes = 0

    def basic_publish(self, **kwargs):
        body = kwargs["body"]
        self.publish_count += 1
        self.body_bytes += len(body.encode("utf-8"))


def _build_bundle(object_count: int) -> str:
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--publish-chunking-benchmark",
            "objects": [
                {
                    "id": f"indicator--{index}",
                    "type": "indicator",
                    "name": f"benchmark-{index}",
                }
                for index in range(object_count)
            ],
        }
    )


def _build_helper(channel: _FakeChannel) -> OpenCTIConnectorHelper:
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
        "push_exchange": "exchange",
        "push_routing": "routing",
    }
    helper.connector_logger = _NoopLogger()
    helper.connect_name = "benchmark"
    helper.metric = _NoopMetric()
    helper.connector_info = SimpleNamespace(buffering=False)
    helper.applicant_id = "benchmark-applicant"
    helper._publisher_lock = threading.RLock()
    helper._publisher_last_used_at = None
    helper._get_publisher_channel = lambda: channel
    return helper


def _run_once(
    object_count: int, max_bundle_objects: int
) -> tuple[float, int, int, int, int]:
    channel = _FakeChannel()
    helper = _build_helper(channel)
    bundle = _build_bundle(object_count)

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    bundles = helper.send_stix2_bundle(
        bundle, bundle_split_max_objects=max_bundle_objects
    )
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    emitted_objects = sum(
        len(json.loads(split_bundle)["objects"]) for split_bundle in bundles
    )
    if emitted_objects != object_count:
        raise AssertionError("published chunks did not preserve object count")

    return (
        elapsed_seconds,
        peak_bytes,
        channel.publish_count,
        channel.body_bytes,
        len(bundles),
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
    bundle_samples = [sample[4] for sample in samples]

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
        "median_returned_bundle_count": int(statistics.median(bundle_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
