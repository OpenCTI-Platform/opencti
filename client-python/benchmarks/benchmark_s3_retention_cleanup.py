"""Microbenchmark for S3 retention scans during bundle uploads."""

from __future__ import annotations

import argparse
import datetime
import gc
import json
import statistics
import threading
import time
import tracemalloc

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class _NoopLogger:
    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class _FakePaginator:
    def __init__(self, client):
        self.client = client

    def paginate(self, **kwargs):
        self.client.list_calls += 1
        return [{"Contents": self.client.objects}]


class _FakeS3Client:
    def __init__(self, retained_files: int):
        last_modified = datetime.datetime.now(datetime.timezone.utc)
        self.objects = [
            {"Key": f"benchmark-{index}.json", "LastModified": last_modified}
            for index in range(retained_files)
        ]
        self.list_calls = 0

    def put_object(self, **kwargs):
        pass

    def get_paginator(self, name):
        if name != "list_objects_v2":
            raise AssertionError(f"Unexpected paginator {name}")
        return _FakePaginator(self)

    def delete_object(self, **kwargs):
        pass


def _build_helper(client: _FakeS3Client):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.bundle_send_to_s3_bucket = "benchmark-bucket"
    helper.bundle_send_to_s3_folder = "bundles"
    helper.bundle_send_to_s3_retention = 7
    helper._s3_client = client
    helper._s3_cleanup_lock = threading.Lock()
    helper._next_s3_cleanup_at = 0
    helper.connect_name = "benchmark"
    helper.connector_logger = _NoopLogger()
    return helper


def _run_once(iterations: int, retained_files: int) -> tuple[float, int, int]:
    client = _FakeS3Client(retained_files)
    helper = _build_helper(client)
    bundle = json.dumps({"type": "bundle", "id": "bundle--benchmark", "objects": []})

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    for index in range(iterations):
        helper._send_bundle_to_s3(bundle, f"bundle-{index}.json")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return elapsed_seconds, peak_bytes, client.list_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--retained-files", type=int, default=5000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 2), args.retained_files)
    samples = [
        _run_once(args.iterations, args.retained_files) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    list_call_samples = [sample[2] for sample in samples]

    result = {
        "iterations": args.iterations,
        "retained_files": args.retained_files,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_list_calls": statistics.median(list_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
