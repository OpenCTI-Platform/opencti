"""Microbenchmark for deleting expired S3 bundles during retention cleanup."""

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
    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class _FakePaginator:
    def __init__(self, client):
        self.client = client

    def paginate(self, **kwargs):
        return [
            {"Contents": self.client.objects[index : index + 1000]}
            for index in range(0, len(self.client.objects), 1000)
        ]


class _FakeS3Client:
    def __init__(self, expired_files: int):
        last_modified = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=8)
        self.objects = [
            {"Key": f"bundles/benchmark-{index}.json", "LastModified": last_modified}
            for index in range(expired_files)
        ]
        self.delete_request_count = 0
        self.deleted_key_count = 0

    def get_paginator(self, name):
        if name != "list_objects_v2":
            raise AssertionError(f"Unexpected paginator {name}")
        return _FakePaginator(self)

    def delete_object(self, **kwargs):
        self.delete_request_count += 1
        self.deleted_key_count += 1

    def delete_objects(self, **kwargs):
        self.delete_request_count += 1
        self.deleted_key_count += len(kwargs["Delete"]["Objects"])


def _build_helper():
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.bundle_send_to_s3_bucket = "benchmark-bucket"
    helper.bundle_send_to_s3_folder = "bundles"
    helper.bundle_send_to_s3_retention = 7
    helper._s3_cleanup_lock = threading.Lock()
    helper._next_s3_cleanup_at = 0
    helper.connect_name = "benchmark"
    helper.connector_logger = _NoopLogger()
    return helper


def _run_once(expired_files: int) -> tuple[float, int, int, int]:
    client = _FakeS3Client(expired_files)
    helper = _build_helper()

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    helper._cleanup_old_s3_bundles(client)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return (
        elapsed_seconds,
        peak_bytes,
        client.delete_request_count,
        client.deleted_key_count,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expired-files", type=int, default=50000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.expired_files, 2))
    samples = [_run_once(args.expired_files) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    request_samples = [sample[2] for sample in samples]
    deleted_key_samples = [sample[3] for sample in samples]

    result = {
        "expired_files": args.expired_files,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_delete_requests": statistics.median(request_samples),
        "median_deleted_keys": statistics.median(deleted_key_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
