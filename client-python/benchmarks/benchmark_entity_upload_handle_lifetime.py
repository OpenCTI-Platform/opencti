"""Benchmark entity-wrapper upload file-handle lifetime.

The benchmark isolates the path-based upload helpers on the entity wrappers
that open files themselves. A synthetic client retains each upload object
after the synchronous query returns so wrapper-owned handles that were not
closed remain observable and contribute to the process descriptor count.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import json
import os
import statistics
import tempfile
import time
from ctypes import wintypes

from pycti.api.opencti_api_client import File
from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.entities.opencti_stix_domain_object import StixDomainObject


class _NullLogger:
    def info(self, *args, **kwargs):
        del args, kwargs

    def error(self, *args, **kwargs):
        del args, kwargs


class _RetainingClient:
    def __init__(self):
        self.app_logger = _NullLogger()
        self.retained_uploads = []

    @staticmethod
    def file(name, data, mime):
        return File(name, data, mime)

    def query(self, query, variables):
        del query
        self.retained_uploads.append(variables["file"])
        return {"data": {"artifactImport": {"id": "artifact--benchmark"}}}

    @staticmethod
    def process_multiple_fields(data):
        return data


def _descriptor_count():
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessHandleCount.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.GetProcessHandleCount.restype = wintypes.BOOL
        count = wintypes.DWORD()
        if kernel32.GetProcessHandleCount(
            kernel32.GetCurrentProcess(), ctypes.byref(count)
        ):
            return count.value
        return None
    proc_fd = "/proc/self/fd"
    if os.path.isdir(proc_fd):
        return len(os.listdir(proc_fd))
    return None


def _run_once(file_name: str, iterations: int) -> tuple[float, int, int | None]:
    client = _RetainingClient()
    external_reference = ExternalReference(client)
    stix_domain_object = StixDomainObject(client)
    stix_cyber_observable = StixCyberObservable(client)
    operations = (
        lambda: external_reference.add_file(
            id="external-reference--1", file_name=file_name
        ),
        lambda: stix_domain_object.add_file(id="report--1", file_name=file_name),
        lambda: stix_cyber_observable.add_file(id="artifact--1", file_name=file_name),
        lambda: stix_cyber_observable.upload_artifact(file_name=file_name),
    )

    gc.collect()
    before_descriptors = _descriptor_count()
    started_at = time.perf_counter()
    try:
        for _ in range(iterations):
            for operation in operations:
                operation()
        elapsed_seconds = time.perf_counter() - started_at
        open_wrapper_handles = sum(
            1 for upload in client.retained_uploads if not upload.data.closed
        )
        after_descriptors = _descriptor_count()
        descriptor_delta = (
            None
            if before_descriptors is None or after_descriptors is None
            else after_descriptors - before_descriptors
        )
        return elapsed_seconds, open_wrapper_handles, descriptor_delta
    finally:
        for upload in client.retained_uploads:
            if hasattr(upload.data, "close") and not upload.data.closed:
                upload.data.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as upload_file:
        upload_file.write(b'{"benchmark": true}')
        file_name = upload_file.name

    try:
        _run_once(file_name, min(args.iterations, 10))
        samples = [_run_once(file_name, args.iterations) for _ in range(args.repeat)]
        elapsed_samples = [sample[0] for sample in samples]
        open_handle_samples = [sample[1] for sample in samples]
        descriptor_samples = [sample[2] for sample in samples if sample[2] is not None]
        result = {
            "iterations": args.iterations,
            "operations_per_iteration": 4,
            "repeat": args.repeat,
            "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
            "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
            "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
            "median_open_wrapper_handles": int(statistics.median(open_handle_samples)),
            "median_descriptor_delta": (
                None
                if not descriptor_samples
                else int(statistics.median(descriptor_samples))
            ),
        }
        print(json.dumps(result, sort_keys=True))
    finally:
        os.unlink(file_name)


if __name__ == "__main__":
    main()
