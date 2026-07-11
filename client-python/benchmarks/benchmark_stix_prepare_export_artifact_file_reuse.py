"""Microbenchmark for duplicate artifact file downloads during STIX export.

The benchmark isolates OpenCTIStix2.prepare_export(..., mode="simple") for an
artifact with one import file. Before the optimization, the same file is
fetched once for payload_bin and again for x_opencti_files.
"""

from __future__ import annotations

import argparse
import base64
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _EmptyCollection:
    def list(self, **kwargs):
        del kwargs
        return []


class _SyntheticOpenCTI:
    def __init__(self, size_bytes: int, request_delay_ms: float):
        self.api_url = "http://benchmark.invalid/graphql"
        self.stix_nested_ref_relationship = _EmptyCollection()
        self.size_bytes = size_bytes
        self.request_delay_seconds = request_delay_ms / 1000
        self.fetch_calls = 0
        self.returned_serialized_bytes = 0

    def fetch_opencti_file(self, *args, **kwargs):
        del args, kwargs
        self.fetch_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        data = base64.b64encode(b"x" * self.size_bytes).decode("ascii")
        self.returned_serialized_bytes += len(data)
        return data


def _build_helper(
    size_bytes: int, request_delay_ms: float
) -> tuple[OpenCTIStix2, _SyntheticOpenCTI]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    opencti = _SyntheticOpenCTI(size_bytes, request_delay_ms)
    helper.opencti = opencti
    return helper, opencti


def _build_artifact() -> dict:
    return {
        "id": "artifact--benchmark",
        "type": "artifact",
        "x_opencti_id": "artifact-internal--benchmark",
        "importFiles": [
            {
                "id": "file--benchmark",
                "name": "payload.bin",
                "metaData": {"mimetype": "application/octet-stream"},
                "objectMarking": [],
            }
        ],
        "importFilesIds": ["file--benchmark"],
    }


def _run_once(size_bytes: int, request_delay_ms: float) -> tuple[float, int, int, int]:
    helper, opencti = _build_helper(size_bytes, request_delay_ms)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.prepare_export(_build_artifact(), mode="simple")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    artifact = result[-1]
    if artifact["payload_bin"] != artifact["x_opencti_files"][0]["data"]:
        raise AssertionError(
            "prepare_export() returned inconsistent artifact file data"
        )
    return (
        elapsed_seconds,
        peak_bytes,
        opencti.fetch_calls,
        opencti.returned_serialized_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mib", type=int, default=16)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_mib * 1024 * 1024
    _run_once(min(size_bytes, 1024 * 1024), args.request_delay_ms)
    samples = [_run_once(size_bytes, args.request_delay_ms) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    fetch_call_samples = [sample[2] for sample in samples]
    serialized_byte_samples = [sample[3] for sample in samples]

    result = {
        "size_mib": args.size_mib,
        "request_delay_ms": args.request_delay_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_fetch_calls": statistics.median(fetch_call_samples),
        "median_returned_serialized_kib": round(
            statistics.median(serialized_byte_samples) / 1024, 3
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
