"""Microbenchmark for repeated embedded markdown image reads during export.

The benchmark isolates export_selected() over entities whose markdown fields
reference the same embedded image path. Before export-scoped image caching,
each markdown field fetches and base64-serializes the same storage object
independently.
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


def _build_helper(size_bytes: int, request_delay_ms: float):
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    opencti = _SyntheticOpenCTI(size_bytes, request_delay_ms)
    helper.opencti = opencti
    helper.generate_export = lambda entity: entity.copy()
    return helper, opencti


def _build_entities(item_count: int) -> list[dict]:
    markdown = "![img](embedded/Report/shared/payload.png)"
    return [
        {
            "id": f"report--{index:08d}",
            "type": "report",
            "entity_type": "Report",
            "x_opencti_id": f"internal-report-{index:08d}",
            "description": markdown,
            "x_opencti_description": markdown,
            "content": markdown,
        }
        for index in range(item_count)
    ]


def _run_once(
    item_count: int, size_bytes: int, request_delay_ms: float
) -> tuple[float, int, int, int]:
    helper, opencti = _build_helper(size_bytes, request_delay_ms)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(_build_entities(item_count), mode="simple")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count:
        raise AssertionError("export_selected() did not preserve root entity count")
    if any(
        not entity[field].startswith("![img](data:image/png;base64,")
        for entity in result["objects"]
        for field in ("description", "x_opencti_description", "content")
    ):
        raise AssertionError("export_selected() did not rewrite embedded image data")
    return (
        elapsed_seconds,
        peak_bytes,
        opencti.fetch_calls,
        opencti.returned_serialized_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=1000)
    parser.add_argument("--size-kib", type=int, default=1)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_kib * 1024
    _run_once(min(args.items, 10), size_bytes, args.request_delay_ms)
    samples = [
        _run_once(args.items, size_bytes, args.request_delay_ms)
        for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    fetch_call_samples = [sample[2] for sample in samples]
    serialized_byte_samples = [sample[3] for sample in samples]

    result = {
        "items": args.items,
        "size_kib": args.size_kib,
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
