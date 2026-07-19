"""Microbenchmark for STIX object deduplication by ID."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


def _build_items(unique_items: int, duplicate_factor: int) -> list[dict[str, str]]:
    items = [{"id": f"indicator--{index:08d}"} for index in range(unique_items)]
    return items * duplicate_factor


def _run_once(unique_items: int, duplicate_factor: int) -> tuple[float, int]:
    items = _build_items(unique_items, duplicate_factor)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = OpenCTIConnectorHelper.stix2_deduplicate_objects(items)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result) != unique_items:
        raise AssertionError(f"expected {unique_items} unique items, got {len(result)}")
    if result[0]["id"] != "indicator--00000000":
        raise AssertionError("deduplication did not preserve the first item")
    if result[-1]["id"] != f"indicator--{unique_items - 1:08d}":
        raise AssertionError("deduplication did not preserve the last unique item")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unique-items", type=int, default=20000)
    parser.add_argument("--duplicate-factor", type=int, default=2)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.unique_items, 1000), args.duplicate_factor)
    samples = [
        _run_once(args.unique_items, args.duplicate_factor) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "unique_items": args.unique_items,
        "duplicate_factor": args.duplicate_factor,
        "input_items": args.unique_items * args.duplicate_factor,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
