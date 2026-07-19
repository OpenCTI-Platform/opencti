"""Benchmark unnecessary JSON serialization for dict splitter output."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils import opencti_stix2_splitter as splitter_module
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def _build_bundle(object_count: int) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--splitter-dict-serialization",
        "objects": [
            {
                "id": f"indicator--{index:08d}",
                "type": "indicator",
                "name": f"indicator-{index:08d}",
            }
            for index in range(object_count)
        ],
    }


def _run_once(object_count: int) -> tuple[float, float, int]:
    splitter = OpenCTIStix2Splitter()
    bundle = _build_bundle(object_count)
    json_dumps_calls = 0
    original_json_dumps = splitter_module.json.dumps

    def count_json_dumps(*args, **kwargs):
        nonlocal json_dumps_calls
        json_dumps_calls += 1
        return original_json_dumps(*args, **kwargs)

    splitter_module.json.dumps = count_json_dumps
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    try:
        expectations, incompatible_items, bundles = (
            splitter.split_bundle_with_expectations(bundle, use_json=False)
        )
    finally:
        splitter_module.json.dumps = original_json_dumps
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if expectations != object_count:
        raise AssertionError("splitter did not preserve object count")
    if incompatible_items:
        raise AssertionError("splitter marked flat valid objects as incompatible")
    if len(bundles) != object_count:
        raise AssertionError("splitter changed one-object default bundle output")
    if not all(isinstance(split_bundle, dict) for split_bundle in bundles):
        raise AssertionError("splitter did not return dict bundles")
    return elapsed_seconds, peak_bytes / 1024, json_dumps_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100))
    samples = [_run_once(args.objects) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_memory_samples = [sample[1] for sample in samples]
    json_dumps_call_samples = [sample[2] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_memory_kib": round(statistics.median(peak_memory_samples), 3),
        "median_json_dumps_calls": statistics.median(json_dumps_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
