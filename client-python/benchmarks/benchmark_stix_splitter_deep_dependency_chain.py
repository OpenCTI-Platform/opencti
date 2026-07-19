"""Benchmark splitter ancestry tracking on a deep dependency chain."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def _build_bundle(item_count: int) -> dict:
    objects = []
    for index in range(item_count):
        item = {
            "id": f"indicator--{index:08d}",
            "type": "indicator",
        }
        if index + 1 < item_count:
            item["object_refs"] = [f"indicator--{index + 1:08d}"]
        objects.append(item)
    return {
        "type": "bundle",
        "id": "bundle--splitter-deep-chain",
        "objects": objects,
    }


def _run_once(item_count: int) -> tuple[float, int]:
    splitter = OpenCTIStix2Splitter()
    bundle = _build_bundle(item_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    expectations, incompatible_items, bundles = splitter.split_bundle_with_expectations(
        bundle, use_json=False
    )
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if expectations != item_count:
        raise AssertionError("splitter did not preserve the full dependency chain")
    if incompatible_items:
        raise AssertionError("splitter marked valid chain objects as incompatible")
    if len(bundles) != item_count:
        raise AssertionError("splitter changed one-object default bundle output")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=800)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.items, 100))
    samples = [_run_once(args.items) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    result = {
        "items": args.items,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
