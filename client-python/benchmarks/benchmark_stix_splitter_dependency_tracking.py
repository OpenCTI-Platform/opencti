"""Microbenchmark for STIX splitter reference tracking.

The benchmark isolates split_bundle_with_expectations() on a bundle where one
root object contains many repeated object_refs. This exercises the splitter's
reference deduplication and dependency tracking without any GraphQL work.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def _build_bundle(item_count: int) -> dict:
    target_ids = [f"indicator--{index:08d}" for index in range(item_count)]
    return {
        "type": "bundle",
        "id": "bundle--splitter-benchmark",
        "objects": [
            {
                "id": "report--root",
                "type": "report",
                "object_refs": target_ids + target_ids,
            },
            *[
                {
                    "id": target_id,
                    "type": "indicator",
                }
                for target_id in target_ids
            ],
        ],
    }


def _run_once(item_count: int) -> tuple[float, int]:
    splitter = OpenCTIStix2Splitter()
    bundle = _build_bundle(item_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    expectations, _, bundles = splitter.split_bundle_with_expectations(
        bundle, use_json=False
    )
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if expectations != item_count + 1:
        raise AssertionError("splitter did not preserve unique object count")
    root = next(
        item
        for split_bundle in bundles
        for item in split_bundle["objects"]
        if item["id"] == "report--root"
    )
    if len(root["object_refs"]) != item_count:
        raise AssertionError("splitter did not deduplicate repeated object refs")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.items, 100))
    samples = [_run_once(args.items) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "items": args.items,
        "refs": args.items * 2,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
