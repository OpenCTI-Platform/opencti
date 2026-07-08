"""Benchmark STIX object reference counting.

The benchmark isolates compute_object_refs_number() on a representative object
shape. The function runs for every imported item when objects_max_refs checks
are evaluated.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


def _build_entity(field_count: int, ref_count: int) -> dict:
    entity = {f"field_{index}": index for index in range(field_count)}
    entity.update(
        {
            "object_refs": [f"indicator--{index:08d}" for index in range(ref_count)],
            "created_by_ref": "identity--benchmark",
            "external_references": [
                {"source_name": f"source-{index:08d}"} for index in range(ref_count)
            ],
            "kill_chain_phases": [
                {"phase_name": f"phase-{index:08d}"} for index in range(ref_count)
            ],
        }
    )
    return entity


def _run_once(field_count: int, ref_count: int, calls: int) -> tuple[float, int]:
    entity = _build_entity(field_count, ref_count)
    expected_refs = (ref_count * 3) + 1
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    total_refs = 0
    for _ in range(calls):
        total_refs += OpenCTIStix2Utils.compute_object_refs_number(entity)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if total_refs != expected_refs * calls:
        raise AssertionError("reference count changed during benchmark")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fields", type=int, default=50)
    parser.add_argument("--refs", type=int, default=10)
    parser.add_argument("--calls", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.fields, 10), min(args.refs, 2), min(args.calls, 10))
    samples = [
        _run_once(args.fields, args.refs, args.calls) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "fields": args.fields,
        "refs": args.refs,
        "calls": args.calls,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
