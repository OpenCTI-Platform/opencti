"""Microbenchmark for case-insensitive enum membership checks."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.constants import IdentityTypes, LocationTypes, StixCyberObservableTypes


def _run_once(iterations: int) -> tuple[float, int]:
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    hits = 0
    for _ in range(iterations):
        hits += StixCyberObservableTypes.has_value("url")
        hits += StixCyberObservableTypes.has_value("not-an-observable")
        hits += LocationTypes.has_value("city")
        hits += IdentityTypes.has_value("sector")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    expected_hits = iterations * 3
    if hits != expected_hits:
        raise AssertionError(f"expected {expected_hits} hits, got {hits}")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=250000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "iterations": args.iterations,
        "lookups": args.iterations * 4,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
