"""Benchmark list scanning in OpenCTIApiClient.not_empty()."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.api.opencti_api_client import OpenCTIApiClient


def _run_once(values: list[str], iterations: int) -> tuple[float, int]:
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    result_checksum = 0

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for _ in range(iterations):
            result_checksum += client.not_empty(values)
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    return elapsed_seconds, result_checksum


def _benchmark_case(values: list[str], iterations: int, repeat: int) -> dict:
    _run_once(values, min(iterations, 1000))
    samples = [_run_once(values, iterations) for _ in range(repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_checksum = samples[0][1]
    if any(sample[1] != expected_checksum for sample in samples):
        raise AssertionError("not_empty result changed between runs")
    return {
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--list-size", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    first_non_empty = ["value"] + [""] * (args.list_size - 1)
    all_empty = [""] * args.list_size
    result = {
        "iterations": args.iterations,
        "list_size": args.list_size,
        "repeat": args.repeat,
        "first_non_empty": _benchmark_case(
            first_non_empty, args.iterations, args.repeat
        ),
        "all_empty": _benchmark_case(all_empty, args.iterations, args.repeat),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
