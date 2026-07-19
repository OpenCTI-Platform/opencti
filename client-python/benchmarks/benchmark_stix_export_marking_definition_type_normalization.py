"""Benchmark repeated marking-definition type normalization during export."""

from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import sys
import time
from pathlib import Path

_PACKAGE_ROOT = Path(
    os.environ.get("PYCTI_BENCHMARK_PACKAGE_ROOT", Path(__file__).resolve().parents[1])
)
sys.path.insert(0, str(_PACKAGE_ROOT))

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _CountingString(str):
    def __new__(cls, value: str):
        instance = super().__new__(cls, value)
        instance.lower_calls = 0
        return instance

    def lower(self):
        self.lower_calls += 1
        return super().lower()


def _build_marking_definition(definition_type: str = "statement"):
    return {
        "standard_id": "marking-definition--benchmark",
        "definition_type": definition_type,
        "definition": "Benchmark",
        "created": "2026-01-01T00:00:00.000Z",
    }


def _run_once(iterations: int) -> tuple[float, int]:
    marking_definition = _build_marking_definition()
    checksum = 0

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for _ in range(iterations):
            result = OpenCTIStix2._build_export_marking_definition(marking_definition)
            checksum += len(result["definition_type"])
            checksum += len(result["definition"]["statement"])
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return elapsed_seconds, checksum


def _count_definition_type_lower_calls() -> int:
    definition_type = _CountingString("statement")
    OpenCTIStix2._build_export_marking_definition(
        _build_marking_definition(definition_type)
    )
    return definition_type.lower_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_checksum = samples[0][1]
    if any(sample[1] != expected_checksum for sample in samples):
        raise AssertionError("result checksum changed between runs")

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "definition_type_lower_calls_per_build": _count_definition_type_lower_calls(),
        "median_checksum": statistics.median(sample[1] for sample in samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
