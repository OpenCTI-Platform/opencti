"""Benchmark duplicate extension-backed MarkingDefinition order reads."""

from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

_PACKAGE_ROOT = Path(
    os.environ.get("PYCTI_BENCHMARK_PACKAGE_ROOT", Path(__file__).resolve().parents[1])
)
sys.path.insert(0, str(_PACKAGE_ROOT))

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_marking_definition import MarkingDefinition

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def _build_marking_definition(index: int):
    return {
        "id": f"marking-definition--{index}",
        "type": "marking-definition",
        "definition_type": "statement",
        "definition": "benchmark",
        "extensions": {_OPENCTI_EXTENSION: {"order": 42}},
    }


def _build_api() -> tuple[_OpenCTI, MarkingDefinition]:
    opencti = _OpenCTI()
    api = MarkingDefinition(opencti)
    api.create = lambda **kwargs: kwargs
    return opencti, api


def _run_once(iterations: int) -> tuple[float, Counter, int]:
    opencti, api = _build_api()
    checksum = 0

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            result = api.import_from_stix2(stixObject=_build_marking_definition(index))
            checksum += result["x_opencti_order"]
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return elapsed_seconds, opencti.extension_lookup_counts, checksum


def _summarize(samples, iterations: int):
    elapsed_samples = [sample[0] for sample in samples]
    expected_lookup_counts = samples[0][1]
    expected_checksum = samples[0][2]
    if any(sample[1] != expected_lookup_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_checksum for sample in samples):
        raise AssertionError("result checksum changed between runs")
    return {
        "iterations": iterations,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_lookup_counts.items())),
        "median_checksum": statistics.median(sample[2] for sample in samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    result = {
        "repeat": args.repeat,
        "import_from_stix2": _summarize(samples, args.iterations),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
