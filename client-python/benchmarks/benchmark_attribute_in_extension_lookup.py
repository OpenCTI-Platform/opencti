"""Benchmark OpenCTI extension attribute lookup helpers."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

PRIMARY_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
SECONDARY_EXTENSION_ID = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"

LOOKUP_CASES = [
    (
        {
            "extensions": {
                PRIMARY_EXTENSION_ID: {"score": 42},
                SECONDARY_EXTENSION_ID: {"score": 43},
            },
            "score": 44,
        },
        "score",
    ),
    ({"extensions": {SECONDARY_EXTENSION_ID: {"score": 43}}, "score": 44}, "score"),
    ({"score": 44}, "score"),
    ({"extensions": {PRIMARY_EXTENSION_ID: {"other": 1}}}, "score"),
    ({"type": "indicator"}, "type"),
]


def _run_once(lookup, iterations: int) -> tuple[float, int]:
    total = 0
    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            stix_object, key = LOOKUP_CASES[index % len(LOOKUP_CASES)]
            value = lookup(key, stix_object)
            if value is not None:
                total += value
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    return elapsed_seconds, total


def _measure(lookup, iterations: int, repeat: int) -> dict:
    _run_once(lookup, min(iterations, 10000))
    samples = [_run_once(lookup, iterations) for _ in range(repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_total = samples[0][1]
    if any(sample[1] != expected_total for sample in samples):
        raise AssertionError("extension lookup results changed between benchmark runs")
    return {
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "api_client": _measure(
            OpenCTIApiClient.get_attribute_in_extension,
            args.iterations,
            args.repeat,
        ),
        "connector_helper": _measure(
            OpenCTIConnectorHelper.get_attribute_in_extension,
            args.iterations,
            args.repeat,
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
