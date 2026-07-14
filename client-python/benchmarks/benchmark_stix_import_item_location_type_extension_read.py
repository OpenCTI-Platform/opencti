"""Benchmark duplicate location_type extension reads during import_item scope filtering."""

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
from types import SimpleNamespace

_PACKAGE_ROOT = Path(
    os.environ.get("PYCTI_BENCHMARK_PACKAGE_ROOT", Path(__file__).resolve().parents[1])
)
sys.path.insert(0, str(_PACKAGE_ROOT))

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.app_logger = SimpleNamespace(debug=lambda *_args, **_kwargs: None)

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


class _ImportRecorder:
    def __init__(self):
        self.calls = 0

    def __call__(self, *_args, **_kwargs):
        self.calls += 1


def _build_location(index: int):
    return {
        "id": f"location--{index}",
        "type": "location",
        "extensions": {_OPENCTI_EXTENSION: {"location_type": "city"}},
    }


def _build_stix2() -> tuple[_OpenCTI, OpenCTIStix2, _ImportRecorder]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    recorder = _ImportRecorder()
    stix2.import_object = recorder
    return opencti, stix2, recorder


def _run_once(iterations: int) -> tuple[float, Counter, int]:
    opencti, stix2, recorder = _build_stix2()
    stix_objects = (_build_location(0), _build_location(1))

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            stix2.import_item(stix_objects[index & 1], types=["city"])
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return elapsed_seconds, opencti.extension_lookup_counts, recorder.calls


def _summarize(samples, iterations: int):
    elapsed_samples = [sample[0] for sample in samples]
    expected_lookup_counts = samples[0][1]
    expected_import_calls = samples[0][2]
    if any(sample[1] != expected_lookup_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_import_calls for sample in samples):
        raise AssertionError("import call count changed between runs")
    return {
        "iterations": iterations,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_lookup_counts.items())),
        "median_import_calls": statistics.median(sample[2] for sample in samples),
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
        "import_item": _summarize(samples, args.iterations),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
