"""Benchmark repeated extension reads during observable create preparation."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable

_SCO_EXTENSION_ID = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"


class _NullLogger:
    @staticmethod
    def info(*_args, **_kwargs):
        return None

    @staticmethod
    def error(*_args, **_kwargs):
        raise AssertionError("unexpected observable create error")


class _BenchmarkClient:
    def __init__(self):
        self.app_logger = _NullLogger()
        self.extension_lookup_counts = Counter()
        self.checksum = 0
        self.response = {
            "data": {
                "stixCyberObservableAdd": {
                    "id": "observable--benchmark",
                    "standard_id": "observable--benchmark",
                    "entity_type": "Stix-Cyber-Observable",
                    "parent_types": [],
                }
            }
        }

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def query(self, _query, variables):
        self.checksum += variables["x_opencti_score"] or 0
        return self.response

    @staticmethod
    def process_multiple_fields(value):
        return value


def _build_observable(index: int) -> dict:
    case = index % 4
    extension = {"score": 80}
    if case == 0:
        return {
            "type": "domain-name",
            "id": f"domain-name--{index}",
            "value": "example.test",
            "extensions": {_SCO_EXTENSION_ID: extension},
        }
    if case == 1:
        extension["additional_names"] = ["payload.bin"]
        return {
            "type": "artifact",
            "id": f"artifact--{index}",
            "mime_type": "application/octet-stream",
            "extensions": {_SCO_EXTENSION_ID: extension},
        }
    if case == 2:
        extension["additional_names"] = ["payload.bin"]
        return {
            "type": "file",
            "id": f"file--{index}",
            "name": "payload.bin",
            "extensions": {_SCO_EXTENSION_ID: extension},
        }
    extension["x_opencti_product"] = "benchmark"
    return {
        "type": "software",
        "id": f"software--{index}",
        "name": "benchmark",
        "extensions": {_SCO_EXTENSION_ID: extension},
    }


def _run_once(iterations: int) -> tuple[float, Counter, int]:
    client = _BenchmarkClient()
    observable_api = StixCyberObservable(client)
    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            observable_api.create(
                observableData=_build_observable(index),
                resolve_result_indicators=True,
            )
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    return elapsed_seconds, client.extension_lookup_counts, client.checksum


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_counts = samples[0][1]
    expected_checksum = samples[0][2]
    if any(sample[1] != expected_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_checksum for sample in samples):
        raise AssertionError("observable create results changed between runs")
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_counts.items())),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
