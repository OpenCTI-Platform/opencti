"""Benchmark observable type normalization during local create preparation."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable


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

    @staticmethod
    def get_attribute_in_extension(_key, _stix_object):
        return None

    def query(self, _query, variables):
        self.checksum += len(variables["type"])
        return self.response

    @staticmethod
    def process_multiple_fields(value):
        return value


OBSERVABLE_CASES = [
    {"type": "domain-name", "id": "domain-name--benchmark", "value": "example.test"},
    {
        "type": "x-opencti-payment-card",
        "id": "payment-card--benchmark",
        "card_number": "4111111111111111",
    },
    {"type": "x-opencti-imsi", "id": "imsi--benchmark", "value": "123456789012345"},
    {"type": "file", "id": "file--benchmark", "name": "payload.bin"},
]


def _run_once(iterations: int) -> tuple[float, int]:
    client = _BenchmarkClient()
    observable_api = StixCyberObservable(client)
    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            observable_api.create(
                observableData=OBSERVABLE_CASES[index % len(OBSERVABLE_CASES)],
                resolve_result_indicators=True,
            )
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    return elapsed_seconds, client.checksum


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_checksum = samples[0][1]
    if any(sample[1] != expected_checksum for sample in samples):
        raise AssertionError("observable normalization results changed between runs")
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
