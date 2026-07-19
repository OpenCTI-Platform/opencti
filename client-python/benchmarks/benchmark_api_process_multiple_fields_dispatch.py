"""Benchmark repeated entity-specific dispatch in ``process_multiple_fields()``."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
from types import SimpleNamespace

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


class _Processor:
    def __init__(self):
        self.calls = 0

    def process_multiple_fields(self, data):
        self.calls += 1
        return data


def _build_client() -> OpenCTIApiClient:
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    client.indicator = SimpleNamespace()
    client.user = _Processor()
    return client


def _run_once(iterations: int) -> tuple[float, int]:
    client = _build_client()
    indicator_row = {"entity_type": "Indicator"}
    user_row = {"entity_type": "User"}
    resolver_calls = 0
    original_resolver = OpenCTIStix2Utils.retrieve_class_for_method

    def count_resolver_calls(*args, **kwargs):
        nonlocal resolver_calls
        resolver_calls += 1
        return original_resolver(*args, **kwargs)

    OpenCTIStix2Utils.retrieve_class_for_method = staticmethod(count_resolver_calls)
    try:
        gc.collect()
        started_at = time.perf_counter()
        for _ in range(iterations):
            client.process_multiple_fields(indicator_row)
            client.process_multiple_fields(user_row)
        elapsed_seconds = time.perf_counter() - started_at
    finally:
        OpenCTIStix2Utils.retrieve_class_for_method = staticmethod(original_resolver)

    if client.user.calls != iterations:
        raise AssertionError("custom process_multiple_fields() dispatch changed")
    return elapsed_seconds, resolver_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    resolver_call_samples = [sample[1] for sample in samples]

    result = {
        "iterations": args.iterations,
        "rows_processed": args.iterations * 2,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_resolver_calls": statistics.median(resolver_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
