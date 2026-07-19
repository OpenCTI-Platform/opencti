"""Benchmark observable delete dispatch in the STIX element operation helper."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _DeleteRecorder:
    def __init__(self):
        self.delete_calls = 0

    def delete(self, **_kwargs):
        self.delete_calls += 1


class _OpenCTI:
    def __init__(self):
        self.stix_cyber_observable = _DeleteRecorder()
        self.stix_core_relationship = _DeleteRecorder()
        self.external_reference = _DeleteRecorder()
        self.stix_sighting_relationship = _DeleteRecorder()
        self.stix = _DeleteRecorder()
        self.stix_core_object = _DeleteRecorder()


def _run_once(iterations: int) -> tuple[float, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    item = {"id": "domain-name--benchmark", "type": "domain-name"}

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for _ in range(iterations):
            stix2.element_operation_delete(item, "delete")
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return elapsed_seconds, opencti.stix_cyber_observable.delete_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    delete_call_samples = [sample[1] for sample in samples]
    expected_delete_calls = args.iterations
    if any(
        delete_calls != expected_delete_calls for delete_calls in delete_call_samples
    ):
        raise AssertionError("observable delete dispatch count changed between runs")

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_delete_calls": statistics.median(delete_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
