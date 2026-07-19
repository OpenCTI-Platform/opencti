"""Microbenchmark for ObservedData embedded observable import.

This benchmark isolates the local bookkeeping cost in
ObservedData.import_from_stix2() by replacing GraphQL calls with in-memory
fakes. It measures the cost of building object references for a single
ObservedData object containing many embedded observables.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.entities.opencti_observed_data import ObservedData


class _FakeObservableApi:
    def __init__(self) -> None:
        self.calls = 0

    def create(self, **kwargs):
        del kwargs
        standard_id = f"observable--{self.calls}"
        self.calls += 1
        return {"standard_id": standard_id}


class _FakeLogger:
    def error(self, *args, **kwargs) -> None:
        del args, kwargs


class _FakeOpenCTI:
    def __init__(self) -> None:
        self.stix_cyber_observable = _FakeObservableApi()
        self.app_logger = _FakeLogger()

    @staticmethod
    def get_attribute_in_extension(*args, **kwargs):
        del args, kwargs
        return None


class _CaptureObservedData(ObservedData):
    def __init__(self, opencti) -> None:
        super().__init__(opencti)
        self.last_objects = None

    def create(self, **kwargs):
        self.last_objects = kwargs["objects"]
        return {"id": "observed-data--benchmark"}


def _build_stix_object(object_count: int) -> dict:
    return {
        "id": "observed-data--benchmark",
        "type": "observed-data",
        "objects": {
            str(index): {"type": "ipv4-addr", "value": f"198.51.100.{index % 255}"}
            for index in range(object_count)
        },
    }


def _run_once(object_count: int) -> tuple[float, int, int]:
    opencti = _FakeOpenCTI()
    observed_data = _CaptureObservedData(opencti)
    stix_object = _build_stix_object(object_count)

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    observed_data.import_from_stix2(stixObject=stix_object, extras={"object_ids": []})
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return elapsed_seconds, peak_bytes, len(observed_data.last_objects or [])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=2000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100))
    samples = [_run_once(args.objects) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    ref_counts = [sample[2] for sample in samples]

    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "reference_count": ref_counts[-1],
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
