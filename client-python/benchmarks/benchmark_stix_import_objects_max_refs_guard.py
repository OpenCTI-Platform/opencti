"""Benchmark disabled objects_max_refs checks during STIX bundle import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


class _OpenCTI:
    def __init__(self):
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_objects_max_refs_guard"
        )

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def query(_query):
        return {"data": {"vocabularyCategories": []}}

    @staticmethod
    def logger_class(_name):
        return logging.getLogger("benchmark_stix_import_objects_max_refs_guard.worker")


def _run_once(object_count: int, field_count: int) -> tuple[float, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    compute_calls = 0
    original_compute = OpenCTIStix2Utils.compute_object_refs_number

    def count_compute(entity):
        nonlocal compute_calls
        compute_calls += 1
        return original_compute(entity)

    stix2.import_item_with_retries = lambda *_args, **_kwargs: None
    bundle = {
        "type": "bundle",
        "id": "bundle--objects-max-refs-benchmark",
        "objects": [
            {
                "id": f"malware--{index:08d}",
                "type": "malware",
                "name": f"malware-{index:08d}",
                **{
                    f"field_{field_index:03d}": field_index
                    for field_index in range(field_count)
                },
            }
            for index in range(object_count)
        ],
    }

    OpenCTIStix2Utils.compute_object_refs_number = staticmethod(count_compute)
    try:
        started_at = time.perf_counter()
        imported, rejected = stix2.import_bundle(bundle, objects_max_refs=0)
        elapsed_seconds = time.perf_counter() - started_at
    finally:
        OpenCTIStix2Utils.compute_object_refs_number = staticmethod(original_compute)

    if len(imported) != object_count:
        raise AssertionError("import did not preserve object count")
    if rejected:
        raise AssertionError("disabled max-ref limit rejected objects")
    return elapsed_seconds, compute_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--fields", type=int, default=50)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100), args.fields)
    samples = [_run_once(args.objects, args.fields) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    compute_call_samples = [sample[1] for sample in samples]
    result = {
        "objects": args.objects,
        "fields": args.fields,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_compute_object_refs_number_calls": statistics.median(
            compute_call_samples
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
