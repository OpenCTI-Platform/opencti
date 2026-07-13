"""Benchmark container object-ref policy checks in ``prepare_export()``."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc
from types import SimpleNamespace

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _StaticCollection:
    def list(self, **kwargs):
        return []


def _build_helper() -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = SimpleNamespace(stix_nested_ref_relationship=_StaticCollection())
    return helper


def _build_entity(root_type: str, object_count: int) -> dict:
    return {
        "id": f"{root_type}--root",
        "type": root_type,
        "x_opencti_id": "root",
        "objects": [
            {
                "id": f"target-{index:08d}",
                "standard_id": f"malware--{index:08d}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(object_count)
        ],
        "objectsIds": [f"target-{index:08d}" for index in range(object_count)],
    }


def _run_once(root_type: str, object_count: int) -> tuple[float, int, int]:
    helper = _build_helper()
    entity = _build_entity(root_type, object_count)

    gc.collect()
    gc.disable()
    tracemalloc.start()
    started_at = time.perf_counter()
    try:
        result = helper.prepare_export(entity=entity, mode="simple")
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        gc.enable()

    object_ref_count = len(result[0]["object_refs"])
    if object_ref_count != object_count:
        raise AssertionError(
            f"prepare_export() returned {object_ref_count} object refs instead of {object_count}"
        )
    return elapsed_seconds, peak_bytes, object_ref_count


def _benchmark_case(root_type: str, object_count: int, repeat: int) -> dict:
    _run_once(root_type, min(object_count, 1000))
    samples = [_run_once(root_type, object_count) for _ in range(repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    return {
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "report": _benchmark_case("report", args.objects, args.repeat),
        "x_opencti_task": _benchmark_case("x-opencti-task", args.objects, args.repeat),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
