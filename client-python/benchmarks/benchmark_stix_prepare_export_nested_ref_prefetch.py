"""Microbenchmark for nested-ref list calls during full export.

The benchmark isolates OpenCTIStix2.prepare_export(..., mode="full") with one
root entity linked to many unique core relationships and targets. The export
knows the relationship and target IDs before converting them to simple STIX
objects, so issuing one nested-ref list request per converted object is
avoidable request amplification.
"""

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
    def __init__(self, items):
        self.items = items

    def list(self, **kwargs):
        del kwargs
        return self.items


class _CountingNestedRefCollection:
    def __init__(self, delay_seconds: float):
        self.delay_seconds = delay_seconds
        self.list_calls = 0

    def list(self, **kwargs):
        del kwargs
        self.list_calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return []


class _TargetLister:
    def __init__(self, targets_by_id: dict[str, dict]):
        self.targets_by_id = targets_by_id

    def __call__(self, **kwargs):
        return [self.targets_by_id[target_id] for target_id in kwargs["filters"]]


def _build_relationships(item_count: int) -> list[dict]:
    return [
        {
            "id": f"relationship-internal-{index:08d}",
            "standard_id": f"relationship--{index:08d}",
            "entity_type": "uses",
            "parent_types": [
                "basic-relationship",
                "stix-relationship",
                "stix-core-relationship",
            ],
            "from": {
                "id": "root",
                "standard_id": "indicator--root",
                "entity_type": "Indicator",
                "parent_types": ["Stix-Domain-Object"],
            },
            "to": {
                "id": f"target-{index:08d}",
                "standard_id": f"malware--{index:08d}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            },
        }
        for index in range(item_count)
    ]


def _build_targets_by_id(item_count: int) -> dict[str, dict]:
    return {
        f"target-{index:08d}": {
            "id": f"target-{index:08d}",
            "standard_id": f"malware--{index:08d}",
            "entity_type": "Malware",
            "parent_types": ["Stix-Domain-Object"],
        }
        for index in range(item_count)
    }


def _build_helper(
    item_count: int, delay_seconds: float
) -> tuple[OpenCTIStix2, _CountingNestedRefCollection]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    nested_ref_collection = _CountingNestedRefCollection(delay_seconds)
    targets_by_id = _build_targets_by_id(item_count)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=nested_ref_collection,
        stix_core_relationship=_StaticCollection(_build_relationships(item_count)),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_StaticCollection([{}]),
    )
    helper.generate_export = lambda entity: (
        {
            "id": entity["standard_id"],
            "type": entity["entity_type"].lower(),
            "x_opencti_id": entity["id"],
        }
        if "standard_id" in entity
        else entity.copy()
    )
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
    helper.get_reader = lambda resolve_type: lambda filters: targets_by_id[filters]
    helper.get_lister = lambda resolve_type: _TargetLister(targets_by_id)
    return helper, nested_ref_collection


def _run_once(item_count: int, delay_seconds: float) -> tuple[float, int, int]:
    helper, nested_ref_collection = _build_helper(item_count, delay_seconds)
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.prepare_export(entity=entity, mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result) != item_count * 2 + 1:
        raise AssertionError(
            "prepare_export() did not preserve root, relation, and target count"
        )
    return elapsed_seconds, peak_bytes, nested_ref_collection.list_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    args = parser.parse_args()

    delay_seconds = args.request_delay_ms / 1000
    _run_once(min(args.items, 100), delay_seconds)
    samples = [_run_once(args.items, delay_seconds) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    list_call_samples = [sample[2] for sample in samples]

    result = {
        "items": args.items,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_nested_ref_list_calls": int(statistics.median(list_call_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
