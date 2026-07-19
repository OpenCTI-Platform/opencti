"""Microbenchmark for batching nested-ref target reads across full exports.

The benchmark isolates ``OpenCTIStix2.export_selected(..., mode="full")`` with
many root entities that each have one unique nested ref target. The nested ref
relationships are already known before the per-root conversion loop starts, so
one related-object read per root is avoidable.
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
        return self.items


class _NestedRefRelationshipCollection:
    def __init__(self, relationships_by_root: dict[str, list[dict]]):
        self.relationships_by_root = relationships_by_root
        self.list_calls = 0

    def list(self, **kwargs):
        self.list_calls += 1
        if kwargs.get("filters") is not None:
            from_ids = kwargs["filters"]["filters"][0]["values"]
        else:
            from_ids = kwargs["fromId"]
        if isinstance(from_ids, str):
            from_ids = [from_ids]
        relationships = []
        for from_id in from_ids:
            relationships.extend(self.relationships_by_root.get(from_id, []))
        return relationships


class _CountingReader:
    def __init__(self, targets_by_id: dict[str, dict], delay_seconds: float):
        self.targets_by_id = targets_by_id
        self.delay_seconds = delay_seconds
        self.read_calls = 0

    def __call__(self, filters):
        self.read_calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return self.targets_by_id[filters]


class _CountingLister:
    def __init__(self, targets_by_id: dict[str, dict], delay_seconds: float):
        self.targets_by_id = targets_by_id
        self.delay_seconds = delay_seconds
        self.list_calls = 0

    def __call__(self, **kwargs):
        self.list_calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return [self.targets_by_id[target_id] for target_id in kwargs["filters"]]


def _build_targets_by_id(item_count: int) -> dict[str, dict]:
    targets_by_id = {}
    for index in range(item_count):
        target = {
            "id": f"target-{index:08d}",
            "standard_id": f"malware--{index:08d}",
            "entity_type": "Malware",
            "parent_types": ["Stix-Domain-Object"],
        }
        targets_by_id[target["id"]] = target
        targets_by_id[target["standard_id"]] = target
    return targets_by_id


def _build_root_entities(item_count: int) -> list[dict]:
    return [
        {
            "id": f"indicator--root-{index:08d}",
            "type": "indicator",
            "x_opencti_id": f"root-{index:08d}",
        }
        for index in range(item_count)
    ]


def _build_nested_refs(
    item_count: int, targets_by_id: dict[str, dict]
) -> dict[str, list[dict]]:
    return {
        f"root-{index:08d}": [
            {
                "id": f"nested-ref--{index:08d}",
                "relationship_type": "sample",
                "from": {
                    "id": f"root-{index:08d}",
                    "standard_id": f"indicator--root-{index:08d}",
                    "entity_type": "Indicator",
                    "parent_types": ["Stix-Domain-Object"],
                },
                "to": targets_by_id[f"target-{index:08d}"],
            }
        ]
        for index in range(item_count)
    }


def _build_helper(item_count: int, delay_seconds: float) -> tuple[
    OpenCTIStix2,
    _NestedRefRelationshipCollection,
    _CountingReader,
    _CountingLister,
]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    targets_by_id = _build_targets_by_id(item_count)
    nested_refs = _NestedRefRelationshipCollection(
        _build_nested_refs(item_count, targets_by_id)
    )
    reader = _CountingReader(targets_by_id, delay_seconds)
    lister = _CountingLister(targets_by_id, delay_seconds)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=nested_refs,
        stix_core_relationship=_StaticCollection([]),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_StaticCollection([]),
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
    helper.get_reader = lambda resolve_type: reader
    helper.get_lister = lambda resolve_type: lister
    return helper, nested_refs, reader, lister


def _run_once(
    item_count: int, delay_seconds: float
) -> tuple[float, int, int, int, int]:
    helper, nested_refs, reader, lister = _build_helper(item_count, delay_seconds)
    entities = _build_root_entities(item_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(entities_list=entities, mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count * 2:
        raise AssertionError(
            "export_selected() did not preserve root and nested-ref target count"
        )
    return (
        elapsed_seconds,
        peak_bytes,
        nested_refs.list_calls,
        reader.read_calls,
        lister.list_calls,
    )


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
    nested_ref_list_call_samples = [sample[2] for sample in samples]
    reader_call_samples = [sample[3] for sample in samples]
    lister_call_samples = [sample[4] for sample in samples]

    result = {
        "items": args.items,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_nested_ref_list_calls": int(
            statistics.median(nested_ref_list_call_samples)
        ),
        "median_read_calls": int(statistics.median(reader_call_samples)),
        "median_list_calls": int(statistics.median(lister_call_samples)),
        "median_total_requests": int(
            statistics.median(
                [
                    nested_ref_list_calls + reader_calls + lister_calls
                    for _, _, nested_ref_list_calls, reader_calls, lister_calls in samples
                ]
            )
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
