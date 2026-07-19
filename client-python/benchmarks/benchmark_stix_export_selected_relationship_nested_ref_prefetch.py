"""Benchmark nested-ref prefetching for relationships across full exports.

The benchmark isolates OpenCTIStix2.export_selected(..., mode="full") with
many roots that each expose one unique core relationship and one unique target.
The multi-root export already knows every relationship and target ID before
recursive simple conversion starts, so one nested-ref list request per
relationship is avoidable request amplification.
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

    def list(self, **_kwargs):
        return self.items


class _RelationshipCollection:
    def __init__(self, relationships_by_root):
        self.relationships_by_root = relationships_by_root

    def list(self, **kwargs):
        root_ids = kwargs["fromOrToId"]
        if isinstance(root_ids, str):
            root_ids = [root_ids]
        relationships = []
        for root_id in root_ids:
            relationships.extend(self.relationships_by_root.get(root_id, []))
        return relationships


class _CountingNestedRefCollection:
    def __init__(self, delay_seconds: float):
        self.delay_seconds = delay_seconds
        self.list_calls = 0

    def list(self, **_kwargs):
        self.list_calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return []


class _CountingAccessCollection:
    def list(self, **kwargs):
        entity_ids = kwargs["filters"]
        if isinstance(entity_ids, str):
            entity_ids = [entity_ids]
        return [{"id": entity_id} for entity_id in entity_ids]


class _TargetLister:
    def __init__(self, targets_by_id):
        self.targets_by_id = targets_by_id

    def __call__(self, **kwargs):
        return [self.targets_by_id[target_id] for target_id in kwargs["filters"]]


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


def _build_relationships_by_root(
    item_count: int, targets_by_id: dict[str, dict]
) -> dict[str, list[dict]]:
    return {
        f"root-{index:08d}": [
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
                    "id": f"root-{index:08d}",
                    "standard_id": f"indicator--{index:08d}",
                    "entity_type": "Indicator",
                    "parent_types": ["Stix-Domain-Object"],
                },
                "to": targets_by_id[f"target-{index:08d}"],
            }
        ]
        for index in range(item_count)
    }


def _build_roots(item_count: int) -> list[dict]:
    return [
        {
            "id": f"indicator--{index:08d}",
            "type": "indicator",
            "x_opencti_id": f"root-{index:08d}",
        }
        for index in range(item_count)
    ]


def _build_helper(
    item_count: int, delay_seconds: float
) -> tuple[OpenCTIStix2, _CountingNestedRefCollection]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    targets_by_id = _build_targets_by_id(item_count)
    nested_refs = _CountingNestedRefCollection(delay_seconds)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=nested_refs,
        stix_core_relationship=_RelationshipCollection(
            _build_relationships_by_root(item_count, targets_by_id)
        ),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_CountingAccessCollection(),
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
    helper._rewrite_embedded_image_uris_in_bundle_for_export = lambda bundle: None
    return helper, nested_refs


def _run_once(item_count: int, delay_seconds: float) -> tuple[float, int, int]:
    helper, nested_refs = _build_helper(item_count, delay_seconds)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(_build_roots(item_count), mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count * 3:
        raise AssertionError(
            "export_selected() did not preserve root, relationship, and target count"
        )
    return elapsed_seconds, peak_bytes, nested_refs.list_calls


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
