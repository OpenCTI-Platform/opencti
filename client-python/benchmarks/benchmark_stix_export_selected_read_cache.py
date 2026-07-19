"""Microbenchmark for repeated related-object reads across full exports.

The benchmark isolates OpenCTIStix2.export_selected(..., mode="full") with
many root entities that each have one relationship to the same target. The
exported bundle only needs one copy of the target object, so repeated reader
calls across top-level roots represent avoidable GraphQL round trips.
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


class _RelationshipCollection:
    def __init__(self, relationships_by_root):
        self.relationships_by_root = relationships_by_root

    def list(self, **kwargs):
        return self.relationships_by_root.get(kwargs["fromOrToId"], [])


class _CountingReader:
    def __init__(self, read_delay_seconds: float):
        self.read_delay_seconds = read_delay_seconds
        self.read_calls = 0

    def __call__(self, filters):
        self.read_calls += 1
        if self.read_delay_seconds:
            time.sleep(self.read_delay_seconds)
        return {
            "id": "malware--shared",
            "type": "malware",
            "x_opencti_id": "target-shared",
        }


def _build_root_entities(item_count: int) -> list[dict]:
    return [
        {
            "id": f"indicator--root-{index:08d}",
            "type": "indicator",
            "x_opencti_id": f"root-{index:08d}",
        }
        for index in range(item_count)
    ]


def _build_relationships_by_root(item_count: int) -> dict[str, list[dict]]:
    return {
        f"root-{index:08d}": [
            {
                "id": f"relationship--{index:08d}",
                "type": "uses",
                "x_opencti_id": f"relationship-internal-{index:08d}",
                "from": {
                    "id": f"root-{index:08d}",
                    "standard_id": f"indicator--root-{index:08d}",
                    "entity_type": "Indicator",
                    "parent_types": ["Stix-Domain-Object"],
                },
                "to": {
                    "id": "target-shared",
                    "standard_id": "malware--shared",
                    "entity_type": "Malware",
                    "parent_types": ["Stix-Domain-Object"],
                },
            }
        ]
        for index in range(item_count)
    }


def _build_helper(
    item_count: int, read_delay_seconds: float
) -> tuple[OpenCTIStix2, _CountingReader]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    reader = _CountingReader(read_delay_seconds)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=_StaticCollection([]),
        stix_core_relationship=_RelationshipCollection(
            _build_relationships_by_root(item_count)
        ),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_StaticCollection([{}]),
    )
    helper.generate_export = lambda entity: entity.copy()
    helper.prepare_id_filters_export = lambda entity_id, access_filter: None
    helper.get_reader = lambda resolve_type: reader
    return helper, reader


def _run_once(item_count: int, read_delay_seconds: float) -> tuple[float, int, int]:
    helper, reader = _build_helper(item_count, read_delay_seconds)
    entities = _build_root_entities(item_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(entities_list=entities, mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count * 2 + 1:
        raise AssertionError(
            "export_selected() did not preserve root, relation, and target count"
        )
    return elapsed_seconds, peak_bytes, reader.read_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--read-delay-ms", type=float, default=1.0)
    args = parser.parse_args()

    read_delay_seconds = args.read_delay_ms / 1000
    _run_once(min(args.items, 100), read_delay_seconds)
    samples = [_run_once(args.items, read_delay_seconds) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    read_call_samples = [sample[2] for sample in samples]

    result = {
        "items": args.items,
        "repeat": args.repeat,
        "read_delay_ms": args.read_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_read_calls": int(statistics.median(read_call_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
