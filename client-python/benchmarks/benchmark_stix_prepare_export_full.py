"""Microbenchmark for full STIX export relation accumulation.

The benchmark isolates OpenCTIStix2.prepare_export(..., mode="full") with a
single root entity and many related STIX relationships. It stubs GraphQL reads
so the local deduplication and result-growth cost is measurable.
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


def _build_root_entity() -> dict:
    return {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }


def _build_relationships(item_count: int) -> list[dict]:
    return [
        {
            "id": f"relationship--{index:08d}",
            "type": "uses",
            "x_opencti_id": f"relationship-internal-{index:08d}",
            "from": {
                "id": "root",
                "standard_id": "indicator--root",
                "entity_type": "Indicator",
                "parent_types": ["Stix-Domain-Object"],
            },
            "to": {
                "id": f"malware-internal-{index:08d}",
                "standard_id": f"malware--{index:08d}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            },
        }
        for index in range(item_count)
    ]


def _build_helper(relationships: list[dict]) -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=_StaticCollection([]),
        stix_core_relationship=_StaticCollection(relationships),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_StaticCollection([{}]),
    )
    helper.generate_export = lambda entity: entity
    helper.prepare_id_filters_export = lambda entity_id, access_filter: None
    helper.get_reader = lambda resolve_type: lambda filters: None
    return helper


def _run_once(item_count: int) -> tuple[float, int]:
    helper = _build_helper(_build_relationships(item_count))
    entity = _build_root_entity()
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.prepare_export(entity=entity, mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result) != item_count + 1:
        raise AssertionError("prepare_export() did not preserve unique relation count")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.items, 100))
    samples = [_run_once(args.items) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "items": args.items,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
