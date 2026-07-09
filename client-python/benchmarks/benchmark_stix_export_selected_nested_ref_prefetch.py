"""Microbenchmark for batching nested ref listing across full exports.

The benchmark isolates OpenCTIStix2.export_selected(..., mode="full") with many
root entities that have no nested ref relationships. The current export path
still issues one stixNestedRefRelationships query per root before learning that
each result is empty, so a small synthetic request delay makes the round-trip
cost visible without mixing in related-object serialization work.
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


class _CountingNestedRefCollection:
    def __init__(self, delay_seconds: float):
        self.delay_seconds = delay_seconds
        self.list_calls = 0

    def list(self, **kwargs):
        self.list_calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return []


def _build_entities(item_count: int) -> list[dict]:
    return [
        {
            "id": f"indicator--{index:08d}",
            "type": "indicator",
            "x_opencti_id": f"root-{index:08d}",
        }
        for index in range(item_count)
    ]


def _build_helper(
    delay_seconds: float,
) -> tuple[OpenCTIStix2, _CountingNestedRefCollection]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    nested_refs = _CountingNestedRefCollection(delay_seconds)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=nested_refs,
        stix_core_relationship=_StaticCollection([]),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_StaticCollection([]),
    )
    helper.generate_export = lambda entity: entity.copy()
    helper.get_reader = lambda resolve_type: lambda filters: None
    helper.get_lister = lambda resolve_type: None
    helper._rewrite_embedded_image_uris_in_bundle_for_export = lambda bundle: None
    return helper, nested_refs


def _run_once(item_count: int, delay_seconds: float) -> tuple[float, int, int]:
    helper, nested_refs = _build_helper(delay_seconds)
    entities = _build_entities(item_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(entities_list=entities, mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count:
        raise AssertionError("export_selected() did not preserve root object count")
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
