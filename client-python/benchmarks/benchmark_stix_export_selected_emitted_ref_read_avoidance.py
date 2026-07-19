"""Microbenchmark for avoiding rereads of already-emitted full-export refs.

The benchmark isolates ``OpenCTIStix2.export_selected(..., mode="full")`` with
many roots that each already emit a unique creator, data source, and marking
definition before the full-export extra-ref scan runs. Those emitted objects
already satisfy the generated ``*_ref`` fields, so rereading them is avoidable.
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


def _build_targets_by_id(item_count: int) -> dict[str, dict]:
    targets_by_id = {}
    for index in range(item_count):
        creator = {
            "id": f"creator-{index:08d}",
            "standard_id": f"identity--creator-{index:08d}",
            "entity_type": "Identity",
            "parent_types": ["Stix-Domain-Object"],
        }
        data_source = {
            "id": f"data-source-{index:08d}",
            "standard_id": f"data-source--{index:08d}",
            "entity_type": "Data-Source",
            "parent_types": ["Stix-Domain-Object"],
        }
        marking_definition = {
            "id": f"marking-{index:08d}",
            "standard_id": f"marking-definition--{index:08d}",
            "entity_type": "Marking-Definition",
            "parent_types": ["Stix-Domain-Object"],
        }
        for target in (creator, data_source, marking_definition):
            targets_by_id[target["standard_id"]] = target
    return targets_by_id


def _build_root_entities(item_count: int, targets_by_id: dict[str, dict]) -> list[dict]:
    return [
        {
            "id": f"indicator--root-{index:08d}",
            "type": "indicator",
            "x_opencti_id": f"root-{index:08d}",
            "createdBy": targets_by_id[f"identity--creator-{index:08d}"],
            "createdById": f"creator-{index:08d}",
            "dataSource": targets_by_id[f"data-source--{index:08d}"],
            "dataSourceId": f"data-source-{index:08d}",
            "objectMarking": [
                {
                    "id": f"marking-{index:08d}",
                    "standard_id": f"marking-definition--{index:08d}",
                    "definition_type": "TLP",
                    "definition": "TLP:CLEAR",
                    "created": "2017-01-20T00:00:00.000Z",
                }
            ],
            "objectMarkingIds": [f"marking-{index:08d}"],
        }
        for index in range(item_count)
    ]


def _build_helper(item_count: int, delay_seconds: float) -> tuple[
    OpenCTIStix2,
    _CountingNestedRefCollection,
    _CountingReader,
]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    targets_by_id = _build_targets_by_id(item_count)
    nested_refs = _CountingNestedRefCollection(delay_seconds)
    reader = _CountingReader(targets_by_id, delay_seconds)
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
    helper.get_lister = lambda resolve_type: None
    helper._benchmark_targets_by_id = targets_by_id
    return helper, nested_refs, reader


def _run_once(item_count: int, delay_seconds: float) -> tuple[float, int, int, int]:
    helper, nested_refs, reader = _build_helper(item_count, delay_seconds)
    entities = _build_root_entities(item_count, helper._benchmark_targets_by_id)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(entities_list=entities, mode="full")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count * 4:
        raise AssertionError(
            "export_selected() did not preserve root and already-emitted ref count"
        )
    return elapsed_seconds, peak_bytes, nested_refs.list_calls, reader.read_calls


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
        "median_total_requests": int(
            statistics.median(
                [
                    nested_ref_list_calls + reader_calls
                    for _, _, nested_ref_list_calls, reader_calls in samples
                ]
            )
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
