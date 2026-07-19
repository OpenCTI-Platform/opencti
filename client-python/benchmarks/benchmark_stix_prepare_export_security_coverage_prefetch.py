"""Benchmark full-export batching for Security-Coverage related objects.

The benchmark isolates OpenCTIStix2.prepare_export(..., mode="full") with one
root entity linked to many unique Security-Coverage targets. Security-Coverage
already exposes a paginated list() API, so falling back to one read per target
is avoidable once the export lister map includes that type.
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


class _CountingSecurityCoverageLister:
    def __init__(self, targets_by_id: dict[str, dict], delay_seconds: float):
        self.targets_by_id = targets_by_id
        self.delay_seconds = delay_seconds
        self.list_calls = 0

    def list(self, **kwargs):
        self.list_calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return [self.targets_by_id[target_id] for target_id in kwargs["filters"]]


def _build_relationships(item_count: int) -> list[dict]:
    return [
        {
            "id": f"relationship--{index:08d}",
            "type": "covers",
            "x_opencti_id": f"relationship-internal-{index:08d}",
            "from": {
                "id": "root",
                "standard_id": "indicator--root",
                "entity_type": "Indicator",
                "parent_types": ["Stix-Domain-Object"],
            },
            "to": {
                "id": f"target-{index:08d}",
                "standard_id": f"security-coverage--{index:08d}",
                "entity_type": "Security-Coverage",
                "parent_types": ["Stix-Domain-Object"],
            },
        }
        for index in range(item_count)
    ]


def _build_targets_by_id(item_count: int) -> dict[str, dict]:
    return {
        f"target-{index:08d}": {
            "id": f"target-{index:08d}",
            "standard_id": f"security-coverage--{index:08d}",
            "entity_type": "Security-Coverage",
            "parent_types": ["Stix-Domain-Object"],
        }
        for index in range(item_count)
    }


def _build_helper(
    item_count: int, delay_seconds: float
) -> tuple[OpenCTIStix2, _CountingReader, _CountingSecurityCoverageLister]:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    targets_by_id = _build_targets_by_id(item_count)
    reader = _CountingReader(targets_by_id, delay_seconds)
    lister = _CountingSecurityCoverageLister(targets_by_id, delay_seconds)
    helper.opencti = SimpleNamespace(
        security_coverage=lister,
        stix_nested_ref_relationship=_StaticCollection([]),
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
    helper.get_reader = lambda _resolve_type: reader
    return helper, reader, lister


def _run_once(item_count: int, delay_seconds: float) -> tuple[float, int, int, int]:
    helper, reader, lister = _build_helper(item_count, delay_seconds)
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
    return elapsed_seconds, peak_bytes, reader.read_calls, lister.list_calls


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
    reader_call_samples = [sample[2] for sample in samples]
    lister_call_samples = [sample[3] for sample in samples]

    result = {
        "items": args.items,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_read_calls": int(statistics.median(reader_call_samples)),
        "median_list_calls": int(statistics.median(lister_call_samples)),
        "median_total_requests": int(
            statistics.median(
                [
                    reader_calls + lister_calls
                    for _, _, reader_calls, lister_calls in samples
                ]
            )
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
