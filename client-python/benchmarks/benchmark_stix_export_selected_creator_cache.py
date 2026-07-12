"""Microbenchmark for repeated shared creator conversion during export.

The benchmark isolates export_selected() over many roots that share one
createdBy identity. Before export-scoped creator caching, prepare_export()
calls generate_export() for the same creator once per root even though bundle
deduplication retains only one copy.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _EmptyCollection:
    def list(self, **kwargs):
        del kwargs
        return []


class _SyntheticOpenCTI:
    api_url = "http://benchmark.invalid/graphql"
    stix_nested_ref_relationship = _EmptyCollection()

    @staticmethod
    def not_empty(value):
        return value not in (None, "", [], {})


def _build_helper() -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = _SyntheticOpenCTI()
    return helper


def _build_entities(item_count: int) -> list[dict]:
    shared_creator = {
        "id": "identity-internal--shared",
        "standard_id": "identity--shared",
        "entity_type": "Organization",
        "parent_types": ["Stix-Domain-Object"],
        "name": "Shared Creator",
        "description": "Synthetic shared creator for export benchmarking.",
        "identity_class": "organization",
        "sectors": ["technology"],
    }
    return [
        {
            "id": f"indicator-internal--{index:08d}",
            "standard_id": f"indicator--{index:08d}",
            "entity_type": "Indicator",
            "parent_types": ["Stix-Domain-Object"],
            "createdBy": shared_creator.copy(),
            "createdById": "identity-internal--shared",
        }
        for index in range(item_count)
    ]


def _run_once(item_count: int) -> tuple[float, int]:
    helper = _build_helper()
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = helper.export_selected(_build_entities(item_count), mode="simple")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result["objects"]) != item_count + 1:
        raise AssertionError("export_selected() did not deduplicate shared creator")
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
