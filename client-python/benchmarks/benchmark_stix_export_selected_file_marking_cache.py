"""Microbenchmark for repeated shared file-marking construction during export.

The benchmark isolates export_selected() over many roots that each carry one
attached file with the same marking definition. Before file markings reuse the
export-scoped marking cache, prepare_export() reconstructs the same
marking-definition dictionary once per root even though bundle deduplication
retains only one copy.
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

    @staticmethod
    def fetch_opencti_file(url, binary=False, serialize=False):
        del url, binary, serialize
        return "ZGF0YQ=="


def _build_helper() -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = _SyntheticOpenCTI()
    return helper


def _build_entities(item_count: int) -> list[dict]:
    shared_marking = {
        "standard_id": "marking-definition--shared",
        "definition_type": "TLP",
        "definition": "TLP:AMBER",
        "created": "2026-01-01T00:00:00.000Z",
    }
    return [
        {
            "id": f"indicator-internal--{index:08d}",
            "standard_id": f"indicator--{index:08d}",
            "entity_type": "Indicator",
            "parent_types": ["Stix-Domain-Object"],
            "importFiles": [
                {
                    "id": "file--shared",
                    "name": "shared.bin",
                    "metaData": {"mimetype": "application/octet-stream"},
                    "objectMarking": [shared_marking.copy()],
                }
            ],
            "importFilesIds": ["file--shared"],
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
        raise AssertionError(
            "export_selected() did not deduplicate shared file marking"
        )
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
