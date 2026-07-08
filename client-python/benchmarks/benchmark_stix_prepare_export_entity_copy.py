"""Microbenchmark for avoidable prepare_export() entity copies.

The benchmark isolates simple STIX export of ordinary entities with custom
attributes enabled. It exercises the default path where prepare_export() does
not need an entity snapshot for x_* field removal.
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


class _EmptyCollection:
    def list(self, **kwargs):
        return []


def _build_helper() -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=_EmptyCollection(),
        api_url="http://localhost/graphql",
    )
    return helper


def _build_entity(field_count: int) -> dict:
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }
    entity.update({f"field_{index}": "value" for index in range(field_count)})
    return entity


def _run_once(call_count: int, field_count: int) -> tuple[float, int]:
    helper = _build_helper()
    entity = _build_entity(field_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    for _ in range(call_count):
        result = helper.prepare_export(entity.copy(), mode="simple")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result) != 1:
        raise AssertionError("prepare_export() did not preserve the entity")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=100000)
    parser.add_argument("--fields", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.calls, 100), args.fields)
    samples = [_run_once(args.calls, args.fields) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "calls": args.calls,
        "fields": args.fields,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
