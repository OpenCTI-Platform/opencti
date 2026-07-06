"""Microbenchmark for selected STIX export accumulation.

The benchmark isolates OpenCTIStix2.export_selected() with one exported STIX
object per selected entity. It avoids GraphQL work so the cost of deduplication,
bundle growth, and bundle-level post-processing is measurable.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2 import OpenCTIStix2


def _build_helper() -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.generate_export = lambda entity: entity
    helper.prepare_export = lambda entity, mode, access_filter: [entity]
    return helper


def _build_entities(item_count: int) -> list[dict]:
    return [
        {
            "id": f"indicator--{index:08d}",
            "type": "indicator",
            "name": f"indicator-{index}",
        }
        for index in range(item_count)
    ]


def _run_once(helper: OpenCTIStix2, entities: list[dict]) -> tuple[float, int]:
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    bundle = helper.export_selected(entities)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(bundle["objects"]) != len(entities):
        raise AssertionError("export_selected() did not preserve unique object count")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    helper = _build_helper()
    entities = _build_entities(args.items)
    _run_once(helper, _build_entities(min(args.items, 100)))
    samples = [_run_once(helper, entities) for _ in range(args.repeat)]
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
