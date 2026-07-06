"""Microbenchmark for STIX list export accumulation.

The benchmark isolates OpenCTIStix2.export_list() with one exported STIX
object per listed entity. It avoids GraphQL work so the cost of deduplication
and bundle growth is measurable.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2 import OpenCTIStix2


def _build_helper(entities: list[dict]) -> OpenCTIStix2:
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.export_entities_list = lambda **kwargs: entities
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


def _run_once(helper: OpenCTIStix2, item_count: int) -> tuple[float, int]:
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    bundle = helper.export_list(entity_type="Indicator")
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(bundle["objects"]) != item_count:
        raise AssertionError("export_list() did not preserve unique object count")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    entities = _build_entities(args.items)
    helper = _build_helper(entities)
    _run_once(
        _build_helper(_build_entities(min(args.items, 100))), min(args.items, 100)
    )
    samples = [_run_once(helper, args.items) for _ in range(args.repeat)]
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
