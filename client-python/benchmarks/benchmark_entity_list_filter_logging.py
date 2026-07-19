"""Benchmark suppressed entity-list filter logging overhead.

The benchmark calls Campaign.list() with a disabled INFO logger and a large
filter tree. It isolates work done before the stubbed GraphQL request, where
eager filter serialization is otherwise paid even though no log record is
emitted.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.entities.opencti_campaign import Campaign
from pycti.utils.opencti_logger import logger


class _StubClient:
    def __init__(self):
        self.app_logger = logger("ERROR", json_logging=False)("benchmark")

    @staticmethod
    def query(_query, _variables):
        return {
            "data": {
                "campaigns": {
                    "edges": [],
                    "pageInfo": {"hasNextPage": False},
                }
            }
        }

    @staticmethod
    def process_multiple(_data, _with_pagination=False):
        return []


def _build_filters(filter_count: int) -> dict:
    return {
        "mode": "and",
        "filters": [
            {
                "key": ["name"],
                "values": [f"indicator-{index:08d}", f"campaign-{index:08d}"],
                "operator": "eq",
                "mode": "or",
            }
            for index in range(filter_count)
        ],
        "filterGroups": [],
    }


def _run_once(filter_count: int, calls: int) -> tuple[float, int]:
    campaign = Campaign(_StubClient())
    filters = _build_filters(filter_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    for _ in range(calls):
        campaign.list(filters=filters)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--filters", type=int, default=1000)
    parser.add_argument("--calls", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.filters, 10), 1)
    samples = [_run_once(args.filters, args.calls) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "filters": args.filters,
        "calls": args.calls,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
