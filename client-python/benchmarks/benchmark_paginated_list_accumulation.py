"""Microbenchmark for paginated entity list accumulation.

The benchmark isolates the copied getAll pagination pattern used by entity
list methods. GraphQL requests are stubbed so the cost of growing the final
result list across many pages is measurable.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.entities.opencti_stix_core_object import StixCoreObject


class _NoOpLogger:
    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class _PagedClient:
    def __init__(self, item_count: int, page_size: int):
        self.app_logger = _NoOpLogger()
        self.pages = []
        for page_start in range(0, item_count, page_size):
            page_end = min(page_start + page_size, item_count)
            self.pages.append(
                {
                    "items": [
                        {"id": f"indicator--{index:08d}"}
                        for index in range(page_start, page_end)
                    ],
                    "pageInfo": {
                        "endCursor": str(len(self.pages)),
                        "hasNextPage": page_end < item_count,
                    },
                }
            )

    def query(self, query, variables):
        after = variables["after"]
        page_index = 0 if after is None else int(after) + 1
        return {"data": {"stixCoreObjects": self.pages[page_index]}}

    def process_multiple(self, page, with_pagination=False):
        return page["items"]


def _run_once(item_count: int, page_size: int) -> tuple[float, int]:
    client = _PagedClient(item_count, page_size)
    entity = StixCoreObject(client)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = entity.list(getAll=True, first=page_size)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(result) != item_count:
        raise AssertionError("list(getAll=True) did not preserve item count")
    if result[0]["id"] != "indicator--00000000":
        raise AssertionError("list(getAll=True) did not preserve first item order")
    if result[-1]["id"] != f"indicator--{item_count - 1:08d}":
        raise AssertionError("list(getAll=True) did not preserve last item order")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=100000)
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.items, 1000), args.page_size)
    samples = [_run_once(args.items, args.page_size) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "items": args.items,
        "page_size": args.page_size,
        "pages": (args.items + args.page_size - 1) // args.page_size,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
