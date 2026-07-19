"""Microbenchmark for draining a preloaded connector batch backlog.

The benchmark isolates BatchCallbackWrapper._extract_batch_data() by filling
the in-memory backlog once and draining it in fixed-size chunks. Callback and
network work are intentionally excluded so repeated buffer copying is visible.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.connector.opencti_connector_helper import BatchCallbackWrapper


class _NoOpLogger:
    def info(self, *args, **kwargs):
        pass


class _Helper:
    def __init__(self):
        self.connector_logger = _NoOpLogger()


def _run_once(item_count: int, batch_size: int) -> tuple[float, int]:
    original_interval = BatchCallbackWrapper._TIMER_CHECK_INTERVAL
    BatchCallbackWrapper._TIMER_CHECK_INTERVAL = 3600.0
    wrapper = BatchCallbackWrapper(
        _Helper(),
        lambda _batch_data: None,
        batch_size=batch_size,
        batch_timeout=3600.0,
    )
    try:
        with wrapper._lock:
            wrapper.batch.extend(range(item_count))
            wrapper.batch_start_time = time.time()

        gc.collect()
        tracemalloc.start()
        started_at = time.perf_counter()
        drained = []
        while True:
            with wrapper._lock:
                if len(wrapper.batch) == 0:
                    break
                batch_data = wrapper._extract_batch_data("benchmark")
            drained.extend(batch_data["events"])
        elapsed_seconds = time.perf_counter() - started_at
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        wrapper.stop()
        BatchCallbackWrapper._TIMER_CHECK_INTERVAL = original_interval

    if len(drained) != item_count:
        raise AssertionError("batch drain did not preserve item count")
    if drained[0] != 0:
        raise AssertionError("batch drain did not preserve first item order")
    if drained[-1] != item_count - 1:
        raise AssertionError("batch drain did not preserve last item order")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=100000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.items, 1000), args.batch_size)
    samples = [_run_once(args.items, args.batch_size) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "items": args.items,
        "batch_size": args.batch_size,
        "batches": (args.items + args.batch_size - 1) // args.batch_size,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
