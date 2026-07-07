"""Microbenchmark for connector state read/update/write cycles."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


def _build_helper() -> OpenCTIConnectorHelper:
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.connector_state = json.dumps(
        {
            "start_from": "0-0",
            "recover_until": "2026-07-07T00:00:00.000Z",
            "cursor": {"partition": "main", "sequence": 1},
        }
    )
    return helper


def _run_once(iterations: int) -> tuple[float, int]:
    helper = _build_helper()
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    for index in range(iterations):
        state = helper.get_state()
        if state is None:
            raise AssertionError("connector state unexpectedly disappeared")
        state["start_from"] = f"{index}-0"
        state["cursor"]["sequence"] = index
        helper.set_state(state)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    final_state = helper.get_state()
    if final_state is None or final_state["cursor"]["sequence"] != iterations - 1:
        raise AssertionError("connector state was not preserved")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
