"""Benchmark suppressed entity update log serialization.

Feedback.update_field() and Task.update_field() log their full update payload.
Connector clients commonly run above INFO, so serializing a large update payload
for a suppressed log line is pure overhead.
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import statistics
import time
import tracemalloc

from pycti.entities.opencti_feedback import Feedback
from pycti.entities.opencti_task import Task
from pycti.utils.opencti_logger import logger


class _BenchmarkClient:
    def __init__(self):
        self.app_logger = logger(logging.ERROR, json_logging=False)(
            "benchmark-entity-update-logging"
        )
        self.query_calls = 0

    def query(self, query, variables):
        self.query_calls += 1
        if "FeedbackEdit" in query:
            return {
                "data": {"stixDomainObjectEdit": {"fieldPatch": {"id": "feedback--1"}}}
            }
        return {"data": {"taskFieldPatch": {"id": "task--1"}}}

    @staticmethod
    def process_multiple_fields(data):
        return data


def _build_input(field_count: int) -> list:
    return [
        {
            "key": f"field_{index:04d}",
            "value": [f"value-{index:04d}-" + ("x" * 64)],
            "operation": "replace",
        }
        for index in range(field_count)
    ]


def _run_once(field_count: int, calls: int) -> tuple[float, int]:
    client = _BenchmarkClient()
    feedback = Feedback(client)
    task = Task(client)
    update_input = _build_input(field_count)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    for _ in range(calls):
        feedback.update_field(id="feedback--1", input=update_input)
        task.update_field(id="task--1", input=update_input)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if client.query_calls != calls * 2:
        raise AssertionError("benchmark update calls did not complete")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fields", type=int, default=100)
    parser.add_argument("--calls", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.fields, 2), min(args.calls, 2))
    samples = [_run_once(args.fields, args.calls) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "fields": args.fields,
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
