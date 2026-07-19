"""Benchmark request pressure from async rule polling.

The backend may return ``False`` while a long-running rule application is still
active. The client should wait between those checks instead of issuing a tight
poll loop. This benchmark models a short long-running operation and records the
number of GraphQL requests plus CPU time needed to observe completion.
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.entities.opencti_stix_core_object import StixCoreObject


class _OpenCTI:
    def __init__(self, complete_after_ms: float):
        self.complete_after_seconds = complete_after_ms / 1000
        self.started_at = 0.0
        self.query_calls = 0
        self.app_logger = logging.getLogger("benchmark_rule_async_polling")

    def query(self, _query, _variables):
        self.query_calls += 1
        return {
            "data": {
                "ruleApplyAsync": (
                    time.perf_counter() - self.started_at >= self.complete_after_seconds
                )
            }
        }


def _run_once(
    complete_after_ms: float, poll_interval_ms: float
) -> tuple[float, float, int]:
    opencti = _OpenCTI(complete_after_ms)
    stix_core_object = StixCoreObject(opencti)
    opencti.started_at = time.perf_counter()
    cpu_started_at = time.process_time()
    stix_core_object.rule_apply_async(
        element_id="indicator--benchmark",
        rule_id="rule--benchmark",
        execution_id="execution--benchmark",
        poll_interval_seconds=poll_interval_ms / 1000,
    )
    cpu_seconds = time.process_time() - cpu_started_at
    elapsed_seconds = time.perf_counter() - opencti.started_at
    return elapsed_seconds, cpu_seconds, opencti.query_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--complete-after-ms", type=float, default=50)
    parser.add_argument("--poll-interval-ms", type=float, default=1)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(args.complete_after_ms, args.poll_interval_ms)
    samples = [
        _run_once(args.complete_after_ms, args.poll_interval_ms)
        for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    cpu_samples = [sample[1] for sample in samples]
    query_call_samples = [sample[2] for sample in samples]
    result = {
        "complete_after_ms": args.complete_after_ms,
        "poll_interval_ms": args.poll_interval_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "median_cpu_ms": round(statistics.median(cpu_samples) * 1000, 3),
        "median_query_calls": int(statistics.median(query_call_samples)),
        "min_query_calls": min(query_call_samples),
        "max_query_calls": max(query_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
