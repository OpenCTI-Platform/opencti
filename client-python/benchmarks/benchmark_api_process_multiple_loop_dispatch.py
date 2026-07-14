"""Benchmark row-loop dispatch overhead in ``OpenCTIApiClient.process_multiple()``."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.api.opencti_api_client import OpenCTIApiClient


class _BenchmarkClient(OpenCTIApiClient):
    def process_multiple_fields(self, data):
        return data


def _build_client() -> OpenCTIApiClient:
    return _BenchmarkClient.__new__(_BenchmarkClient)


def _run_once(client, data, with_pagination: bool) -> tuple[float, int]:
    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        result = client.process_multiple(data, with_pagination=with_pagination)
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    rows = result["entities"] if with_pagination else result
    return elapsed_seconds, len(rows)


def _benchmark_case(client, data, with_pagination: bool, repeat: int) -> dict:
    _run_once(client, data, with_pagination)
    samples = [_run_once(client, data, with_pagination) for _ in range(repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_count = samples[0][1]
    if any(sample[1] != expected_count for sample in samples):
        raise AssertionError("processed row count changed between runs")
    return {
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "rows_processed": expected_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=500000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    row = {"id": "benchmark-row"}
    list_rows = [row] * args.rows
    edge_rows = {"edges": [{"node": row}] * args.rows, "pageInfo": {"count": args.rows}}
    client = _build_client()
    result = {
        "rows": args.rows,
        "repeat": args.repeat,
        "list": _benchmark_case(client, list_rows, False, args.repeat),
        "list_paginated": _benchmark_case(client, list_rows, True, args.repeat),
        "edges": _benchmark_case(client, edge_rows, False, args.repeat),
        "edges_paginated": _benchmark_case(client, edge_rows, True, args.repeat),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
