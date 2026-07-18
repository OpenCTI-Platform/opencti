"""Microbenchmark for non-upload GraphQL variable extraction.

The benchmark isolates the work performed by OpenCTIApiClient.query() before a
non-upload request is handed to requests. The fake session keeps network and
JSON encoding out of the measurement so the cost of probing GraphQL variables
for File objects is visible.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc

from pycti.api.opencti_api_client import OpenCTIApiClient


class _FakeResponse:
    status_code = 200

    @staticmethod
    def json():
        return {"data": {"ok": True}}


class _FakeSession:
    @staticmethod
    def post(*args, **kwargs):
        del args, kwargs
        return _FakeResponse()


def _build_client() -> OpenCTIApiClient:
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    client.api_url = "http://benchmark.invalid/graphql"
    client.request_headers = {}
    client.ssl_verify = False
    client.cert = None
    client.proxies = None
    client.session_requests_timeout = 300
    client.session = _FakeSession()
    client.extract_files_root_calls = 0
    client.contains_file_calls = 0
    extract_files = client._extract_files
    contains_file = client._contains_file

    def tracking_extract_files(obj, path_prefix=""):
        if path_prefix == "":
            client.extract_files_root_calls += 1
        return extract_files(obj, path_prefix)

    def tracking_contains_file(obj):
        client.contains_file_calls += 1
        return contains_file(obj)

    client._extract_files = tracking_extract_files
    client._contains_file = tracking_contains_file
    return client


def _build_variables(item_count: int) -> dict:
    return {
        "filters": [
            {
                "key": ["entity_type"],
                "values": [f"Indicator-{index}", f"Report-{index}"],
                "mode": "or",
                "operator": "eq",
                "nested": {
                    "labels": [f"label-{index}", f"tag-{index}"],
                    "enabled": True,
                },
            }
            for index in range(item_count)
        ],
        "search": "benchmark",
        "first": item_count,
    }


def _run_once(
    client: OpenCTIApiClient, variables: dict
) -> tuple[float, int, bool, int, int]:
    gc.collect()
    tracemalloc.start()
    client.extract_files_root_calls = 0
    client.contains_file_calls = 0
    started_at = time.perf_counter()
    client.query("query Benchmark { about { version } }", variables)
    elapsed_seconds = time.perf_counter() - started_at
    extract_files_root_calls = client.extract_files_root_calls
    contains_file_calls = client.contains_file_calls
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    cleaned, files = client._extract_files(variables)
    return (
        elapsed_seconds,
        peak_bytes,
        cleaned is variables and files == [],
        extract_files_root_calls,
        contains_file_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    client = _build_client()
    variables = _build_variables(args.items)
    _run_once(client, _build_variables(min(args.items, 100)))
    samples = [_run_once(client, variables) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    extract_files_root_call_samples = [sample[3] for sample in samples]
    contains_file_call_samples = [sample[4] for sample in samples]

    result = {
        "items": args.items,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "reuses_variable_tree": samples[-1][2],
        "median_extract_files_root_calls": statistics.median(
            extract_files_root_call_samples
        ),
        "median_contains_file_calls": statistics.median(contains_file_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
