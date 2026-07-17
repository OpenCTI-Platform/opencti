"""Benchmark concurrent request-header context isolation.

The benchmark runs two overlapping logical requests against one
OpenCTIApiClient instance. Each request sets distinct draft, work, applicant,
and retry headers, then reads them after the other request has also mutated the
client. Shared mutable headers cause the first request to observe the second
request's values.
"""

from __future__ import annotations

import argparse
import json
import statistics
import threading
import time

from pycti.api.opencti_api_client import OpenCTIApiClient


def _client():
    client = object.__new__(OpenCTIApiClient)
    client.request_headers = {
        "Authorization": "Bearer benchmark",
        "Content-Type": "application/json",
    }
    client.draft_id = ""
    return client


def _snapshot(client):
    headers = client.get_request_headers(hide_token=False)
    return {
        "draft_id": client.get_draft_id(),
        "work_id": headers.get("opencti-work-id"),
        "applicant_id": headers.get("opencti-applicant-id"),
        "retry_number": headers.get("opencti-retry-number"),
    }


def _run_once(iterations: int) -> tuple[float, int]:
    client = _client()
    leaked_snapshots = 0
    started_at = time.perf_counter()

    for index in range(iterations):
        first_ready = threading.Event()
        second_ready = threading.Event()
        snapshots = {}

        def first_request():
            client.set_draft_id(f"draft-a-{index}")
            client.set_work_id(f"work-a-{index}")
            client.set_applicant_id_header(f"applicant-a-{index}")
            client.set_retry_number(index)
            first_ready.set()
            second_ready.wait()
            snapshots["a"] = _snapshot(client)

        def second_request():
            first_ready.wait()
            client.set_draft_id(f"draft-b-{index}")
            client.set_work_id(f"work-b-{index}")
            client.set_applicant_id_header(f"applicant-b-{index}")
            client.set_retry_number(index + 1)
            second_ready.set()
            snapshots["b"] = _snapshot(client)

        first_thread = threading.Thread(target=first_request)
        second_thread = threading.Thread(target=second_request)
        first_thread.start()
        second_thread.start()
        first_thread.join()
        second_thread.join()

        expected = {
            "a": {
                "draft_id": f"draft-a-{index}",
                "work_id": f"work-a-{index}",
                "applicant_id": f"applicant-a-{index}",
                "retry_number": str(index),
            },
            "b": {
                "draft_id": f"draft-b-{index}",
                "work_id": f"work-b-{index}",
                "applicant_id": f"applicant-b-{index}",
                "retry_number": str(index + 1),
            },
        }
        leaked_snapshots += sum(
            1
            for request_id in ("a", "b")
            if snapshots[request_id] != expected[request_id]
        )

    return time.perf_counter() - started_at, leaked_snapshots


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 10))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    runtime_samples = [sample[0] for sample in samples]
    leaked_snapshot_samples = [sample[1] for sample in samples]
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(runtime_samples) * 1000, 3),
        "min_runtime_ms": round(min(runtime_samples) * 1000, 3),
        "max_runtime_ms": round(max(runtime_samples) * 1000, 3),
        "median_leaked_snapshots": int(statistics.median(leaked_snapshot_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
