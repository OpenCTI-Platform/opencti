"""Benchmark overlapping connector callback context isolation.

The benchmark overlaps two ListenQueue._data_handler() calls on one helper
instance. Each logical request carries distinct work, draft, applicant, and
validation context. Shared helper attributes cause the first callback to
observe the second callback's values once both requests are in flight.
"""

from __future__ import annotations

import argparse
import json
import statistics
import threading
import time

from pycti.connector.opencti_connector_helper import ListenQueue, OpenCTIConnectorHelper


class _NoopLogger:
    def error(self, *_args, **_kwargs):
        pass


class _NoopMetric:
    def inc(self, *_args, **_kwargs):
        pass


class _FakeWork:
    def to_received(self, *_args, **_kwargs):
        pass

    def to_processed(self, *_args, **_kwargs):
        pass


class _FakeApi:
    def __init__(self):
        self.work = _FakeWork()
        self.draft_id = ""
        self.applicant_id = None

    def set_draft_id(self, draft_id):
        self.draft_id = draft_id

    def set_applicant_id_header(self, applicant_id):
        self.applicant_id = applicant_id


def _helper():
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.work_id = None
    helper.validation_mode = "workbench"
    helper.force_validation = False
    helper.draft_id = None
    helper.playbook = None
    helper.enrichment_shared_organizations = None
    helper.applicant_id = "connector-applicant"
    helper.connect_type = "EXTERNAL_IMPORT"
    helper.api = _FakeApi()
    helper.api_impersonate = _FakeApi()
    helper.metric = _NoopMetric()
    helper.connector_logger = _NoopLogger()
    return helper


def _message(request_id: str, index: int):
    return {
        "event": {
            "marker": request_id,
            "validation_mode": f"validation-{request_id}-{index}",
            "force_validation": request_id == "b",
        },
        "internal": {
            "work_id": f"work-{request_id}-{index}",
            "draft_id": f"draft-{request_id}-{index}",
            "applicant_id": f"applicant-{request_id}-{index}",
        },
    }


def _snapshot(helper):
    return {
        "work_id": helper.work_id,
        "draft_id": helper.draft_id,
        "applicant_id": helper.applicant_id,
        "validation_mode": helper.validation_mode,
        "force_validation": helper.force_validation,
    }


def _run_once(iterations: int) -> tuple[float, int]:
    helper = _helper()
    leaked_snapshots = 0
    started_at = time.perf_counter()

    for index in range(iterations):
        first_ready = threading.Event()
        second_ready = threading.Event()
        snapshots = {}

        def callback(event_data):
            marker = event_data["marker"]
            if marker == "a":
                first_ready.set()
                second_ready.wait()
            else:
                second_ready.set()
            snapshots[marker] = _snapshot(helper)
            return "done"

        listen_queue = object.__new__(ListenQueue)
        listen_queue.helper = helper
        listen_queue.callback = callback
        listen_queue.connector_applicant_id = "connector-applicant"

        first_thread = threading.Thread(
            target=listen_queue._data_handler, args=(_message("a", index),)
        )
        second_thread = threading.Thread(
            target=listen_queue._data_handler, args=(_message("b", index),)
        )
        first_thread.start()
        first_ready.wait()
        second_thread.start()
        first_thread.join()
        second_thread.join()

        expected = {
            "a": {
                "work_id": f"work-a-{index}",
                "draft_id": f"draft-a-{index}",
                "applicant_id": f"applicant-a-{index}",
                "validation_mode": f"validation-a-{index}",
                "force_validation": False,
            },
            "b": {
                "work_id": f"work-b-{index}",
                "draft_id": f"draft-b-{index}",
                "applicant_id": f"applicant-b-{index}",
                "validation_mode": f"validation-b-{index}",
                "force_validation": True,
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
