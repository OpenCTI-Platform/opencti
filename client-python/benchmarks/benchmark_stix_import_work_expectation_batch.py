"""Benchmark work expectation reporting during bundle import.

The benchmark isolates the successful-item progress path used by
OpenCTIStix2.import_bundle(..., work_id=...). Each imported item currently
reports one work expectation through GraphQL even when the queue message
contains many same-level objects.
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time
from types import SimpleNamespace

from pycti.api.opencti_api_work import OpenCTIApiWork
from pycti.utils.opencti_stix2 import OpenCTIStix2


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.bundle_send_to_queue = True
        self.request_delay_seconds = request_delay_ms / 1000
        self.query_calls = 0
        self.reported_expectations = 0
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_work_expectation_batch"
        )
        self.external_reference = SimpleNamespace(
            generate_id=lambda *_args, **_kwargs: None
        )
        self.work = OpenCTIApiWork(self)

    def query(self, _query, variables=None, *_args, **_kwargs):
        self.query_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        self.reported_expectations += variables.get("expectations", 1)
        return {"data": {"workEdit": {"reportExpectation": variables["id"]}}}

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def logger_class(_name):
        return logging.getLogger("benchmark_stix_import_work_expectation_batch.worker")


def _run_once(object_count: int, request_delay_ms: float) -> tuple[float, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    stix2._prefetch_import_vocabularies = lambda _items: None
    stix2._prefetch_import_external_references = lambda _items: None
    stix2._prefetch_import_kill_chain_phases = lambda _items: None
    stix2._prefetch_import_labels = lambda _items: None

    def import_item_with_retries(_item, _update, _types, work_id, _bundle_id):
        stix2.opencti.work.report_expectation(work_id, None)
        return None

    stix2.import_item_with_retries = import_item_with_retries
    bundle = {
        "type": "bundle",
        "id": "bundle--benchmark",
        "objects": [
            {
                "id": f"malware--{index:08d}",
                "type": "malware",
            }
            for index in range(object_count)
        ],
    }

    started_at = time.perf_counter()
    stix2.import_bundle(bundle, work_id="work--benchmark")
    elapsed_seconds = time.perf_counter() - started_at
    if opencti.reported_expectations != object_count:
        raise AssertionError("import_bundle() did not preserve expectation count")
    return elapsed_seconds, opencti.query_calls, opencti.reported_expectations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    args = parser.parse_args()

    _run_once(min(args.objects, 100), args.request_delay_ms)
    samples = [
        _run_once(args.objects, args.request_delay_ms) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    query_call_samples = [sample[1] for sample in samples]
    expectation_samples = [sample[2] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_query_calls": int(statistics.median(query_call_samples)),
        "median_reported_expectations": int(statistics.median(expectation_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
