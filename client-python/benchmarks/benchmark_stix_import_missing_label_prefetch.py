"""Benchmark avoiding redundant reads for labels proven missing by prefetch."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _LabelCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.list_calls = 0
        self.read_calls = 0
        self.create_calls = 0

    def _delay(self):
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)

    def list(self, **kwargs):
        self.list_calls += 1
        self._delay()
        return []

    def read_or_create_unchecked(self, **kwargs):
        self.read_calls += 1
        self._delay()
        self.create_calls += 1
        self._delay()
        value = kwargs["value"]
        return {"id": f"label--{value}", "value": value}

    def create(self, **kwargs):
        self.create_calls += 1
        self._delay()
        value = kwargs["value"]
        return {"id": f"label--{value}", "value": value}


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.label = _LabelCollection(request_delay_ms)
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_missing_label_prefetch"
        )

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def query(_query):
        return {"data": {"vocabularyCategories": []}}

    @staticmethod
    def logger_class(_name):
        return logging.getLogger("benchmark_stix_import_missing_label_prefetch.worker")


def _run_once(
    object_count: int, request_delay_ms: float
) -> tuple[float, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)

    def import_item_with_retries(item, *_args, **_kwargs):
        stix2.extract_embedded_relationships(item)
        return None

    stix2.import_item_with_retries = import_item_with_retries
    bundle = {
        "type": "bundle",
        "id": "bundle--benchmark",
        "objects": [
            {
                "id": f"malware--{index}",
                "type": "malware",
                "labels": [f"label-{index}"],
            }
            for index in range(object_count)
        ],
    }

    started_at = time.perf_counter()
    stix2.import_bundle(bundle)
    elapsed_seconds = time.perf_counter() - started_at
    return (
        elapsed_seconds,
        opencti.label.list_calls,
        opencti.label.read_calls,
        opencti.label.create_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--request-delay-ms", type=float, default=0)
    args = parser.parse_args()

    _run_once(args.objects, args.request_delay_ms)
    samples = [
        _run_once(args.objects, args.request_delay_ms) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    list_call_samples = [sample[1] for sample in samples]
    read_call_samples = [sample[2] for sample in samples]
    create_call_samples = [sample[3] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_list_calls": int(statistics.median(list_call_samples)),
        "median_read_calls": int(statistics.median(read_call_samples)),
        "median_create_calls": int(statistics.median(create_call_samples)),
        "median_total_requests": int(
            statistics.median(
                [
                    list_calls + read_calls + create_calls
                    for _, list_calls, read_calls, create_calls in samples
                ]
            )
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
