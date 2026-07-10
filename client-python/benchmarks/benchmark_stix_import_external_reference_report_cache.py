"""Benchmark repeated external-reference report materialization during STIX import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _ExternalReferenceCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.create_calls = 0

    @staticmethod
    def generate_id(url, source_name, external_id):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def create(self, **kwargs):
        self.create_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        return {
            "id": self.generate_id(
                kwargs.get("url"), kwargs.get("source_name"), kwargs.get("external_id")
            )
        }


class _MarkingDefinitionCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.read_calls = 0

    def read(self, **_kwargs):
        self.read_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        return {"id": "marking-definition--tlp-clear"}


class _ReportCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.create_calls = 0

    @staticmethod
    def generate_fixed_fake_id(name, published=None):
        return f"report--{name}|{published}"

    def create(self, **kwargs):
        self.create_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        return {"id": kwargs["id"]}


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.external_reference = _ExternalReferenceCollection(request_delay_ms)
        self.marking_definition = _MarkingDefinitionCollection(request_delay_ms)
        self.report = _ReportCollection(request_delay_ms)
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_external_reference_report_cache"
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
        return logging.getLogger(
            "benchmark_stix_import_external_reference_report_cache.worker"
        )


def _run_once(
    object_count: int, request_delay_ms: float
) -> tuple[float, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    types = ["external-reference-as-report"]

    def import_item_with_retries(item, *_args, **_kwargs):
        stix2.extract_embedded_relationships(item, types)
        return None

    stix2.import_item_with_retries = import_item_with_retries
    bundle = {
        "type": "bundle",
        "id": "bundle--benchmark",
        "objects": [
            {
                "id": f"malware--{index}",
                "type": "malware",
                "external_references": [
                    {
                        "source_name": "benchmark",
                        "url": "https://example.test/reference",
                    }
                ],
            }
            for index in range(object_count)
        ],
    }

    started_at = time.perf_counter()
    stix2.import_bundle(bundle, types=types)
    elapsed_seconds = time.perf_counter() - started_at
    return (
        elapsed_seconds,
        opencti.external_reference.create_calls,
        opencti.marking_definition.read_calls,
        opencti.report.create_calls,
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
    external_reference_create_samples = [sample[1] for sample in samples]
    marking_read_samples = [sample[2] for sample in samples]
    report_create_samples = [sample[3] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_external_reference_create_calls": statistics.median(
            external_reference_create_samples
        ),
        "median_marking_read_calls": statistics.median(marking_read_samples),
        "median_report_create_calls": statistics.median(report_create_samples),
        "median_total_requests": statistics.median(
            [
                external_reference_create_calls
                + marking_read_calls
                + report_create_calls
                for (
                    _,
                    external_reference_create_calls,
                    marking_read_calls,
                    report_create_calls,
                ) in samples
            ]
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
