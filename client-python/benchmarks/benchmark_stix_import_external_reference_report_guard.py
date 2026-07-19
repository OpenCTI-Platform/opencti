"""Benchmark report-only external-reference type checks during ordinary import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _CountingType(str):
    def __new__(cls, value):
        instance = super().__new__(cls, value)
        instance.eq_calls = 0
        return instance

    def __eq__(self, other):
        self.eq_calls += 1
        return super().__eq__(other)

    __hash__ = str.__hash__


class _OpenCTI:
    def __init__(self):
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_external_reference_report_guard"
        )

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def query(_query):
        return {"data": {"vocabularyCategories": []}}

    @staticmethod
    def logger_class(_name):
        return logging.getLogger(
            "benchmark_stix_import_external_reference_report_guard.worker"
        )


def _run_once(
    external_reference_count: int, count_type_checks: bool = False
) -> tuple[float, int | None]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    stix2._get_external_reference_generated_id = (
        lambda _url, _source_name, _external_id: "external-reference--benchmark"
    )
    stix2._create_or_get_external_reference = (
        lambda *_args: "external-reference--benchmark"
    )
    object_type = _CountingType("indicator") if count_type_checks else "indicator"
    stix_object = {
        "type": object_type,
        "external_references": [
            {
                "source_name": "benchmark",
                "url": f"https://example.test/reference/{index}",
            }
            for index in range(external_reference_count)
        ],
    }

    started_at = time.perf_counter()
    stix2.extract_embedded_relationships(stix_object)
    elapsed_seconds = time.perf_counter() - started_at
    return elapsed_seconds, getattr(object_type, "eq_calls", None)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-references", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.external_references, 100))
    samples = [_run_once(args.external_references) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    _, probe_type_eq_calls = _run_once(args.external_references, count_type_checks=True)
    result = {
        "external_references": args.external_references,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "probe_type_eq_calls": probe_type_eq_calls,
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
