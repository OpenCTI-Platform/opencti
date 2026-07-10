"""Benchmark repeated external-reference cache probes during import prefetch."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.entities.opencti_external_reference import ExternalReference
from pycti.utils.opencti_stix2 import OpenCTIStix2


class _ExternalReferenceCollection:
    def __init__(self):
        self.generate_id_calls = 0

    def generate_id(self, url, source_name, external_id):
        self.generate_id_calls += 1
        return ExternalReference.generate_id(url, source_name, external_id)


class _OpenCTI:
    def __init__(self):
        self.external_reference = _ExternalReferenceCollection()
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_external_reference_prefetch_dedupe"
        )

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None


class _CountingOpenCTIStix2(OpenCTIStix2):
    def __init__(self, opencti):
        super().__init__(opencti)
        self.get_in_cache_calls = 0

    def get_in_cache(self, data_id):
        self.get_in_cache_calls += 1
        return super().get_in_cache(data_id)


def _run_once(object_count: int) -> tuple[float, int, int]:
    opencti = _OpenCTI()
    stix2 = _CountingOpenCTIStix2(opencti)
    objects = [
        {
            "type": "malware",
            "external_references": [
                {
                    "source_name": "benchmark",
                    "url": "https://example.test/reference",
                }
            ],
        }
        for _ in range(object_count)
    ]

    started_at = time.perf_counter()
    stix2._prefetch_import_external_references(objects)
    elapsed_seconds = time.perf_counter() - started_at
    return (
        elapsed_seconds,
        stix2.get_in_cache_calls,
        opencti.external_reference.generate_id_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100))
    samples = [_run_once(args.objects) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    get_in_cache_call_samples = [sample[1] for sample in samples]
    generate_id_call_samples = [sample[2] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_get_in_cache_calls": statistics.median(get_in_cache_call_samples),
        "median_external_reference_generate_id_calls": statistics.median(
            generate_id_call_samples
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
