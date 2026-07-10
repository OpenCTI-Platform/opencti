"""Benchmark repeated external-reference ID generation during STIX import."""

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
        self.create_calls = 0

    def generate_id(self, url, source_name, external_id):
        self.generate_id_calls += 1
        return ExternalReference.generate_id(url, source_name, external_id)

    def create(self, **kwargs):
        self.create_calls += 1
        return {"id": f"internal--{kwargs.get('url') or kwargs.get('source_name')}"}


class _OpenCTI:
    def __init__(self):
        self.external_reference = _ExternalReferenceCollection()
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_external_reference_id_cache"
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
            "benchmark_stix_import_external_reference_id_cache.worker"
        )


def _run_once(object_count: int) -> tuple[float, int, int]:
    opencti = _OpenCTI()
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
    stix2.import_bundle(bundle)
    elapsed_seconds = time.perf_counter() - started_at
    return (
        elapsed_seconds,
        opencti.external_reference.generate_id_calls,
        opencti.external_reference.create_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100))
    samples = [_run_once(args.objects) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    generate_id_call_samples = [sample[1] for sample in samples]
    create_call_samples = [sample[2] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_external_reference_generate_id_calls": statistics.median(
            generate_id_call_samples
        ),
        "median_external_reference_create_calls": statistics.median(
            create_call_samples
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
