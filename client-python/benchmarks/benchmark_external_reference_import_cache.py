"""Benchmark repeated external-reference resolution during STIX import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _ExternalReference:
    def __init__(self):
        self.create_calls = 0

    @staticmethod
    def generate_id(url, source_name, external_id):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def create(self, **kwargs):
        self.create_calls += 1
        return {
            "id": self.generate_id(
                kwargs["url"], kwargs["source_name"], kwargs["external_id"]
            )
        }


class _OpenCTI:
    def __init__(self):
        self.external_reference = _ExternalReference()
        self.app_logger = logging.getLogger("benchmark_external_reference_import_cache")

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def query(_query):
        return {"data": {"vocabularyCategories": []}}


def _run_once(object_count: int) -> tuple[float, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix_object = {
        "type": "malware",
        "external_references": [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
            }
        ],
    }
    started_at = time.perf_counter()
    for _ in range(object_count):
        stix2.extract_embedded_relationships(dict(stix_object))
    elapsed_seconds = time.perf_counter() - started_at
    return elapsed_seconds, opencti.external_reference.create_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object-count", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(args.object_count)
    samples = [_run_once(args.object_count) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    create_call_samples = [sample[1] for sample in samples]
    result = {
        "object_count": args.object_count,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_external_reference_create_calls": statistics.median(
            create_call_samples
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
