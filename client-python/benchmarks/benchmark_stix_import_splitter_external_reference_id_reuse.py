"""Benchmark cross-phase external-reference ID reuse during STIX import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time
import tracemalloc

from pycti.entities.opencti_external_reference import ExternalReference
from pycti.utils import opencti_stix2_splitter
from pycti.utils.opencti_stix2 import OpenCTIStix2
from pycti.utils.opencti_stix2_identifier import external_reference_generate_id


class _ExternalReferenceCollection:
    def __init__(self):
        self.generate_id_calls = 0
        self.list_calls = 0
        self.create_calls = 0
        self.refs_by_standard_id = {}

    def generate_id(self, url, source_name, external_id):
        self.generate_id_calls += 1
        standard_id = ExternalReference.generate_id(url, source_name, external_id)
        self.refs_by_standard_id[standard_id] = (url, source_name, external_id)
        return standard_id

    def list(self, **kwargs):
        self.list_calls += 1
        standard_ids = kwargs["filters"]["filters"][0]["values"]
        return [
            {
                "id": f"internal--{standard_id}",
                "standard_id": standard_id,
                "source_name": self.refs_by_standard_id[standard_id][1],
                "url": self.refs_by_standard_id[standard_id][0],
                "external_id": self.refs_by_standard_id[standard_id][2],
                "description": None,
            }
            for standard_id in standard_ids
        ]

    def create(self, **_kwargs):
        self.create_calls += 1
        raise AssertionError("Prefetched references should not be created")


class _OpenCTI:
    def __init__(self):
        self.external_reference = _ExternalReferenceCollection()
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_splitter_external_reference_id_reuse"
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
            "benchmark_stix_import_splitter_external_reference_id_reuse.worker"
        )


def _run_once(object_count: int) -> tuple[float, float, int, int, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    splitter_generate_id_calls = 0
    original_splitter_generate_id = (
        opencti_stix2_splitter.external_reference_generate_id
    )

    def count_splitter_generate_id(url=None, source_name=None, external_id=None):
        nonlocal splitter_generate_id_calls
        splitter_generate_id_calls += 1
        standard_id = external_reference_generate_id(
            url=url,
            source_name=source_name,
            external_id=external_id,
        )
        opencti.external_reference.refs_by_standard_id[standard_id] = (
            url,
            source_name,
            external_id,
        )
        return standard_id

    opencti_stix2_splitter.external_reference_generate_id = count_splitter_generate_id

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
                        "url": f"https://example.test/reference/{index}",
                    }
                ],
            }
            for index in range(object_count)
        ],
    }

    tracemalloc.start()
    started_at = time.perf_counter()
    try:
        stix2.import_bundle(bundle)
    finally:
        opencti_stix2_splitter.external_reference_generate_id = (
            original_splitter_generate_id
        )
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return (
        elapsed_seconds,
        peak_bytes / 1024,
        splitter_generate_id_calls,
        opencti.external_reference.generate_id_calls,
        opencti.external_reference.list_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100))
    samples = [_run_once(args.objects) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_memory_samples = [sample[1] for sample in samples]
    splitter_generate_id_call_samples = [sample[2] for sample in samples]
    api_generate_id_call_samples = [sample[3] for sample in samples]
    list_call_samples = [sample[4] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_memory_kib": round(statistics.median(peak_memory_samples), 3),
        "median_splitter_generate_id_calls": statistics.median(
            splitter_generate_id_call_samples
        ),
        "median_api_generate_id_calls": statistics.median(api_generate_id_call_samples),
        "median_total_generate_id_calls": statistics.median(
            [
                splitter_calls + import_calls
                for _, _, splitter_calls, import_calls, _ in samples
            ]
        ),
        "median_list_calls": statistics.median(list_call_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
