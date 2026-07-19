"""Benchmark repeated embedded relationship extraction during sighting import.

One STIX sighting can expand into many OpenCTI sighting relationships through
``where_sighted_refs``. Before reusing the embedded relationship extraction
result, each generated edge reprocessed the same file-bearing external
reference and uploaded its file again.
"""

from __future__ import annotations

import argparse
import base64
import gc
import json
import logging
import statistics
import time
import tracemalloc
from types import SimpleNamespace

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _ExternalReferenceCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.create_calls = 0
        self.uploaded_bytes = 0

    @staticmethod
    def generate_id(url, source_name, external_id):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def create(self, **kwargs):
        self.create_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        for file_obj in kwargs.get("files") or []:
            self.uploaded_bytes += len(file_obj.data)
        return {"id": "internal--external-reference"}


class _SightingCollection:
    def __init__(self):
        self.create_calls = 0

    def create(self, **kwargs):
        self.create_calls += 1
        return {
            "id": f"internal--sighting-{self.create_calls}",
            "entity_type": "stix-sighting-relationship",
        }


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.external_reference = _ExternalReferenceCollection(request_delay_ms)
        self.stix_sighting_relationship = _SightingCollection()
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_sighting_embedded_relationship_reuse"
        )

    @staticmethod
    def file(name, data, mime):
        return SimpleNamespace(name=name, data=data, mime=mime)

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def logger_class(_name):
        return logging.getLogger(
            "benchmark_stix_import_sighting_embedded_relationship_reuse.worker"
        )


def _build_sighting(target_count: int, size_bytes: int) -> dict:
    encoded_data = base64.b64encode(b"x" * size_bytes).decode("ascii")
    return {
        "id": "sighting--benchmark",
        "type": "sighting",
        "sighting_of_ref": "indicator--source",
        "where_sighted_refs": [
            f"identity--target-{index:08d}" for index in range(target_count)
        ],
        "external_references": [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "x_opencti_files": [
                    {
                        "name": "payload.bin",
                        "data": encoded_data,
                        "mime_type": "application/octet-stream",
                    }
                ],
            }
        ],
    }


def _run_once(
    target_count: int, size_bytes: int, request_delay_ms: float
) -> tuple[float, int, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    stix2.import_item(_build_sighting(target_count, size_bytes))
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if opencti.stix_sighting_relationship.create_calls != target_count:
        raise AssertionError("import_item() did not preserve sighting edge count")
    return (
        elapsed_seconds,
        peak_bytes,
        opencti.external_reference.create_calls,
        opencti.stix_sighting_relationship.create_calls,
        opencti.external_reference.uploaded_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--size-kib", type=int, default=1)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_kib * 1024
    _run_once(min(args.targets, 10), size_bytes, args.request_delay_ms)
    samples = [
        _run_once(args.targets, size_bytes, args.request_delay_ms)
        for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    external_reference_create_samples = [sample[2] for sample in samples]
    sighting_create_samples = [sample[3] for sample in samples]
    uploaded_byte_samples = [sample[4] for sample in samples]

    result = {
        "targets": args.targets,
        "size_kib": args.size_kib,
        "request_delay_ms": args.request_delay_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_external_reference_create_calls": statistics.median(
            external_reference_create_samples
        ),
        "median_sighting_create_calls": statistics.median(sighting_create_samples),
        "median_uploaded_kib": round(
            statistics.median(uploaded_byte_samples) / 1024, 3
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
