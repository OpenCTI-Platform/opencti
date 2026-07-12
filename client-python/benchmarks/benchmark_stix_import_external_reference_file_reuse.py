"""Benchmark repeated file-bearing external-reference resolution during STIX import.

OpenCTI exports can repeat the same embedded external reference across many
objects. When that reference carries the same file payload each time, repeated
resolution should not upload the same external-reference file once per parent
object.
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


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.external_reference = _ExternalReferenceCollection(request_delay_ms)
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_external_reference_file_reuse"
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
    def query(_query):
        return {"data": {"vocabularyCategories": []}}

    @staticmethod
    def logger_class(_name):
        return logging.getLogger(
            "benchmark_stix_import_external_reference_file_reuse.worker"
        )


def _build_object(size_bytes: int) -> dict:
    encoded_data = base64.b64encode(b"x" * size_bytes).decode("ascii")
    return {
        "type": "malware",
        "external_references": [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
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
    object_count: int, size_bytes: int, request_delay_ms: float
) -> tuple[float, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    stix_object = _build_object(size_bytes)
    bundle = {
        "type": "bundle",
        "id": "bundle--benchmark",
        "objects": [
            {
                **stix_object,
                "id": f"malware--{index:08d}",
            }
            for index in range(object_count)
        ],
    }

    def import_item_with_retries(item, *_args, **_kwargs):
        result = stix2.extract_embedded_relationships(item)
        if result["external_references"] != ["internal--external-reference"]:
            raise AssertionError("external reference resolution changed output")
        return None

    stix2.import_item_with_retries = import_item_with_retries

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    stix2.import_bundle(bundle)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return (
        elapsed_seconds,
        peak_bytes,
        opencti.external_reference.create_calls,
        opencti.external_reference.uploaded_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=1000)
    parser.add_argument("--size-kib", type=int, default=1)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_kib * 1024
    _run_once(min(args.objects, 10), size_bytes, args.request_delay_ms)
    samples = [
        _run_once(args.objects, size_bytes, args.request_delay_ms)
        for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    create_call_samples = [sample[2] for sample in samples]
    uploaded_byte_samples = [sample[3] for sample in samples]

    result = {
        "objects": args.objects,
        "size_kib": args.size_kib,
        "request_delay_ms": args.request_delay_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_external_reference_create_calls": statistics.median(
            create_call_samples
        ),
        "median_uploaded_kib": round(
            statistics.median(uploaded_byte_samples) / 1024, 3
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
