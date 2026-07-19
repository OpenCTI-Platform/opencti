"""Benchmark duplicate Artifact payload upload work during STIX import.

An Artifact exported by OpenCTI carries the primary import file in both the
standard ``payload_bin`` field and the OpenCTI ``x_opencti_files`` extension.
Before the optimization, importing that object uploaded the same file once in
the create mutation and again through a follow-up ``importPush`` mutation.
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

from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.utils.opencti_stix2 import OpenCTIStix2


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_artifact_payload_file_reuse"
        )
        self.stix_cyber_observable = StixCyberObservable(self)
        self.create_calls = 0
        self.add_file_calls = 0
        self.uploaded_bytes = 0

    @staticmethod
    def file(name, data, mime):
        return SimpleNamespace(name=name, data=data, mime=mime)

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def process_multiple_fields(value):
        return value

    def query(self, query, variables):
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        if "StixCyberObservableAdd" in query:
            self.create_calls += 1
            for file_obj in variables["Artifact"].get("files") or []:
                self.uploaded_bytes += len(file_obj.data)
            return {
                "data": {
                    "stixCyberObservableAdd": {
                        "id": f"artifact-internal--{self.create_calls}",
                        "entity_type": "Artifact",
                    }
                }
            }
        if "StixCyberObservableEdit" in query:
            self.add_file_calls += 1
            self.uploaded_bytes += len(variables["file"].data)
            return {"data": {"stixCyberObservableEdit": {"importPush": {}}}}
        raise AssertionError("Unexpected GraphQL query")


def _empty_embedded_relationships(_stix_object, _types=None):
    return {
        "created_by": None,
        "object_marking": [],
        "object_label": [],
        "open_vocabs": {},
        "granted_refs": [],
        "kill_chain_phases": [],
        "object_refs": [],
        "external_references": [],
        "reports": {},
        "sample_refs": [],
    }


def _build_artifacts(artifact_count: int, size_bytes: int) -> list[dict]:
    encoded_data = base64.b64encode(b"x" * size_bytes).decode("ascii")
    return [
        {
            "id": f"artifact--benchmark-{index:08d}",
            "type": "artifact",
            "mime_type": "application/octet-stream",
            "x_opencti_additional_names": ["payload.bin"],
            "payload_bin": encoded_data,
            "x_opencti_files": [
                {
                    "name": "payload.bin",
                    "data": encoded_data,
                    "mime_type": "application/octet-stream",
                }
            ],
        }
        for index in range(artifact_count)
    ]


def _run_once(
    artifact_count: int, size_bytes: int, request_delay_ms: float
) -> tuple[float, int, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    stix2.extract_embedded_relationships = _empty_embedded_relationships
    artifacts = _build_artifacts(artifact_count, size_bytes)

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    for artifact in artifacts:
        stix2.import_observable(artifact)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if opencti.create_calls != artifact_count:
        raise AssertionError("import_observable() did not create every artifact")
    return (
        elapsed_seconds,
        peak_bytes,
        opencti.create_calls,
        opencti.add_file_calls,
        opencti.uploaded_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=int, default=1000)
    parser.add_argument("--size-kib", type=int, default=1)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_kib * 1024
    _run_once(min(args.artifacts, 10), size_bytes, args.request_delay_ms)
    samples = [
        _run_once(args.artifacts, size_bytes, args.request_delay_ms)
        for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    create_call_samples = [sample[2] for sample in samples]
    add_file_call_samples = [sample[3] for sample in samples]
    uploaded_byte_samples = [sample[4] for sample in samples]

    result = {
        "artifacts": args.artifacts,
        "size_kib": args.size_kib,
        "request_delay_ms": args.request_delay_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_create_calls": statistics.median(create_call_samples),
        "median_add_file_calls": statistics.median(add_file_call_samples),
        "median_total_requests": statistics.median(
            [
                create_calls + add_file_calls
                for create_calls, add_file_calls in zip(
                    create_call_samples, add_file_call_samples
                )
            ]
        ),
        "median_uploaded_kib": round(
            statistics.median(uploaded_byte_samples) / 1024, 3
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
