"""Benchmark STIX import memory for base64-backed file uploads.

The benchmark isolates the import-side conversion of ``x_opencti_files`` data
from base64 text into the upload object passed to the entity wrapper. The
input bundle already owns the encoded string before tracing starts, so the
reported peak highlights the additional decoded representation retained during
one synchronous create mutation.
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


class _OpenCTI:
    def __init__(self):
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_base64_upload_memory"
        )
        self.stix_cyber_observable = SimpleNamespace(create=self._create_observable)
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

    def _create_observable(self, **kwargs):
        for file_obj in kwargs.get("files") or []:
            data = file_obj.data
            if hasattr(data, "read"):
                while True:
                    chunk = data.read(1024 * 1024)
                    if not chunk:
                        break
                    self.uploaded_bytes += len(chunk)
                data.seek(0)
            else:
                self.uploaded_bytes += len(data)
        return {"id": "observable--benchmark", "entity_type": "Stix-Cyber-Observable"}


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


def _build_observable(size_bytes: int) -> dict:
    encoded_data = base64.b64encode(b"x" * size_bytes).decode("ascii")
    return {
        "id": "ipv4-addr--11111111-1111-4111-8111-111111111111",
        "type": "ipv4-addr",
        "value": "1.2.3.4",
        "x_opencti_files": [
            {
                "name": "payload.bin",
                "data": encoded_data,
                "mime_type": "application/octet-stream",
            }
        ],
    }


def _run_once(size_bytes: int) -> tuple[float, int, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.extract_embedded_relationships = _empty_embedded_relationships
    observable = _build_observable(size_bytes)

    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    stix2.import_observable(observable)
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if opencti.uploaded_bytes != size_bytes:
        raise AssertionError(
            "import_observable() did not upload the full decoded payload"
        )
    return elapsed_seconds, peak_bytes, opencti.uploaded_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mib", type=int, default=16)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_mib * 1024 * 1024
    _run_once(min(size_bytes, 1024 * 1024))
    samples = [_run_once(size_bytes) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    uploaded_byte_samples = [sample[2] for sample in samples]

    result = {
        "size_mib": args.size_mib,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "median_uploaded_kib": round(
            statistics.median(uploaded_byte_samples) / 1024, 3
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
