"""Benchmark duplicate extension-backed file reads during STIX import setup."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
from collections import Counter
from types import SimpleNamespace

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _NullLogger:
    @staticmethod
    def info(*_args, **_kwargs):
        return None


class _OpenCTI:
    def __init__(self):
        self.app_logger = _NullLogger()
        self.extension_lookup_counts = Counter()
        self.observable_creates = 0
        self.stix_cyber_observable = SimpleNamespace(
            create=self._create_observable,
        )

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    @staticmethod
    def get_draft_id():
        return ""

    def _create_observable(self, **_kwargs):
        self.observable_creates += 1
        return {"id": "observable--benchmark", "entity_type": "Directory"}


class _ObjectHelper:
    def __init__(self):
        self.object_creates = 0

    def import_from_stix2(self, **_kwargs):
        self.object_creates += 1
        return {"id": "malware--benchmark", "entity_type": "Malware"}


def _embedded_relationships():
    return {
        "created_by": None,
        "object_marking": None,
        "object_label": None,
        "open_vocabs": {},
        "granted_refs": [],
        "kill_chain_phases": [],
        "object_refs": [],
        "external_references": [],
        "reports": {},
        "sample_refs": [],
    }


def _build_object():
    return {
        "id": "malware--benchmark",
        "type": "malware",
        "name": "benchmark",
        "is_family": False,
        "extensions": {_OPENCTI_EXTENSION: {"files": []}},
    }


def _build_observable():
    return {
        "id": "directory--benchmark",
        "type": "directory",
        "path": "/benchmark",
        "extensions": {_OPENCTI_EXTENSION: {"files": []}},
    }


def _run_once(iterations: int) -> tuple[float, Counter, int]:
    opencti = _OpenCTI()
    object_helper = _ObjectHelper()
    stix2 = OpenCTIStix2(opencti)
    stix2.extract_embedded_relationships = lambda *_args, **_kwargs: (
        _embedded_relationships()
    )
    stix2.get_stix_helper = lambda: {"malware": object_helper}
    stix_object = _build_object()
    stix_observable = _build_observable()

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            if index % 2 == 0:
                stix2.import_object(stix_object, update=False)
            else:
                stix2.import_observable(stix_observable, update=False)
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return (
        elapsed_seconds,
        opencti.extension_lookup_counts,
        object_helper.object_creates + opencti.observable_creates,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    expected_lookup_counts = samples[0][1]
    expected_import_count = args.iterations
    if any(sample[1] != expected_lookup_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_import_count for sample in samples):
        raise AssertionError("import count changed between runs")

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_lookup_counts.items())),
        "median_import_count": statistics.median(sample[2] for sample in samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
