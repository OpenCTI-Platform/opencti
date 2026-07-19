"""Benchmark duplicate external-reference file extension reads during extraction."""

from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

_PACKAGE_ROOT = Path(
    os.environ.get("PYCTI_BENCHMARK_PACKAGE_ROOT", Path(__file__).resolve().parents[1])
)
sys.path.insert(0, str(_PACKAGE_ROOT))

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _ExternalReference:
    @staticmethod
    def generate_id(url, source_name, external_id):
        return f"external-reference--{url}|{source_name}|{external_id}"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.external_reference = _ExternalReference()
        self.app_logger = SimpleNamespace(warning=lambda *_args, **_kwargs: None)

    @staticmethod
    def get_draft_id():
        return ""

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    @staticmethod
    def query(_query):
        return {"data": {"vocabularyCategories": []}}

    @staticmethod
    def logger_class(_name):
        return SimpleNamespace(warning=lambda *_args, **_kwargs: None)


def _build_stix_object(index: int):
    field_name = (
        "external_references" if index % 2 == 0 else "x_opencti_external_references"
    )
    return {
        "id": f"malware--{index}",
        "type": "malware",
        "created_by_ref": None,
        "object_marking_refs": [],
        "labels": [],
        "kill_chain_phases": [],
        "x_opencti_granted_refs": [],
        field_name: [
            {
                "source_name": "benchmark",
                "url": f"https://example.test/reference/{index}",
                "external_id": f"REF-{index}",
                "extensions": {
                    _OPENCTI_EXTENSION: {"files": [{"name": "payload.txt"}]}
                },
            }
        ],
    }


def _build_stix2() -> tuple[_OpenCTI, OpenCTIStix2]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    stix2._create_or_get_external_reference = (
        lambda generated_ref_id, *_args: generated_ref_id
    )
    return opencti, stix2


def _run_once(iterations: int) -> tuple[float, Counter, int]:
    opencti, stix2 = _build_stix2()
    stix_objects = (_build_stix_object(0), _build_stix_object(1))
    checksum = 0

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            result = stix2.extract_embedded_relationships(stix_objects[index & 1])
            checksum += len(result["external_references"][0])
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return elapsed_seconds, opencti.extension_lookup_counts, checksum


def _summarize(samples, iterations: int):
    elapsed_samples = [sample[0] for sample in samples]
    expected_lookup_counts = samples[0][1]
    expected_checksum = samples[0][2]
    if any(sample[1] != expected_lookup_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_checksum for sample in samples):
        raise AssertionError("result checksum changed between runs")
    return {
        "iterations": iterations,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_lookup_counts.items())),
        "median_checksum": statistics.median(sample[2] for sample in samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    result = {
        "repeat": args.repeat,
        "extract_embedded_relationships": _summarize(samples, args.iterations),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
