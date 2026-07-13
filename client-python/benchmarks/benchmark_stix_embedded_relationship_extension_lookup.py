"""Benchmark repeated root extension lookups during embedded relationship extraction."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
_EXTENSION_VALUES = {
    "created_by_ref": "identity--benchmark",
    "labels": [],
    "kill_chain_phases": [],
    "external_references": [],
    "granted_refs": [],
}


class _BenchmarkOpenCTI:
    def __init__(self):
        self.extension_lookup_calls = 0

    @staticmethod
    def get_draft_id():
        return ""

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_calls += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def _build_stix_object() -> dict:
    return {
        "id": "malware--benchmark",
        "type": "malware",
        "extensions": {_OPENCTI_EXTENSION: _EXTENSION_VALUES},
    }


def _run_once(iterations: int) -> tuple[float, int, int]:
    opencti = _BenchmarkOpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    result_checksum = 0

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for _ in range(iterations):
            result = stix2.extract_embedded_relationships(_build_stix_object())
            result_checksum += len(result["granted_refs"])
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    return elapsed_seconds, opencti.extension_lookup_calls, result_checksum


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    lookup_call_samples = [sample[1] for sample in samples]
    expected_checksum = samples[0][2]
    if any(sample[2] != expected_checksum for sample in samples):
        raise AssertionError(
            "embedded relationship extraction result changed between runs"
        )
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_extension_lookup_calls": int(statistics.median(lookup_call_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
