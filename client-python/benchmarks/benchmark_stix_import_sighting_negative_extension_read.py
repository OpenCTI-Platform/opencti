"""Benchmark duplicate negative extension reads during sighting import setup."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _SightingCollection:
    def __init__(self):
        self.create_calls = 0
        self.negative_checksum = 0

    def create(self, **kwargs):
        self.create_calls += 1
        self.negative_checksum += int(kwargs["x_opencti_negative"])
        return {
            "id": "sighting--benchmark",
            "entity_type": "stix-sighting-relationship",
        }


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.stix_sighting_relationship = _SightingCollection()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    @staticmethod
    def get_draft_id():
        return ""


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


def _build_sighting(index: int):
    return {
        "id": f"sighting--{index}",
        "type": "sighting",
        "extensions": {_OPENCTI_EXTENSION: {"negative": True}},
    }


def _run_once(iterations: int) -> tuple[float, Counter, int, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    embedded_relationships = _embedded_relationships()

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            stix2.import_sighting(
                _build_sighting(index),
                "indicator--benchmark",
                "identity--benchmark",
                embedded_relationships=embedded_relationships,
            )
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return (
        elapsed_seconds,
        opencti.extension_lookup_counts,
        opencti.stix_sighting_relationship.create_calls,
        opencti.stix_sighting_relationship.negative_checksum,
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
    expected_create_calls = args.iterations
    expected_negative_checksum = args.iterations
    if any(sample[1] != expected_lookup_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_create_calls for sample in samples):
        raise AssertionError("sighting create count changed between runs")
    if any(sample[3] != expected_negative_checksum for sample in samples):
        raise AssertionError("negative sighting values changed between runs")

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_lookup_counts.items())),
        "median_create_calls": statistics.median(sample[2] for sample in samples),
        "median_negative_checksum": statistics.median(sample[3] for sample in samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
