"""Benchmark duplicate extension-backed AttackPattern order reads."""

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

_PACKAGE_ROOT = Path(
    os.environ.get("PYCTI_BENCHMARK_PACKAGE_ROOT", Path(__file__).resolve().parents[1])
)
sys.path.insert(0, str(_PACKAGE_ROOT))

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_attack_pattern import AttackPattern

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def pick_aliases(_stix_object):
        return []


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.stix2 = _Stix2()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def _build_attack_pattern(index: int):
    return {
        "id": f"attack-pattern--{index}",
        "type": "attack-pattern",
        "name": f"Benchmark attack pattern {index}",
        "x_mitre_id": f"T{index}",
        "x_mitre_platforms": [],
        "x_mitre_permissions_required": [],
        "x_mitre_detection": "",
        "x_opencti_stix_ids": [],
        "x_opencti_granted_refs": [],
        "x_opencti_workflow_id": None,
        "x_opencti_modified_at": None,
        "opencti_upsert_operations": None,
        "extensions": {_OPENCTI_EXTENSION: {"order": 42}},
    }


def _build_api() -> tuple[_OpenCTI, AttackPattern]:
    opencti = _OpenCTI()
    api = AttackPattern(opencti)
    api.create = lambda **kwargs: kwargs
    return opencti, api


def _run_once(iterations: int) -> tuple[float, Counter, int]:
    opencti, api = _build_api()
    checksum = 0

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            stix_object = _build_attack_pattern(index)
            api.import_from_stix2(stixObject=stix_object)
            checksum += stix_object["x_opencti_order"]
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
        "import_from_stix2": _summarize(samples, args.iterations),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
