"""Benchmark duplicate extension-backed kill-chain phase order reads."""

from __future__ import annotations

import argparse
import gc
import json
import logging
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
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _KillChainPhase:
    def __init__(self):
        self.create_calls = 0
        self.order_checksum = 0

    def create(self, **kwargs):
        self.create_calls += 1
        self.order_checksum += kwargs["x_opencti_order"]
        return {
            "id": f"kill-chain-phase--{self.create_calls}",
            "entity_type": "Kill-Chain-Phase",
        }


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.kill_chain_phase = _KillChainPhase()
        self.app_logger = logging.getLogger(
            "benchmark_stix_embedded_kill_chain_order_extension_read"
        )

    @staticmethod
    def get_draft_id():
        return ""

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def _build_stix2() -> tuple[_OpenCTI, OpenCTIStix2]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    return opencti, stix2


def _build_object(index: int, legacy: bool):
    phase = {
        "kill_chain_name": "benchmark",
        "phase_name": f"phase-{index}",
        "extensions": {_OPENCTI_EXTENSION: {"order": 42}},
    }
    stix_object = {
        "id": f"malware--{index}",
        "type": "malware",
        "created_by_ref": None,
        "labels": [],
        "external_references": [],
        "x_opencti_granted_refs": [],
    }
    if legacy:
        stix_object["x_opencti_kill_chain_phases"] = [phase]
    else:
        stix_object["kill_chain_phases"] = [phase]
    return stix_object


def _run_once(iterations: int, legacy: bool) -> tuple[float, Counter, int, int]:
    opencti, stix2 = _build_stix2()

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            stix2.extract_embedded_relationships(_build_object(index, legacy))
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()

    return (
        elapsed_seconds,
        opencti.extension_lookup_counts,
        opencti.kill_chain_phase.create_calls,
        opencti.kill_chain_phase.order_checksum,
    )


def _summarize(samples, iterations: int):
    elapsed_samples = [sample[0] for sample in samples]
    expected_lookup_counts = samples[0][1]
    expected_create_calls = iterations
    expected_order_checksum = iterations * 42
    if any(sample[1] != expected_lookup_counts for sample in samples):
        raise AssertionError("extension lookup counts changed between runs")
    if any(sample[2] != expected_create_calls for sample in samples):
        raise AssertionError("kill-chain phase create count changed between runs")
    if any(sample[3] != expected_order_checksum for sample in samples):
        raise AssertionError("kill-chain phase order values changed between runs")
    return {
        "iterations": iterations,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "extension_lookup_counts": dict(sorted(expected_lookup_counts.items())),
        "median_create_calls": statistics.median(sample[2] for sample in samples),
        "median_order_checksum": statistics.median(sample[3] for sample in samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000), legacy=False)
    _run_once(min(args.iterations, 1000), legacy=True)
    standard_samples = [
        _run_once(args.iterations, legacy=False) for _ in range(args.repeat)
    ]
    legacy_samples = [
        _run_once(args.iterations, legacy=True) for _ in range(args.repeat)
    ]
    result = {
        "repeat": args.repeat,
        "standard": _summarize(standard_samples, args.iterations),
        "legacy": _summarize(legacy_samples, args.iterations),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
