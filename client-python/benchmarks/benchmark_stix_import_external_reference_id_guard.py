"""Benchmark cached external-reference ID lookups for repeated valid inputs."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.entities.opencti_external_reference import ExternalReference
from pycti.utils.opencti_stix2 import OpenCTIStix2


class _ExternalReferenceCollection:
    def __init__(self):
        self.generate_id_calls = 0

    def generate_id(self, url, source_name, external_id):
        self.generate_id_calls += 1
        return ExternalReference.generate_id(url, source_name, external_id)


class _OpenCTI:
    def __init__(self):
        self.external_reference = _ExternalReferenceCollection()
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_external_reference_id_guard"
        )

    @staticmethod
    def get_draft_id():
        return ""


def _run_once(iterations: int) -> tuple[float, int]:
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    url = "https://example.test/reference"
    source_name = "benchmark"
    external_id = "REF-1"

    stix2._get_external_reference_generated_id(url, source_name, external_id)
    started_at = time.perf_counter()
    for _ in range(iterations):
        stix2._get_external_reference_generated_id(url, source_name, external_id)
    elapsed_seconds = time.perf_counter() - started_at
    return elapsed_seconds, opencti.external_reference.generate_id_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 100))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    generate_id_call_samples = [sample[1] for sample in samples]
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_external_reference_generate_id_calls": statistics.median(
            generate_id_call_samples
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
