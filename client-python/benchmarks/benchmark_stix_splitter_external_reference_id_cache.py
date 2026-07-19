"""Microbenchmark for repeated external-reference ID generation in the splitter."""

from __future__ import annotations

import argparse
import json
import statistics
import time

from pycti.utils import opencti_stix2_splitter as splitter_module
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def _build_bundle(object_count: int) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--splitter-external-reference-benchmark",
        "objects": [
            {
                "id": f"malware--{index:08d}",
                "type": "malware",
                "external_references": [
                    {
                        "source_name": "benchmark",
                        "url": "https://example.test/reference",
                    }
                ],
            }
            for index in range(object_count)
        ],
    }


def _run_once(object_count: int) -> tuple[float, int]:
    splitter = OpenCTIStix2Splitter()
    bundle = _build_bundle(object_count)
    generate_id_calls = 0
    original_generate_id = splitter_module.external_reference_generate_id

    def count_generate_id(*args, **kwargs):
        nonlocal generate_id_calls
        generate_id_calls += 1
        return original_generate_id(*args, **kwargs)

    splitter_module.external_reference_generate_id = count_generate_id
    try:
        started_at = time.perf_counter()
        expectations, _, bundles = splitter.split_bundle_with_expectations(
            bundle, use_json=False
        )
        elapsed_seconds = time.perf_counter() - started_at
    finally:
        splitter_module.external_reference_generate_id = original_generate_id

    if expectations != object_count:
        raise AssertionError("splitter did not preserve object count")
    if len(bundles) != object_count:
        raise AssertionError("splitter did not emit one bundle per object")
    if any(
        len(split_bundle["objects"][0]["external_references"]) != 1
        for split_bundle in bundles
    ):
        raise AssertionError("splitter did not preserve external references")
    return elapsed_seconds, generate_id_calls


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=10000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.objects, 100))
    samples = [_run_once(args.objects) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    generate_id_call_samples = [sample[1] for sample in samples]

    result = {
        "objects": args.objects,
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
