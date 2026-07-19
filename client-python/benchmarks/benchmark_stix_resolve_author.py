"""Microbenchmark for repeated author resolution on unmatched report titles."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from types import SimpleNamespace

from pycti.utils.opencti_stix2 import OpenCTIStix2


def _run_once(iterations: int) -> float:
    stix2 = OpenCTIStix2(SimpleNamespace())
    started_at = time.perf_counter()
    for _ in range(iterations):
        if stix2.resolve_author("benchmark external reference") is not None:
            raise AssertionError("unmatched title unexpectedly resolved an author")
    return time.perf_counter() - started_at


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(samples) * 1000, 3),
        "min_runtime_ms": round(min(samples) * 1000, 3),
        "max_runtime_ms": round(max(samples) * 1000, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
