"""Microbenchmark for repeated OpenCTI STIX helper dispatch lookups."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
import tracemalloc
from types import SimpleNamespace

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _Helper:
    def read(self, **_kwargs):
        return None


def _build_opencti() -> SimpleNamespace:
    helper_names = {
        "attack_pattern",
        "campaign",
        "capability",
        "case_incident",
        "case_rfi",
        "case_rft",
        "channel",
        "course_of_action",
        "data_component",
        "data_source",
        "draft",
        "event",
        "external_reference",
        "feedback",
        "group",
        "grouping",
        "identity",
        "incident",
        "indicator",
        "infrastructure",
        "internal_file",
        "intrusion_set",
        "kill_chain_phase",
        "label",
        "language",
        "location",
        "malware",
        "malware_analysis",
        "marking_definition",
        "narrative",
        "note",
        "notification",
        "observed_data",
        "opinion",
        "playbook",
        "public_dashboard",
        "report",
        "role",
        "security_coverage",
        "settings",
        "stix_core_object",
        "stix_core_relationship",
        "stix_cyber_observable",
        "stix_domain_object",
        "stix_nested_ref_relationship",
        "stix_sighting_relationship",
        "task",
        "threat_actor",
        "threat_actor_group",
        "threat_actor_individual",
        "tool",
        "trash",
        "user",
        "vocabulary",
        "vulnerability",
        "work",
        "workspace",
    }
    return SimpleNamespace(**{name: _Helper() for name in helper_names})


def _run_once(iterations: int) -> tuple[float, int]:
    stix2 = OpenCTIStix2(_build_opencti())
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    hits = 0
    for _ in range(iterations):
        hits += stix2.get_reader("Malware") is not None
        hits += stix2.get_stix_helper().get("malware") is not None
        hits += stix2.get_internal_helper().get("user") is not None
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    expected_hits = iterations * 3
    if hits != expected_hits:
        raise AssertionError(f"expected {expected_hits} hits, got {hits}")
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "iterations": args.iterations,
        "lookups": args.iterations * 3,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
