"""Benchmark STIX2 patch object-ref mutation request amplification."""

import argparse
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _RelationAdder:
    def __init__(self, latency_seconds, added_ids):
        self.latency_seconds = latency_seconds
        self.calls = 0
        self.added_ids = added_ids

    def add_stix_object_or_stix_relationship(self, id, stixObjectOrStixRelationshipId):
        self.calls += 1
        self.added_ids.append(stixObjectOrStixRelationshipId)
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        return True


class _NestedRefRelationship:
    def __init__(self, latency_seconds, added_ids):
        self.latency_seconds = latency_seconds
        self.calls = 0
        self.added_ids = added_ids

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.calls += 1
        self.added_ids.extend(to_ids)
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        return True


class _OpenCTI:
    def __init__(self, latency_seconds):
        self.added_ids = []
        self.report = _RelationAdder(latency_seconds, self.added_ids)
        self.stix_nested_ref_relationship = _NestedRefRelationship(
            latency_seconds, self.added_ids
        )


def _run_once(refs, latency_seconds):
    opencti = _OpenCTI(latency_seconds)
    updater = OpenCTIStix2Update(opencti)
    object_refs = [{"value": f"indicator--{index}"} for index in range(refs)]

    tracemalloc.start()
    start = time.perf_counter()
    updater.add_object_refs("report", "report--benchmark", object_refs)
    runtime_ms = (time.perf_counter() - start) * 1000
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    expected_ids = [object_ref["value"] for object_ref in object_refs]
    if opencti.added_ids != expected_ids:
        raise AssertionError("add_object_refs() changed ref ordering or dropped refs")

    return {
        "runtime_ms": runtime_ms,
        "peak_kib": peak_bytes / 1024,
        "single_calls": opencti.report.calls,
        "bulk_calls": opencti.stix_nested_ref_relationship.calls,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refs", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--latency-ms", type=float, default=1.0)
    args = parser.parse_args()

    results = [_run_once(args.refs, args.latency_ms / 1000) for _ in range(args.repeat)]
    print(
        json.dumps(
            {
                "refs": args.refs,
                "repeat": args.repeat,
                "latency_ms": args.latency_ms,
                "median_runtime_ms": round(
                    statistics.median(result["runtime_ms"] for result in results), 3
                ),
                "median_peak_kib": round(
                    statistics.median(result["peak_kib"] for result in results), 3
                ),
                "median_single_calls": statistics.median(
                    result["single_calls"] for result in results
                ),
                "median_bulk_calls": statistics.median(
                    result["bulk_calls"] for result in results
                ),
                "median_total_calls": statistics.median(
                    result["single_calls"] + result["bulk_calls"] for result in results
                ),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
