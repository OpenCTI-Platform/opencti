"""Benchmark STIX2 patch label lookup and relation request amplification."""

import argparse
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _Label:
    def __init__(self, latency_seconds, label_ids):
        self.latency_seconds = latency_seconds
        self.label_ids = label_ids
        self.list_calls = 0
        self.create_calls = 0

    def list(self, filters, getAll=True):
        self.list_calls += 1
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        values = filters["filters"][0]["values"]
        return [{"id": self.label_ids[value], "value": value} for value in values]

    def create(self, value):
        self.create_calls += 1
        label_id = self.label_ids.setdefault(value, f"label--created-{value}")
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        return {"id": label_id, "value": value}


class _RelationAdder:
    def __init__(self, latency_seconds, label_ids, added_ids):
        self.latency_seconds = latency_seconds
        self.label_ids = label_ids
        self.added_ids = added_ids
        self.read_calls = 0
        self.relation_calls = 0

    def add_label(self, id, label_name=None, label_id=None):
        if label_name is not None:
            self.read_calls += 1
            label_id = self.label_ids[label_name]
            if self.latency_seconds:
                time.sleep(self.latency_seconds)
        self.relation_calls += 1
        self.added_ids.append(label_id)
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        return True


class _NestedRefRelationship:
    def __init__(self, latency_seconds, added_ids):
        self.latency_seconds = latency_seconds
        self.added_ids = added_ids
        self.calls = 0

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.calls += 1
        self.added_ids.extend(to_ids)
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        return True


class _OpenCTI:
    def __init__(self, latency_seconds, refs):
        self.label_ids = {f"label-{index}": f"label--{index}" for index in range(refs)}
        self.added_ids = []
        self.label = _Label(latency_seconds, self.label_ids)
        self.stix_domain_object = _RelationAdder(
            latency_seconds, self.label_ids, self.added_ids
        )
        self.stix_nested_ref_relationship = _NestedRefRelationship(
            latency_seconds, self.added_ids
        )


def _run_once(refs, latency_seconds):
    opencti = _OpenCTI(latency_seconds, refs)
    updater = OpenCTIStix2Update(opencti)
    labels = [{"value": f"label-{index}"} for index in range(refs)]

    tracemalloc.start()
    start = time.perf_counter()
    updater.add_labels("indicator", "indicator--benchmark", labels)
    runtime_ms = (time.perf_counter() - start) * 1000
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    expected_ids = [opencti.label_ids[label["value"]] for label in labels]
    if opencti.added_ids != expected_ids:
        raise AssertionError("add_labels() changed ref ordering or dropped refs")

    return {
        "runtime_ms": runtime_ms,
        "peak_kib": peak_bytes / 1024,
        "list_calls": opencti.label.list_calls,
        "read_calls": opencti.stix_domain_object.read_calls,
        "create_calls": opencti.label.create_calls,
        "single_relation_calls": opencti.stix_domain_object.relation_calls,
        "bulk_relation_calls": opencti.stix_nested_ref_relationship.calls,
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
                "median_list_calls": statistics.median(
                    result["list_calls"] for result in results
                ),
                "median_read_calls": statistics.median(
                    result["read_calls"] for result in results
                ),
                "median_create_calls": statistics.median(
                    result["create_calls"] for result in results
                ),
                "median_single_relation_calls": statistics.median(
                    result["single_relation_calls"] for result in results
                ),
                "median_bulk_relation_calls": statistics.median(
                    result["bulk_relation_calls"] for result in results
                ),
                "median_total_calls": statistics.median(
                    result["list_calls"]
                    + result["read_calls"]
                    + result["create_calls"]
                    + result["single_relation_calls"]
                    + result["bulk_relation_calls"]
                    for result in results
                ),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
