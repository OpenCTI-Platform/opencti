"""Benchmark STIX2 patch external-reference reuse for existing references."""

import argparse
import json
import statistics
import time
import tracemalloc

from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _ExternalReference:
    def __init__(self, latency_seconds, existing_refs, created_ids):
        self.latency_seconds = latency_seconds
        self.existing_refs = existing_refs
        self.created_ids = created_ids
        self.list_calls = 0
        self.create_calls = 0

    @staticmethod
    def generate_id(url=None, source_name=None, external_id=None):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def list(self, **kwargs):
        self.list_calls += 1
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        ids = kwargs["filters"]["filters"][0]["values"]
        return [self.existing_refs[standard_id] for standard_id in ids]

    def create(self, **kwargs):
        self.create_calls += 1
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        standard_id = self.generate_id(
            kwargs.get("url"), kwargs.get("source_name"), kwargs.get("external_id")
        )
        external_reference_id = self.existing_refs[standard_id]["id"]
        self.created_ids.append(external_reference_id)
        return {"id": external_reference_id}


class _RelationAdder:
    def __init__(self, latency_seconds, added_ids):
        self.latency_seconds = latency_seconds
        self.calls = 0
        self.added_ids = added_ids

    def add_external_reference(self, id, external_reference_id):
        self.calls += 1
        self.added_ids.append(external_reference_id)
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
    def __init__(self, latency_seconds, external_references):
        self.created_ids = []
        self.added_ids = []
        existing_refs = {}
        for external_reference in external_references:
            value = external_reference["value"]
            standard_id = _ExternalReference.generate_id(
                value.get("url"),
                value.get("source_name"),
                value.get("external_id"),
            )
            existing_refs[standard_id] = {
                "id": f"internal--{standard_id}",
                "standard_id": standard_id,
                "source_name": value.get("source_name"),
                "url": value.get("url"),
                "external_id": value.get("external_id"),
                "description": value.get("description"),
            }
        self.external_reference = _ExternalReference(
            latency_seconds, existing_refs, self.created_ids
        )
        self.stix_domain_object = _RelationAdder(latency_seconds, self.added_ids)
        self.stix_nested_ref_relationship = _NestedRefRelationship(
            latency_seconds, self.added_ids
        )


def _run_once(refs, latency_seconds):
    external_references = [
        {
            "value": {
                "source_name": "benchmark",
                "url": f"https://example.test/{index}",
            }
        }
        for index in range(refs)
    ]
    opencti = _OpenCTI(latency_seconds, external_references)
    updater = OpenCTIStix2Update(opencti)

    tracemalloc.start()
    start = time.perf_counter()
    updater.add_external_references(
        "indicator", "indicator--benchmark", external_references
    )
    runtime_ms = (time.perf_counter() - start) * 1000
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    expected_ids = [
        f"internal--external-reference--https://example.test/{index}"
        for index in range(refs)
    ]
    if opencti.added_ids != expected_ids:
        raise AssertionError(
            "add_external_references() changed ref ordering or dropped refs"
        )

    return {
        "runtime_ms": runtime_ms,
        "peak_kib": peak_bytes / 1024,
        "list_calls": opencti.external_reference.list_calls,
        "create_calls": opencti.external_reference.create_calls,
        "single_relation_calls": opencti.stix_domain_object.calls,
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
