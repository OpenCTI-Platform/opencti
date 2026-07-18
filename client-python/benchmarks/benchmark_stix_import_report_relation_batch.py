"""Benchmark report object-ref mutation batching during STIX relationship import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _ReportCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.add_calls = []

    def add_stix_object_or_stix_relationship(self, **kwargs):
        self.add_calls.append((kwargs["id"], kwargs["stixObjectOrStixRelationshipId"]))
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        return True


class _NestedRefCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.add_many_calls = []

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.add_many_calls.append((from_id, tuple(to_ids), relationship_type))
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        return True


class _StixCoreRelationshipCollection:
    @staticmethod
    def import_from_stix2(**kwargs):
        stix_relation = kwargs["stixRelation"]
        return {
            "id": stix_relation["id"],
            "entity_type": "stix-core-relationship",
        }


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.report = _ReportCollection(request_delay_ms)
        self.stix_nested_ref_relationship = _NestedRefCollection(request_delay_ms)
        self.stix_core_relationship = _StixCoreRelationshipCollection()
        self.app_logger = logging.getLogger(
            "benchmark_stix_import_report_relation_batch"
        )

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def logger_class(_name):
        return logging.getLogger("benchmark_stix_import_report_relation_batch.worker")

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None


def _embedded_relationships():
    return {
        "created_by": None,
        "object_marking": None,
        "object_label": [],
        "open_vocabs": {},
        "granted_refs": [],
        "kill_chain_phases": [],
        "object_refs": [],
        "external_references": ["external-reference--shared"],
        "reports": {
            "external-reference--shared": {
                "id": "report--shared",
            }
        },
        "sample_refs": [],
    }


def _run_once(
    relationship_count: int, request_delay_ms: float
) -> tuple[float, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    stix2.extract_embedded_relationships = lambda *_args, **_kwargs: (
        _embedded_relationships()
    )

    started_at = time.perf_counter()
    with stix2._report_object_ref_dedupe_scope():
        for index in range(relationship_count):
            stix2.import_relationship(
                {
                    "id": f"relationship--{index}",
                    "type": "relationship",
                    "source_ref": "malware--shared-source",
                    "target_ref": "indicator--shared-target",
                }
            )
    elapsed_seconds = time.perf_counter() - started_at

    return (
        elapsed_seconds,
        len(opencti.report.add_calls),
        len(opencti.stix_nested_ref_relationship.add_many_calls),
        sum(
            len(to_ids)
            for _, to_ids, _ in opencti.stix_nested_ref_relationship.add_many_calls
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--relationships", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--request-delay-ms", type=float, default=0)
    args = parser.parse_args()

    _run_once(args.relationships, args.request_delay_ms)
    samples = [
        _run_once(args.relationships, args.request_delay_ms) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    single_add_call_samples = [sample[1] for sample in samples]
    bulk_add_call_samples = [sample[2] for sample in samples]
    bulk_add_ref_samples = [sample[3] for sample in samples]
    result = {
        "relationships": args.relationships,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_single_report_relation_add_calls": statistics.median(
            single_add_call_samples
        ),
        "median_bulk_report_relation_add_calls": statistics.median(
            bulk_add_call_samples
        ),
        "median_bulk_report_relation_refs": statistics.median(bulk_add_ref_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
