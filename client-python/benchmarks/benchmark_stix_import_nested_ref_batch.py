"""Benchmark nested-ref relationship mutations during observable import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time
from types import SimpleNamespace

from pycti.entities.opencti_stix_nested_ref_relationship import (
    StixNestedRefRelationship,
)
from pycti.utils.opencti_stix2 import OpenCTIStix2


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.query_calls = 0
        self.relationship_inputs = []
        self.app_logger = logging.getLogger("benchmark_stix_import_nested_ref_batch")
        self.stix_cyber_observable = SimpleNamespace(create=self._create_observable)
        self.stix_nested_ref_relationship = StixNestedRefRelationship(self)

    @staticmethod
    def _create_observable(**_kwargs):
        return {"id": "observable--benchmark", "entity_type": "Network-Traffic"}

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    def query(self, query, variables):
        self.query_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        if "stixCoreObjectEdit" in query:
            for to_id in variables["input"]["toIds"]:
                self.relationship_inputs.append(
                    {
                        "fromId": variables["id"],
                        "toId": to_id,
                        "relationship_type": variables["input"]["relationship_type"],
                    }
                )
            return {"data": {"stixCoreObjectEdit": {"relationsAdd": {"id": "source"}}}}
        if "input" in variables:
            self.relationship_inputs.append(variables["input"])
            return {
                "data": {
                    "stixRefRelationshipAdd": {
                        "id": "nested-ref--benchmark",
                        "standard_id": "nested-ref--benchmark",
                        "entity_type": "stix-nested-relationship",
                        "parent_types": ["stix-nested-relationship"],
                    }
                }
            }

        raise AssertionError("Unexpected nested-ref mutation shape")

    @staticmethod
    def process_multiple_fields(data):
        return data


def _embedded_relationships():
    return {
        "created_by": None,
        "object_marking": None,
        "object_label": None,
        "open_vocabs": {},
        "granted_refs": [],
        "kill_chain_phases": [],
        "object_refs": [],
        "external_references": [],
        "reports": {},
        "sample_refs": [],
    }


def _build_observable(ref_count: int):
    return {
        "id": "directory--benchmark",
        "type": "directory",
        "path": "/benchmark",
        "contains_refs": [f"artifact--{index:08d}" for index in range(ref_count)],
    }


def _run_once(ref_count: int, request_delay_ms: float) -> tuple[float, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)
    stix2.extract_embedded_relationships = lambda *_args, **_kwargs: (
        _embedded_relationships()
    )

    started_at = time.perf_counter()
    stix2.import_observable(_build_observable(ref_count), update=False)
    elapsed_seconds = time.perf_counter() - started_at

    if len(opencti.relationship_inputs) != ref_count:
        raise AssertionError("import_observable() did not preserve nested-ref count")
    return elapsed_seconds, opencti.query_calls, len(opencti.relationship_inputs)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refs", type=int, default=1000)
    parser.add_argument("--request-delay-ms", type=float, default=1.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.refs, 10), args.request_delay_ms)
    samples = [_run_once(args.refs, args.request_delay_ms) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    query_call_samples = [sample[1] for sample in samples]
    relationship_input_samples = [sample[2] for sample in samples]
    result = {
        "refs": args.refs,
        "request_delay_ms": args.request_delay_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_query_calls": statistics.median(query_call_samples),
        "median_nested_ref_inputs": statistics.median(relationship_input_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
