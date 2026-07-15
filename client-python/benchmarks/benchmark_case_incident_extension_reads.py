"""Benchmark repeated extension reads during CaseIncident STIX import."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_case_incident import CaseIncident

PRIMARY_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def convert_markdown(value):
        return value


class _OpenCTI:
    def __init__(self):
        self.stix2 = _Stix2()
        self.extension_lookup_calls = 0
        self.bulk_extension_lookup_calls = 0

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_calls += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_extension_lookup_calls += 1
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def _build_case_incident(index: int) -> dict:
    return {
        "id": f"case-incident--{index}",
        "type": "case-incident",
        "name": f"Case Incident {index}",
        "extensions": {
            PRIMARY_EXTENSION_ID: {
                "stix_ids": [f"case-incident--legacy-{index}"],
                "granted_refs": ["identity--organization"],
                "workflow_id": "workflow--case-incident",
                "content": f"Case content {index}",
                "assignee_ids": ["identity--assignee"],
                "participant_ids": ["identity--participant"],
                "modified_at": "2026-07-15T00:00:00.000Z",
                "opencti_upsert_operations": [{"key": "name", "operation": "replace"}],
            }
        },
    }


def _run_once(iterations: int) -> tuple[float, int, int]:
    opencti = _OpenCTI()
    case_incident = CaseIncident(opencti)
    case_incident.create = lambda **kwargs: kwargs

    gc.collect()
    gc.disable()
    started_at = time.perf_counter()
    try:
        for index in range(iterations):
            case_incident.import_from_stix2(stixObject=_build_case_incident(index))
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        gc.enable()
    return (
        elapsed_seconds,
        opencti.extension_lookup_calls,
        opencti.bulk_extension_lookup_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    _run_once(min(args.iterations, 1000))
    samples = [_run_once(args.iterations) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    extension_lookup_samples = [sample[1] for sample in samples]
    bulk_extension_lookup_samples = [sample[2] for sample in samples]
    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_extension_lookup_calls": statistics.median(extension_lookup_samples),
        "median_bulk_extension_lookup_calls": statistics.median(
            bulk_extension_lookup_samples
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
