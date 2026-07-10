"""Benchmark bundle-level vocabulary prefetching during STIX import."""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _VocabularyCollection:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.list_calls = 0
        self.read_or_create_calls = 0

    def list(self, **kwargs):
        self.list_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        values = kwargs["filters"]["filters"][0]["values"]
        return [{"id": f"vocabulary--{value}", "name": value} for value in values]

    def read_or_create_unchecked_with_cache(self, vocab, cache, field):
        vocab_key = "vocab_" + vocab
        if vocab_key not in cache:
            self.read_or_create_calls += 1
            if self.request_delay_seconds:
                time.sleep(self.request_delay_seconds)
            cache[vocab_key] = {"id": f"vocabulary--{vocab}", "name": vocab}
        return cache[vocab_key]


class _OpenCTI:
    def __init__(self, request_delay_ms: float):
        self.request_delay_seconds = request_delay_ms / 1000
        self.vocabulary = _VocabularyCollection(request_delay_ms)
        self.label = _VocabularyCollection(request_delay_ms)
        self.app_logger = logging.getLogger("benchmark_stix_import_vocabulary_prefetch")
        self.category_query_calls = 0

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    def query(self, _query):
        self.category_query_calls += 1
        if self.request_delay_seconds:
            time.sleep(self.request_delay_seconds)
        return {
            "data": {
                "vocabularyCategories": [
                    {
                        "key": "malware_type_ov",
                        "fields": [{"key": "malware_types", "required": False}],
                    }
                ]
            }
        }

    @staticmethod
    def logger_class(_name):
        return logging.getLogger("benchmark_stix_import_vocabulary_prefetch.worker")


def _run_once(
    object_count: int, request_delay_ms: float
) -> tuple[float, int, int, int]:
    opencti = _OpenCTI(request_delay_ms)
    stix2 = OpenCTIStix2(opencti)

    def import_item_with_retries(item, *_args, **_kwargs):
        stix2.extract_embedded_relationships(item)
        return None

    stix2.import_item_with_retries = import_item_with_retries
    bundle = {
        "type": "bundle",
        "id": "bundle--benchmark",
        "objects": [
            {
                "id": f"malware--{index}",
                "type": "malware",
                "malware_types": [f"vocab-{index}"],
            }
            for index in range(object_count)
        ],
    }

    started_at = time.perf_counter()
    stix2.import_bundle(bundle)
    elapsed_seconds = time.perf_counter() - started_at
    return (
        elapsed_seconds,
        opencti.category_query_calls,
        opencti.vocabulary.read_or_create_calls,
        opencti.vocabulary.list_calls,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objects", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--request-delay-ms", type=float, default=0)
    args = parser.parse_args()

    _run_once(args.objects, args.request_delay_ms)
    samples = [
        _run_once(args.objects, args.request_delay_ms) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    category_query_samples = [sample[1] for sample in samples]
    read_or_create_call_samples = [sample[2] for sample in samples]
    list_call_samples = [sample[3] for sample in samples]
    result = {
        "objects": args.objects,
        "repeat": args.repeat,
        "request_delay_ms": args.request_delay_ms,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_category_query_calls": statistics.median(category_query_samples),
        "median_read_or_create_calls": statistics.median(read_or_create_call_samples),
        "median_list_calls": statistics.median(list_call_samples),
        "median_total_requests": statistics.median(
            [
                category_query_calls + read_or_create_calls + list_calls
                for (
                    _,
                    category_query_calls,
                    read_or_create_calls,
                    list_calls,
                ) in samples
            ]
        ),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
