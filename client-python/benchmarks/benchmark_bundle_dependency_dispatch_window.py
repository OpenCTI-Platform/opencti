"""Model concurrent queue dispatch for dependency-bearing split bundles.

This benchmark isolates splitter output and models a prefetch-one RabbitMQ queue
with multiple workers. A dependent bundle is unsafe when it can start before
all lower-dependency bundles have completed.
"""

from __future__ import annotations

import argparse
import heapq
import json

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def _build_dependency_bundle(prerequisite_count: int) -> dict:
    prerequisites = [
        {"id": f"indicator--{index}", "type": "indicator"}
        for index in range(prerequisite_count)
    ]
    return {
        "type": "bundle",
        "id": "bundle--dependency-dispatch-window",
        "objects": [
            *prerequisites,
            {
                "id": "report--dependent",
                "type": "report",
                "object_refs": [item["id"] for item in prerequisites],
            },
        ],
    }


def _build_independent_bundle(object_count: int) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--independent-dispatch-window",
        "objects": [
            {"id": f"indicator--{index}", "type": "indicator"}
            for index in range(object_count)
        ],
    }


def _simulate_dispatch(bundles: list[dict], consumer_count: int) -> dict:
    workers = [(0, index) for index in range(consumer_count)]
    heapq.heapify(workers)
    completed_by_level = {}
    unsafe_dependent_starts = 0
    first_dependent_start = None
    all_lower_levels_complete_at = 0

    for bundle in bundles:
        start_at, worker_index = heapq.heappop(workers)
        dependency_level = bundle["x_opencti_seq"]
        lower_level_completion = max(
            (
                completed_at
                for level, completed_at in completed_by_level.items()
                if level < dependency_level
            ),
            default=0,
        )
        if dependency_level > 1:
            if first_dependent_start is None:
                first_dependent_start = start_at
                all_lower_levels_complete_at = lower_level_completion
            if start_at < lower_level_completion:
                unsafe_dependent_starts += 1
        finish_at = start_at + len(bundle["objects"])
        completed_by_level[dependency_level] = max(
            completed_by_level.get(dependency_level, 0), finish_at
        )
        heapq.heappush(workers, (finish_at, worker_index))

    return {
        "published_bundles": len(bundles),
        "unsafe_dependent_starts": unsafe_dependent_starts,
        "first_dependent_start_work_units": first_dependent_start,
        "all_lower_levels_complete_at_work_units": all_lower_levels_complete_at,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prerequisites", type=int, default=100)
    parser.add_argument("--independent-objects", type=int, default=1000)
    parser.add_argument("--max-bundle-objects", type=int, default=100)
    parser.add_argument("--consumers", type=int, default=5)
    args = parser.parse_args()

    splitter = OpenCTIStix2Splitter()
    _, _, dependency_bundles = splitter.split_bundle_with_expectations(
        _build_dependency_bundle(args.prerequisites),
        use_json=False,
        max_bundle_objects=args.max_bundle_objects,
    )
    independent_splitter = OpenCTIStix2Splitter()
    _, _, independent_bundles = independent_splitter.split_bundle_with_expectations(
        _build_independent_bundle(args.independent_objects),
        use_json=False,
        max_bundle_objects=args.max_bundle_objects,
    )

    result = {
        "prerequisites": args.prerequisites,
        "independent_objects": args.independent_objects,
        "max_bundle_objects": args.max_bundle_objects,
        "consumers": args.consumers,
        "dependency_bundle": _simulate_dispatch(dependency_bundles, args.consumers),
        "independent_bundle_published_bundles": len(independent_bundles),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
