"""Microbenchmark for directory retention scans during bundle sends."""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import tempfile
import threading
import time
import tracemalloc
import uuid
from pathlib import Path
from types import SimpleNamespace

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class _NoopLogger:
    def info(self, *args, **kwargs):
        pass


class _NoopMetric:
    def inc(self, *args, **kwargs):
        pass


def _build_helper(directory: str):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.work_id = None
    helper.validation_mode = "workbench"
    helper.draft_id = None
    helper.force_validation = False
    helper.bundle_send_to_queue = False
    helper.bundle_send_to_directory = True
    helper.bundle_send_to_directory_path = directory
    helper.bundle_send_to_directory_retention = 7
    helper._directory_cleanup_lock = threading.Lock()
    helper._directory_cleanup_deadlines = {}
    helper.bundle_send_to_s3 = False
    helper.enrichment_shared_organizations = None
    helper.playbook = None
    helper.connect_validate_before_import = False
    helper.connect_name = "benchmark"
    helper.connect_id = "benchmark-id"
    helper.connect_type = "EXTERNAL_IMPORT"
    helper.connect_scope = "benchmark"
    helper.connect_auto = False
    helper.applicant_id = "benchmark-applicant"
    helper.connector_logger = _NoopLogger()
    helper.metric = _NoopMetric()
    helper.connector_info = SimpleNamespace(buffering=False)
    return helper


def _populate_directory(directory: Path, retained_files: int) -> None:
    for index in range(retained_files):
        (directory / f"retained-{index}.json").write_text("{}", encoding="utf-8")


def _run_once(iterations: int, retained_files: int) -> tuple[float, int]:
    with tempfile.TemporaryDirectory() as tmp_dir:
        directory = Path(tmp_dir)
        _populate_directory(directory, retained_files)
        helper = _build_helper(tmp_dir)
        bundle = json.dumps(
            {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []}
        )

        gc.collect()
        tracemalloc.start()
        started_at = time.perf_counter()
        for _ in range(iterations):
            helper.send_stix2_bundle(bundle, no_split=True)
        elapsed_seconds = time.perf_counter() - started_at
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--retained-files", type=int, default=5000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    _run_once(min(args.iterations, 2), args.retained_files)
    samples = [
        _run_once(args.iterations, args.retained_files) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "iterations": args.iterations,
        "retained_files": args.retained_files,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
