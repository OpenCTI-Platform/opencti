"""Microbenchmark for AMQP bundle publisher connection churn.

The benchmark publishes small bundles to a local RabbitMQ broker through
OpenCTIConnectorHelper.send_stix2_bundle(). It isolates the cost of creating a
new AMQP connection and channel for every send.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import threading
import time
import tracemalloc
import uuid
from types import SimpleNamespace

import pika

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class _NoopLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class _NoopMetric:
    def inc(self, *args, **kwargs):
        pass


def _connection_config() -> dict:
    return {
        "host": os.getenv("BENCHMARK_MQ_HOST", "127.0.0.1"),
        "port": int(os.getenv("BENCHMARK_MQ_PORT", "5672")),
        "vhost": os.getenv("BENCHMARK_MQ_VHOST", "/"),
        "user": os.getenv("BENCHMARK_MQ_USER", "guest"),
        "pass": os.getenv("BENCHMARK_MQ_PASS", "guest"),
        "use_ssl": False,
    }


def _connection_parameters(connection_config: dict) -> pika.ConnectionParameters:
    return pika.ConnectionParameters(
        heartbeat=10,
        host=connection_config["host"],
        port=connection_config["port"],
        virtual_host=connection_config["vhost"],
        credentials=pika.PlainCredentials(
            connection_config["user"], connection_config["pass"]
        ),
    )


def _build_helper(connection_config: dict, exchange: str, routing_key: str):
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.work_id = None
    helper.validation_mode = "workbench"
    helper.draft_id = None
    helper.force_validation = False
    helper.bundle_send_to_queue = True
    helper.bundle_send_to_directory = False
    helper.bundle_send_to_directory_path = None
    helper.bundle_send_to_directory_retention = 0
    helper.bundle_send_to_s3 = False
    helper.enrichment_shared_organizations = None
    helper.playbook = None
    helper.connect_validate_before_import = False
    helper.queue_protocol = "amqp"
    helper.connector_config = {
        "connection": connection_config,
        "push_exchange": exchange,
        "push_routing": routing_key,
    }
    helper.config = {}
    helper.connector_logger = _NoopLogger()
    helper.connect_name = "benchmark"
    helper.metric = _NoopMetric()
    helper.connector_info = SimpleNamespace(buffering=False)
    helper.applicant_id = "benchmark-applicant"
    helper._publisher_lock = threading.RLock()
    helper._publisher_connection = None
    helper._publisher_channel = None
    helper._publisher_heartbeat = 10
    helper._publisher_last_used_at = None
    return helper


def _run_once(iterations: int, connection_config: dict) -> tuple[float, int]:
    exchange = f"benchmark-pycti-publish-{uuid.uuid4()}"
    routing_key = "bundle"
    control_connection = pika.BlockingConnection(
        _connection_parameters(connection_config)
    )
    control_channel = control_connection.channel()
    control_channel.exchange_declare(
        exchange=exchange, exchange_type="direct", auto_delete=True
    )
    queue_name = control_channel.queue_declare(queue="", exclusive=True).method.queue
    control_channel.queue_bind(
        queue=queue_name, exchange=exchange, routing_key=routing_key
    )

    helper = _build_helper(connection_config, exchange, routing_key)
    bundle = json.dumps(
        {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []}
    )
    try:
        gc.collect()
        tracemalloc.start()
        started_at = time.perf_counter()
        for _ in range(iterations):
            helper.send_stix2_bundle(bundle, no_split=True)
        elapsed_seconds = time.perf_counter() - started_at
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        helper._close_publisher_connection()
        control_connection.close()

    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    connection_config = _connection_config()
    _run_once(min(args.iterations, 5), connection_config)
    samples = [
        _run_once(args.iterations, connection_config) for _ in range(args.repeat)
    ]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]

    result = {
        "iterations": args.iterations,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
