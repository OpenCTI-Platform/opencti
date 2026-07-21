"""Regression benchmark for cached AMQP publisher heartbeats.

The cached publisher uses a synchronous pika.BlockingConnection. If it
advertises a short RabbitMQ heartbeat and then sits idle while a connector does
other work, RabbitMQ closes the connection before the next publish. This
benchmark publishes once, leaves that cached connection idle, then probes it to
measure whether the broker already closed it.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import threading
import time
import uuid
from types import SimpleNamespace

import pika
from pika.exceptions import AMQPError

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


def _connection_parameters(
    connection_config: dict, heartbeat: int
) -> pika.ConnectionParameters:
    return pika.ConnectionParameters(
        heartbeat=heartbeat,
        host=connection_config["host"],
        port=connection_config["port"],
        virtual_host=connection_config["vhost"],
        credentials=pika.PlainCredentials(
            connection_config["user"], connection_config["pass"]
        ),
    )


def _build_helper(
    connection_config: dict, exchange: str, routing_key: str, heartbeat: int
):
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
    helper._publisher_heartbeat = heartbeat
    helper._publisher_idle_timeout = 10
    helper._publisher_last_used_at = None
    return helper


def _run_once(
    idle_seconds: float, heartbeat: int, connection_config: dict
) -> tuple[bool, str | None, float]:
    exchange = f"benchmark-pycti-heartbeat-{uuid.uuid4()}"
    routing_key = "bundle"
    control_connection = pika.BlockingConnection(
        _connection_parameters(connection_config, heartbeat=0)
    )
    control_channel = control_connection.channel()
    control_channel.exchange_declare(
        exchange=exchange, exchange_type="direct", auto_delete=True
    )
    queue_name = control_channel.queue_declare(queue="", exclusive=True).method.queue
    control_channel.queue_bind(
        queue=queue_name, exchange=exchange, routing_key=routing_key
    )

    helper = _build_helper(connection_config, exchange, routing_key, heartbeat)
    bundle = json.dumps(
        {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []}
    )
    probe_error = None
    try:
        helper.send_stix2_bundle(bundle, no_split=True)
        cached_connection = helper._publisher_connection
        time.sleep(idle_seconds)
        started_at = time.perf_counter()
        try:
            cached_connection.process_data_events(time_limit=0)
        except AMQPError as err:
            probe_error = type(err).__name__
        probe_seconds = time.perf_counter() - started_at
        probe_failed = probe_error is not None or cached_connection.is_closed
    finally:
        helper._close_publisher_connection()
        control_connection.close()

    return probe_failed, probe_error, probe_seconds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--heartbeat", type=int, default=10)
    parser.add_argument("--idle-seconds", type=float, default=35.0)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()

    connection_config = _connection_config()
    samples = [
        _run_once(args.idle_seconds, args.heartbeat, connection_config)
        for _ in range(args.repeat)
    ]
    failed_samples = [sample for sample in samples if sample[0]]
    probe_samples = [sample[2] for sample in samples]
    result = {
        "heartbeat": args.heartbeat,
        "idle_seconds": args.idle_seconds,
        "repeat": args.repeat,
        "failed_idle_probes": len(failed_samples),
        "successful_idle_probes": args.repeat - len(failed_samples),
        "error_types": sorted({sample[1] for sample in failed_samples if sample[1]}),
        "median_probe_ms": round(statistics.median(probe_samples) * 1000, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
