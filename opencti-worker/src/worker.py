import functools
import os
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

import pika
import yaml
from opentelemetry import metrics
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from prometheus_client import start_http_server
from pycti import OpenCTIApiClient
from pycti.connector.opencti_connector_helper import (
    create_mq_ssl_context,
    get_config_variable,
)

from message_queue_consumer import MessageQueueConsumer
from listen_handler import ListenHandler
from push_handler import PushHandler
from thread_pool_selector import ThreadPoolSelector

# Telemetry variables definition
meter = metrics.get_meter(__name__)
bundles_global_counter = meter.create_counter(
    name="opencti_bundles_global_counter",
    description="number of bundles processed",
)
bundles_processing_time_gauge = meter.create_histogram(
    name="opencti_bundles_processing_time_gauge",
    description="processing time of bundles",
)
max_ingestion_units_count = meter.create_gauge(
    name="opencti_max_ingestion_units",
    description="Maximum number of ingestion units (configuration)",
)
running_ingestion_units_gauge = meter.create_gauge(
    name="opencti_running_ingestion_units",
    description="Number of running ingestion units",
)


def is_priority_connector(connector_priority_group: str) -> bool:
    return connector_priority_group == "REALTIME"


@dataclass(unsafe_hash=True)
class Worker:  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    consumers: Dict[str, MessageQueueConsumer] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        self.exit_event = threading.Event()
        # Get configuration
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        if os.path.isfile(config_file_path):
            with open(config_file_path, "r") as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        else:
            config = {}

        # Load API config
        self.config = config
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.opencti_ssl_verify = get_config_variable(
            "OPENCTI_SSL_VERIFY", ["opencti", "ssl_verify"], config, default=False
        )
        self.opencti_json_logging = get_config_variable(
            "OPENCTI_JSON_LOGGING", ["opencti", "json_logging"], config, default=True
        )
        self.opencti_pool_size = get_config_variable(
            "OPENCTI_EXECUTION_POOL_SIZE",
            ["opencti", "execution_pool_size"],
            config,
            True,
            default=2,
        )
        self.opencti_realtime_pool_size = get_config_variable(
            "OPENCTI_REALTIME_EXECUTION_POOL_SIZE",
            ["opencti", "realtime_execution_pool_size"],
            config,
            True,
            default=3,
        )
        self.listen_pool_size = get_config_variable(
            "WORKER_LISTEN_POOL_SIZE",
            ["worker", "listen_pool_size"],
            config,
            True,
            default=5,
        )
        self.opencti_api_custom_headers = get_config_variable(
            "OPENCTI_CUSTOM_HEADERS",
            ["opencti", "custom_headers"],
            config,
            default=None,
        )
        # Load worker config
        self.log_level = get_config_variable(
            "WORKER_LOG_LEVEL",
            ["worker", "log_level"],
            config,
            default="info",
        )
        self.listen_api_ssl_verify = get_config_variable(
            "WORKER_LISTEN_API_SSL_VERIFY",
            ["worker", "listen_api_ssl_verify"],
            config,
            default=False,
        )
        self.listen_api_http_proxy = get_config_variable(
            "WORKER_LISTEN_API_HTTP_PROXY",
            ["worker", "listen_api_http_proxy"],
            config,
            default="",
        )
        self.listen_api_https_proxy = get_config_variable(
            "WORKER_LISTEN_API_HTTPS_PROXY",
            ["worker", "listen_api_https_proxy"],
            config,
            default="",
        )
        # Telemetry
        self.telemetry_enabled = get_config_variable(
            "WORKER_TELEMETRY_ENABLED",
            ["worker", "telemetry_enabled"],
            config,
            False,
            False,
        )
        self.telemetry_prometheus_port = get_config_variable(
            "WORKER_PROMETHEUS_TELEMETRY_PORT",
            ["worker", "telemetry_prometheus_port"],
            config,
            True,
            14270,
        )
        self.telemetry_prometheus_host = get_config_variable(
            "WORKER_PROMETHEUS_TELEMETRY_HOST",
            ["worker", "telemetry_prometheus_host"],
            config,
            False,
            "0.0.0.0",
        )
        self.objects_max_refs = get_config_variable(
            "WORKER_OBJECTS_MAX_REFS",
            ["worker", "objects_max_refs"],
            config,
            True,
            0,
        )
        # Telemetry
        if self.telemetry_enabled:
            self.prom_httpd, self.prom_t = start_http_server(
                port=self.telemetry_prometheus_port, addr=self.telemetry_prometheus_host
            )
            provider = MeterProvider(
                resource=Resource(attributes={SERVICE_NAME: "opencti-worker"}),
                metric_readers=[PrometheusMetricReader()],
            )
            metrics.set_meter_provider(provider)

        # Check if openCTI is available
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            json_logging=self.opencti_json_logging,
            ssl_verify=self.opencti_ssl_verify,
            perform_health_check=False,  # No need to prevent worker start if API is not available yet
            custom_headers=self.opencti_api_custom_headers,
        )
        self.worker_logger = self.api.logger_class("worker")

    def build_pika_parameters(
        self, connector_config: Dict[str, Any]
    ) -> pika.ConnectionParameters:
        ssl_options = None
        if connector_config["connection"]["use_ssl"]:
            ssl_options = pika.SSLOptions(
                create_mq_ssl_context(self.config),
                connector_config["connection"]["host"],
            )

        return pika.ConnectionParameters(
            host=connector_config["connection"]["host"],
            port=connector_config["connection"]["port"],
            virtual_host=connector_config["connection"]["vhost"],
            credentials=pika.PlainCredentials(
                connector_config["connection"]["user"],
                connector_config["connection"]["pass"],
            ),
            ssl_options=ssl_options,
        )

    def stop(self) -> None:
        # Initiate stop for all consumers
        for consumer in self.consumers.values():
            consumer.request_stop()
        # Wait for all consumers to stop
        for consumer in self.consumers.values():
            consumer.wait_for_completion()
        if self.telemetry_enabled:
            self.prom_httpd.shutdown()
            self.prom_httpd.server_close()
            self.prom_t.join()
        self.exit_event.set()

    # Start the main loop
    def start(self) -> None:
        push_execution_pool = ThreadPoolExecutor(max_workers=self.opencti_pool_size)
        realtime_push_execution_pool = ThreadPoolExecutor(
            max_workers=self.opencti_realtime_pool_size
        )

        push_thread_pool_selector = ThreadPoolSelector(
            self.opencti_pool_size,
            push_execution_pool,
            self.opencti_realtime_pool_size,
            realtime_push_execution_pool,
        )

        listen_execution_pool = ThreadPoolExecutor(max_workers=self.listen_pool_size)
        def listen_execution_pool_submit(task: Callable[[], None]):
            return listen_execution_pool.submit(task)

        while not self.exit_event.is_set():
            try:
                # Telemetry
                max_ingestion_units_count.set(self.opencti_pool_size)
                running_ingestion_units_gauge.set(
                    len(push_execution_pool._threads)
                    + len(realtime_push_execution_pool._threads)
                )

                # Fetch queue configuration from API
                queues: List[Any] = []
                connectors: List[Any] = self.api.connector.list()

                # Check if all queues are consumed
                for connector in connectors:
                    connector_config = connector["config"]
                    # Push to ingest message
                    push_queue = connector_config["push"]
                    queues.append(push_queue)
                    push_consumer = self.consumers.get(push_queue)
                    if push_consumer is None or not push_consumer.is_alive():
                        if push_consumer is not None:
                            self.worker_logger.info(
                                "Thread for queue not alive, creating a new one...",
                                {"queue": push_queue},
                            )

                        pika_parameters = self.build_pika_parameters(connector_config)
                        push_handler = PushHandler(
                            self.worker_logger,
                            self.log_level,
                            self.opencti_json_logging,
                            self.opencti_url,
                            self.opencti_token,
                            self.opencti_ssl_verify,
                            connector["id"],
                            connector_config["push_exchange"],
                            connector_config["listen_exchange"],
                            connector_config["push_routing"],
                            connector_config["dead_letter_routing"],
                            pika_parameters,
                            bundles_global_counter,
                            bundles_processing_time_gauge,
                            self.objects_max_refs,
                        )
                        is_realtime = is_priority_connector(
                            connector["connector_priority_group"]
                        )

                        self.consumers[push_queue] = MessageQueueConsumer(
                            self.worker_logger,
                            "push",
                            push_queue,
                            pika_parameters,
                            functools.partial(push_thread_pool_selector.submit, is_realtime),
                            push_handler.handle_message,
                        )

                    # Listen for webhook message
                    listen_callback_uri = connector_config.get("listen_callback_uri")
                    if listen_callback_uri is not None:
                        listen_queue = connector_config["listen"]
                        queues.append(listen_queue)
                        listen_consumer = self.consumers.get(listen_queue)
                        if listen_consumer is None or not listen_consumer.is_alive():
                            listen_handler = ListenHandler(
                                self.worker_logger,
                                connector["connector_user"]["api_token"],
                                listen_callback_uri,
                                self.listen_api_ssl_verify,
                                self.listen_api_http_proxy,
                                self.listen_api_https_proxy,
                            )
                            self.consumers[listen_queue] = MessageQueueConsumer(
                                self.worker_logger,
                                "listen",
                                listen_queue,
                                self.build_pika_parameters(connector_config),
                                listen_execution_pool_submit,
                                listen_handler.handle_message,
                            )

                # Stop consumers whose queues no longer exist
                # Iterate over a copy since self.consumers may be modified during iteration
                for consumer_queue in list(self.consumers):
                    if consumer_queue not in queues:
                        self.worker_logger.info(
                            "Queue no longer exists, killing thread...",
                            {"queue": consumer_queue},
                        )
                        self.consumers[consumer_queue].request_stop()
                        self.consumers.pop(consumer_queue, None)
            except Exception as e:  # pylint: disable=broad-except
                self.worker_logger.error(type(e).__name__, {"reason": str(e)})
            self.exit_event.wait(60)
        self.worker_logger.info("Thread for worker terminated")


if __name__ == "__main__":
    worker: Worker = Worker()

    def exit_handler(_signum, _frame):
        worker.stop()

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    worker.start()
