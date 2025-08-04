# coding: utf-8

import base64
import datetime
import functools
import json
import os
import random
import signal
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Thread
from typing import Any, Dict, List, Union

import pika
import requests
import yaml
from opentelemetry import metrics
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from prometheus_client import start_http_server
from pycti import OpenCTIApiClient, OpenCTIStix2Splitter, __version__
from pycti.connector.opencti_connector_helper import (
    create_mq_ssl_context,
    get_config_variable,
)
from pycti.utils.opencti_logger import logger
from requests import RequestException, Timeout

ERROR_TYPE_BAD_GATEWAY = "Bad Gateway"
ERROR_TYPE_TIMEOUT = "Request timed out"

# Telemetry variables definition
meter = metrics.get_meter(__name__)
resource = Resource(attributes={SERVICE_NAME: "opencti-worker"})
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


@dataclass(unsafe_hash=True)
class ApiConsumer(Thread):  # pylint: disable=too-many-instance-attributes
    execution_pool: ThreadPoolExecutor
    pika_parameters: pika.ConnectionParameters
    queue_name: str
    log_level: str
    json_logging: bool
    connector_token: str
    callback_uri: str
    listen_api_ssl_verify: bool
    listen_api_http_proxy: str
    listen_api_https_proxy: str

    def __post_init__(self) -> None:
        self._is_interrupted: bool = False
        self.logger_class = logger(self.log_level.upper(), self.json_logging)
        self.worker_logger = self.logger_class("worker")
        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        try:
            self.channel.confirm_delivery()
        except Exception as err:  # pylint: disable=broad-except
            self.worker_logger.warning(str(err))
        self.channel.basic_qos(prefetch_count=1)

    def nack_message(self, delivery_tag: int, requeue=True) -> None:
        if self.channel.is_open:
            self.worker_logger.info("Message rejected", {"tag": delivery_tag})
            self.channel.basic_nack(delivery_tag, requeue=requeue)
        else:
            self.worker_logger.info(
                "Message NOT rejected (channel closed)", {"tag": delivery_tag}
            )

    def ack_message(self, delivery_tag: int) -> None:
        if self.channel.is_open:
            self.worker_logger.info("Message acknowledged", {"tag": delivery_tag})
            self.channel.basic_ack(delivery_tag)
        else:
            self.worker_logger.info(
                "Message NOT acknowledged (channel closed)", {"tag": delivery_tag}
            )

    # Data handling
    def api_data_handler(  # pylint: disable=too-many-statements, too-many-locals
        self,
        delivery_tag: str,
        data: str,
    ) -> None:
        try:
            request_headers = {
                "User-Agent": "pycti/" + __version__,
                "Authorization": "Bearer " + self.connector_token,
            }
            response = requests.post(
                self.callback_uri,
                data=data,
                headers=request_headers,
                verify=self.listen_api_ssl_verify,
                proxies={
                    "http": self.listen_api_http_proxy,
                    "https": self.listen_api_https_proxy,
                },
                timeout=300,
            )
            if response.status_code != 202:
                raise RequestException(response.status_code, response.text)
            else:
                # Ack the message
                cb = functools.partial(self.ack_message, delivery_tag)
                self.pika_connection.add_callback_threadsafe(cb)
        except (RequestException, Timeout):
            self.worker_logger.error(
                "Error executing listen handling, a connection error or timeout occurred"
            )
            # Platform is under heavy load: wait for unlock & retry almost indefinitely.
            sleep_jitter = round(random.uniform(10, 30), 2)
            time.sleep(sleep_jitter)
            # Nack the message
            cb = functools.partial(self.nack_message, delivery_tag)
            self.pika_connection.add_callback_threadsafe(cb)
        except Exception as ex:
            # Technical unmanaged exception
            self.worker_logger.error(
                "Error executing listen handling", {"reason": str(ex)}
            )
            error_msg = traceback.format_exc()
            if ERROR_TYPE_BAD_GATEWAY in error_msg or ERROR_TYPE_TIMEOUT in error_msg:
                # Nack the message and requeue
                cb = functools.partial(self.nack_message, delivery_tag)
                self.pika_connection.add_callback_threadsafe(cb)
            else:
                # Technical error, log and continue, Reject the message
                cb = functools.partial(self.nack_message, delivery_tag, False)
                self.pika_connection.add_callback_threadsafe(cb)

    def stop(self):
        self._is_interrupted = True

    def run(self) -> None:
        try:
            # Consume the queue
            self.worker_logger.info(
                "Thread for listen queue started", {"queue": self.queue_name}
            )
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self._is_interrupted:
                    break
                if not all(message):
                    continue
                method, properties, body = message
                self.worker_logger.info(
                    "Processing a new message, launching a thread...",
                    {"tag": method.delivery_tag},
                )
                task_future = self.execution_pool.submit(
                    self.api_data_handler,
                    method.delivery_tag,
                    body,
                )
                while task_future.running():  # Loop while the thread is processing
                    self.pika_connection.sleep(0.05)
                self.worker_logger.info("Message processed, thread terminated")
        except Exception as e:
            self.worker_logger.error("Unhandled exception", {"exception": e})
        finally:
            self.worker_logger.info(
                "Thread for listen queue terminated", {"queue": self.queue_name}
            )


@dataclass(unsafe_hash=True)
class Consumer(Thread):  # pylint: disable=too-many-instance-attributes
    execution_pool: ThreadPoolExecutor
    pika_parameters: pika.ConnectionParameters
    queue_name: str
    log_level: str
    json_logging: bool
    opencti_url: str
    opencti_token: str
    ssl_verify: Union[bool, str]
    push_exchange: str
    push_routing: str

    def __post_init__(self) -> None:
        self._is_interrupted: bool = False
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            json_logging=self.json_logging,
            ssl_verify=self.ssl_verify,
        )
        self.worker_logger = self.api.logger_class("worker")

        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        try:
            self.channel.confirm_delivery()
        except Exception as err:  # pylint: disable=broad-except
            self.worker_logger.warning(str(err))
        self.channel.basic_qos(prefetch_count=1)

    def nack_message(self, delivery_tag: int, requeue=True) -> None:
        if self.channel.is_open:
            self.worker_logger.info("Message rejected", {"tag": delivery_tag})
            self.channel.basic_nack(delivery_tag, requeue=requeue)
        else:
            self.worker_logger.info(
                "Message NOT rejected (channel closed)", {"tag": delivery_tag}
            )

    def ack_message(self, delivery_tag: int) -> None:
        if self.channel.is_open:
            self.worker_logger.info("Message acknowledged", {"tag": delivery_tag})
            self.channel.basic_ack(delivery_tag)
        else:
            self.worker_logger.info(
                "Message NOT acknowledged (channel closed)", {"tag": delivery_tag}
            )

    # Data handling
    def data_handler(  # pylint: disable=too-many-statements, too-many-locals
        self,
        delivery_tag: str,
        body: str,
    ) -> None:
        try:
            data: Dict[str, Any] = json.loads(body)
        except Exception as e:
            self.worker_logger.error(
                "Could not process message",
                {"body": body, "exception": e},
            )
            # Nack message, no requeue for this unprocessed message
            cb = functools.partial(self.nack_message, delivery_tag, False)
            self.pika_connection.add_callback_threadsafe(cb)
            return None

        imported_items = []
        start_processing = datetime.datetime.now()
        try:
            # Set the API headers
            self.api.set_applicant_id_header(data.get("applicant_id"))
            self.api.set_playbook_id_header(data.get("playbook_id"))
            self.api.set_event_id(data.get("event_id"))
            self.api.set_draft_id(data.get("draft_id"))
            work_id = data["work_id"] if "work_id" in data else None
            no_split = data["no_split"] if "no_split" in data else False
            synchronized = data["synchronized"] if "synchronized" in data else False
            self.api.set_synchronized_upsert_header(synchronized)
            previous_standard = data.get("previous_standard")
            self.api.set_previous_standard_header(previous_standard)
            # Execute the import
            event_type = data["type"] if "type" in data else "bundle"
            types = (
                data["entities_types"]
                if "entities_types" in data and len(data["entities_types"]) > 0
                else None
            )
            if event_type == "bundle":
                # Event type bundle
                # Standard event with STIX information
                content = base64.b64decode(data["content"]).decode("utf-8")
                content_json = json.loads(content)
                if "objects" not in content_json or len(content_json["objects"]) == 0:
                    raise ValueError("JSON data type is not a STIX2 bundle")
                if len(content_json["objects"]) == 1 or no_split:
                    update = data["update"] if "update" in data else False
                    imported_items = self.api.stix2.import_bundle_from_json(
                        content, update, types, work_id
                    )
                else:
                    # As bundle is received as complete, split and requeue
                    # Create a specific channel to push the split bundles
                    push_pika_connection = pika.BlockingConnection(self.pika_parameters)
                    push_channel = push_pika_connection.channel()
                    try:
                        push_channel.confirm_delivery()
                    except Exception as err:  # pylint: disable=broad-except
                        self.worker_logger.warning(str(err))
                    # Instance spliter and split the big bundle
                    event_version = (
                        content_json["x_opencti_event_version"]
                        if "x_opencti_event_version" in content_json
                        else None
                    )
                    stix2_splitter = OpenCTIStix2Splitter()
                    expectations, _, bundles = (
                        stix2_splitter.split_bundle_with_expectations(
                            content_json, False, event_version
                        )
                    )
                    # Add expectations to the work
                    if work_id is not None:
                        self.api.work.add_expectations(work_id, expectations)
                    # For each split bundle, send it to the same queue
                    for bundle in bundles:
                        text_bundle = json.dumps(bundle)
                        data["content"] = base64.b64encode(
                            text_bundle.encode("utf-8", "escape")
                        ).decode("utf-8")
                        push_channel.basic_publish(
                            exchange=self.push_exchange,
                            routing_key=self.push_routing,
                            body=json.dumps(data),
                            properties=pika.BasicProperties(
                                delivery_mode=2,
                                content_encoding="utf-8",  # make message persistent
                            ),
                        )
                    push_channel.close()
                    push_pika_connection.close()
            # Event type event
            # Specific OpenCTI event operation with specific operation
            elif event_type == "event":
                event = base64.b64decode(data["content"]).decode("utf-8")
                event_content = json.loads(event)
                event_type = event_content["type"]
                match event_type:
                    # Standard knowledge
                    case "create" | "update":
                        bundle = {
                            "type": "bundle",
                            "objects": [event_content["data"]],
                        }
                        imported_items = self.api.stix2.import_bundle(
                            bundle, True, types, work_id
                        )
                    # Specific knowledge merge
                    case "merge":
                        # Start with a merge
                        target_id = event_content["data"]["id"]
                        source_ids = list(
                            map(
                                lambda source: source["id"],
                                event_content["context"]["sources"],
                            )
                        )
                        merge_object = event_content["data"]
                        merge_object["opencti_operation"] = event_type
                        merge_object["merge_target_id"] = target_id
                        merge_object["merge_source_ids"] = source_ids
                        bundle = {
                            "type": "bundle",
                            "objects": [merge_object],
                        }
                        imported_items = self.api.stix2.import_bundle(
                            bundle, True, types, work_id
                        )
                    # All standard operations
                    case (
                        "delete"  # Standard delete
                        | "restore"  # Restore an operation from trash
                        | "delete_force"  # Delete with no trash
                        | "share"  # Share an element
                        | "unshare"  # Unshare an element
                        | "rule_apply"  # Applying a rule (start engine)
                        | "rule_clear"  # Clearing a rule (stop engine)
                        | "rules_rescan"  # Rescan a rule (massive operation in UI)
                        | "enrichment"  # Ask for enrichment (massive operation in UI)
                        | "clear_access_restriction"  # Clear access members (massive operation in UI)
                        | "revert_draft"  # Cancel draft modification (massive operation in UI)
                    ):
                        data_object = event_content["data"]
                        data_object["opencti_operation"] = event_type
                        bundle = {
                            "type": "bundle",
                            "objects": [data_object],
                        }
                        imported_items = self.api.stix2.import_bundle(
                            bundle, True, types, work_id
                        )
                    case _:
                        raise ValueError(
                            "Unsupported operation type", {"event_type": event_type}
                        )
            else:
                raise ValueError("Unsupported event type", {"event_type": event_type})
            # Ack the message
            cb = functools.partial(self.ack_message, delivery_tag)
            self.pika_connection.add_callback_threadsafe(cb)
        except Exception as ex:
            # Technical unmanaged exception
            self.worker_logger.error(
                "Error executing data handling", {"reason": str(ex)}
            )
            # Nack message and discard
            cb = functools.partial(self.nack_message, delivery_tag, False)
            self.pika_connection.add_callback_threadsafe(cb)
        finally:
            bundles_global_counter.add(len(imported_items))
            processing_delta = datetime.datetime.now() - start_processing
            bundles_processing_time_gauge.record(processing_delta.seconds)

    def stop(self):
        self._is_interrupted = True

    def run(self) -> None:
        try:
            self.worker_logger.info(
                "Thread for queue started", {"queue": self.queue_name}
            )
            for message in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self._is_interrupted:
                    break
                if not all(message):
                    continue
                method, properties, body = message
                self.worker_logger.info(
                    "Processing a new message, launching a thread...",
                    {"queue": self.queue_name, "tag": method.delivery_tag},
                )
                task_future = self.execution_pool.submit(
                    self.data_handler,
                    method.delivery_tag,
                    body,
                )
                while task_future.running():  # Loop while the thread is processing
                    self.pika_connection.sleep(0.05)
                self.worker_logger.info("Message processed, thread terminated")
        except Exception as e:
            self.worker_logger.error("Unhandled exception", {"exception": e})
        finally:
            self.worker_logger.info(
                "Thread for queue terminated", {"queue": self.queue_name}
            )


@dataclass(unsafe_hash=True)
class Worker:  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    consumer_threads: Dict[str, Any] = field(default_factory=dict, hash=False)
    listen_api_threads: Dict[str, Any] = field(default_factory=dict, hash=False)

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
            default=5,
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

        # Telemetry
        if self.telemetry_enabled:
            self.prom_httpd, self.prom_t = start_http_server(
                port=self.telemetry_prometheus_port, addr=self.telemetry_prometheus_host
            )
            provider = MeterProvider(
                resource=resource, metric_readers=[PrometheusMetricReader()]
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

    def build_pika_parameters(self, connector_config: Dict[str, Any]) -> pika.ConnectionParameters:
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
        for thread in self.listen_api_threads:
            self.listen_api_threads[thread].stop()
            self.listen_api_threads[thread].join()
        for thread in self.consumer_threads:
            self.consumer_threads[thread].stop()
            self.consumer_threads[thread].join()
        if self.telemetry_enabled:
            self.prom_httpd.shutdown()
            self.prom_httpd.server_close()
            self.prom_t.join()
        self.exit_event.set()

    # Start the main loop
    def start(self) -> None:
        execution_pool = ThreadPoolExecutor(max_workers=self.opencti_pool_size)
        listen_api_execution_pool = ThreadPoolExecutor(
            max_workers=self.listen_pool_size
        )

        while not self.exit_event.is_set():
            try:
                # Telemetry
                max_ingestion_units_count.set(self.opencti_pool_size)
                running_ingestion_units_gauge.set(len(execution_pool._threads))

                # Fetch queue configuration from API
                queues: List[Any] = []
                connectors: List[Any] = self.api.connector.list()

                # Check if all queues are consumed
                for connector in connectors:
                    connector_config = connector["config"]
                    # Push to ingest message
                    push_queue = connector_config["push"]
                    queues.append(push_queue)
                    push_thread = self.consumer_threads.get(push_queue)
                    if push_thread is None or not push_thread.is_alive():
                        if not push_thread.is_alive():
                            self.worker_logger.info(
                                "Thread for queue not alive, creating a new one...",
                                {"queue": push_queue},
                            )

                        self.consumer_threads[push_queue] = Consumer(
                            execution_pool,
                            self.build_pika_parameters(connector_config),
                            push_queue,
                            self.log_level,
                            self.opencti_json_logging,
                            self.opencti_url,
                            self.opencti_token,
                            self.opencti_ssl_verify,
                            connector_config["push_exchange"],
                            connector_config["push_routing"],
                        )
                        self.consumer_threads[push_queue].name = push_queue
                        self.consumer_threads[push_queue].start()

                    # Listen for webhook message
                    listen_callback_uri = connector_config.get("listen_callback_uri")
                    if listen_callback_uri is not None:
                        listen_queue = connector_config["listen"]
                        queues.append(listen_queue)
                        listen_thread = self.listen_api_threads.get(listen_queue)
                        if listen_thread is None or not listen_thread.is_alive():
                            self.listen_api_threads[listen_queue] = ApiConsumer(
                                listen_api_execution_pool,
                                self.build_pika_parameters(connector_config),
                                listen_queue,
                                self.log_level,
                                self.opencti_json_logging,
                                connector["connector_user"]["api_token"],
                                listen_callback_uri,
                                self.listen_api_ssl_verify,
                                self.listen_api_http_proxy,
                                self.listen_api_https_proxy,
                            )
                            self.listen_api_threads[listen_queue].name = listen_queue
                            self.listen_api_threads[listen_queue].start()

                # Check if some threads must be stopped
                for thread in list(self.consumer_threads):
                    if thread not in queues:
                        self.worker_logger.info(
                            "Queue no longer exists, killing thread...",
                            {"thread": thread},
                        )
                        try:
                            self.consumer_threads[thread].stop()
                            self.consumer_threads.pop(thread, None)
                        except:
                            self.worker_logger.info(
                                "Unable to kill the thread for queue, an operation is running, keep trying...",
                                {"thread": thread},
                            )
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
