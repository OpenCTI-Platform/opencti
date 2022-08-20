# coding: utf-8


import base64
import ctypes
import functools
import json
import logging
import os
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from threading import Thread
from typing import Any, Dict, List, Optional, Union

import pika
import yaml
from pika.adapters.blocking_connection import BlockingChannel
from pycti import OpenCTIApiClient
from pycti.connector.opencti_connector_helper import (
    create_ssl_context,
    get_config_variable,
)
from requests.exceptions import RequestException, Timeout

PROCESSING_COUNT: int = 4
MAX_PROCESSING_COUNT: int = 60


@dataclass(unsafe_hash=True)
class Consumer(Thread):  # pylint: disable=too-many-instance-attributes
    connector: Dict[str, Any] = field(hash=False)
    opencti_url: str
    opencti_token: str
    log_level: str
    ssl_verify: Union[bool, str] = False
    json_logging: bool = False

    def __post_init__(self) -> None:
        super().__init__()
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            ssl_verify=self.ssl_verify,
            json_logging=self.json_logging,
        )
        self.queue_name = self.connector["config"]["push"]
        self.pika_credentials = pika.PlainCredentials(
            self.connector["config"]["connection"]["user"],
            self.connector["config"]["connection"]["pass"],
        )
        self.pika_parameters = pika.ConnectionParameters(
            self.connector["config"]["connection"]["host"],
            self.connector["config"]["connection"]["port"],
            self.connector["config"]["connection"]["vhost"],
            self.pika_credentials,
            ssl_options=pika.SSLOptions(create_ssl_context())
            if self.connector["config"]["connection"]["use_ssl"]
            else None,
        )

        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        self.channel.basic_qos(prefetch_count=1)
        self.processing_count: int = 0
        self.current_bundle_id: [str, None] = None
        self.current_bundle_seq: int = 0

    @property
    def id(self) -> Any:  # pylint: disable=inconsistent-return-statements
        if hasattr(self, "_thread_id"):
            return self._thread_id  # type: ignore  # pylint: disable=no-member
        # pylint: disable=protected-access
        for id_, thread in threading._active.items():  # type: ignore
            if thread is self:
                return id_

    def terminate(self) -> None:
        thread_id = self.id
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
            thread_id, ctypes.py_object(SystemExit)
        )
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            logging.info("Unable to kill the thread")

    def nack_message(self, channel: BlockingChannel, delivery_tag: int) -> None:
        if channel.is_open:
            logging.info("%s", f"Message (delivery_tag={delivery_tag}) rejected")
            channel.basic_nack(delivery_tag)
        else:
            logging.info(
                "%s",
                f"Message (delivery_tag={delivery_tag}) NOT rejected (channel closed)",
            )

    def ack_message(self, channel: BlockingChannel, delivery_tag: int) -> None:
        if channel.is_open:
            logging.info("%s", f"Message (delivery_tag={delivery_tag}) acknowledged")
            channel.basic_ack(delivery_tag)
        else:
            logging.info(
                "%s",
                (
                    f"Message (delivery_tag={delivery_tag}) "
                    "NOT acknowledged (channel closed)"
                ),
            )

    def stop_consume(self, channel: BlockingChannel) -> None:
        if channel.is_open:
            channel.stop_consuming()

    # Callable for consuming a message
    def _process_message(
        self,
        channel: BlockingChannel,
        method: Any,
        properties: None,  # pylint: disable=unused-argument
        body: str,
    ) -> None:
        data = json.loads(body)
        logging.info(
            "%s",
            (
                f"Processing a new message (delivery_tag={method.delivery_tag})"
                ", launching a thread..."
            ),
        )
        thread = Thread(
            target=self.data_handler,
            args=[self.pika_connection, channel, method.delivery_tag, data],
        )
        thread.start()

        while thread.is_alive():  # Loop while the thread is processing
            self.pika_connection.sleep(0.05)
        logging.info("Message processed, thread terminated")

    # Data handling
    def data_handler(  # pylint: disable=too-many-statements, too-many-locals
        self,
        connection: Any,
        channel: BlockingChannel,
        delivery_tag: str,
        data: Dict[str, Any],
    ) -> Optional[bool]:
        # Set the API headers
        applicant_id = data["applicant_id"]
        self.api.set_applicant_id_header(applicant_id)
        work_id = data["work_id"] if "work_id" in data else None
        # Execute the import
        self.processing_count += 1
        content = "Unparseable"
        try:
            event_type = data["type"] if "type" in data else "bundle"
            types = (
                data["entities_types"]
                if "entities_types" in data and len(data["entities_types"]) > 0
                else None
            )
            processing_count = self.processing_count
            if self.processing_count == PROCESSING_COUNT:
                processing_count = None  # type: ignore
            if event_type == "bundle":
                content = base64.b64decode(data["content"]).decode("utf-8")
                update = data["update"] if "update" in data else False
                self.api.stix2.import_bundle_from_json(
                    content, update, types, processing_count
                )
                # Ack the message
                cb = functools.partial(self.ack_message, channel, delivery_tag)
                connection.add_callback_threadsafe(cb)
                if work_id is not None:
                    self.api.work.report_expectation(work_id, None)
                self.processing_count = 0
                return True
            elif event_type == "event":
                event = base64.b64decode(data["content"]).decode("utf-8")
                event_content = json.loads(event)
                event_type = event_content["type"]
                if event_type == "create" or event_type == "update":
                    bundle = {
                        "type": "bundle",
                        "objects": [event_content["data"]],
                    }
                    self.api.stix2.import_bundle(
                        bundle, True, types, processing_count
                    )
                elif event_type == "delete":
                    delete_id = event_content["data"]["id"]
                    self.api.stix.delete(id=delete_id)
                elif event_type == "merge":
                    # Start with a merge
                    target_id = event_content["data"]["id"]
                    source_ids = list(map(lambda source: source["id"], event_content["context"]["sources"]))
                    self.api.stix_core_object.merge(id=target_id, object_ids=source_ids)
                    # Update the target entity after merge
                    bundle = {
                        "type": "bundle",
                        "objects": [event_content["data"]],
                    }
                    self.api.stix2.import_bundle(
                        bundle, True, types, processing_count
                    )
                # Ack the message
                cb = functools.partial(self.ack_message, channel, delivery_tag)
                connection.add_callback_threadsafe(cb)
                self.processing_count = 0
                return True
            else:
                # Unknown type, just move on.
                return True
        except Timeout as te:
            logging.warning("%s", f"A connection timeout occurred: {{ {te} }}")
            # Platform is under heavy load: wait for unlock & retry almost indefinitely.
            sleep_jitter = round(random.uniform(10, 30), 2)
            time.sleep(sleep_jitter)
            self.data_handler(connection, channel, delivery_tag, data)
            return True
        except RequestException as re:
            logging.error("%s", f"A connection error occurred: {{ {re} }}")
            time.sleep(60)
            logging.info(
                "%s", f"Message (delivery_tag={delivery_tag}) NOT acknowledged"
            )
            cb = functools.partial(self.nack_message, channel, delivery_tag)
            connection.add_callback_threadsafe(cb)
            self.processing_count = 0
            return False
        except Exception as ex:  # pylint: disable=broad-except
            error = str(ex)
            if "LockError" in error and self.processing_count < MAX_PROCESSING_COUNT:
                # Platform is under heavy load:
                # wait for unlock & retry almost indefinitely.
                sleep_jitter = round(random.uniform(10, 30), 2)
                time.sleep(sleep_jitter)
                self.data_handler(connection, channel, delivery_tag, data)
            elif (
                "MissingReferenceError" in error
                and self.processing_count < PROCESSING_COUNT
            ):
                # In case of missing reference, wait & retry
                sleep_jitter = round(random.uniform(1, 3), 2)
                time.sleep(sleep_jitter)
                logging.info(
                    "%s",
                    (
                        f"Message (delivery_tag={delivery_tag}) "
                        f"reprocess (retry nb: {self.processing_count})"
                    ),
                )
                self.data_handler(connection, channel, delivery_tag, data)
            elif "Bad Gateway" in error:
                logging.error("%s", f"A connection error occurred: {{ {error} }}")
                time.sleep(60)
                logging.info(
                    "%s", f"Message (delivery_tag={delivery_tag}) NOT acknowledged"
                )
                cb = functools.partial(self.nack_message, channel, delivery_tag)
                connection.add_callback_threadsafe(cb)
                self.processing_count = 0
                return False
            else:
                # Platform does not know what to do and raises an error:
                # fail and acknowledge the message.
                logging.error(error)
                self.processing_count = 0
                cb = functools.partial(self.ack_message, channel, delivery_tag)
                connection.add_callback_threadsafe(cb)
                if work_id is not None:
                    self.api.work.report_expectation(
                        work_id,
                        {
                            "error": error,
                            "source": content
                            if len(content) < 50000
                            else "Bundle too large",
                        },
                    )
                return False
            return None

    def run(self) -> None:
        try:
            # Consume the queue
            logging.info("%s", f"Thread for queue {self.queue_name} started")
            self.channel.basic_consume(
                queue=self.queue_name,
                on_message_callback=self._process_message,
            )
            self.channel.start_consuming()
        finally:
            self.channel.stop_consuming()
            logging.info("%s", f"Thread for queue {self.queue_name} terminated")


@dataclass(unsafe_hash=True)
class Worker:  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    logs_all_queue: str = "logs_all"
    consumer_threads: Dict[str, Any] = field(default_factory=dict, hash=False)
    logger_threads: Dict[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
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
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.opencti_ssl_verify = get_config_variable(
            "OPENCTI_SSL_VERIFY", ["opencti", "ssl_verify"], config, False, False
        )
        self.opencti_json_logging = get_config_variable(
            "OPENCTI_JSON_LOGGING", ["opencti", "json_logging"], config
        )
        # Load worker config
        self.log_level = get_config_variable(
            "WORKER_LOG_LEVEL", ["worker", "log_level"], config
        )

        # Check if openCTI is available
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            ssl_verify=self.opencti_ssl_verify,
            json_logging=self.opencti_json_logging,
        )

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {self.log_level}")
        logging.basicConfig(level=numeric_level)

        # Initialize variables
        self.connectors: List[Any] = []
        self.queues: List[Any] = []

    # Start the main loop
    def start(self) -> None:
        sleep_delay = 60
        while True:
            try:
                # Fetch queue configuration from API
                self.connectors = self.api.connector.list()
                self.queues = list(
                    map(lambda x: x["config"]["push"], self.connectors)  # type: ignore
                )

                # Check if all queues are consumed
                for connector in self.connectors:
                    queue = connector["config"]["push"]
                    if queue in self.consumer_threads:
                        if not self.consumer_threads[queue].is_alive():
                            logging.info(
                                "%s",
                                (
                                    f"Thread for queue {queue} not alive"
                                    ", creating a new one..."
                                ),
                            )
                            self.consumer_threads[queue] = Consumer(
                                connector,
                                self.opencti_url,
                                self.opencti_token,
                                self.log_level,
                                self.opencti_ssl_verify,
                                self.opencti_json_logging,
                            )
                            self.consumer_threads[queue].start()
                    else:
                        self.consumer_threads[queue] = Consumer(
                            connector,
                            self.opencti_url,
                            self.opencti_token,
                            self.log_level,
                            self.opencti_ssl_verify,
                            self.opencti_json_logging,
                        )
                        self.consumer_threads[queue].start()

                # Check if some threads must be stopped
                for thread in list(self.consumer_threads):
                    if thread not in self.queues:
                        logging.info(
                            "%s",
                            f"Queue {thread} no longer exists, killing thread...",
                        )
                        try:
                            self.consumer_threads[thread].terminate()
                            self.consumer_threads.pop(thread, None)
                        except:  # TODO: remove bare except
                            logging.info(
                                "%s",
                                (
                                    f"Unable to kill the thread for queue {thread}"
                                    ", an operation is running, keep trying..."
                                ),
                            )
                time.sleep(sleep_delay)
            except KeyboardInterrupt:
                # Graceful stop
                for thread in self.consumer_threads:
                    if thread not in self.queues:
                        self.consumer_threads[thread].terminate()
                sys.exit(0)
            except Exception as e:  # pylint: disable=broad-except
                logging.error(e)
                time.sleep(60)


if __name__ == "__main__":
    worker = Worker()
    try:
        worker.start()
    except Exception as e:  # pylint: disable=broad-except
        logging.error(e)
        sys.exit(1)
