# coding: utf-8

import logging
import functools
import random

import yaml
import pika
import os
import time
import json
import base64
import threading
import ctypes

from requests.exceptions import RequestException
from pycti import OpenCTIApiClient

PROCESSING_COUNT = 5


class Consumer(threading.Thread):
    def __init__(self, connector, opencti_url, opencti_token):
        threading.Thread.__init__(self)
        self.opencti_url = opencti_url
        self.opencti_token = opencti_token
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_token)
        self.queue_name = connector["config"]["push"]
        self.pika_credentials = pika.PlainCredentials(
            connector["config"]["connection"]["user"],
            connector["config"]["connection"]["pass"],
        )
        self.pika_parameters = pika.ConnectionParameters(
            connector["config"]["connection"]["host"],
            connector["config"]["connection"]["port"],
            "/",
            self.pika_credentials,
        )
        self.pika_connection = pika.BlockingConnection(self.pika_parameters)
        self.channel = self.pika_connection.channel()
        self.channel.basic_qos(prefetch_count=1)
        self.processing_count = 0

    def get_id(self):
        if hasattr(self, "_thread_id"):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def terminate(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
            thread_id, ctypes.py_object(SystemExit)
        )
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            logging.info("Unable to kill the thread")

    def nack_message(self, channel, delivery_tag):
        if channel.is_open:
            logging.info("Message (delivery_tag=" + str(delivery_tag) + ") rejected")
            channel.basic_nack(delivery_tag)
        else:
            logging.info(
                "Message (delivery_tag="
                + str(delivery_tag)
                + ") NOT rejected (channel closed)"
            )
            pass

    def ack_message(self, channel, delivery_tag):
        if channel.is_open:
            logging.info(
                "Message (delivery_tag=" + str(delivery_tag) + ") acknowledged"
            )
            channel.basic_ack(delivery_tag)
        else:
            logging.info(
                "Message (delivery_tag="
                + str(delivery_tag)
                + ") NOT acknowledged (channel closed)"
            )
            pass

    def stop_consume(self, channel):
        if channel.is_open:
            channel.stop_consuming()

    # Callable for consuming a message
    def _process_message(self, channel, method, properties, body):
        data = json.loads(body)
        logging.info(
            "Processing a new message (delivery_tag="
            + str(method.delivery_tag)
            + "), launching a thread..."
        )
        thread = threading.Thread(
            target=self.data_handler,
            args=[self.pika_connection, channel, method.delivery_tag, data],
        )
        thread.start()

        while thread.is_alive():  # Loop while the thread is processing
            self.pika_connection.sleep(0.05)
        logging.info("Message processed, thread terminated")

    # Data handling
    def data_handler(self, connection, channel, delivery_tag, data):
        # Set the API headers
        applicant_id = data["applicant_id"]
        self.api.set_applicant_id_header(applicant_id)
        work_id = data["work_id"] if "work_id" in data else None
        # Execute the import
        self.processing_count += 1
        content = "Unparseable"
        try:
            content = base64.b64decode(data["content"]).decode("utf-8")
            types = (
                data["entities_types"]
                if "entities_types" in data and len(data["entities_types"]) > 0
                else None
            )
            update = data["update"] if "update" in data else False
            processing_count = self.processing_count
            if self.processing_count == PROCESSING_COUNT:
                processing_count = None
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
        except RequestException as re:
            logging.error("A connection error occurred: { " + str(re) + " }")
            time.sleep(60)
            logging.info(
                "Message (delivery_tag=" + str(delivery_tag) + ") NOT acknowledged"
            )
            cb = functools.partial(self.nack_message, channel, delivery_tag)
            connection.add_callback_threadsafe(cb)
            self.processing_count = 0
            return False
        except Exception as ex:
            error = str(ex)
            if (
                "UnsupportedError" not in error
                and self.processing_count < PROCESSING_COUNT
            ):
                # Sleep between 1 and 3 secs before retrying
                sleep_jitter = round(random.uniform(1, 3), 2)
                time.sleep(sleep_jitter)
                logging.info(
                    "Message (delivery_tag="
                    + str(delivery_tag)
                    + ") reprocess (retry nb: "
                    + str(self.processing_count)
                    + ")"
                )
                self.data_handler(connection, channel, delivery_tag, data)
            else:
                logging.error(str(ex))
                self.processing_count = 0
                cb = functools.partial(self.ack_message, channel, delivery_tag)
                connection.add_callback_threadsafe(cb)
                if work_id is not None:
                    self.api.work.report_expectation(
                        work_id, {"error": str(ex), "source": content}
                    )
                return False

    def run(self):
        try:
            # Consume the queue
            logging.info("Thread for queue " + self.queue_name + " started")
            self.channel.basic_consume(
                queue=self.queue_name, on_message_callback=self._process_message
            )
            self.channel.start_consuming()
        finally:
            self.channel.stop_consuming()
            logging.info("Thread for queue " + self.queue_name + " terminated")


class Worker:
    def __init__(self):
        self.logs_all_queue = "logs_all"
        self.consumer_threads = {}
        self.logger_threads = {}

        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.log_level = os.getenv("WORKER_LOG_LEVEL") or config["worker"]["log_level"]
        self.opencti_url = os.getenv("OPENCTI_URL") or config["opencti"]["url"]
        self.opencti_token = os.getenv("OPENCTI_TOKEN") or config["opencti"]["token"]

        # Check if openCTI is available
        self.api = OpenCTIApiClient(
            self.opencti_url, self.opencti_token, self.log_level
        )

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError("Invalid log level: " + self.log_level)
        logging.basicConfig(level=numeric_level)

        # Initialize variables
        self.connectors = []
        self.queues = []

    # Start the main loop
    def start(self):
        while True:
            try:
                # Fetch queue configuration from API
                self.connectors = self.api.connector.list()
                self.queues = list(map(lambda x: x["config"]["push"], self.connectors))

                # Check if all queues are consumed
                for connector in self.connectors:
                    queue = connector["config"]["push"]
                    if queue in self.consumer_threads:
                        if not self.consumer_threads[queue].is_alive():
                            logging.info(
                                "Thread for queue "
                                + queue
                                + " not alive, creating a new one..."
                            )
                            self.consumer_threads[queue] = Consumer(
                                connector,
                                self.opencti_url,
                                self.opencti_token,
                            )
                            self.consumer_threads[queue].start()
                    else:
                        self.consumer_threads[queue] = Consumer(
                            connector,
                            self.opencti_url,
                            self.opencti_token,
                        )
                        self.consumer_threads[queue].start()

                # Check if some threads must be stopped
                for thread in list(self.consumer_threads):
                    if thread not in self.queues:
                        logging.info(
                            "Queue " + thread + " no longer exists, killing thread..."
                        )
                        try:
                            self.consumer_threads[thread].terminate()
                            self.consumer_threads.pop(thread, None)
                        except:
                            logging.info(
                                "Unable to kill the thread for queue "
                                + thread
                                + ", an operation is running, keep trying..."
                            )
                time.sleep(60)
            except KeyboardInterrupt:
                # Graceful stop
                for thread in self.consumer_threads.keys():
                    if thread not in self.queues:
                        self.consumer_threads[thread].terminate()
                exit(0)
            except Exception as e:
                logging.error(e)
                time.sleep(60)


if __name__ == "__main__":
    worker = Worker()
    try:
        worker.start()
    except Exception as e:
        logging.error(e)
        exit(1)
