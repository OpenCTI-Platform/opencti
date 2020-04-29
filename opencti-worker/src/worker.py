# coding: utf-8

import logging
import functools
import yaml
import pika
import os
import time
import json
import base64
import threading
import ctypes
import uuid

from requests.exceptions import RequestException
from itertools import groupby
from elasticsearch import Elasticsearch
from pycti import OpenCTIApiClient


class Consumer(threading.Thread):
    def __init__(self, connector, opencti_url, opencti_token):
        threading.Thread.__init__(self)
        self.opencti_url = opencti_url
        self.opencti_token = opencti_token
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_token)
        self.queue_name = connector['config']['push']
        self.pika_connection = pika.BlockingConnection(pika.URLParameters(connector['config']['uri']))
        self.channel = self.pika_connection.channel()
        self.channel.basic_qos(prefetch_count=1)

    def get_id(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def terminate(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            logging.info('Unable to kill the thread')

    def ack_message(self, channel, delivery_tag):
        if channel.is_open:
            logging.info('Message (delivery_tag=' + str(delivery_tag) + ') acknowledged')
            channel.basic_ack(delivery_tag)
        else:
            logging.info('Message (delivery_tag=' + str(delivery_tag) + ') NOT acknowledged (channel closed)')
            pass

    def stop_consume(self, channel):
        if channel.is_open:
            channel.stop_consuming()

    # Callable for consuming a message
    def _process_message(self, channel, method, properties, body):
        data = json.loads(body)
        logging.info('Processing a new message (delivery_tag=' + str(method.delivery_tag) + '), launching a thread...')
        thread = threading.Thread(target=self.data_handler,
                                  args=[self.pika_connection, channel, method.delivery_tag, data])
        thread.start()

        while thread.is_alive():  # Loop while the thread is processing
            self.pika_connection.sleep(1.0)
        logging.info('Message processed, thread terminated')

    # Data handling
    def data_handler(self, connection, channel, delivery_tag, data):
        job_id = data['job_id']
        token = None
        if "token" in data:
            token = data["token"]
        try:
            content = base64.b64decode(data['content']).decode('utf-8')
            types = data['entities_types'] if 'entities_types' in data else []
            update = data['update'] if 'update' in data else False
            if token:
                self.api.set_token(token)
            imported_data = self.api.stix2.import_bundle_from_json(content, update, types)
            self.api.set_token(self.opencti_token)
            if job_id is not None:
                messages = []
                by_types = groupby(imported_data, key=lambda x: x['type'])
                for key, grp in by_types:
                    messages.append(str(len(list(grp))) + ' imported ' + key)
                self.api.job.update_job(job_id, 'complete', messages)
            cb = functools.partial(self.ack_message, channel, delivery_tag)
            connection.add_callback_threadsafe(cb)
            return True
        except RequestException as re:
            logging.error('A connection error occurred: { ' + str(re) + ' }')
            logging.info('Message (delivery_tag=' + str(delivery_tag) + ') NOT acknowledged')
            cb = functools.partial(self.stop_consume, channel)
            connection.add_callback_threadsafe(cb)
            return False
        except Exception as e:
            logging.error('An unexpected error occurred: { ' + str(e) + ' }')
            cb = functools.partial(self.ack_message, channel, delivery_tag)
            connection.add_callback_threadsafe(cb)
            if job_id is not None:
                self.api.job.update_job(job_id, 'error', [str(e)])
            return False

    def run(self):
        try:
            # Consume the queue
            logging.info('Thread for queue ' + self.queue_name + ' started')
            self.channel.basic_consume(queue=self.queue_name, on_message_callback=self._process_message)
            self.channel.start_consuming()
        finally: 
            self.channel.stop_consuming()
            logging.info('Thread for queue ' + self.queue_name + ' terminated')


class Logger(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.config = config
        self.queue_name = "logs_all"
        self.pika_connection = pika.BlockingConnection(pika.URLParameters(config['rabbitmq_url']))
        self.channel = self.pika_connection.channel()
        self.elasticsearch = Elasticsearch([config['elasticsearch_url']])
        self.elasticsearch_index = config['elasticsearch_index']

    def get_id(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def terminate(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            logging.info('Unable to kill the thread')

    def stop_consume(self, channel):
        if channel.is_open:
            channel.stop_consuming()

    # Callable for consuming a message
    def _process_message(self, channel, method, properties, body):
        data = json.loads(body)
        data['internal_id_key'] = uuid.uuid4()
        self.elasticsearch.index(index=self.elasticsearch_index, id=data['internal_id_key'], body=data)
        channel.basic_ack(method.delivery_tag)

    def run(self):
        try:
            # Consume the queue
            logging.info('Thread for queue ' + self.queue_name + ' started')
            self.channel.basic_consume(queue=self.queue_name, on_message_callback=self._process_message)
            self.channel.start_consuming()
        finally:
            self.channel.stop_consuming()
            logging.info('Thread for queue ' + self.queue_name + ' terminated')

class Worker:
    def __init__(self):
        self.logs_all_queue = 'logs_all'
        self.consumer_threads = {}
        self.logger_threads = {}

        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.log_level = os.getenv('WORKER_LOG_LEVEL') or config['worker']['log_level']
        self.opencti_url = os.getenv('OPENCTI_URL') or config['opencti']['url']
        self.opencti_token = os.getenv('OPENCTI_TOKEN') or config['opencti']['token']

        # Check if openCTI is available
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_token)

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + self.log_level)
        logging.basicConfig(level=numeric_level)

        # Get logger config
        self.logger_config = self.api.get_logs_worker_config()

        # Initialize variables
        self.connectors = []
        self.queues = []

    # Start the main loop
    def start(self):
        while True:
            try:
                # Fetch queue configuration from API
                self.connectors = self.api.connector.list()
                self.queues = list(map(lambda x: x['config']['push'], self.connectors))

                # Check if all queues are consumed
                for connector in self.connectors:
                    queue = connector['config']['push']
                    if queue in self.consumer_threads:
                        if not self.consumer_threads[queue].is_alive():
                            logging.info('Thread for queue ' + queue + ' not alive, creating a new one...')
                            self.consumer_threads[queue] = Consumer(connector, self.opencti_url, self.opencti_token)
                            self.consumer_threads[queue].start()
                    else:
                        self.consumer_threads[queue] = Consumer(connector, self.opencti_url, self.opencti_token)
                        self.consumer_threads[queue].start()
                # Check logs queue is consumed
                if self.logs_all_queue in self.logger_threads:
                    if not self.logger_threads[self.logs_all_queue].is_alive():
                        logging.info('Thread for queue ' + self.logs_all_queue + ' not alive, creating a new one...')
                        self.logger_threads[self.logs_all_queue] = Logger(self.logger_config)
                        self.logger_threads[self.logs_all_queue].start()
                else:
                    self.logger_threads[self.logs_all_queue] = Logger(self.logger_config)
                    self.logger_threads[self.logs_all_queue].start()

                # Check if some threads must be stopped
                for thread in list(self.consumer_threads):
                    if thread not in self.queues:
                        logging.info('Queue ' + thread + ' no longer exists, killing thread...')
                        try:
                            self.consumer_threads[thread].terminate()
                            self.consumer_threads.pop(thread, None)
                        except:
                            logging.info('Unable to kill the thread for queue '
                                         + thread + ', an operation is running, keep trying...')
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


if __name__ == '__main__':
    worker = Worker()
    try:
        worker.start()
    except Exception as e:
        logging.error(e)
        exit(1)
