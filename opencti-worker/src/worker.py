# coding: utf-8

import logging
import yaml
import pika
import os
import time
import requests
import json
import base64
import threading
import ctypes

from requests.auth import HTTPBasicAuth
from pycti import OpenCTIApiClient

EXCHANGE_NAME = 'amqp.opencti'

class Consumer(threading.Thread):
    def __init__(self, queue_name, api):
        threading.Thread.__init__(self)
        self.api = api
        self.queue_name = queue_name
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.type = config['worker']['type']
            self.opencti_url = config['opencti']['url']
            self.opencti_token = config['opencti']['token']
            self.rabbitmq_hostname = config['rabbitmq']['hostname']
            self.rabbitmq_port = config['rabbitmq']['port']
            self.rabbitmq_username = config['rabbitmq']['username']
            self.rabbitmq_password = config['rabbitmq']['password']
        else:
            self.type = os.getenv('WORKER_TYPE', 'import')
            self.opencti_url = os.getenv('OPENCTI_URL', 'http://localhost:4000')
            self.opencti_token = os.getenv('OPENCTI_TOKEN', 'ChangeMe')
            self.rabbitmq_hostname = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.rabbitmq_port = os.getenv('RABBITMQ_PORT', 5672)
            self.rabbitmq_username = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.rabbitmq_password = os.getenv('RABBITMQ_PASSWORD', 'guest')

        # Check configuration
        if self.type == 'import':
            self.DEFAULT_QUEUE_NAME = 'import-platform'
            self.DEFAULT_ROUTING_KEY = 'import.platform'
            self.CONNECTOR_QUEUE_PREFIX = 'import-connectors-'
        elif self.type == 'export':
            self.DEFAULT_QUEUE_NAME = 'export-platform'
            self.DEFAULT_ROUTING_KEY = 'export.platform'
            self.CONNECTOR_QUEUE_PREFIX = 'export-connectors-'

        # Connect to RabbitMQ
        self.connection = self._connect()
        self.channel = self.connection.channel()
        self.channel.basic_qos(prefetch_count=1)
        self._create_exchange()
        self._create_default_queue()

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

    # Connect to RabbitMQ
    def _connect(self):
        try:
            credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)
            parameters = pika.ConnectionParameters(self.rabbitmq_hostname, self.rabbitmq_port, '/', credentials)
            return pika.BlockingConnection(parameters)
        except:
            logging.error('Unable to connect to RabbitMQ with the given parameters')
            return None

    # Create the exchange
    def _create_exchange(self):
        self.channel.exchange_declare(exchange=EXCHANGE_NAME, exchange_type='direct', durable=True)

    # Create the default queue for import coming from the platform
    def _create_default_queue(self):
        self.channel.queue_declare(self.DEFAULT_QUEUE_NAME, durable=True)
        self.channel.queue_bind(queue=self.DEFAULT_QUEUE_NAME, exchange=EXCHANGE_NAME, routing_key=self.DEFAULT_ROUTING_KEY)

    # Callable for consuming a message
    def _process_message(self, channel, method, properties, body):
        data = json.loads(body)
        logging.info('Processing a new message (type=' + data['type'] + ', delivery_tag=' + str(method.delivery_tag) + '), launching a thread...')
        thread = threading.Thread(target=self.data_handler, args=[data])
        thread.start()

        while thread.is_alive():  # Loop while the thread is processing
            self.connection.sleep(1.0)
        logging.info('Message (type=' + data['type'] + ', delivery_tag=' + str(method.delivery_tag) + ') processed, thread terminated')
        self.channel.basic_ack(delivery_tag=method.delivery_tag)

    # Data handling
    def data_handler(self, data):
        try:
            if data['type'] == 'stix2-bundle' or data['type'] == 'stix2bundle':
                content = base64.b64decode(data['content']).decode('utf-8')
                self.api.stix2_import_bundle(content, True, data['entities_types'] if 'entities_types' in data else [])
            if data['type'] == 'stix2-bundle-simple':
                bundle = self.api.stix2_export_entity(data['entity_type'], data['entity_id'], 'simple')
                if bundle is not None:
                    bundle = json.dumps(bundle, indent=4)
                    self.api.push_stix_domain_entity_export(data['entity_id'], data['export_id'], bundle)
            if data["type"] == 'stix2-bundle-full':
                bundle = self.api.stix2_export_entity(data['entity_type'], data['entity_id'], 'full')
                if bundle is not None:
                    bundle = json.dumps(bundle, indent=4)
                    self.api.push_stix_domain_entity_export(data['entity_id'], data['export_id'], bundle)
        except Exception as e:
            logging.error('An unexpected error occurred: { ' + str(e) + ' }')
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

class Worker:
    def __init__(self):
        self.consumer_threads = {}

        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.type = config['worker']['type']
            self.log_level = config['worker']['log_level']
            self.opencti_url = config['opencti']['url']
            self.opencti_token = config['opencti']['token']
            self.rabbitmq_hostname = config['rabbitmq']['hostname']
            self.rabbitmq_port = config['rabbitmq']['port']
            self.rabbitmq_port_management = config['rabbitmq']['port_management']
            self.rabbitmq_management_ssl = config['rabbitmq']['management_ssl']
            self.rabbitmq_username = config['rabbitmq']['username']
            self.rabbitmq_password = config['rabbitmq']['password']
        else:
            self.type = os.getenv('WORKER_TYPE', 'import')
            self.log_level = os.getenv('WORKER_LOG_LEVEL', 'info')
            self.opencti_url = os.getenv('OPENCTI_URL', 'http://localhost:4000')
            self.opencti_token = os.getenv('OPENCTI_TOKEN', 'ChangeMe')
            self.rabbitmq_hostname = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.rabbitmq_port = os.getenv('RABBITMQ_PORT', 5672)
            self.rabbitmq_port_management = os.getenv('RABBITMQ_PORT_MANAGEMENT', 15672)
            self.rabbitmq_management_ssl = os.getenv('RABBITMQ_MANAGEMENT_SSL', "false") == "true"
            self.rabbitmq_username = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.rabbitmq_password = os.getenv('RABBITMQ_PASSWORD', 'guest')

        # Check configuration
        if len(self.opencti_token) == 0 or self.opencti_token == 'ChangeMe':
            raise ValueError('Token configuration must be the same as APP__ADMIN__TOKEN')

        # Check if openCTI is available
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_token)
        if not self.api.health_check():
            raise ValueError('OpenCTI API seems down')

        if self.type == 'import':
            self.DEFAULT_QUEUE_NAME = 'import-platform'
            self.DEFAULT_ROUTING_KEY = 'import.platform'
            self.CONNECTOR_QUEUE_PREFIX = 'import-connectors-'
        elif self.type == 'export':
            self.DEFAULT_QUEUE_NAME = 'export-platform'
            self.DEFAULT_ROUTING_KEY = 'export.platform'
            self.CONNECTOR_QUEUE_PREFIX = 'export-connectors-'

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + self.log_level)
        logging.basicConfig(level=numeric_level)

    # List all connectors queues
    def _list_connectors_queues(self):
        try:
            # Get all existing queues
            scheme = 'https' if self.rabbitmq_management_ssl else 'http'
            queues_request = requests.get(
                scheme + '://' + self.rabbitmq_hostname + ':' + str(self.rabbitmq_port_management) + '/api/queues',
                auth=HTTPBasicAuth(self.rabbitmq_username, self.rabbitmq_password)
            )
            queues_request.raise_for_status()
            queues = queues_request.json()
            queues_list = []
            for queue in queues:
                if self.CONNECTOR_QUEUE_PREFIX in queue['name']:
                    queues_list.append(queue['name'])
            return queues_list
        except:
            logging.error('Unable to list queues and bind them')
            return []

    # Start the main loop
    def start(self):
        try:
            while True:
                # Check existing queues
                queues = self._list_connectors_queues()
                queues.append(self.DEFAULT_QUEUE_NAME)

                # Check if all queues are consumed
                for queue in queues:
                    if queue in self.consumer_threads:
                        if not self.consumer_threads[queue].is_alive():
                            logging.info('Thread for queue ' + queue + ' not alive, creating a new one...')
                            self.consumer_threads[queue] = Consumer(queue, self.api)
                            self.consumer_threads[queue].start()
                    else:
                        self.consumer_threads[queue] = Consumer(queue, self.api)
                        self.consumer_threads[queue].start()

                # Check if some threads must be stopped
                for thread in list(self.consumer_threads):
                    if thread not in queues:
                        logging.info('Queue ' + thread + ' no longer exists, killing thread...')
                        try:
                            self.consumer_threads[thread].terminate()
                            self.consumer_threads.pop(thread, None)
                        except:
                            logging.info('Unable to kill the thread for queue ' + thread + ', an operation is running, keep trying...')
                time.sleep(5)
        except KeyboardInterrupt:
            # Graceful stop
            queues = self._list_connectors_queues()
            queues.append(self.DEFAULT_QUEUE_NAME)
            for thread in self.consumer_threads.keys():
                if thread not in queues:
                    self.consumer_threads[thread].terminate()
            exit(0)

if __name__ == '__main__':
    worker = Worker()
    try:
        worker.start()
    except Exception as e:
        logging.error(e)
        exit(1)
