# coding: utf-8

import logging
import yaml
import pika
import os
import time
import requests
import json
import base64

from requests.auth import HTTPBasicAuth
from pycti import OpenCTIApiClient

EXCHANGE_NAME = 'amqp.opencti'


class Worker:
    def __init__(self):
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
        if self.type == 'import':
            self.DEFAULT_QUEUE_NAME = 'import-platform'
            self.DEFAULT_ROUTING_KEY = 'import.platform'
            self.CONNECTOR_QUEUE_PREFIX = 'import-connectors-'
        elif self.type == 'export':
            self.DEFAULT_QUEUE_NAME = 'export-platform'
            self.DEFAULT_ROUTING_KEY = 'export.platform'
            self.CONNECTOR_QUEUE_PREFIX = 'export-connectors-'
        else:
            raise ValueError('Type not supported: ' + self.type)

        if len(self.opencti_token) == 0 or self.opencti_token == '<Must be the same as APP__ADMIN__TOKEN>':
            raise ValueError('Configuration not found')

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + self.log_level)
        logging.basicConfig(level=numeric_level)

        # Initialize OpenCTI client
        self.opencti_api_client = OpenCTIApiClient(self.opencti_url, self.opencti_token)

        # Connect to RabbitMQ
        self.connection = self._connect()
        self.channel = self.connection.channel()
        self._create_exchange()
        self._create_default_queue()

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

    def _reconnect(self):
        self.connection = self._connect()
        self.channel = self.connection.channel()
        self._create_exchange()
        self._create_default_queue()
        logging.info('Successfully connected to RabbitMQ')

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

    # Callable for consuming a message
    def _process_message(self, body):
        try:
            data = json.loads(body)
            logging.info('Received a new message of type "' + data['type'] + '"')
            if data['type'] == 'stix2-bundle' or data['type'] == 'stix2bundle':
                content = base64.b64decode(data['content']).decode('utf-8')
                self.opencti_api_client.stix2_import_bundle(content, True, data['entities_types'] if 'entities_types' in data else [])
            if data['type'] == 'stix2-bundle-simple':
                bundle = self.opencti_api_client.stix2_export_entity(data['entity_type'], data['entity_id'], 'simple')
                if bundle is not None:
                    bundle = base64.b64encode(bytes(json.dumps(bundle, indent=4), 'utf-8')).decode('utf-8')
                    self.opencti_api_client.push_stix_domain_entity_export(data['entity_id'], data['export_id'], bundle)
            if data["type"] == 'stix2-bundle-full':
                bundle = self.opencti_api_client.stix2_export_entity(data['entity_type'], data['entity_id'], 'full')
                if bundle is not None:
                    bundle = base64.b64encode(bytes(json.dumps(bundle, indent=4), 'utf-8')).decode('utf-8')
                    self.opencti_api_client.push_stix_domain_entity_export(data['entity_id'], data['export_id'], bundle)
        except Exception as e:
            logging.error('An unexpected error occurred: { ' + str(e) + ' }')
            return False

    # Consume the queues during 1 minute
    def _consume(self):
        timeout = time.time() + 60
        queues = self._list_connectors_queues()
        queues.append(self.DEFAULT_QUEUE_NAME)
        logging.info('Worker has been loaded with type: ' + self.type)
        while True:
            if time.time() > timeout:
                break
            for queue in queues:
                method, header, body = self.channel.basic_get(queue=queue)
                if method:
                    self._process_message(body)
                    self.channel.basic_ack(delivery_tag=method.delivery_tag)
            time.sleep(1)

    # Start the main loop
    def start(self):
        self._reconnect()
        try:
            while True:
                self._consume()
                time.sleep(1)
        except:
            raise ValueError('Unable to start the worker')


if __name__ == '__main__':
    worker = Worker()
    while True:
        try:
            worker.start()
        except Exception as e:
            logging.error(e)
            time.sleep(5)
