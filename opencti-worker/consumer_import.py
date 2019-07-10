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
from pycti import OpenCTI


class ConsumerImport:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.worker_log_level = config['worker']['log_level']
            self.opencti_api_url = config['opencti']['api_url']
            self.opencti_token = config['opencti']['token']
            self.rabbitmq_hostname = config['rabbitmq']['hostname']
            self.rabbitmq_port = config['rabbitmq']['port']
            self.rabbitmq_port_management = config['rabbitmq']['port_management']
            self.rabbitmq_management_ssl = config['rabbitmq']['management_ssl']
            self.rabbitmq_username = config['rabbitmq']['username']
            self.rabbitmq_password = config['rabbitmq']['password']
        else:
            self.worker_log_level = os.getenv('WORKER_LOG_LEVEL', 'info')
            self.opencti_api_url = os.getenv('OPENCTI_API_URL', 'http://localhost:4000')
            self.opencti_token = os.getenv('OPENCTI_TOKEN', 'ChangeMe')
            self.rabbitmq_hostname = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.rabbitmq_port = os.getenv('RABBITMQ_PORT', 5672)
            self.rabbitmq_port_management = os.getenv('RABBITMQ_PORT_MANAGEMENT', 15672)
            self.rabbitmq_management_ssl = os.getenv('RABBITMQ_MANAGEMENT_SSL', False)
            self.rabbitmq_username = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.rabbitmq_password = os.getenv('RABBITMQ_PASSWORD', 'guest')

        # Check configuration
        if len(self.opencti_token) == 0 or self.opencti_token == 'ChangeMe':
            raise ValueError('Configuration not found')

        # Configure logger
        numeric_level = getattr(logging, self.worker_log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + self.worker_log_level)
        logging.basicConfig(level=numeric_level)

        # Initialize OpenCTI client
        self.opencti = OpenCTI(self.opencti_api_url, self.opencti_token)

    # Connect to RabbitMQ
    def _create_connection(self):
        try:
            credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)
            parameters = pika.ConnectionParameters(self.rabbitmq_hostname, self.rabbitmq_port, '/', credentials)
            return pika.BlockingConnection(parameters)
        except:
            logging.error('Unable to connect to RabbitMQ with the given parameters')
            return None

    # Create the exchange
    def _create_exchange(self, channel):
        channel.exchange_declare(exchange='amqp.opencti', exchange_type='direct', durable=True)

    # Create the default queue for import coming from the platform
    def _create_default_queue(self, channel):
        channel.queue_declare('import-platform', durable=True)
        channel.queue_bind(queue='import-platform', exchange='opencti', routing_key='import')

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
                if 'import-connectors-' in queue['name']:
                    queues_list.append(queue['name'])
            return queues_list
        except:
            logging.error('Unable to list queues and bind them')
            return []

    # Callable for consuming a message
    def _consume_message(self, channel, method, properties, body):
        try:
            data = json.loads(body)
            logging.info('Received a new import of type "' + data['type'] + '"')
            if data['type'] == 'stix2-bundle':
                self.opencti.stix2_import_bundle(base64.b64decode(data['content']).decode('utf-8'))
        except Exception as e:
            logging.error('An unexpected error occurred: { ' + str(e) + ' }')
            return False
        channel.basic_ack(delivery_tag=method.delivery_tag)

    # Consume the queues during 1 minute
    def _consume(self, channel):
        timeout = time.time() + 60
        queues = self._list_connectors_queues()
        queues.append('import-platform')
        logging.info('Consumer has been started')
        while True:
            if time.time() > timeout:
                break
            for queue in queues:
                channel.basic_get(queue, self._consume_message)
            time.sleep(1)

    # Start the main loop
    def start(self):
        try:
            connection = self._create_connection()
            channel = connection.channel()
            self._create_exchange(channel)
            self._create_default_queue(channel)
            while True:
                self._consume(channel)
                time.sleep(1)
        except:
            raise ValueError('Unable to start the consumer')


if __name__ == '__main__':
    consumer_import = ConsumerImport()
    while True:
        try:
            consumer_import.start()
        except Exception as e:
            logging.error(e)
            time.sleep(5)
