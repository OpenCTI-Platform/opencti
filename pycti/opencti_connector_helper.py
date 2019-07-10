# coding: utf-8

import pika
import logging
import json
import base64
from stix2validator import validate_string

EXCHANGE_NAME = 'amqp.opencti'


class OpenCTIConnectorHelper:
    """
        Python API for OpenCTI connector
        :param identifier: Connector identifier
        :param config: Connector configuration
        :param rabbitmq_hostname: RabbitMQ hostname
        :param rabbitmq_port: RabbitMQ hostname
        :param rabbitmq_username: RabbitMQ hostname
        :param rabbitmq_password: RabbitMQ password
    """

    def __init__(self, identifier, connector_config, rabbitmq_config, log_level='info'):
        # Configure logger
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + log_level)
        logging.basicConfig(level=numeric_level)

        # Initialize configuration
        self.connection = None
        self.identifier = identifier
        self.config = connector_config
        self.rabbitmq_hostname = rabbitmq_config['hostname']
        self.rabbitmq_port = rabbitmq_config['port']
        self.rabbitmq_username = rabbitmq_config['username']
        self.rabbitmq_password = rabbitmq_config['password']
        self.queue_name = 'import-connectors-' + self.identifier
        self.routing_key = 'import.connectors.' + self.identifier

        # Encode the configuration
        config_encoded = base64.b64encode(json.dumps(self.config).encode('utf-8')).decode('utf-8')

        # Connect to RabbitMQ
        self.connection = self._connect()
        self.channel = self._create_channel()
        logging.info('Successfully connected to RabbitMQ')

        # Declare the queue for the connector
        self.channel.queue_delete(self.queue_name)
        self.channel.queue_declare(self.queue_name, durable=True, arguments={'config': config_encoded})
        self.channel.queue_bind(queue=self.queue_name, exchange=EXCHANGE_NAME, routing_key=self.routing_key)

    def _connect(self):
        try:
            credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)
            parameters = pika.ConnectionParameters(self.rabbitmq_hostname, self.rabbitmq_port, '/', credentials)
            return pika.BlockingConnection(parameters)
        except:
            logging.error('Unable to connect to RabbitMQ with the given parameters')

    def _create_channel(self):
        try:
            channel = self.connection.channel()
            channel.exchange_declare(exchange=EXCHANGE_NAME, exchange_type='direct', durable=True)
            return channel
        except:
            logging.error('Unable to open channel to RabbitMQ with the given parameters')

    def _reconnect(self):
        self.connection = self._connect()
        self.channel = self._create_channel()

    def send_stix2_bundle(self, bundle):
        """
            This method send a STIX2 bundle to RabbitMQ to be consumed by workers
            :param bundle: A valid STIX2 bundle
        """
        if not self.channel.is_open:
            self._reconnect()

        # Validate the STIX 2 bundle
        #validation = validate_string(bundle)
        #if not validation.is_valid:
            #raise ValueError('The bundle is not a valid STIX2 JSON:' + bundle)

        # Prepare the message
        message = {
            'type': 'stix2-bundle',
            'content': base64.b64encode(bundle.encode('utf-8')).decode('utf-8')
        }

        # Send the message
        self.channel.basic_publish(EXCHANGE_NAME, self.routing_key, json.dumps(message))
        logging.info('STIX2 bundle has been sent')
