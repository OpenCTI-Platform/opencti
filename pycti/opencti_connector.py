# coding: utf-8

import pika
import logging
import json
import base64
from stix2validator import validate_string

EXCHANGE_NAME = 'amqp.opencti'


class OpenCTIConnector:
    """
        Python API for OpenCTI connector
        :param identifier: Connector identifier
        :param config: Connector configuration
        :param rabbitmq_hostname: RabbitMQ hostname
        :param rabbitmq_port: RabbitMQ hostname
        :param rabbitmq_username: RabbitMQ hostname
        :param rabbitmq_password: RabbitMQ password
    """

    def __init__(self, identifier, config, rabbitmq_hostname, rabbitmq_port, rabbitmq_username, rabbitmq_password):
        # Initialize configuration
        self.connection = None
        self.identifier = identifier
        self.config = config
        self.rabbitmq_hostname = rabbitmq_hostname
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_username = rabbitmq_username
        self.rabbitmq_password = rabbitmq_password
        self.queue_name = 'import-connectors-' + self.identifier
        self.routing_key = 'import.connectors.' + self.identifier

        # Encode the configuration
        config_encoded = base64.b64encode(json.dumps(self.config).encode('utf-8')).decode('utf-8')

        # Declare the queue for the connector
        channel = self._connect()
        channel.queue_delete(self.queue_name)
        channel.queue_declare(self.queue_name, durable=True, arguments={'config': config_encoded})
        channel.queue_bind(queue=self.queue_name, exchange=EXCHANGE_NAME, routing_key=self.routing_key)
        channel.close()
        self._disconnect()

    def _connect(self):
        try:
            credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)
            parameters = pika.ConnectionParameters(self.rabbitmq_hostname, self.rabbitmq_port, '/', credentials)
            self.connection = pika.BlockingConnection(parameters)
            channel = self.connection.channel()
            channel.exchange_declare(exchange=EXCHANGE_NAME, exchange_type='direct', durable=True)
            return channel
        except:
            logging.error('Unable to connect to RabbitMQ with the given parameters')

    def _disconnect(self):
        if self.connection is not None and not self.connection.is_closed:
            self.connection.close()

    def send_stix2_bundle(self, bundle):
        """
            This method send a STIX2 bundle to RabbitMQ to be consumed by workers
            :param bundle: A valid STIX2 bundle
        """
        logging.info('Sending a STI2 bundle to RabbitMQ...')

        # Validate the STIX 2 bundle
        validation = validate_string(bundle)
        if not validation.is_valid:
            raise ValueError('The bundle is not a valid STIX2 JSON')

        # Prepare the message
        message = {
            'type': 'stix2-bundle',
            'content': base64.b64encode(bundle.encode('utf-8')).decode('utf-8')
        }

        # Send the message
        channel = self._connect()
        channel.basic_publish(EXCHANGE_NAME, self.routing_key, json.dumps(message))
        channel.close()
        self._disconnect()
        logging.info('STIX2 bundle has been sent')
