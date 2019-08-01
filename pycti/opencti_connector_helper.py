# coding: utf-8

import pika
import logging
import json
import base64
import uuid
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
        self.channel = None
        self.identifier = identifier
        self.config = connector_config
        self.rabbitmq_hostname = rabbitmq_config['hostname']
        self.rabbitmq_port = rabbitmq_config['port']
        self.rabbitmq_username = rabbitmq_config['username']
        self.rabbitmq_password = rabbitmq_config['password']
        self.queue_name = 'import-connectors-' + self.identifier
        self.routing_key = 'import.connectors.' + self.identifier

        # Connect to RabbitMQ
        self.connection = self._connect()
        self.channel = self._create_channel()
        self._create_queue()
        logging.info('Successfully connected to RabbitMQ')

        # Initialize caching
        self.cache_index = {}
        self.cache_added = []

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

    def _create_queue(self):
        if self.channel is not None:
            config_encoded = base64.b64encode(json.dumps(self.config).encode('utf-8')).decode('utf-8')
            check = self.channel.queue_declare(self.queue_name, durable=True, passive=True, arguments={'config': config_encoded})
            if not check:
                self.channel.queue_delete(self.queue_name)
                self.channel.queue_declare(self.queue_name, durable=True, arguments={'config': config_encoded})
            self.channel.queue_bind(queue=self.queue_name, exchange=EXCHANGE_NAME, routing_key=self.routing_key)

    def _reconnect(self):
        self.connection = self._connect()
        self.channel = self._create_channel()

    def send_stix2_bundle(self, bundle, entities_types=[]):
        bundles = self.split_stix2_bundle(bundle)
        for bundle in bundles:
            self._send_bundle('stix2-bundle', bundle, entities_types)

    def _send_bundle(self, type, bundle, entities_types=[]):
        """
            This method send a STIX2 bundle to RabbitMQ to be consumed by workers
            :param bundle: A valid STIX2 bundle
            :param entities_types: Entities types to ingest
        """
        if self.channel is None or not self.channel.is_open:
            self._reconnect()

        # Validate the STIX 2 bundle
        # validation = validate_string(bundle)
        # if not validation.is_valid:
        # raise ValueError('The bundle is not a valid STIX2 JSON:' + bundle)

        # Prepare the message
        message = {
            'type': type,
            'entities_types': entities_types,
            'content': base64.b64encode(bundle.encode('utf-8')).decode('utf-8')
        }

        # Send the message
        try:
            self.channel.basic_publish(EXCHANGE_NAME, self.routing_key, json.dumps(message))
            logging.info('Bundle has been sent')
        except:
            logging.error('Unable to send bundle, reconnecting and resending...')
            self._reconnect()
            self.channel.basic_publish(EXCHANGE_NAME, self.routing_key, json.dumps(message))

    def split_stix2_bundle(self, bundle):
        self.cache_index = {}
        self.cache_added = []
        bundle_data = json.loads(bundle)

        # Index all objects by id
        for item in bundle_data['objects']:
            self.cache_index[item['id']] = item

        bundles = []
        # Reports must be handled because of object_refs
        for item in bundle_data['objects']:
            if item['type'] == 'report':
                items_to_send = self.stix2_deduplicate_objects(self.stix2_get_report_objects(item))
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send['id'])
                bundles.append(self.stix2_create_bundle(items_to_send))

        # Relationships not added in previous reports
        for item in bundle_data['objects']:
            if item['type'] == 'relationship' and item['id'] not in self.cache_added:
                items_to_send = self.stix2_deduplicate_objects(self.stix2_get_relationship_objects(item))
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send['id'])
                bundles.append(self.stix2_create_bundle(items_to_send))

        # Entities not added in previous reports and relationships
        for item in bundle_data['objects']:
            if item['type'] != 'relationship' and item['id'] not in self.cache_added:
                items_to_send = self.stix2_deduplicate_objects(self.stix2_get_entity_objects(item))
                for item_to_send in items_to_send:
                    self.cache_added.append(item_to_send['id'])
                bundles.append(self.stix2_create_bundle(items_to_send))

        return bundles

    def stix2_create_bundle(self, items):
        bundle = {
            'type': 'bundle',
            'id': 'bundle--' + str(uuid.uuid4()),
            'spec_version': '2.0',
            'objects': items
        }
        return json.dumps(bundle)

    def stix2_get_embedded_objects(self, item):
        # Marking definitions
        object_marking_refs = []
        if 'object_marking_refs' in item:
            for object_marking_ref in item['object_marking_refs']:
                if object_marking_ref in self.cache_index:
                    object_marking_refs.append(self.cache_index[object_marking_ref])
        # Created by ref
        created_by_ref = None
        if 'created_by_ref' in item and item['created_by_ref'] in self.cache_index:
            created_by_ref = self.cache_index[item['created_by_ref']]

        return {'object_marking_refs': object_marking_refs, 'created_by_ref': created_by_ref}

    def stix2_get_entity_objects(self, entity):
        items = [entity]
        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(entity)
        # Add created by ref
        if embedded_objects['created_by_ref'] is not None:
            items.append(embedded_objects['created_by_ref'])
        # Add marking definitions
        if len(embedded_objects['object_marking_refs']) > 0:
            items = items + embedded_objects['object_marking_refs']

        return items

    def stix2_get_relationship_objects(self, relationship):
        items = [relationship]
        # Get source ref
        if relationship['source_ref'] in self.cache_index:
            items.append(self.cache_index[relationship['source_ref']])
        else:
            return []

        # Get target ref
        if relationship['target_ref'] in self.cache_index:
            items.append(self.cache_index[relationship['target_ref']])
        else:
            return []

        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(relationship)
        # Add created by ref
        if embedded_objects['created_by_ref'] is not None:
            items.append(embedded_objects['created_by_ref'])
        # Add marking definitions
        if len(embedded_objects['object_marking_refs']) > 0:
            items = items + embedded_objects['object_marking_refs']

        return items

    def stix2_get_report_objects(self, report):
        items = [report]
        # Add all object refs
        for object_ref in report['object_refs']:
            items.append(self.cache_index[object_ref])
        for item in items:
            if item['type'] == 'relationship':
                items = items + self.stix2_get_relationship_objects(item)
            else:
                items = items + self.stix2_get_entity_objects(item)
        return items

    def stix2_deduplicate_objects(self, items):
        ids = []
        final_items = []
        for item in items:
            if item['id'] not in ids:
                final_items.append(item)
                ids.append(item['id'])
        return final_items
