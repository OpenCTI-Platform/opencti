import datetime
import threading
import pika
import logging
import json
import time
import base64
import uuid
import os

from typing import Callable, Dict, List
from pika.exceptions import UnroutableError, NackError
from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.connector.opencti_connector import OpenCTIConnector


class ListenQueue(threading.Thread):
    def __init__(self, helper, config, callback):
        threading.Thread.__init__(self)
        self.pika_connection = None
        self.channel = None
        self.helper = helper
        self.callback = callback
        self.uri = config['uri']
        self.queue_name = config['listen']

    # noinspection PyUnusedLocal
    def _process_message(self, channel, method, properties, body):
        json_data = json.loads(body)
        thread = threading.Thread(target=self._data_handler, args=[json_data])
        thread.start()
        while thread.is_alive():  # Loop while the thread is processing
            self.pika_connection.sleep(1.0)
        logging.info('Message (delivery_tag=' + str(method.delivery_tag) + ') processed, thread terminated')
        channel.basic_ack(delivery_tag=method.delivery_tag)

    def _data_handler(self, json_data):
        job_id = json_data['job_id'] if 'job_id' in json_data else None
        try:
            work_id = json_data['work_id']
            self.helper.current_work_id = work_id
            self.helper.api.job.update_job(job_id, 'progress', ['Starting process'])
            messages = self.callback(json_data)
            self.helper.api.job.update_job(job_id, 'complete', messages)
        except Exception as e:
            logging.exception('Error in message processing, reporting error to API')
            try:
                self.helper.api.job.update_job(job_id, 'error', [str(e)])
            except:
                logging.error('Failing reporting the processing')

    def run(self):
        while True:
            try:
                # Connect the broker
                self.pika_connection = pika.BlockingConnection(pika.URLParameters(self.uri))
                self.channel = self.pika_connection.channel()
                self.channel.basic_consume(queue=self.queue_name, on_message_callback=self._process_message)
                self.channel.start_consuming()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info('Connector stop')
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(10)


class PingAlive(threading.Thread):
    def __init__(self, connector_id, api, get_state):
        threading.Thread.__init__(self)
        self.connector_id = connector_id
        self.in_error = False
        self.api = api
        self.get_state = get_state

    def ping(self):
        while True:
            try:
                self.api.connector.ping(self.connector_id, self.get_state())
                if self.in_error:
                    self.in_error = False
                    logging.info('API Ping back to normal')
            except Exception:
                self.in_error = True
                logging.info('Error pinging the API')
            time.sleep(40)

    def run(self):
        logging.info('Starting ping alive thread')
        self.ping()


class OpenCTIConnectorHelper:
    """
        Python API for OpenCTI connector
        :param config: Dict standard config
    """
    def __init__(self, config: dict):
        # Load API config
        self.opencti_url = os.getenv('OPENCTI_URL') or config['opencti']['url']
        self.opencti_token = os.getenv('OPENCTI_TOKEN') or config['opencti']['token']
        # Load connector config
        self.connect_id = os.getenv('CONNECTOR_ID') or config['connector']['id']
        self.connect_type = os.getenv('CONNECTOR_TYPE') or config['connector']['type']
        self.connect_name = os.getenv('CONNECTOR_NAME') or config['connector']['name']
        self.connect_confidence_level = os.getenv('CONNECTOR_CONFIDENCE_LEVEL') or \
                                        config['connector']['confidence_level']
        self.connect_scope = os.getenv('CONNECTOR_SCOPE') or config['connector']['scope']
        self.log_level = os.getenv('CONNECTOR_LOG_LEVEL') or config['connector']['log_level']

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + self.log_level)
        logging.basicConfig(level=numeric_level)

        # Initialize configuration
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_token, self.log_level)
        self.current_work_id = None

        # Register the connector in OpenCTI
        self.connector = OpenCTIConnector(self.connect_id, self.connect_name, self.connect_type, self.connect_scope)
        connector_configuration = self.api.connector.register(self.connector)
        self.connector_id = connector_configuration['id']
        self.connector_state = connector_configuration['connector_state']
        self.config = connector_configuration['config']

        # Start ping thread
        self.ping = PingAlive(self.connector.id, self.api, self.get_state)
        self.ping.start()

        # Initialize caching
        self.cache_index = {}
        self.cache_added = []

    def set_state(self, state) -> None:
        self.connector_state = json.dumps(state)

    def get_state(self):
        return None if self.connector_state is None else json.loads(self.connector_state)

    def listen(self, message_callback: Callable[[Dict], List[str]]) -> None:
        listen_queue = ListenQueue(self, self.config, message_callback)
        listen_queue.start()

    def get_connector(self):
        return self.connector

    def log_error(self, msg):
        logging.error(msg)

    def log_info(self, msg):
        logging.info(msg)

    def date_now(self):
        return datetime.datetime.utcnow().replace(microsecond=0, tzinfo=datetime.timezone.utc).isoformat()

    # Push Stix2 helper
    def send_stix2_bundle(self, bundle, entities_types=None):
        if entities_types is None:
            entities_types = []
        bundles = self.split_stix2_bundle(bundle)
        if len(bundles) == 0:
            raise ValueError('Nothing to import')
        pika_connection = pika.BlockingConnection(pika.URLParameters(self.config['uri']))
        channel = pika_connection.channel()
        for bundle in bundles:
            self._send_bundle(channel, bundle, entities_types)
        channel.close()
        return bundles

    def _send_bundle(self, channel, bundle, entities_types=None):
        """
            This method send a STIX2 bundle to RabbitMQ to be consumed by workers
            :param bundle: A valid STIX2 bundle
            :param entities_types: Entities types to ingest
        """
        if entities_types is None:
            entities_types = []

        # Create a job log expectation
        if self.current_work_id is not None:
            job_id = self.api.job.initiate_job(self.current_work_id)
        else:
            job_id = None

        # Validate the STIX 2 bundle
        # validation = validate_string(bundle)
        # if not validation.is_valid:
        # raise ValueError('The bundle is not a valid STIX2 JSON')

        # Prepare the message
        # if self.current_work_id is None:
        #    raise ValueError('The job id must be specified')
        message = {
            'job_id': job_id,
            'entities_types': entities_types,
            'content': base64.b64encode(bundle.encode('utf-8')).decode('utf-8')
        }

        # Send the message
        try:
            routing_key = 'push_routing_' + self.connector_id
            channel.basic_publish(self.config['push_exchange'], routing_key, json.dumps(message))
            logging.info('Bundle has been sent')
        except (UnroutableError, NackError) as e:
            logging.error('Unable to send bundle, retry...', e)
            self._send_bundle(bundle, entities_types)

    def split_stix2_bundle(self, bundle):
        self.cache_index = {}
        self.cache_added = []
        try:
            bundle_data = json.loads(bundle)
        except:
            raise Exception('File data is not a valid JSON')

        # validation = validate_parsed_json(bundle_data)
        # if not validation.is_valid:
        #     raise ValueError('The bundle is not a valid STIX2 JSON:' + bundle)

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

        # Get target ref
        if relationship['target_ref'] in self.cache_index:
            items.append(self.cache_index[relationship['target_ref']])

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

    @staticmethod
    def stix2_deduplicate_objects(items):
        ids = []
        final_items = []
        for item in items:
            if item['id'] not in ids:
                final_items.append(item)
                ids.append(item['id'])
        return final_items

    @staticmethod
    def stix2_create_bundle(items):
        bundle = {
            'type': 'bundle',
            'id': 'bundle--' + str(uuid.uuid4()),
            'spec_version': '2.0',
            'objects': items
        }
        return json.dumps(bundle)
