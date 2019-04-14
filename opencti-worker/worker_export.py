# coding: utf-8

import os
import yaml
import pika
import json
import base64

from pycti import OpenCTI


class WorkerExport:
    def __init__(self, verbose=True):
        # Load configuration
        self.config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'), Loader=yaml.FullLoader)

        # Initialize OpenCTI client
        self.opencti = OpenCTI(self.config['opencti']['api_url'], self.config['opencti']['api_key'],
                               self.config['opencti']['verbose'])

        # Initialize the RabbitMQ connection
        credentials = pika.PlainCredentials(self.config['rabbitmq']['username'], self.config['rabbitmq']['password'])
        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=self.config['rabbitmq']['hostname'],
            port=self.config['rabbitmq']['port'],
            virtual_host='/',
            credentials=credentials
        ))
        self.channel = connection.channel()
        self.channel.exchange_declare(exchange='opencti', exchange_type='topic', durable=True)
        self.channel.queue_declare('opencti-export', durable=True)
        self.channel.queue_bind(exchange='opencti', queue='opencti-export', routing_key='export.*.*')

    def export_action(self, ch, method, properties, body):
        try:
            print('Receiving new action...')
            data = json.loads(body)
            bundle = None
            if data['type'] == 'export.stix2.simple':
                bundle = self.opencti.stix2_export_entity(data['entity_type'], data['entity_id'], 'simple')
            if data["type"] == 'export.stix2.full':
                bundle = self.opencti.stix2_export_entity(data['entity_type'], data['entity_id'], 'full')

            if bundle is not None:
                bundle = base64.b64encode(bytes(json.dumps(bundle, indent=4), 'utf-8')).decode('utf-8')
                self.opencti.push_stix_domain_entity_export(data['entity_id'], data['export_id'], bundle)
        except Exception as e:
            print(e)
            return False

    def consume(self):
        self.channel.basic_consume(queue='opencti-export', on_message_callback=self.export_action, auto_ack=True)
        self.channel.start_consuming()


if __name__ == '__main__':
    worker_export = WorkerExport()
    worker_export.consume()
