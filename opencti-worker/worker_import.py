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
        self.config = yaml.load(open(os.path.dirname(os.path.abspath(__file__)) + '/config.yml'), Loader=yaml.FullLoader)

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
        self.channel.queue_declare('opencti-import', durable=True)
        self.channel.queue_bind(exchange='opencti', queue='opencti-import', routing_key='import.*.*')

    def import_action(self, ch, method, properties, body):
        try:
            print('Receiving new action...')
            data = json.loads(body)
            if data['type'] == 'import.stix2.bundle':
                self.opencti.stix2_import_bundle(base64.b64decode(data['content']).decode('utf-8'))
        except:
            return False

    def consume(self):
        self.channel.basic_consume(queue='opencti-import', on_message_callback=self.import_action, auto_ack=True)
        self.channel.start_consuming()


if __name__ == '__main__':
    worker_export = WorkerExport()
    worker_export.consume()
