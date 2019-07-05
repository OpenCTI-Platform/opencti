# coding: utf-8

import os
import yaml
import pika
import json
import base64
import time
from logger import Logger
from pycti import OpenCTI


class WorkerImport:
    def __init__(self, verbose=True):
        # Initialize logger
        self.logger = Logger(os.path.dirname(os.path.abspath(__file__)) + '/logs/worker.log')

        # Load configuration
        self.config = yaml.load(open(os.path.dirname(os.path.abspath(__file__)) + '/config.yml'))

        # Initialize OpenCTI client
        self.opencti = OpenCTI(
            self.config['opencti']['api_url'],
            self.config['opencti']['api_key'],
            os.path.dirname(os.path.abspath(__file__)) + '/logs/worker.log',
            self.config['opencti']['verbose']
        )

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
            data = json.loads(body)
            self.logger.log('Receiving new action of type: { ' + data['type'] + ' }')
            if data['type'] == 'import.stix2.bundle':
                self.opencti.stix2_import_bundle(base64.b64decode(data['content']).decode('utf-8'))
        except Exception as e:
            self.logger.log('An unexpected error occurred: { ' + str(e) + ' }')
            return False

    def consume(self):
        self.channel.basic_consume(queue='opencti-import', on_message_callback=self.import_action, auto_ack=True)
        self.channel.start_consuming()


if __name__ == '__main__':
    while True:
        try:
            worker_import = WorkerImport()
            worker_import.consume()
        except Exception as e:
            print(e)
            time.sleep(5)
