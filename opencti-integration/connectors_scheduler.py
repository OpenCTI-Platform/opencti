# coding: utf-8

import os
import yaml
import json
import base64
import importlib
import time
import pika
import schedule
from logger import Logger
from pycti import OpenCTI


class ConnectorsScheduler:
    def __init__(self, verbose=True):

        # Initialize connectors object
        self.connectors = {}

        # Initialize logger
        self.logger = Logger(os.path.dirname(os.path.abspath(__file__)) + '/scheduler.log')

        # Load configuration
        self.config = yaml.load(open(os.path.dirname(os.path.abspath(__file__)) + '/config.yml'))

        # Initialize OpenCTI client
        self.opencti = OpenCTI(
            self.config['opencti']['api_url'],
            self.config['opencti']['api_key'],
            os.path.dirname(os.path.abspath(__file__)) + '/scheduler.log',
            self.config['opencti']['verbose']
        )

    def send_stix2_bundle(self, bundle):
        self.logger.log('Sending a message to the import workers')
        # Prepare
        message = {
            'type': 'import.stix2.bundle',
            'content': base64.b64encode(bundle.encode('utf-8')).decode('utf-8')
        }

        # Initialize the RabbitMQ connection
        credentials = pika.PlainCredentials(self.config['rabbitmq']['username'], self.config['rabbitmq']['password'])
        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=self.config['rabbitmq']['hostname'],
            port=self.config['rabbitmq']['port'],
            virtual_host='/',
            credentials=credentials
        ))
        channel = connection.channel()
        channel.exchange_declare(exchange='opencti', exchange_type='topic', durable=True)
        channel.basic_publish('opencti', 'import.stix2.bundle', json.dumps(message))
        connection.close()

    def init_connectors(self):
        self.logger.log('Configuring connectors')
        connectors = self.opencti.get_connectors()
        for connector in connectors:
            try:
                if connector['config'] is not None:
                    connector_config = json.loads(base64.b64decode(connector['config']))
                    config = self.config

                    # First time, load code, create instance
                    if connector['identifier'] not in self.connectors:
                        config[connector['identifier']] = connector_config
                        connector_module = importlib.import_module('connectors.' + connector['identifier'] + '.' + connector['identifier'])
                        connector_class = getattr(connector_module, connector['identifier'].capitalize())
                        self.connectors[connector['identifier']] = {"config": config, "instance": connector_class(config, self)}
                        self.logger.log('Connector ' + connector['identifier'] + ' initialized')
                        self.schedule_connectors()
                    # Code is already there, just reconfigure
                    else:
                        # If cron changed, reschedule
                        current_config = self.connectors[connector['identifier']]['instance'].get_config()
                        if connector_config['cron'] != current_config['cron']:
                            self.logger.log('Connector ' + connector['identifier'] + ' has to be rescheduled')
                            self.schedule_connectors()

                        # Reconfigure
                        config[connector['identifier']] = connector_config
                        self.connectors[connector['identifier']]['instance'].set_config(config)
                        self.connectors[connector['identifier']]['config'] = config
                        self.logger.log('Connector ' + connector['identifier'] + ' configured')

                    # Manual trigger of the connector
                    if 'triggered' in connector_config and connector_config['triggered'] is True:
                        connector_config['triggered'] = False
                        self.opencti.update_connector_config(connector['identifier'], connector_config)
                        self.run_connector(connector['identifier'])
            except Exception as e:
                self.logger.log('Unable to initialize ' + connector['identifier'] + ': {' + str(e) + '}')

    def run_connector(self, identifier):
        try:
            if 'active' in self.connectors[identifier]['config'][identifier] and self.connectors[identifier]['config'][identifier]['active'] is True:
                self.logger.log('Running ' + identifier)
                self.connectors[identifier]['instance'].run()
        except Exception as e:
            self.logger.log('Unable to run ' + identifier + ': {' + str(e) + '}')

    def schedule_connectors(self):
        schedule.clear()
        self.logger.log('Scheduling connectors')
        schedule.every(1).minutes.do(self.init_connectors)
        for identifier, connector in self.connectors.items():
            connector_config = connector['instance'].get_config()
            if connector_config['cron'] == 'realtime':
                schedule.every(1).minutes.do(self.run_connector, identifier=identifier)
            elif connector_config['cron'] == 'hourly':
                schedule.every(1).hours.do(self.run_connector, identifier=identifier)
            elif connector_config['cron'] == 'daily':
                schedule.every().day.at("02:30").do(self.run_connector, identifier=identifier)
            elif connector_config['cron'] == 'weekly':
                schedule.every().wednesday.at("04:30").do(self.run_connector, identifier=identifier)
            elif connector_config['cron'] == 'monthly':
                schedule.every(30).day.at("04:30").do(self.run_connector, identifier=identifier)

    def run(self):
        while True:
            schedule.run_pending()
            time.sleep(1)

    def init(self):
        self.init_connectors()
        self.schedule_connectors()
        self.run()


if __name__ == '__main__':
    while True:
        try:
            connectors_scheduler = ConnectorsScheduler()
            connectors_scheduler.init()
        except Exception as e:
            print(e)
            time.sleep(5)
