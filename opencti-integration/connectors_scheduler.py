# coding: utf-8

import os
import yaml
import json
import base64
import importlib
import time
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

    def init_connectors(self):
        self.logger.log('Configuring connectors')
        connectors = self.opencti.get_connectors()
        for connector in connectors:
            if connector['config'] is not None:
                connector_config = json.loads(base64.b64decode(connector['config']))
                config = self.config
                config[connector['identifier']] = connector_config

                if connector['identifier'] not in self.connectors:
                    connector_module = importlib.import_module('connectors.' + connector['identifier'] + '.' + connector['identifier'])
                    connector_class = getattr(connector_module, connector['identifier'].capitalize())
                    self.connectors[connector['identifier']] = {"config": config, "instance": connector_class(config)}
                    self.logger.log('Connector ' + connector['identifier'] + ' initialized')
                else:
                    self.connectors[connector['identifier']]['instance'].set_config(config)
                    self.connectors[connector['identifier']]['config'] = config
                    self.logger.log('Connector ' + connector['identifier'] + ' configured')

                if 'triggered' in connector_config and connector_config['triggered'] is True:
                    connector_config['triggered'] = False
                    self.opencti.update_connector_config(connector['identifier'], connector_config)
                    self.run_connector(connector['identifier'])

    def run_connector(self, identifier):
        try:
            if 'active' in self.connectors[identifier]['config'][identifier] and self.connectors[identifier]['config'][identifier]['active'] is True:
                self.logger.log('Running ' + identifier)
                self.connectors[identifier]['instance'].run()
        except Exception as e:
            self.logger.log('Unable to run ' + identifier + ': {' + str(e) + '}')

    def run_connectors(self):
        self.logger.log('Starting connectors')
        schedule.every(1).minutes.do(self.init_connectors)
        for identifier, connector in self.connectors.items():
            connector_config = connector['instance'].get_config()
            if connector_config['cron'] == 'realtime':
                schedule.every(1).minutes.do(self.run_connector, identifier=identifier)
            elif connector_config['cron'] == 'daily':
                schedule.every().day.at("02:30").do(self.run_connector, identifier=identifier)
        while True:
            schedule.run_pending()
            time.sleep(1)

    def init(self):
        self.init_connectors()
        self.run_connectors()


if __name__ == '__main__':
    while True:
        try:
            connectors_scheduler = ConnectorsScheduler()
            connectors_scheduler.init()
        except Exception as e:
            print(e)
            time.sleep(5)
