import logging
import os
import sys
import pika
import json
import uuid

from elasticsearch import Elasticsearch
from pycti.api.opencti_api_client import OpenCTIApiClient


class TestLocalWorker:

    def __init__(self, api_url, api_token):
        self.api_url = api_url
        self.api_token = api_token
        self.opencti_api_client = OpenCTIApiClient(self.api_url, self.api_token)
        self.logger_config = self.opencti_api_client.get_logs_worker_config()
        self.queue_name = "logs_all"
        self.pika_connection = pika.BlockingConnection(pika.URLParameters(self.logger_config['rabbitmq_url']))
        self.channel = self.pika_connection.channel()
        self.elasticsearch = Elasticsearch([self.logger_config['elasticsearch_url']])
        self.elasticsearch_index = self.logger_config['elasticsearch_index']

    def _process_message(self, channel, method, properties, body):
        data = json.loads(body)
        data['internal_id_key'] = uuid.uuid4()
        self.elasticsearch.index(index=self.elasticsearch_index, id=data['internal_id_key'], body=data)
        channel.basic_ack(method.delivery_tag)

    def consume(self):
        while True:
            method, properties, body = self.channel.basic_get(self.queue_name)
            if method:
                self._process_message(self.channel, method, properties, body)
            else:
                break
if __name__ == '__main__':
    try:
        api_url = sys.argv[1]
        api_token = sys.argv[2]
        testLocalWorker = TestLocalWorker(api_url, api_token)
        testLocalWorker.consume()
    except Exception as e:
        logging.exception(str(e))
        exit(1)
