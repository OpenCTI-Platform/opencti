# coding: utf-8

import os
import time
import yaml
import datetime

config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

from grakn.client import GraknClient
from elasticsearch import Elasticsearch

multiple_attributes = ['alias']


class Indexor:
    def __init__(self, verbose=True):
        # Load configuration
        self.config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

        # Initialize Grakn client
        self.grakn = GraknClient(uri=self.config['grakn']['hostname'] + ':' + str(self.config['grakn']['port']))
        self.session = self.grakn.session(keyspace='grakn')

        # Initialize ElasticSearch client
        self.elasticsearch = Elasticsearch(
            [{'host': self.config['elasticsearch']['hostname'], 'port': self.config['elasticsearch']['port']}])

    def get_attributes(self, entity):
        attributes = {'id': entity.id}
        attributes_iterator = entity.attributes()
        for attribute in attributes_iterator:
            attribute_type = attribute.type()
            if attribute_type.label() in multiple_attributes:
                if attribute_type.label() not in attributes:
                    attributes[attribute_type.label()] = [attribute.value().replace('\\"', '"')]
                else:
                    attributes[attribute_type.label()].append(attribute.value().replace('\\"', '"'))
            else:
                if str(attribute_type.data_type()) == 'DataType.DATE':
                    attributes[attribute_type.label()] = attribute.value().strftime('%Y-%m-%dT%H:%M:%SZ')
                elif str(attribute_type.data_type()) == 'DataType.STRING':
                    attributes[attribute_type.label()] = attribute.value().replace('\\"', '"')
                else:
                    attributes[attribute_type.label()] = attribute.value()
        return attributes

    def index_stix_domain_entities(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa Stix-Domain-Entity; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_data = self.get_attributes(entity)
            self.elasticsearch.index(
                index='stix-domain-entities',
                id=entity_data['id'],
                doc_type='stix_domain_entity',
                body=entity_data,
            )

    def index_stix_observables(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa Stix-Observable; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_data = self.get_attributes(entity)
            self.elasticsearch.index(
                index='stix-observables',
                id=entity_data['id'],
                doc_type='stix_observable',
                body=entity_data,
            )

    def index_external_references(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa External-Reference; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_data = self.get_attributes(entity)
            self.elasticsearch.index(
                index='external-references',
                id=entity_data['id'],
                doc_type='external_reference',
                body=entity_data,
            )

    def loop(self):
        while True:
            print('Starting indexing...')
            self.index_stix_observables()
            self.index_stix_domain_entities()
            self.index_external_references()
            print('Index done.')
            time.sleep(self.config['indexor']['interval'])


if __name__ == '__main__':
    indexor = Indexor()
    indexor.loop()
