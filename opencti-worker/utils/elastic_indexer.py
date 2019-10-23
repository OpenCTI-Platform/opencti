# coding: utf-8

from grakn.client import GraknClient
from elasticsearch import Elasticsearch

multiple_attributes = ['stix_label', 'alias', 'grant', 'platform', 'required_permission']


class ElasticIndexer:
    def __init__(self):
        # Initialize Grakn client
        self.grakn = GraknClient(uri='localhost:48555')
        self.session = self.grakn.session(keyspace='grakn')

        # Initialize ElasticSearch client
        self.elasticsearch = Elasticsearch([{'host': 'localhost', 'port': 9200}], timeout=30)

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
                index='stix_domain_entities',
                id=entity_data['id'],
                body=entity_data,
            )

    def index_stix_observables(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa Stix-Observable; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_data = self.get_attributes(entity)
            self.elasticsearch.index(
                index='stix_observables',
                id=entity_data['id'],
                body=entity_data,
            )

    def index_external_references(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa External-Reference; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_data = self.get_attributes(entity)
            self.elasticsearch.index(
                index='external_references',
                id=entity_data['id'],
                body=entity_data,
            )

    def index_relations(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa stix_relation; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_data = self.get_attributes(entity)
            self.elasticsearch.index(
                index='stix_relations',
                id=entity_data['id'],
                body=entity_data,
            )

    def index(self):
        print('Indexing...')
        print('Observables...')
        self.index_stix_observables()
        print('Entities...')
        self.index_stix_domain_entities()
        print('External references...')
        self.index_external_references()
        print('Relations...')
        self.index_relations()
        print('Index done.')


if __name__ == '__main__':
    indexer = ElasticIndexer()
    indexer.index()
