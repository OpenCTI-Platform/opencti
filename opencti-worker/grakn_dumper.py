# coding: utf-8

import os
import yaml

from grakn.client import GraknClient

multiple_attributes = ['stix_label', 'alias', 'grant', 'platform', 'required_permission']


class GraknDumper:
    def __init__(self):
        # Load configuration
        self.config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

        # Initialize Grakn client
        self.grakn = GraknClient(uri=self.config['grakn']['hostname'] + ':' + str(self.config['grakn']['port']))
        self.session = self.grakn.session(keyspace='grakn')

        # Open the dump file
        self.dump_file = open(self.config['dumper']['file'], 'w')

        # Entities
        self.entities = {}

        # Relations
        self.relations = {}

    def get_attributes(self, entity):
        attributes = {}
        attributes_iterator = entity.attributes()
        for attribute in attributes_iterator:
            attribute_type = attribute.type()
            if str(attribute_type.data_type()) == 'DataType.STRING':
                attribute_value = '"' + attribute.value() + '"'
            elif str(attribute_type.data_type()) == 'DataType.DATE':
                attribute_value = attribute.value().strftime('%Y-%m-%dT%H:%M:%S')
            elif str(attribute_type.data_type()) == 'DataType.BOOLEAN':
                attribute_value = 'true' if attribute.value() else 'false'
            else:
                attribute_value = attribute.value()
            if attribute_type.label() in multiple_attributes:
                if attribute_type.label() not in attributes:
                    attributes[attribute_type.label()] = [attribute_value]
                else:
                    attributes[attribute_type.label()].append(attribute_value)
            else:
                attributes[attribute_type.label()] = attribute_value
        return attributes

    def dump_entities(self):
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x isa entity; get;')
        for answer in iterator:
            entity = answer.map().get('x')
            entity_id = entity.id
            entity_type = entity.type().label()
            entity_attributes = self.get_attributes(entity)
            entity_dump = 'insert $' + entity_id + ' isa ' + entity_type + '\n'
            for key, value in entity_attributes.items():
                if isinstance(value, list):
                    for val in value:
                        entity_dump += '    ,has ' + key + ' ' + str(val) + '\n'
                else:
                    entity_dump += '    ,has ' + key + ' ' + str(value) + '\n'
            entity_dump += ';\n\n'
            self.entities[entity_id] = entity_attributes['internal_id']
            self.dump_file.write(entity_dump)
        rtx.close()

    def dump_relations(self):
        relations_ids = []
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x($roleFrom: $from, $roleTo: $to); $from isa entity; $to isa entity; get;', infer=False)
        for answer in iterator:
            relation = answer.map().get('x')
            relation_id = relation.id
            relation_type = relation.type().label()
            relation_from_role = answer.map().get('roleFrom').label()
            relation_from = answer.map().get('from')
            relation_to_role = answer.map().get('roleTo').label()
            relation_to = answer.map().get('to')
            if relation_id not in relations_ids:
                relation_attributes = self.get_attributes(relation)
                if relation_from.id in self.entities:
                    relation_from_id = self.entities[relation_from.id]
                else:
                    relation_from_attributes = self.get_attributes(relation_from)
                    relation_from_id = relation_from_attributes['internal_id']
                if relation_to.id in self.entities:
                    relation_to_id = self.entities[relation_to.id]
                else:
                    relation_to_attributes = self.get_attributes(relation_to)
                    relation_to_id = relation_to_attributes['internal_id']

                relation_dump = 'match $from has internal_id "' + relation_from_id + '"; $to has internal_id "' + relation_to_id + '"; insert $' + relation_id + '(' + relation_from_role + ': $from, ' + relation_to_role + ': $to) isa ' + relation_type + '\n'
                for key, value in relation_attributes.items():
                    if isinstance(value, list):
                        for val in value:
                            relation_dump += '    ,has ' + key + ' ' + str(val) + '\n'
                    else:
                        relation_dump += '    ,has ' + key + ' ' + str(value) + '\n'
                relation_dump += ';\n\n'
                relations_ids.append(relation_id)
                self.relations[relation_id] = relation_attributes['internal_id']
                self.dump_file.write(relation_dump)

    def dump_relations_with_relations(self):
        relations_ids = []
        rtx = self.session.transaction().read()
        iterator = rtx.query('match $x($roleFrom: $from, $roleTo: $to); $from isa entity; $to isa relation; get;', infer=False)
        for answer in iterator:
            relation = answer.map().get('x')
            relation_id = relation.id
            relation_type = relation.type().label()
            relation_from_role = answer.map().get('roleFrom').label()
            relation_from = answer.map().get('from')
            relation_to_role = answer.map().get('roleTo').label()
            relation_to = answer.map().get('to')
            if relation_id not in relations_ids:
                relation_attributes = self.get_attributes(relation)
                if relation_from.id in self.entities:
                    relation_from_id = self.entities[relation_from.id]
                else:
                    relation_from_attributes = self.get_attributes(relation_from)
                    relation_from_id = relation_from_attributes['internal_id']
                if relation_to.id in self.relations:
                    relation_to_id = self.relations[relation_to.id]
                else:
                    relation_to_attributes = self.get_attributes(relation_to)
                    relation_to_id = relation_to_attributes['internal_id']

                relation_dump = 'match $from has internal_id "' + relation_from_id + '"; $to has internal_id "' + relation_to_id + '"; insert $' + relation_id + '(' + relation_from_role + ': $from, ' + relation_to_role + ': $to) isa ' + relation_type + '\n'
                for key, value in relation_attributes.items():
                    if isinstance(value, list):
                        for val in value:
                            relation_dump += '    ,has ' + key + ' ' + str(val) + '\n'
                    else:
                        relation_dump += '    ,has ' + key + ' ' + str(value) + '\n'
                relation_dump += ';\n\n'
                relations_ids.append(relation_id)
                self.dump_file.write(relation_dump)

    def dump(self):
        print('Dumping...')
        self.dump_entities()
        self.dump_relations()
        self.dump_relations_with_relations()
        self.dump_file.close()
        print('Dump done.')


if __name__ == '__main__':
    dumper = GraknDumper()
    dumper.dump()
