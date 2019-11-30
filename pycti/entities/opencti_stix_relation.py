# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class StixRelation:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            relationship_type
            description
            weight
            role_played
            first_seen
            last_seen
            created
            modified
            created_at
            updated_at
            from {
                id
                stix_id_key
                entity_type
                ...on StixDomainEntity {
                    name
                    description
                }
            }
            to {
                id
                stix_id_key
                entity_type
                ...on StixDomainEntity {
                    name
                    description
                }                
            }
            createdByRef {
                node {
                    id
                    entity_type
                    stix_id_key
                    stix_label
                    name
                    alias
                    description
                    created
                    modified
                }
                relation {
                    id
                }
            }
            markingDefinitions {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        definition_type
                        definition
                        level
                        color
                        created
                        modified
                    }
                    relation {
                       id
                    }
                }
            }
            killChainPhases {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        kill_chain_name
                        phase_name
                        phase_order
                        created
                        modified
                    }
                    relation {
                       id
                    }
                }
            }
        """

    """
        List stix_relation objects

        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationType: the relation type
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param inferred: includes inferred relations
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination        
        :return List of stix_relation objects
    """

    def list(self, **kwargs):
        from_id = kwargs.get('fromId', None)
        from_types = kwargs.get('fromTypes', None)
        to_id = kwargs.get('toId', None)
        to_types = kwargs.get('toTypes', None)
        relation_type = kwargs.get('relationType', None)
        first_seen_start = kwargs.get('firstSeenStart', None)
        first_seen_stop = kwargs.get('firstSeenStop', None)
        last_seen_start = kwargs.get('lastSeenStart', None)
        last_seen_stop = kwargs.get('lastSeenStop', None)
        inferred = kwargs.get('inferred', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing stix_relations with {from_id: ' + str(from_id) + ', to_id: ' + str(to_id) + '}')
        query = """
            query StixRelations($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $relationType: String, $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $inferred: Boolean, $first: Int, $after: ID, $orderBy: StixRelationsOrdering, $orderMode: OrderingMode) {
                stixRelations(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationType: $relationType, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, inferred: $inferred, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """ + self.properties + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }                        
                }
            }
         """
        result = self.opencti.query(query, {
            'fromId': from_id,
            'fromTypes': from_types,
            'toId': to_id,
            'toTypes': to_types,
            'relationType': relation_type,
            'firstSeenStart': first_seen_start,
            'firstSeenStop': first_seen_stop,
            'lastSeenStart': last_seen_start,
            'lastSeenStop': last_seen_stop,
            'inferred': inferred,
            'first': first,
            'after': after,
            'orderBy': order_by,
            'orderMode': order_mode
        })
        return self.opencti.process_multiple(result['data']['stixRelations'])

    """
        Read a stix_relation object
        
        :param id: the id of the stix_relation
        :param stix_id_key: the STIX id of the stix_relation
        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationType: the relation type
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param inferred: includes inferred relations
        :return stix_relation object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        stix_id_key = kwargs.get('stix_id_key', None)
        from_id = kwargs.get('fromId', None)
        to_id = kwargs.get('toId', None)
        relation_type = kwargs.get('relationType', None)
        first_seen_start = kwargs.get('firstSeenStart', None)
        first_seen_stop = kwargs.get('firstSeenStop', None)
        last_seen_start = kwargs.get('lastSeenStart', None)
        last_seen_stop = kwargs.get('lastSeenStop', None)
        inferred = kwargs.get('inferred', None)
        if id is not None:
            self.opencti.log('info', 'Reading stix_relation {' + id + '}.')
            query = """
                query StixRelation($id: String!) {
                    stixRelation(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['stixRelation'])
        elif stix_id_key is not None:
            self.opencti.log('info', 'Reading stix_relation with stix_id_key {' + stix_id_key + '}.')
            query = """
                query StixRelation($stix_id_key: String!) {
                    stixRelation(stix_id_key: $stix_id_key) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'stix_id_key': stix_id_key})
            return self.opencti.process_multiple_fields(result['data']['stixRelation'])
        else:
            result = self.list(
                fromId=from_id,
                toId=to_id,
                relationType=relation_type,
                firstSeenStart=first_seen_start,
                firstSeenStop=first_seen_stop,
                lastSeenStart=last_seen_start,
                lastSeenStop=last_seen_stop,
                inferred=inferred
            )
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Update a stix_relation object field

        :param id: the stix_relation id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated stix_relation object
    """

    def update_field(self, **kwargs):
        id = kwargs.get('id', None)
        key = kwargs.get('key', None)
        value = kwargs.get('value', None)
        if id is not None and key is not None and value is not None:
            self.opencti.log('info', 'Updating stix_relation {' + id + '} field {' + key + '}.')
            query = """
                mutation StixRelationEdit($id: ID!, $input: EditInput!) {
                    stixRelationEdit(id: $id) {
                        fieldPatch(input: $input) {
                            """ + self.properties + """
                        }
                    }
                }
            """
            result = self.opencti.query(query, {
                'id': id,
                'input': {
                    'key': key,
                    'value': value
                }
            })
            return self.opencti.process_multiple_fields(result['data']['stixRelationEdit']['fieldPatch'])
        else:
            self.opencti.log('error', 'Missing parameters: id and key and value')
            return None

    """
        Add a Kill-Chain-Phase object to stix_relation object (kill_chain_phases)

        :param id: the id of the stix_relation
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :return Boolean
    """

    def add_kill_chain_phase(self, **kwargs):
        id = kwargs.get('id', None)
        kill_chain_phase_id = kwargs.get('kill_chain_phase_id', None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.log('info',
                             'Adding Kill-Chain-Phase {' + kill_chain_phase_id + '} to Stix-Entity {' + id + '}')
            stix_entity = self.read(id=id)
            kill_chain_phases_ids = []
            for marking in stix_entity['killChainPhases']:
                kill_chain_phases_ids.append(marking['id'])
            if kill_chain_phase_id in kill_chain_phases_ids:
                return True
            else:
                query = """
                   mutation StixRelationAddRelation($id: ID!, $input: RelationAddInput) {
                       stixRelationEdit(id: $id) {
                            relationAdd(input: $input) {
                                node {
                                    id
                                }
                            }
                       }
                   }
                """
                self.opencti.query(query, {
                    'id': id,
                    'input': {
                        'fromRole': 'phase_belonging',
                        'toId': kill_chain_phase_id,
                        'toRole': 'kill_chain_phase',
                        'through': 'kill_chain_phases'
                    }
                })
                return True
        else:
            self.opencti.log('error', 'Missing parameters: id and kill_chain_phase_id')
            return False

    """
        Export an stix_relation object in STIX2

        :param id: the id of the stix_relation
        :return stix_relation object
    """

    def to_stix2(self, **kwargs):
        id = kwargs.get('id', None)
        mode = kwargs.get('mode', 'simple')
        max_marking_definition_entity = kwargs.get('max_marking_definition_entity', None)
        entity = kwargs.get('entity', None)
        if id is not None and entity is None:
            entity = self.read(id=id)
        if entity is not None:
            stix_relation = dict()
            stix_relation['id'] = entity['stix_id_key']
            stix_relation['type'] = 'relationship'
            stix_relation['relationship_type'] = entity['relationship_type']
            if self.opencti.not_empty(entity['description']): stix_relation['description'] = entity['description']
            stix_relation['source_ref'] = entity['from']['stix_id_key']
            stix_relation['target_ref'] = entity['to']['stix_id_key']
            stix_relation[CustomProperties.SOURCE_REF] = entity['from']['id']
            stix_relation[CustomProperties.TARGET_REF] = entity['to']['id']
            stix_relation['created'] = self.opencti.stix2.format_date(entity['created'])
            stix_relation['modified'] = self.opencti.stix2.format_date(entity['modified'])
            if self.opencti.not_empty(entity['first_seen']): stix_relation[CustomProperties.FIRST_SEEN] = self.opencti.stix2.format_date(
                entity['first_seen'])
            if self.opencti.not_empty(entity['last_seen']): stix_relation[CustomProperties.LAST_SEEN] = self.opencti.stix2.format_date(
                entity['last_seen'])
            if self.opencti.not_empty(entity['weight']): stix_relation[CustomProperties.WEIGHT] = entity['weight']
            if self.opencti.not_empty(entity['role_played']): stix_relation[CustomProperties.ROLE_PLAYED] = entity['role_played']
            stix_relation[CustomProperties.ID] = entity['id']
            return self.opencti.stix2.prepare_export(entity, stix_relation, mode, max_marking_definition_entity)
        else:
            self.opencti.log('error', 'Missing parameters: id or entity')
