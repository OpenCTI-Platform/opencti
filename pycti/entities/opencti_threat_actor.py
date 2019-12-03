# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class ThreatActor:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            stix_label
            entity_type
            parent_types
            name
            alias
            description
            graph_data
            goal
            sophistication
            resource_level
            primary_motivation
            secondary_motivation
            personal_motivation
            created
            modified            
            created_at
            updated_at
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
            tags {
                edges {
                    node {
                        id
                        tag_type
                        value
                        color
                    }
                    relation {
                        id
                    }
                }
            }
            externalReferences {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        source_name
                        description
                        url
                        hash
                        external_id
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
        List Threat-Actor objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Threat-Actor objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Threat-Actors with filters ' + json.dumps(filters) + '.')
        query = """
            query ThreatActors($filters: [ThreatActorsFiltering], $search: String, $first: Int, $after: ID, $orderBy: ThreatActorsOrdering, $orderMode: OrderingMode) {
                threatActors(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        result = self.opencti.query(query, {'filters': filters, 'search': search, 'first': first, 'after': after, 'orderBy': order_by, 'orderMode': order_mode})
        return self.opencti.process_multiple(result['data']['threatActors'])

    """
        Read a Threat-Actor object
        
        :param id: the id of the Threat-Actor
        :param filters: the filters to apply if no id provided
        :return Threat-Actor object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Threat-Actor {' + id + '}.')
            query = """
                query ThreatActor($id: String!) {
                    threatActor(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['threatActor'])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log('error', 'Missing parameters: id or filters')
            return None

    """
        Export an Threat-Actor object in STIX2
    
        :param id: the id of the Threat-Actor
        :return Threat-Actor object
    """

    def to_stix2(self, **kwargs):
        id = kwargs.get('id', None)
        mode = kwargs.get('mode', 'simple')
        max_marking_definition_entity = kwargs.get('max_marking_definition_entity', None)
        entity = kwargs.get('entity', None)
        if id is not None and entity is None:
            entity = self.read(id=id)
        if entity is not None:
            threat_actor = dict()
            threat_actor['id'] = entity['stix_id_key']
            threat_actor['type'] = 'threat-actor'
            threat_actor['name'] = entity['name']
            if self.opencti.not_empty(entity['stix_label']):
                threat_actor['labels'] = entity['stix_label']
            else:
                threat_actor['labels'] = ['threat-actor']
            if self.opencti.not_empty(entity['alias']): threat_actor['aliases'] = entity['alias']
            if self.opencti.not_empty(entity['description']): threat_actor['description'] = entity['description']
            if self.opencti.not_empty(entity['goal']): threat_actor['goals'] = entity['goal']
            if self.opencti.not_empty(entity['sophistication']): threat_actor['sophistication'] = entity['sophistication']
            if self.opencti.not_empty(entity['resource_level']): threat_actor['resource_level'] = entity['resource_level']
            if self.opencti.not_empty(entity['primary_motivation']): threat_actor['primary_motivation'] = entity[
                'primary_motivation']
            if self.opencti.not_empty(entity['secondary_motivation']): threat_actor['secondary_motivations'] = entity[
                'secondary_motivation']
            threat_actor['created'] = self.opencti.stix2.format_date(entity['created'])
            threat_actor['modified'] = self.opencti.stix2.format_date(entity['modified'])
            threat_actor[CustomProperties.ID] = entity['id']
            return self.opencti.stix2.prepare_export(entity, threat_actor, mode, max_marking_definition_entity)
        else:
            self.opencti.log('error', 'Missing parameters: id or entity')