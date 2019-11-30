# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class Incident:
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
            objective
            first_seen
            last_seen
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
        """

    """
        List Incident objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Incident objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Incidents with filters ' + json.dumps(filters) + '.')
        query = """
            query Incidents($filters: [IncidentsFiltering], $search: String, $first: Int, $after: ID, $orderBy: IncidentsOrdering, $orderMode: OrderingMode) {
                incidents(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result['data']['incidents'])

    """
        Read a Incident object
        
        :param id: the id of the Incident
        :param filters: the filters to apply if no id provided
        :return Incident object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Incident {' + id + '}.')
            query = """
                query Incident($id: String!) {
                    incident(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['incident'])
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
        Export an Incident object in STIX2
    
        :param id: the id of the Incident
        :return Incident object
    """

    def to_stix2(self, **kwargs):
        id = kwargs.get('id', None)
        mode = kwargs.get('mode', 'simple')
        max_marking_definition_entity = kwargs.get('max_marking_definition_entity', None)
        entity = kwargs.get('entity', None)
        if id is not None and entity is None:
            entity = self.read(id=id)
        if entity is not None:
            incident = dict()
            incident['id'] = entity['stix_id_key']
            incident['type'] = 'x-opencti-incident'
            incident['name'] = entity['name']
            if self.opencti.not_empty(entity['stix_label']):
                incident['labels'] = entity['stix_label']
            else:
                incident['labels'] = ['x-opencti-incident']
            if self.opencti.not_empty(entity['alias']): incident['aliases'] = entity['alias']
            if self.opencti.not_empty(entity['description']): incident['description'] = entity['description']
            if self.opencti.not_empty(entity['objective']): incident['objective'] = entity['objective']
            if self.opencti.not_empty(entity['first_seen']): incident['first_seen'] = self.opencti.stix2.format_date(entity['first_seen'])
            if self.opencti.not_empty(entity['last_seen']): incident['last_seen'] = self.opencti.stix2.format_date(entity['last_seen'])
            incident['created'] = self.opencti.stix2.format_date(entity['created'])
            incident['modified'] = self.opencti.stix2.format_date(entity['modified'])
            incident[CustomProperties.ID] = entity['id']
            return self.opencti.stix2.prepare_export(entity, incident, mode, max_marking_definition_entity)
        else:
            self.opencti.log('error', 'Missing parameters: id or entity')
