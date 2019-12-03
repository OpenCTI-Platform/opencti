# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class Tool:
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
            tool_version
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
        List Tool objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Tool objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Tools with filters ' + json.dumps(filters) + '.')
        query = """
            query Tools($filters: [ToolsFiltering], $search: String, $first: Int, $after: ID, $orderBy: ToolsOrdering, $orderMode: OrderingMode) {
                tools(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result['data']['tools'])

    """
        Read a Tool object
        
        :param id: the id of the Tool
        :param filters: the filters to apply if no id provided
        :return Tool object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Tool {' + id + '}.')
            query = """
                query Tool($id: String!) {
                    tool(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['tool'])
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
        Export an Tool object in STIX2
    
        :param id: the id of the Tool
        :return Tool object
    """

    def to_stix2(self, **kwargs):
        id = kwargs.get('id', None)
        mode = kwargs.get('mode', 'simple')
        max_marking_definition_entity = kwargs.get('max_marking_definition_entity', None)
        entity = kwargs.get('entity', None)
        if id is not None and entity is None:
            entity = self.read(id=id)
        if entity is not None:
            entity = self.read(id=id)
            tool = dict()
            tool['id'] = entity['stix_id_key']
            tool['type'] = 'tool'
            tool['name'] = entity['name']
            if self.opencti.not_empty(entity['stix_label']):
                tool['labels'] = entity['stix_label']
            else:
                tool['labels'] = ['tool']
            if self.opencti.not_empty(entity['description']): tool['description'] = entity['description']
            if self.opencti.not_empty(entity['tool_version']): tool['tool_version'] = entity['tool_version']
            tool['created'] = self.opencti.stix2.format_date(entity['created'])
            tool['modified'] = self.opencti.stix2.format_date(entity['modified'])
            if self.opencti.not_empty(entity['alias']): tool[CustomProperties.ALIASES] = entity['alias']
            tool[CustomProperties.ID] = entity['id']
            return self.opencti.stix2.prepare_export(entity, tool, mode, max_marking_definition_entity)
        else:
            self.opencti.log('error', 'Missing parameters: id or entity')