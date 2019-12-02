# coding: utf-8

import json


class MarkingDefinition:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            definition_type
            definition
            level
            color
            created
            modified
            created_at
            updated_at
        """

    """
        List Marking-Definition objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Marking-Definition objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Marking-Definitions with filters ' + json.dumps(filters) + '.')
        query = """
            query MarkingDefinitions($filters: [MarkingDefinitionsFiltering], $first: Int, $after: ID, $orderBy: MarkingDefinitionsOrdering, $orderMode: OrderingMode) {
                markingDefinitions(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        result = self.opencti.query(query, {'filters': filters, 'first': first, 'after': after, 'orderBy': order_by, 'orderMode': order_mode})
        return self.opencti.process_multiple(result['data']['markingDefinitions'])

    """
        Read a Marking-Definition object

        :param id: the id of the Marking-Definition
        :param filters: the filters to apply if no id provided
        :return Marking-Definition object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Marking-Definition {' + id + '}.')
            query = """
                query MarkingDefinition($id: String!) {
                    markingDefinition(id: $id) {
                        """ + self.properties + """
                    }
                }
            """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['markingDefinition'])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log('error', 'Missing parameters: id or filters')
            return None
