# coding: utf-8

import json


class ExternalReference:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
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
            created_at
            updated_at
        """

    """
        List External-Reference objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of External-Reference objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing External-Reference with filters ' + json.dumps(filters) + '.')
        query = """
            query ExternalReferences($filters: [ExternalReferencesFiltering], $first: Int, $after: ID, $orderBy: ExternalReferencesOrdering, $orderMode: OrderingMode) {
                externalReferences(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result['data']['externalReferences'])

    """
        Read a External-Reference object

        :param id: the id of the External-Reference
        :param filters: the filters to apply if no id provided
        :return External-Reference object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading External-Reference {' + id + '}.')
            query = """
                query ExternalReference($id: String!) {
                    externalReference(id: $id) {
                        """ + self.properties + """
                    }
                }
            """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['externalReference'])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log('error', 'Missing parameters: id or filters')
            return None
