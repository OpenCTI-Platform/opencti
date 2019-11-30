# coding: utf-8

import json


class StixObservable:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            name
            description
            observable_value
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
            stixRelations {
                edges {
                    node {
                        id
                        stix_id_key
                        entity_type
                        relationship_type
                        description
                        first_seen
                        last_seen
                        role_played
                        expiration
                        score
                        to {
                            id
                            name
                        }
                    }
                }
            }
        """

    """
        List StixObservable objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row
        :return List of StixObservable objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing StixObservables with filters ' + json.dumps(filters) + '.')
        query = """
            query StixObservables($filters: [StixObservablesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixObservablesOrdering, $orderMode: OrderingMode) {
                stixObservables(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result['data']['stixObservables'])

    """
        Read a StixObservable object

        :param id: the id of the StixObservable
        :param filters: the filters to apply if no id provided
        :return StixObservable object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading StixObservable {' + id + '}.')
            query = """
                query StixObservable($id: String!) {
                    stixObservable(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['stixObservable'])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Read a StixObservable object by stix_id or name

        :param type: the Stix-Domain-Entity type
        :param stix_id_key: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        stix_id_key = kwargs.get('stix_id_key', None)
        name = kwargs.get('name', None)
        published = kwargs.get('published', None)
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(filters=[{'key': 'stix_id_key', 'values': [stix_id_key]}])
        if object_result is None and name is not None and published is not None:
            object_result = self.read(filters=[
                {'key': 'name', 'values': [name]},
                {'key': 'published', 'values': [published]}
            ])
        return object_result
