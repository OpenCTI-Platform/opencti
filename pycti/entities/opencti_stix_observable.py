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
        result = self.opencti.query(query, {'filters': filters, 'search': search, 'first': first, 'after': after,
                                            'orderBy': order_by, 'orderMode': order_mode})
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
        else:
            self.opencti.log('error', 'Missing parameters: id or filters')
            return None

    """
        Create a Stix-Observable object

        :param type: the type of the Observable
        :return Stix-Observable object
    """

    def create_raw(self, **kwargs):
        type = kwargs.get('type', None)
        observable_value = kwargs.get('observable_value', None)
        description = kwargs.get('description', None)
        id = kwargs.get('id', None)
        stix_id_key = kwargs.get('stix_id_key', None)

        if type is not None and observable_value is not None:
            self.opencti.log('info', 'Creating Stix-Observable {' + observable_value + '}.')
            query = """
               mutation StixObservableAdd($input: StixObservableAddInput) {
                   stixObservableAdd(input: $input) {
                       """ + self.properties + """
                   }
               }
            """
            result = self.opencti.query(query, {
                'input': {
                    'type': type,
                    'observable_value': observable_value,
                    'description': description,
                    'internal_id_key': id,
                    'stix_id_key': stix_id_key,
                }
            })
            return self.opencti.process_multiple_fields(result['data']['stixObservableAdd'])
        else:
            self.opencti.log('error', 'Missing parameters: type and observable_value')

    """
        Create a Stix-Observable object only if it not exists, update it on request

        :param name: the name of the Stix-Observable
        :return Stix-Observable object
    """

    def create(self, **kwargs):
        type = kwargs.get('type', None)
        observable_value = kwargs.get('observable_value', None)
        description = kwargs.get('description', None)
        id = kwargs.get('id', None)
        stix_id_key = kwargs.get('stix_id_key', None)
        update = kwargs.get('update', False)

        object_result = self.read(filters=[{'key': 'observable_value', 'values': [observable_value]}])
        if object_result is not None:
            if update:
                if description is not None:
                    self.update_field(id=object_result['id'], key='description', value=description)
                    object_result['description'] = description
            return object_result
        else:
            return self.create_raw(
                type=type,
                observable_value=observable_value,
                description=description,
                id=id,
                stix_id_key=stix_id_key
            )

    """
        Update a Stix-Observable object field

        :param id: the Stix-Observable id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Observable object
    """

    def update_field(self, **kwargs):
        id = kwargs.get('id', None)
        key = kwargs.get('key', None)
        value = kwargs.get('value', None)
        if id is not None and key is not None and value is not None:
            self.opencti.log('info', 'Updating Stix-Observable {' + id + '} field {' + key + '}.')
            query = """
                mutation StixObservableEdit($id: ID!, $input: EditInput!) {
                    stixObservableEdit(id: $id) {
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
            return self.opencti.process_multiple_fields(result['data']['stixObservableEdit']['fieldPatch'])
        else:
            self.opencti.log('error', 'Missing parameters: id and key and value')
            return None
