# coding: utf-8

import json


class StixDomainEntity:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            parent_types
            name
            alias
            description
            graph_data        
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
        List Stix-Domain-Entity objects

        :param types: the array of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Stix-Domain-Entity objects
    """

    def list(self, **kwargs):
        types = kwargs.get('types', None)
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Stix-Domain-Entities with filters ' + json.dumps(filters) + '.')
        query = """
            query StixDomainEntities($types: [String], $filters: [StixDomainEntitiesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixDomainEntitiesOrdering, $orderMode: OrderingMode) {
                stixDomainEntities(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        result = self.opencti.query(query, {'types': types, 'filters': filters, 'search': search, 'first': first, 'after': after, 'orderBy': order_by,
                                            'orderMode': order_mode})
        return self.opencti.process_multiple(result['data']['stixDomainEntities'])

    """
        Read a Stix-Domain-Entity object
        
        :param id: the id of the Stix-Domain-Entity
        :param types: the array of types
        :param filters: the filters to apply if no id provided
        :return Stix-Domain-Entity object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        types = kwargs.get('types', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Stix-Domain-Entity {' + id + '}.')
            query = """
                query StixDomainEntity($id: String!) {
                    stixDomainEntity(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['stixDomainEntity'])
        elif filters is not None:
            result = self.list(types=types, filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log('error', 'Missing parameters: id or filters')
            return None

    """
        Get a Stix-Domain-Entity object by stix_id or name

        :param type: the Stix-Domain-Entity type
        :param stix_id_key: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        types = kwargs.get('types', None)
        stix_id_key = kwargs.get('stix_id_key', None)
        name = kwargs.get('name', None)
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(id=stix_id_key)
        if object_result is None and name is not None and type is not None:
            object_result = self.read(types=types, filters=[{'key': 'name', 'values': [name]}])
            if object_result is None:
                object_result = self.read(types=types, filters=[{'key': 'alias', 'values': [name]}])
        return object_result

    """
        Update a Stix-Domain-Entity object field

        :param id: the Stix-Domain-Entity id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Domain-Entity object
    """

    def update_field(self, **kwargs):
        id = kwargs.get('id', None)
        key = kwargs.get('key', None)
        value = kwargs.get('value', None)
        if id is not None and key is not None and value is not None:
            self.opencti.log('info', 'Updating Stix-Domain-Entity {' + id + '} field {' + key + '}.')
            query = """
                mutation StixDomainEntityEdit($id: ID!, $input: EditInput!) {
                    stixDomainEntityEdit(id: $id) {
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
            return self.opencti.process_multiple_fields(result['data']['stixDomainEntityEdit']['fieldPatch'])
        else:
            self.opencti.log('error', 'Missing parameters: id and key and value')
            return None
