# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class Campaign:
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
        List Campaign objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Campaign objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Campaigns with filters ' + json.dumps(filters) + '.')
        query = """
            query Campaigns($filters: [CampaignsFiltering], $search: String, $first: Int, $after: ID, $orderBy: CampaignsOrdering, $orderMode: OrderingMode) {
                campaigns(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result['data']['campaigns'])

    """
        Read a Campaign object
        
        :param id: the id of the Campaign
        :param filters: the filters to apply if no id provided
        :return Campaign object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Campaign {' + id + '}.')
            query = """
                query Campaign($id: String!) {
                    campaign(id: $id) {
                        """ + self.properties + """
                    }
                }
             """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['campaign'])
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
        Export an Campaign object in STIX2
    
        :param id: the id of the Campaign
        :return Campaign object
    """

    def to_stix2(self, **kwargs):
        id = kwargs.get('id', None)
        mode = kwargs.get('mode', 'simple')
        max_marking_definition_entity = kwargs.get('max_marking_definition_entity', None)
        entity = kwargs.get('entity', None)
        if id is not None and entity is None:
            entity = self.read(id=id)
        if entity is not None:
            campaign = dict()
            campaign['id'] = entity['stix_id_key']
            campaign['type'] = 'campaign'
            campaign['name'] = entity['name']
            if self.opencti.not_empty(entity['stix_label']):
                campaign['labels'] = entity['stix_label']
            else:
                campaign['labels'] = ['campaign']
            if self.opencti.not_empty(entity['alias']): campaign['aliases'] = entity['alias']
            if self.opencti.not_empty(entity['description']): campaign['description'] = entity['description']
            if self.opencti.not_empty(entity['objective']): campaign['objective'] = entity['objective']
            if self.opencti.not_empty(entity['first_seen']): campaign[CustomProperties.FIRST_SEEN] = self.opencti.stix2.format_date(
                entity['first_seen'])
            if self.opencti.not_empty(entity['last_seen']): campaign[CustomProperties.LAST_SEEN] = self.opencti.stix2.format_date(
                entity['last_seen'])
            campaign['created'] = self.opencti.stix2.format_date(entity['created'])
            campaign['modified'] = self.opencti.stix2.format_date(entity['modified'])
            campaign[CustomProperties.ID] = entity['id']
            return self.opencti.stix2.prepare_export(entity, campaign, mode, max_marking_definition_entity)
        else:
            self.opencti.log('error', 'Missing parameters: id or entity')
