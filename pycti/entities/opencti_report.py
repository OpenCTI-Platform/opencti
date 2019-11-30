# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class Report:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            stix_label
            name
            alias
            description
            report_class
            published
            object_status
            source_confidence_level
            graph_data
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
            objectRefs {
                edges {
                    node {
                        id
                        stix_id_key
                        entity_type
                    }
                    relation {
                        id
                    }
                }
            }
            observableRefs {
                edges {
                    node {
                        id
                        stix_id_key
                        entity_type
                    }
                    relation {
                        id
                    }
                }
            }
            relationRefs {
                edges {
                    node {
                        id
                        stix_id_key
                    }
                    relation {
                        id
                    }
                }
            }
        """

    """
        List Report objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Report objects
    """

    def list(self, **kwargs):
        filters = kwargs.get('filters', None)
        search = kwargs.get('search', None)
        first = kwargs.get('first', 500)
        after = kwargs.get('after', None)
        order_by = kwargs.get('orderBy', None)
        order_mode = kwargs.get('orderMode', None)
        self.opencti.log('info', 'Listing Reports with filters ' + json.dumps(filters) + '.')
        query = """
            query Reports($filters: [ReportsFiltering], $search: String, $first: Int, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode) {
                reports(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result['data']['reports'])

    """
        Read a Report object

        :param id: the id of the Report
        :param filters: the filters to apply if no id provided
        :return Report object
    """

    def read(self, **kwargs):
        id = kwargs.get('id', None)
        filters = kwargs.get('filters', None)
        if id is not None:
            self.opencti.log('info', 'Reading Report {' + id + '}.')
            query = """
                query Report($id: String!) {
                    report(id: $id) {
                        """ + self.properties + """
                    }
                }
            """
            result = self.opencti.query(query, {'id': id})
            return self.opencti.process_multiple_fields(result['data']['report'])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Read a Report object by stix_id or name

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

    """
        Add a Stix-Entity object to Report object (object_refs)

        :param id: the id of the Report
        :param entity_id: the id of the Stix-Entity
        :return Boolean
    """

    def add_stix_entity(self, **kwargs):
        id = kwargs.get('id', None)
        entity_id = kwargs.get('entity_id', None)
        if id is not None and entity_id is not None:
            self.opencti.log('info',
                             'Adding Stix-Entity {' + entity_id + '} to Report {' + id + '}')
            report = self.read(id=id)
            refs_ids = []
            for ref in report['objectRefs']:
                refs_ids.append(ref['id'])
            for ref in report['observableRefs']:
                refs_ids.append(ref['id'])
            for ref in report['relationRefs']:
                refs_ids.append(ref['id'])
            if entity_id in refs_ids:
                return True
            else:
                query = """
                   mutation ReportEdit($id: ID!, $input: RelationAddInput) {
                       reportEdit(id: $id) {
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
                        'fromRole': 'knowledge_aggregation',
                        'toId': entity_id,
                        'toRole': 'so',
                        'through': 'object_refs'
                    }
                })
                return True
        else:
            self.opencti.log('error', 'Missing parameters: id and entity_id')
            return False

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
            report = dict()
            report['id'] = entity['stix_id_key']
            report['type'] = 'report'
            report['name'] = entity['name']
            if self.opencti.not_empty(entity['stix_label']):
                report['labels'] = entity['stix_label']
            else:
                report['labels'] = ['report']
            if self.opencti.not_empty(entity['description']): report['description'] = entity['description']
            report['published'] = self.opencti.stix2.format_date(entity['published'])
            report['created'] = self.opencti.stix2.format_date(entity['created'])
            report['modified'] = self.opencti.stix2.format_date(entity['modified'])
            if self.opencti.not_empty(entity['alias']): report[CustomProperties.ALIASES] = entity['alias']
            if self.opencti.not_empty(entity['report_class']): report[CustomProperties.REPORT_CLASS] = entity['report_class']
            if self.opencti.not_empty(entity['object_status']): report[CustomProperties.OBJECT_STATUS] = entity['object_status']
            if self.opencti.not_empty(entity['source_confidence_level']): report[CustomProperties.SRC_CONF_LEVEL] = entity[
                'source_confidence_level']
            if self.opencti.not_empty(entity['graph_data']): report[CustomProperties.GRAPH_DATA] = entity['graph_data']
            report[CustomProperties.ID] = entity['id']
            return self.opencti.stix2.prepare_export(entity, report, mode, max_marking_definition_entity)
        else:
            self.opencti.log('error', 'Missing parameters: id or entity')
