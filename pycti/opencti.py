# coding: utf-8

import os
import requests
import datetime
import dateutil.parser
import json
import uuid
import base64

from pycti.opencti_stix2 import OpenCTIStix2


class OpenCTI:
    """
        Python API for OpenCTI
        :param url: OpenCTI URL
        :param key: The API key
        :param verbose: Log all requests. Defaults to None
        :param stdout: Display log to stdout. Defaults to None
    """

    def __init__(self, url, key, log_file='', verbose=True, stdout=True):
        self.api_url = url + '/graphql'
        self.log_file = log_file
        self.verbose = verbose
        self.stdout = stdout
        self.request_headers = {
            'Authorization': 'Bearer ' + key,
            'Content-Type': 'application/json'
        }

    def log(self, message):
        if self.stdout:
            print(message)
        if self.verbose and len(self.log_file) > 0:
            file = open(self.log_file, 'a')
            file.write('[' + datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S') + '] ' + message + "\n")
            file.close()

    def query(self, query, variables={}):
        r = requests.post(self.api_url, json={'query': query, 'variables': variables}, headers=self.request_headers)
        if r.status_code == requests.codes.ok:
            result = r.json()
            if 'errors' in result:
                self.log(result['errors'][0]['message'])
            else:
                return result
        else:
            self.log(r.text)

    def parse_multiple(self, data):
        result = []
        for edge in data['edges'] if 'edges' in data and data['edges'] is not None else []:
            result.append(self.parse_stix(edge['node']))
        return result

    def health_check(self):
        try:
            test = self.get_threat_actors(1)
            if test is not None:
                return True
        except:
            return False
        return False

    def parse_stix(self, data):
        if 'createdByRef' in data and data['createdByRef'] is not None and 'node' in data['createdByRef']:
            data['createdByRef'] = data['createdByRef']['node']
        if 'markingDefinitions' in data:
            data['markingDefinitions'] = self.parse_multiple(data['markingDefinitions'])
        if 'killChainPhases' in data:
            data['killChainPhases'] = self.parse_multiple(data['killChainPhases'])
        if 'externalReferences' in data:
            data['externalReferences'] = self.parse_multiple(data['externalReferences'])
        if 'objectRefs' in data:
            data['objectRefs'] = self.parse_multiple(data['objectRefs'])
        if 'observableRefs' in data:
            data['observableRefs'] = self.parse_multiple(data['observableRefs'])
        if 'relationRefs' in data:
            data['relationRefs'] = self.parse_multiple(data['relationRefs'])
        if 'stixRelations' in data:
            data['stixRelations'] = self.parse_multiple(data['stixRelations'])
        return data

    def check_existing_stix_domain_entity(self, stix_id=None, name=None, type=None):
        object_result = None
        if stix_id is not None:
            object_result = self.get_stix_domain_entity_by_stix_id(stix_id)
        if object_result is None and name is not None and type is not None:
            object_result = self.search_stix_domain_entity_by_name(name, type)
        return object_result

    def update_settings_field(self, id, key, value):
        self.log('Updating settings field ' + key + ' of ' + id + '...')
        query = """
            mutation SettingsEdit($id: ID!, $input: EditInput!) {
                settingsEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                    }
                }
            }
        """
        self.query(query, {
            'id': id,
            'input': {
                'key': key,
                'value': value
            }
        })

    def get_connectors(self):
        query = """
            query Connectors {
                connectors {
                    identifier
                    config_template
                    config
               }
            }
           """
        result = self.query(query)
        return result['data']['connectors']

    def update_connector_config(self, identifier, config):
        self.log('Updating connector config of ' + identifier + '...')
        query = """
            mutation ConnectorConfig($identifier: String!, $config: String!) {
                connectorConfig(identifier: $identifier, config: $config)
            }
        """
        self.query(query, {
            'identifier': identifier,
            'config': base64.b64encode(json.dumps(config).encode('ascii')).decode('ascii')
        })

    def get_stix_domain_entity(self, id):
        """
            :param id: StixDomain entity identifier
            :return: StixDomainEntity
        """

        query = """
            query StixDomainEntity($id: String) {
                stixDomainEntity(id: $id) {
                    id
                    entity_type
                    alias
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['stixDomainEntity']

    def get_stix_domain_entity_by_external_reference(self, id, type):
        """
            :param id: ExternalReference identifier
            :param type: StixDomain entity type
            :return: StixDomainEntity
        """
        query = """
            query StixDomainEntities($externalReferenceId: String, $type: String) {
                stixDomainEntities(externalReferenceId: $externalReferenceId, type: $type) {
                    edges {
                        node {
                            id
                            entity_type
                            alias
                        }
                    }
                }
            }
        """
        result = self.query(query, {'externalReferenceId': id, 'type': type})
        if len(result['data']['stixDomainEntities']['edges']) > 0:
            return result['data']['stixDomainEntities']['edges'][0]['node']
        else:
            return None

    def get_stix_domain_entity_by_name(self, name, type='Stix-Domain-Entity'):
        query = """
            query StixDomainEntities($name: String, $type: String) {
                stixDomainEntities(name: $name, type: $type) {
                    edges {
                        node {
                            id
                            entity_type
                            alias
                        }
                    }
                }
            }
        """
        result = self.query(query, {'name': name, 'type': type})
        if len(result['data']['stixDomainEntities']['edges']) > 0:
            return result['data']['stixDomainEntities']['edges'][0]['node']
        else:
            return None

    def get_stix_domain_entity_by_stix_id(self, stix_id):
        query = """
            query StixDomainEntities($stix_id: String) {
                stixDomainEntities(stix_id: $stix_id) {
                    edges {
                        node {
                            id
                            entity_type
                            alias
                        }
                    }
                }
            }
        """
        result = self.query(query, {'stix_id': stix_id})
        if len(result['data']['stixDomainEntities']['edges']) > 0:
            return result['data']['stixDomainEntities']['edges'][0]['node']
        else:
            return None

    def search_stix_domain_entities(self, keyword, type='Stix-Domain-Entity'):
        query = """
               query StixDomainEntities($search: String, $type: String) {
                   stixDomainEntities(search: $search, type: $type) {
                       edges {
                           node {
                               id
                               entity_type
                               alias
                           }
                       }
                   }
               }
           """
        result = self.query(query, {'search': keyword, 'type': type})
        return self.parse_multiple(result['data']['stixDomainEntities'])

    def search_stix_domain_entities_by_name(self, name_or_alias, type='Stix-Domain-Entity'):
        query = """
               query StixDomainEntities($name: String, $type: String) {
                   stixDomainEntities(name: $name, type: $type) {
                       edges {
                           node {
                               id
                               entity_type
                               alias
                           }
                       }
                   }
               }
           """
        result = self.query(query, {'name': name_or_alias, 'type': type})
        return self.parse_multiple(result['data']['stixDomainEntities'])

    def search_stix_domain_entity_by_name(self, name_or_alias, type='Stix-Domain-Entity'):
        result = self.search_stix_domain_entities_by_name(name_or_alias, type)
        if len(result) > 0:
            return result[0]
        else:
            return None

    def update_stix_domain_entity_field(self, id, key, value):
        self.log('Updating field ' + key + ' of ' + id + '...')
        query = """
            mutation StixDomainEntityEdit($id: ID!, $input: EditInput!) {
                stixDomainEntityEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                        entity_type
                        alias
                    }
                }
            }
        """
        self.query(query, {
            'id': id,
            'input': {
                'key': key,
                'value': value
            }
        })

    def update_stix_relation_field(self, id, key, value):
        self.log('Updating field ' + key + ' of ' + id + '...')
        query = """
            mutation StixRelationEdit($id: ID!, $input: EditInput!) {
                stixRelationEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                        entity_type
                        alias
                    }
                }
            }
        """
        self.query(query, {
            'id': id,
            'input': {
                'key': key,
                'value': value
            }
        })

    def push_stix_domain_entity_export(self, id, export_id, data):
        query = """
            mutation StixDomainEntityEdit($id: ID!, $exportId: String!, $rawData: String!) {
                stixDomainEntityEdit(id: $id) {
                    exportPush(exportId: $exportId, rawData: $rawData)
                }
            }
        """
        self.query(query, {
            'id': id,
            'exportId': export_id,
            'rawData': data
        })

    def delete_stix_domain_entity(self, id):
        self.log('Deleting + ' + id + '...')
        query = """
             mutation StixDomainEntityEdit($id: ID!) {
                 stixDomainEntityEdit(id: $id) {
                     delete
                 }
             }
         """
        self.query(query, {'id': id})

    def get_stix_relation_by_stix_id(self, stix_id):
        self.log('Getting relation ' + stix_id + '...')
        query = """
            query StixRelations($stix_id: String) {
                stixRelations(stix_id: $stix_id) {
                    edges {
                        node {
                            id
                            entity_type
                        }
                    }
                }
            }
        """
        result = self.query(query, {'stix_id': stix_id})
        if len(result['data']['stixRelations']['edges']) > 0:
            return result['data']['stixRelations']['edges'][0]['node']
        else:
            return None

    def get_stix_relation_by_id(self, id):
        self.log('Getting relation ' + id + '...')
        query = """
            query StixRelation($id: String!) {
                stixRelation(id: $id) {
                    id
                    stix_id
                    entity_type
                    relationship_type
                    description
                    weight
                    role_played
                    score
                    expiration
                    first_seen
                    last_seen
                    created
                    modified
                    from {
                        id
                        stix_id
                    }
                    to {
                        id
                        stix_id
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['stixRelation']

    def get_stix_relations(self, from_id=None, to_id=None, type='stix_relation', first_seen=None, last_seen=None, inferred=False):
        self.log('Getting relations, from: ' + from_id + ', to: ' + to_id + '...')
        if type == 'revoked-by':
            return []

        if first_seen is not None and last_seen is not None:
            first_seen = dateutil.parser.parse(first_seen)
            first_seen_start = (first_seen + datetime.timedelta(days=-1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
            first_seen_stop = (first_seen + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
            last_seen = dateutil.parser.parse(last_seen)
            last_seen_start = (last_seen + datetime.timedelta(days=-1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
            last_seen_stop = (last_seen + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
        else:
            first_seen_start = None
            first_seen_stop = None
            last_seen_start = None
            last_seen_stop = None

        query = """
            query StixRelations($fromId: String, $toId: String, $relationType: String, $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $inferred: Boolean) {
                stixRelations(fromId: $fromId, toId: $toId, relationType: $relationType, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, inferred: $inferred) {
                    edges {
                        node {
                            id
                            stix_id
                            entity_type
                            relationship_type
                            description
                            weight
                            role_played
                            score
                            expiration
                            first_seen
                            last_seen
                            created
                            modified
                            from {
                                id
                                stix_id
                            }
                            to {
                                id
                                stix_id
                            }
                        }
                    }
                }
            }  
        """
        result = self.query(query, {
            'fromId': from_id,
            'toId': to_id,
            'relationType': type,
            'firstSeenStart': first_seen_start,
            'firstSeenStop': first_seen_stop,
            'lastSeenStart': last_seen_start,
            'lastSeenStop': last_seen_stop,
            'inferred': inferred
        })
        return self.parse_multiple(result['data']['stixRelations'])

    def get_stix_relation(self, from_id, to_id, type='stix_relation', first_seen=None, last_seen=None):
        result = self.get_stix_relations(from_id, to_id, type, first_seen, last_seen)
        if len(result) > 0:
            return result[0]
        else:
            return None

    def create_relation(self,
                        from_id,
                        from_role,
                        to_id,
                        to_role,
                        type,
                        description,
                        first_seen,
                        last_seen,
                        weight,
                        role_played=None,
                        score=None,
                        expiration=None,
                        id=None,
                        stix_id=None,
                        created=None,
                        modified=None
                        ):
        self.log('Creating relation ' + from_role + ' => ' + to_role + '...')
        query = """
             mutation StixRelationAdd($input: StixRelationAddInput!) {
                 stixRelationAdd(input: $input) {
                     id
                 }
             }
         """
        result = self.query(query, {
            'input': {
                'fromId': from_id,
                'fromRole': from_role,
                'toId': to_id,
                'toRole': to_role,
                'relationship_type': type,
                'description': description,
                'role_played': role_played,
                'score': score,
                'expiration': expiration,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'weight': weight,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['stixRelationAdd']

    def create_relation_if_not_exists(self,
                                      from_id,
                                      from_type,
                                      to_id,
                                      to_type,
                                      type,
                                      description,
                                      first_seen,
                                      last_seen,
                                      weight,
                                      role_played=None,
                                      score=None,
                                      expiration=None,
                                      id=None,
                                      stix_id=None,
                                      created=None,
                                      modified=None
                                      ):
        stix_relation_result = None
        if stix_id is not None:
            stix_relation_result = self.get_stix_relation_by_stix_id(stix_id)
        if stix_relation_result is None:
            stix_relation_result = self.get_stix_relation(
                from_id,
                to_id,
                type,
                first_seen,
                last_seen)
        if stix_relation_result is not None:
            return stix_relation_result
        else:
            roles = self.resolve_role(type, from_type, to_type)
            if roles is not None:
                final_from_id = from_id
                final_to_id = to_id
            else:
                roles = self.resolve_role(type, to_type, from_type)
                if roles is not None:
                    final_from_id = to_id
                    final_to_id = from_id
                else:
                    self.log('Cannot resolve roles, doing nothing (' + type + ': ' + from_type + ',' + to_type + ')')
                    return None

            return self.create_relation(
                final_from_id,
                roles['from_role'],
                final_to_id,
                roles['to_role'],
                type,
                description,
                first_seen,
                last_seen,
                weight,
                role_played,
                score,
                expiration,
                id,
                stix_id,
                created,
                modified
            )

    def delete_relation(self, id):
        self.log('Deleting ' + id + '...')
        query = """
            mutation StixRelationEdit($id: ID!) {
                stixRelationEdit(id: $id) {
                    delete
                }
            }
        """
        self.query(query, {'id': id})

    def get_stix_observable_by_id(self, id):
        self.log('Getting stix observable ' + id + '...')
        query = """
            query StixObservable($id: String!) {
                stixObservable(id: $id) {
                    id
                    name
                    description
                    stix_id
                    entity_type
                    observable_value
                    created_at
                    updated_at
                    stixRelations {
                        edges {
                            node {
                                id
                                first_seen
                                last_seen
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['stixObservable']

    def get_marking_definition_by_stix_id(self, stix_id):
        query = """
             query MarkingDefinitions($stix_id: String) {
                 markingDefinitions(stix_id: $stix_id) {
                     edges {
                         node {
                             id
                             entity_type
                         }
                     }
                 }
             }
         """
        result = self.query(query, {'stix_id': stix_id})
        if len(result['data']['markingDefinitions']['edges']) > 0:
            return result['data']['markingDefinitions']['edges'][0]['node']
        else:
            return None

    def get_marking_definition_by_definition(self, definition_type, definition):
        query = """
             query MarkingDefinitions($definition_type: String, $definition: String) {
                 markingDefinitions(definition_type: $definition_type, definition: $definition) {
                     edges {
                         node {
                             id
                             entity_type
                         }
                     }
                 }
             }
         """
        result = self.query(query, {'definition_type': definition_type, 'definition': definition})
        if len(result['data']['markingDefinitions']['edges']) > 0:
            return result['data']['markingDefinitions']['edges'][0]['node']
        else:
            return None

    def create_marking_definition(self,
                                  definition_type,
                                  definition,
                                  level=0,
                                  color=None,
                                  id=None,
                                  stix_id=None,
                                  created=None,
                                  modified=None
                                  ):
        self.log('Creating marking definition ' + definition + '...')
        query = """
            mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput) {
                markingDefinitionAdd(input: $input) {
                    id
                    entity_type
                }
            }
        """
        result = self.query(query, {
            'input': {
                'definition_type': definition_type,
                'definition': definition,
                'internal_id': id,
                'level': level,
                'color': color,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['markingDefinitionAdd']

    def create_marking_definition_if_not_exists(self,
                                                definition_type,
                                                definition,
                                                level=0,
                                                color=None,
                                                id=None,
                                                stix_id=None,
                                                created=None,
                                                modified=None
                                                ):
        object_result = None
        if stix_id is not None:
            object_result = self.get_marking_definition_by_stix_id(stix_id)
            if object_result is None:
                object_result = self.get_marking_definition_by_definition(definition_type, definition)
        if object_result is not None:
            return object_result
        else:
            return self.create_marking_definition(
                definition_type,
                definition,
                level,
                color,
                id,
                stix_id,
                created,
                modified
            )

    def get_external_reference_by_url(self, url):
        query = """
             query ExternalReferences($search: String) {
                 externalReferences(search: $search) {
                     edges {
                         node {
                             id
                         }
                     }
                 }
             }
         """
        result = self.query(query, {'search': url})
        if len(result['data']['externalReferences']['edges']) > 0:
            return result['data']['externalReferences']['edges'][0]['node']
        else:
            return None

    def create_external_reference(self,
                                  source_name,
                                  url,
                                  external_id='',
                                  description='',
                                  id=None,
                                  stix_id=None,
                                  created=None,
                                  modified=None
                                  ):
        self.log('Creating external reference ' + source_name + '...')
        query = """
            mutation ExternalReferenceAdd($input: ExternalReferenceAddInput) {
                externalReferenceAdd(input: $input) {
                    id
                }
            }
        """
        result = self.query(query, {
            'input': {
                'source_name': source_name,
                'external_id': external_id,
                'description': description,
                'url': url,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['externalReferenceAdd']

    def create_external_reference_if_not_exists(self,
                                                source_name,
                                                url,
                                                external_id='',
                                                description='',
                                                id=None,
                                                stix_id=None,
                                                created=None,
                                                modified=None
                                                ):
        external_reference_result = self.get_external_reference_by_url(url)
        if external_reference_result is not None:
            return external_reference_result
        else:
            return self.create_external_reference(
                source_name,
                url,
                external_id,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def get_kill_chain_phase(self, phase_name):
        query = """
            query KillChainPhases($phaseName: String) {
                killChainPhases(phaseName: $phaseName) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
        """
        result = self.query(query, {'phaseName': phase_name})
        if len(result['data']['killChainPhases']['edges']) > 0:
            return result['data']['killChainPhases']['edges'][0]['node']
        else:
            return None

    def create_kill_chain_phase(self,
                                kill_chain_name,
                                phase_name,
                                phase_order=0,
                                id=None,
                                stix_id=None,
                                created=None,
                                modified=None):
        self.log('Creating kill chain phase ' + phase_name + '...')
        query = """
               mutation KillChainPhaseAdd($input: KillChainPhaseAddInput) {
                   killChainPhaseAdd(input: $input) {
                       id
                   }
               }
           """
        result = self.query(query, {
            'input': {
                'kill_chain_name': kill_chain_name,
                'phase_name': phase_name,
                'phase_order': phase_order,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['killChainPhaseAdd']

    def create_kill_chain_phase_if_not_exists(self,
                                              kill_chain_name,
                                              phase_name,
                                              phase_order=0,
                                              id=None,
                                              stix_id=None,
                                              created=None,
                                              modified=None):
        kill_chain_phase_result = self.get_kill_chain_phase(phase_name)
        if kill_chain_phase_result is not None:
            return kill_chain_phase_result
        else:
            return self.create_kill_chain_phase(
                kill_chain_name,
                phase_name,
                phase_order,
                id,
                stix_id,
                created,
                modified
            )

    def get_identity(self, id):
        self.log('Getting identity ' + id + '...')
        query = """
            query Identity($id: String!) {
                identity(id: $id) {
                   id
                    entity_type
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['identity']

    def get_identities(self, limit=10000):
        self.log('Getting identities...')
        query = """
            query Identities($first: Int) {
                identities(first: $first) {
                    edges {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['identities'])

    def create_identity(self, type, name, description, id=None, stix_id=None, created=None, modified=None):
        self.log('Creating identity ' + name + '...')
        query = """
            mutation IdentityAdd($input: IdentityAddInput) {
                identityAdd(input: $input) {
                    id
                    entity_type
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'type': type,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['identityAdd']

    def create_identity_if_not_exists(self,
                                      type,
                                      name,
                                      description,
                                      id=None,
                                      stix_id=None,
                                      created=None,
                                      modified=None
                                      ):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, type)
        if object_result is not None:
            return object_result
        else:
            return self.create_identity(
                type,
                name,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def get_threat_actor(self, id):
        self.log('Getting threat actor ' + id + '...')
        query = """
            query ThreatActor($id: String!) {
                threatActor(id: $id) {
                    id
                    entity_type
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    goal
                    sophistication
                    resource_level
                    primary_motivation
                    secondary_motivation
                    personal_motivation
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['threatActor']

    def get_threat_actors(self, limit=10000):
        self.log('Getting threat actors...')
        query = """
            query ThreatActors($first: Int) {
                threatActors(first: $first) {
                    edges {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            goal
                            sophistication
                            resource_level
                            primary_motivation
                            secondary_motivation
                            personal_motivation
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['threatActors'])

    def create_threat_actor(self,
                            name,
                            description,
                            goal=None,
                            sophistication=None,
                            resource_level=None,
                            primary_motivation=None,
                            secondary_motivation=None,
                            personal_motivation=None,
                            id=None,
                            stix_id=None,
                            created=None,
                            modified=None
                            ):
        self.log('Creating threat actor ' + name + '...')
        query = """
            mutation ThreatActorAdd($input: ThreatActorAddInput) {
                threatActorAdd(input: $input) {
                   id
                   entity_type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'goal': goal,
                'sophistication': sophistication,
                'resource_level': resource_level,
                'primary_motivation': primary_motivation,
                'secondary_motivation': secondary_motivation,
                'personal_motivation': personal_motivation,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['threatActorAdd']

    def create_threat_actor_if_not_exists(self,
                                          name,
                                          description,
                                          goal=None,
                                          sophistication=None,
                                          resource_level=None,
                                          primary_motivation=None,
                                          secondary_motivation=None,
                                          personal_motivation=None,
                                          id=None,
                                          stix_id=None,
                                          created=None,
                                          modified=None
                                          ):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Threat-Actor')
        if object_result is not None:
            return object_result
        else:
            return self.create_threat_actor(
                name,
                description,
                goal,
                sophistication,
                resource_level,
                primary_motivation,
                secondary_motivation,
                personal_motivation,
                id,
                stix_id,
                created,
                modified
            )

    def get_intrusion_set(self, id):
        self.log('Getting intrusion set ' + id + '...')
        query = """
            query IntrusionSet($id: String!) {
                intrusionSet(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    goal
                    sophistication
                    resource_level
                    primary_motivation
                    secondary_motivation
                    first_seen
                    last_seen
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['intrusionSet']

    def get_intrusion_sets(self, limit=10000):
        self.log('Getting intrusion sets...')
        query = """
            query IntrusionSets($first: Int) {
                intrusionSets(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            goal
                            sophistication
                            resource_level
                            primary_motivation
                            secondary_motivation
                            first_seen
                            last_seen
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['intrusionSets'])

    def create_intrusion_set(self,
                             name,
                             description,
                             first_seen=None,
                             last_seen=None,
                             goal=None,
                             sophistication=None,
                             resource_level=None,
                             primary_motivation=None,
                             secondary_motivation=None,
                             id=None,
                             stix_id=None,
                             created=None,
                             modified=None
                             ):
        self.log('Creating intrusion set ' + name + '...')
        query = """
            mutation IntrusionSetAdd($input: IntrusionSetAddInput) {
                intrusionSetAdd(input: $input) {
                   id
                   entity_type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'goal': goal,
                'sophistication': sophistication,
                'resource_level': resource_level,
                'primary_motivation': primary_motivation,
                'secondary_motivation': secondary_motivation,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['intrusionSetAdd']

    def create_intrusion_set_if_not_exists(self,
                                           name,
                                           description,
                                           first_seen=None,
                                           last_seen=None,
                                           goal=None,
                                           sophistication=None,
                                           resource_level=None,
                                           primary_motivation=None,
                                           secondary_motivation=None,
                                           id=None,
                                           stix_id=None,
                                           created=None,
                                           modified=None
                                           ):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Intrusion-Set')
        if object_result is not None:
            return object_result
        else:
            return self.create_intrusion_set(
                name,
                description,
                first_seen,
                last_seen,
                goal,
                sophistication,
                resource_level,
                primary_motivation,
                secondary_motivation,
                id,
                stix_id,
                created,
                modified
            )

    def get_campaign(self, id):
        self.log('Getting campaign ' + id + '...')
        query = """
            query Campaign($id: String!) {
                campaign(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    objective
                    first_seen
                    last_seen
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['campaign']

    def get_campaigns(self, limit=10000):
        self.log('Getting campaigns...')
        query = """
            query Campaigns($first: Int) {
                campaigns(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            objective
                            first_seen
                            last_seen
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['campaigns'])

    def create_campaign(self,
                        name,
                        description,
                        objective=None,
                        first_seen=None,
                        last_seen=None,
                        id=None,
                        stix_id=None,
                        created=None,
                        modified=None
                        ):
        self.log('Creating campaign ' + name + '...')
        query = """
            mutation CampaignAdd($input: CampaignAddInput) {
                campaignAdd(input: $input) {
                    id
                    entity_type
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'objective': objective,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['campaignAdd']

    def create_campaign_if_not_exists(self,
                                      name,
                                      description,
                                      objective=None,
                                      first_seen=None,
                                      last_seen=None,
                                      id=None,
                                      stix_id=None,
                                      created=None,
                                      modified=None
                                      ):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Campaign')
        if object_result is not None:
            return object_result
        else:
            return self.create_campaign(
                name,
                description,
                objective,
                first_seen,
                last_seen,
                id,
                stix_id,
                created,
                modified
            )

    def get_incident(self, id):
        self.log('Getting incident ' + id + '...')
        query = """
            query Incident($id: String!) {
                incident(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    objective
                    first_seen
                    last_seen
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['incident']

    def get_incidents(self, limit=10000):
        self.log('Getting incidents...')
        query = """
            query Incidents($first: Int) {
                incidents(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            objective
                            first_seen
                            last_seen
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['incidents'])

    def create_incident(self,
                        name,
                        description,
                        objective=None,
                        first_seen=None,
                        last_seen=None,
                        id=None,
                        stix_id=None,
                        created=None,
                        modified=None
                        ):
        self.log('Creating incident ' + name + '...')
        query = """
           mutation IncidentAdd($input: IncidentAddInput) {
               incidentAdd(input: $input) {
                   id
                   entity_type
                   alias
               }
           }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'objective': objective,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['incidentAdd']

    def create_incident_if_not_exists(self,
                                      name,
                                      description,
                                      objective=None,
                                      first_seen=None,
                                      last_seen=None,
                                      id=None,
                                      stix_id=None,
                                      created=None,
                                      modified=None
                                      ):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Incident')
        if object_result is not None:
            self.update_stix_domain_entity_field(object_result['id'], 'name', name)
            description is not None and self.update_stix_domain_entity_field(object_result['id'], 'description',
                                                                             description)
            first_seen is not None and self.update_stix_domain_entity_field(object_result['id'], 'first_seen',
                                                                            first_seen)
            last_seen is not None and self.update_stix_domain_entity_field(object_result['id'], 'last_seen', last_seen)
            return object_result
        else:
            return self.create_incident(
                name,
                description,
                objective,
                first_seen,
                last_seen,
                id,
                stix_id,
                created,
                modified
            )

    def get_malware(self, id):
        self.log('Getting malware ' + id + '...')
        query = """
            query Malware($id: String!) {
                malware(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                    killChainPhases {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                kill_chain_name
                                phase_name
                                phase_order
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['malware']

    def get_malwares(self, limit=10000):
        self.log('Getting malwares...')
        query = """
            query Malwares($first: Int) {
                malwares(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                            killChainPhases {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        kill_chain_name
                                        phase_name
                                        phase_order
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['malwares'])

    def create_malware(self, name, description, id=None, stix_id=None, created=None, modified=None):
        self.log('Creating malware ' + name + '...')
        query = """
            mutation MalwareAdd($input: MalwareAddInput) {
                malwareAdd(input: $input) {
                   id
                   entity_type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['malwareAdd']

    def create_malware_if_not_exists(self, name, description, id=None, stix_id=None, created=None, modified=None):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Malware')
        if object_result is not None:
            return object_result
        else:
            return self.create_malware(
                name,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def get_tool(self, id):
        self.log('Getting tool ' + id + '...')
        query = """
            query Tool($id: String!) {
                tool(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    tool_version
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['tool']

    def get_tools(self, limit=10000):
        self.log('Getting tools...')
        query = """
            query Tools($first: Int) {
                tools(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            tool_version
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['tools'])

    def create_tool(self, name, description, id=None, stix_id=None, created=None, modified=None):
        self.log('Creating tool ' + name + '...')
        query = """
            mutation ToolAdd($input: ToolAddInput) {
                toolAdd(input: $input) {
                   id
                   entity_type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['toolAdd']

    def create_tool_if_not_exists(self, name, description, id=None, stix_id=None, created=None, modified=None):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Tool')
        if object_result is not None:
            return object_result
        else:
            return self.create_tool(
                name,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def get_vulnerability(self, id):
        self.log('Getting vulnerability ' + id + '...')
        query = """
            query Vulnerability($id: String!) {
                vulnerability(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['vulnerability']

    def get_vulnerabilities(self, limit=10000):
        self.log('Getting vulnerabilities...')
        query = """
            query Vulnerabilities($first: Int) {
                vulnerabilities(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['vulnerabilities'])

    def create_vulnerability(self, name, description, id=None, stix_id=None, created=None, modified=None):
        self.log('Creating tool ' + name + '...')
        query = """
            mutation VulnerabilityAdd($input: VulnerabilityAddInput) {
                vulnerabilityAdd(input: $input) {
                   id
                   entity_type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['vulnerabilityAdd']

    def create_vulnerability_if_not_exists(self, name, description, id=None, stix_id=None, created=None, modified=None):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Vulnerability')
        if object_result is not None:
            return object_result
        else:
            return self.create_vulnerability(
                name,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def get_attack_pattern(self, id):
        self.log('Getting attack pattern ' + id + '...')
        query = """
            query AttackPattern($id: String!) {
                attackPattern(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    platform
                    required_permission
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                    killChainPhases {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                kill_chain_name
                                phase_name
                                phase_order
                                created
                                modified
                            }
                        }
                    }
                    externalReferences {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                source_name
                                description
                                url
                                hash
                                external_id
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['attackPattern']

    def get_attack_patterns(self, limit=10000):
        self.log('Getting attack patterns...')
        query = """
            query AttackPatterns($first: Int) {
                attackPatterns(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            platform
                            required_permission
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                            killChainPhases {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        kill_chain_name
                                        phase_name
                                        phase_order
                                        created
                                        modified
                                    }
                                }
                            }
                            externalReferences {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        source_name
                                        description
                                        url
                                        hash
                                        external_id
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['attackPatterns'])

    def create_attack_pattern(self,
                              name,
                              description,
                              platform=None,
                              required_permission=None,
                              id=None,
                              stix_id=None,
                              created=None,
                              modified=None):
        self.log('Creating attack pattern ' + name + '...')
        query = """
           mutation AttackPatternAdd($input: AttackPatternAddInput) {
               attackPatternAdd(input: $input) {
                   id
                   entity_type
                   alias
               }
           }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'platform': platform,
                'required_permission': required_permission,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['attackPatternAdd']

    def create_attack_pattern_if_not_exists(self,
                                            name,
                                            description,
                                            platform=None,
                                            required_permission=None,
                                            id=None,
                                            stix_id=None,
                                            created=None,
                                            modified=None):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Attack-Pattern')
        if object_result is not None:
            return object_result
        else:
            return self.create_attack_pattern(
                name,
                description,
                platform,
                required_permission,
                id,
                stix_id,
                created,
                modified
            )

    def get_course_of_action(self, id):
        self.log('Getting course of action ' + id + '...')
        query = """
            query CourseOfAction($id: String!) {
                courseOfAction(id: $id) {
                    id
                    stix_id
                    stix_label
                    name
                    alias
                    description
                    created
                    modified
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['courseOfAction']

    def get_course_of_actions(self, limit=10000):
        self.log('Getting course of actions...')
        query = """
            query CourseOfActions($first: Int) {
                courseOfActions(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['courseOfActions'])

    def create_course_of_action(self, name, description, id=None, stix_id=None, created=None, modified=None):
        self.log('Creating course of action ' + name + '...')
        query = """
           mutation CourseOfActionAdd($input: CourseOfActionAddInput) {
               courseOfActionAdd(input: $input) {
                   id
                   entity_type
                   alias
               }
           }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['courseOfActionAdd']

    def create_course_of_action_if_not_exists(self, name, description, id=None, stix_id=None, created=None,
                                              modified=None):
        object_result = self.check_existing_stix_domain_entity(stix_id, name, 'Course-Of-Action')
        if object_result is not None:
            return object_result
        else:
            return self.create_course_of_action(
                name,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def get_report(self, id):
        self.log('Getting report ' + id + '...')
        query = """
            query Report($id: String!) {
                report(id: $id) {
                    id
                    stix_id
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
                    createdByRef {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                    externalReferences {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                source_name
                                description
                                url
                                hash
                                external_id
                                created
                                modified
                            }
                        }
                    }
                    objectRefs {
                        edges {
                            node {
                                id
                                stix_id
                                entity_type
                            }
                        }
                    }
                    observableRefs {
                        edges {
                            node {
                                id
                                stix_id
                                entity_type
                            }
                        }
                    }
                    relationRefs {
                        edges {
                            node {
                                id
                                stix_id
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['report']

    def get_reports(self, limit=10000):
        self.log('Getting reports...')
        query = """
            query Reports($first: Int) {
                reports(first: $first) {
                    edges {
                        node {
                            id
                            stix_id
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
                            createdByRef {
                                node {
                                    id
                                    entity_type
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                            externalReferences {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        source_name
                                        description
                                        url
                                        hash
                                        external_id
                                        created
                                        modified
                                    }
                                }
                            }
                            objectRefs {
                                edges {
                                    node {
                                        id
                                        stix_id
                                    }
                                }
                            }
                            relationRefs {
                                edges {
                                    node {
                                        id
                                        stix_id
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['reports'])

    def create_report(self,
                      name,
                      description,
                      published,
                      report_class,
                      object_status=None,
                      source_confidence_level=None,
                      graph_data=None,
                      id=None,
                      stix_id=None,
                      created=None,
                      modified=None
                      ):
        self.log('Creating report ' + name + '...')
        query = """
           mutation ReportAdd($input: ReportAddInput) {
               reportAdd(input: $input) {
                   id
                   entity_type
                   alias
               }
           }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'published': published,
                'report_class': report_class,
                'object_status': object_status,
                'source_confidence_level': source_confidence_level,
                'graph_data': graph_data,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['reportAdd']

    def create_report_if_not_exists(self,
                                    name,
                                    description,
                                    published,
                                    report_class,
                                    object_status=None,
                                    source_confidence_level=None,
                                    graph_data=None,
                                    id=None,
                                    stix_id=None,
                                    created=None,
                                    modified=None
                                    ):
        if stix_id is not None:
            object_result = self.get_stix_domain_entity_by_stix_id(stix_id)
        else:
            object_result = None
        if object_result is not None:
            return object_result
        else:
            return self.create_report(
                name,
                description,
                published,
                report_class,
                object_status,
                source_confidence_level,
                graph_data,
                id,
                stix_id,
                created,
                modified
            )

    def create_report_if_not_exists_from_external_reference(self,
                                                            external_reference_id,
                                                            name,
                                                            description,
                                                            published,
                                                            report_class,
                                                            object_status=None,
                                                            source_confidence_level=None,
                                                            graph_data=None,
                                                            id=None,
                                                            stix_id=None,
                                                            created=None,
                                                            modified=None
                                                            ):
        object_result = self.get_stix_domain_entity_by_external_reference(external_reference_id, 'Report')
        if object_result is not None:
            return object_result
        else:
            report = self.create_report(
                name,
                description,
                published,
                report_class,
                object_status,
                source_confidence_level,
                graph_data,
                id,
                stix_id,
                created,
                modified
            )
            self.add_external_reference_if_not_exists(report['id'], external_reference_id)
            return report

    def get_stix_observable(self, id):
        self.log('Getting observable ' + id + '...')
        query = """
            query StixObservable($id: String!) {
                stixObservable(id: $id) {
                    id
                    stix_id
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
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                        }
                    }
                    markingDefinitions {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                definition_type
                                definition
                                level
                                color
                                created
                                modified
                            }
                        }
                    }
                    externalReferences {
                        edges {
                            node {
                                id
                                entity_type
                                stix_id
                                source_name
                                description
                                url
                                hash
                                external_id
                                created
                                modified
                            }
                        }
                    }
                    stixRelations {
                        edges {
                            node {
                                id
                                stix_id
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
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['stixObservable']

    def get_stix_observable_by_value(self, observable_value):
        self.log('Getting observable ' + observable_value + '...')
        query = """
            query StixObservables($observableValue: String!) {
                stixObservables(observableValue: $observableValue) {
                    edges {
                        node {
                           id
                            stix_id
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
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                            stixRelations {
                                edges {
                                    node {
                                        id
                                        stix_id
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
                        }
                    }
                }
            }
        """
        result = self.query(query, {'observableValue': observable_value})
        if len(result['data']['stixObservables']['edges']) > 0:
            return result['data']['stixObservables']['edges'][0]['node']
        else:
            return None

    def get_stix_observables(self, limit=10000):
        self.log('Getting observables...')
        query = """
            query StixObservables($first: Int) {
                stixObservables(first: $first) {
                    edges {
                        node {
                           id
                            stix_id
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
                                    stix_id
                                    stix_label
                                    name
                                    alias
                                    description
                                    created
                                    modified
                                }
                            }
                            markingDefinitions {
                                edges {
                                    node {
                                        id
                                        entity_type
                                        stix_id
                                        definition_type
                                        definition
                                        level
                                        color
                                        created
                                        modified
                                    }
                                }
                            }
                            stixRelations {
                                edges {
                                    node {
                                        id
                                        stix_id
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
                        }
                    }
                }
            }
        """
        result = self.query(query, {'first': limit})
        return self.parse_multiple(result['data']['stixObservables'])

    def create_stix_observable(self,
                               type,
                               observable_value,
                               description,
                               id=None,
                               stix_id=None,
                               created=None,
                               modified=None
                               ):
        self.log('Creating observable ' + observable_value + '...')
        query = """
           mutation StixObservableAdd($input: StixObservableAddInput) {
               stixObservableAdd(input: $input) {
                   id
                   entity_type
                   observable_value
               }
           }
        """
        result = self.query(query, {
            'input': {
                'type': type,
                'observable_value': observable_value,
                'description': description,
                'internal_id': id,
                'stix_id': stix_id,
                'created': created,
                'modified': modified
            }
        })
        return result['data']['stixObservableAdd']

    def create_stix_observable_if_not_exists(self,
                                             type,
                                             observable_value,
                                             description,
                                             id=None,
                                             stix_id=None,
                                             created=None,
                                             modified=None
                                             ):
        object_result = self.get_stix_observable_by_value(observable_value)
        if object_result is not None:
            return object_result
        else:
            return self.create_stix_observable(
                type,
                observable_value,
                description,
                id,
                stix_id,
                created,
                modified
            )

    def update_stix_domain_entity_created_by_ref(self, object_id, identity_id):
        query = """
            query StixDomainEntity($id: String!) {
                stixDomainEntity(id: $id) {
                    id
                    createdByRef {
                        node {
                            id
                        }
                        relation {
                            id
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': object_id})
        current_identity_id = None
        current_relation_id = None
        if result['data']['stixDomainEntity']['createdByRef'] is not None:
            current_identity_id = result['data']['stixDomainEntity']['createdByRef']['node']['id']
            current_relation_id = result['data']['stixDomainEntity']['createdByRef']['relation']['id']

        if current_identity_id == identity_id:
            return identity_id
        else:
            if current_relation_id is not None:
                query = """
                   mutation StixDomainEntityEdit($id: ID!, $relationId: ID!) {
                       stixDomainEntityEdit(id: $id) {
                            relationDelete(relationId: $relationId) {
                                node {
                                    id
                                }
                            }
                       }
                   }
                """
                self.query(query, {'id': object_id, 'relationId': current_relation_id})
            query = """
               mutation StixDomainEntityEdit($id: ID!, $input: RelationAddInput) {
                   stixDomainEntityEdit(id: $id) {
                        relationAdd(input: $input) {
                            node {
                                id
                            }
                        }
                   }
               }
            """
            variables = {
                'id': object_id,
                'input': {
                    'fromRole': 'so',
                    'toId': identity_id,
                    'toRole': 'creator',
                    'through': 'created_by_ref'
                }
            }
            self.query(query, variables)

    def update_stix_observable_created_by_ref(self, object_id, identity_id):
        query = """
            query StixObservable($id: String!) {
                stixObservable(id: $id) {
                    id
                    createdByRef {
                        node {
                            id
                        }
                        relation {
                            id
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': object_id})
        current_identity_id = None
        current_relation_id = None
        if result['data']['stixObservable']['createdByRef'] is not None:
            current_identity_id = result['data']['stixObservable']['createdByRef']['node']['id']
            current_relation_id = result['data']['stixObservable']['createdByRef']['relation']['id']

        if current_identity_id == identity_id:
            return identity_id
        else:
            if current_relation_id is not None:
                query = """
                   mutation StixObservableEdit($id: ID!, $relationId: ID!) {
                       stixObservableEdit(id: $id) {
                            relationDelete(relationId: $relationId) {
                                node {
                                    id
                                }
                            }
                       }
                   }
                """
                self.query(query, {'id': object_id, 'relationId': current_relation_id})
            query = """
               mutation StixObservableEdit($id: ID!, $input: RelationAddInput) {
                   stixObservableEdit(id: $id) {
                        relationAdd(input: $input) {
                            node {
                                id
                            }
                        }
                   }
               }
            """
            variables = {
                'id': object_id,
                'input': {
                    'fromRole': 'so',
                    'toId': identity_id,
                    'toRole': 'creator',
                    'through': 'created_by_ref'
                }
            }
            self.query(query, variables)

    def add_marking_definition_if_not_exists(self, object_id, marking_definition_id):
        query = """
            query MarkingDefinitions($objectId: String!) {
                markingDefinitions(objectId: $objectId) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
        """
        result = self.query(query, {'objectId': object_id})
        markings_ids = []
        for marking in result['data']['markingDefinitions']['edges']:
            markings_ids.append(marking['node']['id'])

        if marking_definition_id in markings_ids:
            return True
        else:
            query = """
               mutation MarkingDefinitionAddRelation($id: ID!, $input: RelationAddInput) {
                   markingDefinitionEdit(id: $id) {
                        relationAdd(input: $input) {
                            node {
                                id
                            }
                        }
                   }
               }
            """
            self.query(query, {
                'id': marking_definition_id,
                'input': {
                    'fromRole': 'marking',
                    'toId': object_id,
                    'toRole': 'so',
                    'through': 'object_marking_refs'
                }
            })
            return True

    def add_kill_chain_phase_if_not_exists(self, object_id, kill_chain_phase_id):
        query = """
            query KillChainPhases($objectId: String!) {
                killChainPhases(objectId: $objectId) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
        """
        result = self.query(query, {'objectId': object_id})
        kill_chain_phases_ids = []
        for kill_chain_phase in result['data']['killChainPhases']['edges']:
            kill_chain_phases_ids.append(kill_chain_phase['node']['id'])

        if kill_chain_phase_id in kill_chain_phases_ids:
            return True
        else:
            query = """
               mutation ExternalReferenceAddRelation($id: ID!, $input: RelationAddInput) {
                   externalReferenceEdit(id: $id) {
                        relationAdd(input: $input) {
                            node {
                                id
                            }
                        }
                   }
               }
            """
            self.query(query, {
                'id': kill_chain_phase_id,
                'input': {
                    'fromRole': 'kill_chain_phase',
                    'toId': object_id,
                    'toRole': 'phase_belonging',
                    'through': 'kill_chain_phases'
                }
            })
            return True

    def add_external_reference_if_not_exists(self, object_id, external_reference_id):
        query = """
            query ExternalReference($objectId: String!) {
                externalReferences(objectId: $objectId) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
        """
        result = self.query(query, {'objectId': object_id})
        refs_ids = []
        for ref in result['data']['externalReferences']['edges']:
            refs_ids.append(ref['node']['id'])

        if external_reference_id in refs_ids:
            return True
        else:
            query = """
               mutation ExternalReferenceAddRelation($id: ID!, $input: RelationAddInput) {
                   externalReferenceEdit(id: $id) {
                        relationAdd(input: $input) {
                            node {
                                id
                            }
                        }
                   }
               }
            """
            self.query(query, {
                'id': external_reference_id,
                'input': {
                    'fromRole': 'external_reference',
                    'toId': object_id,
                    'toRole': 'so',
                    'through': 'external_references'
                }
            })
            return True

    def add_object_ref_to_report_if_not_exists(self, report_id, object_id):
        query = """
            query Report($id: String!) {
                report(id: $id) {
                    id
                    objectRefs {
                        edges {
                            node {
                                id
                            }
                        }
                    }
                    observableRefs {
                        edges {
                            node {
                                id
                            }
                        }
                    }
                    relationRefs {
                        edges {
                            node {
                                id
                            }
                        }
                    }
                }
            }
        """
        result = self.query(query, {'id': report_id})
        refs_ids = []
        for ref in result['data']['report']['objectRefs']['edges']:
            refs_ids.append(ref['node']['id'])
        for ref in result['data']['report']['observableRefs']['edges']:
            refs_ids.append(ref['node']['id'])
        for ref in result['data']['report']['relationRefs']['edges']:
            refs_ids.append(ref['node']['id'])
        if object_id in refs_ids:
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
            self.query(query, {
                'id': report_id,
                'input': {
                    'fromRole': 'knowledge_aggregation',
                    'toId': object_id,
                    'toRole': 'so',
                    'through': 'object_refs'
                }
            })
            return True

    def resolve_role(self, relation_type, from_type, to_type):
        if relation_type == 'related-to':
            return {'from_role': 'relate_from', 'to_role': 'relate_to'}

        relation_type = relation_type.lower()
        from_type = from_type.lower()
        to_type = to_type.lower()
        mapping = {
            'uses': {
                'threat-actor': {
                    'malware': {'from_role': 'user', 'to_role': 'usage'},
                    'tool': {'from_role': 'user', 'to_role': 'usage'},
                    'attack-pattern': {'from_role': 'user', 'to_role': 'usage'}
                },
                'intrusion-set': {
                    'malware': {'from_role': 'user', 'to_role': 'usage'},
                    'tool': {'from_role': 'user', 'to_role': 'usage'},
                    'attack-pattern': {'from_role': 'user', 'to_role': 'usage'}
                },
                'campaign': {
                    'malware': {'from_role': 'user', 'to_role': 'usage'},
                    'tool': {'from_role': 'user', 'to_role': 'usage'},
                    'attack-pattern': {'from_role': 'user', 'to_role': 'usage'}
                },
                'incident': {
                    'malware': {'from_role': 'user', 'to_role': 'usage'},
                    'tool': {'from_role': 'user', 'to_role': 'usage'},
                    'attack-pattern': {'from_role': 'user', 'to_role': 'usage'}
                },
                'malware': {
                    'tool': {'from_role': 'user', 'to_role': 'usage'},
                    'attack-pattern': {'from_role': 'user', 'to_role': 'usage'}
                },
                'tool': {
                    'attack-pattern': {'from_role': 'user', 'to_role': 'usage'}
                },
            },
            'variants-of': {
                'malware': {
                    'malware': {'from_role': 'original', 'to_role': 'variation'},
                },
                'tool': {
                    'tool': {'from_role': 'original', 'to_role': 'variation'},
                },
            },
            'targets': {
                'threat-actor': {
                    'identity': {'from_role': 'source', 'to_role': 'target'},
                    'sector': {'from_role': 'source', 'to_role': 'target'},
                    'region': {'from_role': 'source', 'to_role': 'target'},
                    'country': {'from_role': 'source', 'to_role': 'target'},
                    'city': {'from_role': 'source', 'to_role': 'target'},
                    'organization': {'from_role': 'source', 'to_role': 'target'},
                    'vulnerability': {'from_role': 'source', 'to_role': 'target'},
                },
                'intrusion-set': {
                    'identity': {'from_role': 'source', 'to_role': 'target'},
                    'sector': {'from_role': 'source', 'to_role': 'target'},
                    'region': {'from_role': 'source', 'to_role': 'target'},
                    'country': {'from_role': 'source', 'to_role': 'target'},
                    'city': {'from_role': 'source', 'to_role': 'target'},
                    'organization': {'from_role': 'source', 'to_role': 'target'},
                    'vulnerability': {'from_role': 'source', 'to_role': 'target'},
                },
                'campaign': {
                    'identity': {'from_role': 'source', 'to_role': 'target'},
                    'sector': {'from_role': 'source', 'to_role': 'target'},
                    'region': {'from_role': 'source', 'to_role': 'target'},
                    'country': {'from_role': 'source', 'to_role': 'target'},
                    'city': {'from_role': 'source', 'to_role': 'target'},
                    'organization': {'from_role': 'source', 'to_role': 'target'},
                    'vulnerability': {'from_role': 'source', 'to_role': 'target'},
                },
                'incident': {
                    'identity': {'from_role': 'source', 'to_role': 'target'},
                    'sector': {'from_role': 'source', 'to_role': 'target'},
                    'region': {'from_role': 'source', 'to_role': 'target'},
                    'country': {'from_role': 'source', 'to_role': 'target'},
                    'city': {'from_role': 'source', 'to_role': 'target'},
                    'organization': {'from_role': 'source', 'to_role': 'target'},
                    'vulnerability': {'from_role': 'source', 'to_role': 'target'},
                },
                'malware': {
                    'identity': {'from_role': 'source', 'to_role': 'target'},
                    'sector': {'from_role': 'source', 'to_role': 'target'},
                    'region': {'from_role': 'source', 'to_role': 'target'},
                    'country': {'from_role': 'source', 'to_role': 'target'},
                    'city': {'from_role': 'source', 'to_role': 'target'},
                    'organization': {'from_role': 'source', 'to_role': 'target'},
                    'vulnerability': {'from_role': 'source', 'to_role': 'target'},
                },
            },
            'attributed-to': {
                'threat-actor': {
                    'identity': {'from_role': 'attribution', 'to_role': 'origin'},
                    'organization': {'from_role': 'attribution', 'to_role': 'origin'},
                },
                'intrusion-set': {
                    'identity': {'from_role': 'attribution', 'to_role': 'origin'},
                    'threat-actor': {'from_role': 'attribution', 'to_role': 'origin'},
                },
                'campaign': {
                    'identity': {'from_role': 'attribution', 'to_role': 'origin'},
                    'threat-actor': {'from_role': 'attribution', 'to_role': 'origin'},
                    'intrusion-set': {'from_role': 'attribution', 'to_role': 'origin'},
                },
                'incident': {
                    'identity': {'from_role': 'attribution', 'to_role': 'origin'},
                    'threat-actor': {'from_role': 'attribution', 'to_role': 'origin'},
                    'intrusion-set': {'from_role': 'attribution', 'to_role': 'origin'},
                    'campaign': {'from_role': 'attribution', 'to_role': 'origin'},
                },
            },
            'mitigates': {
                'course-of-action': {
                    'attack-pattern': {'from_role': 'mitigation', 'to_role': 'problem'}
                }
            },
            'localization': {
                'country': {
                    'region': {'from_role': 'localized', 'to_role': 'location'}
                },
                'city': {
                    'country': {'from_role': 'localized', 'to_role': 'location'}
                },
                'organization': {
                    'region': {'from_role': 'localized', 'to_role': 'location'},
                    'country': {'from_role': 'localized', 'to_role': 'location'},
                    'city': {'from_role': 'localized', 'to_role': 'location'}
                },
            },
            'indicates': {
                'observable': {
                    'threat-actor': {'from_role': 'indicator', 'to_role': 'characterize'},
                    'intrusion-set': {'from_role': 'indicator', 'to_role': 'characterize'},
                    'campaign': {'from_role': 'indicator', 'to_role': 'characterize'},
                    'malware': {'from_role': 'indicator', 'to_role': 'characterize'},
                    'tool': {'from_role': 'indicator', 'to_role': 'characterize'},
                }
            },
            'gathering': {
                'sector': {
                    'sector': {'from_role': 'gather', 'to_role': 'part_of'},
                    'organization': {'from_role': 'gather', 'to_role': 'part_of'},
                }
            }
        }
        if relation_type in mapping and from_type in mapping[relation_type] and to_type in mapping[relation_type][
            from_type]:
            return mapping[relation_type][from_type][to_type]
        else:
            return None

    def stix2_import_bundle_from_file(self, file_path, update=False, types=[]):
        if not os.path.isfile(file_path):
            self.log('The bundle file does not exists')
            return None

        with open(os.path.join(file_path)) as file:
            data = json.load(file)

        stix2 = OpenCTIStix2(self)
        stix2.import_bundle(data, update, types)

    def stix2_import_bundle(self, json_data, update=False, types=[]):
        data = json.loads(json_data)
        stix2 = OpenCTIStix2(self)
        stix2.import_bundle(data, update, types)

    def stix2_export_entity(self, entity_type, entity_id, mode='simple'):
        stix2 = OpenCTIStix2(self)
        bundle = {
            'type': 'bundle',
            'id': 'bundle--' + str(uuid.uuid4()),
            'spec_version': '2.0',
            'objects': []
        }
        if entity_type == 'report':
            bundle['objects'] = stix2.export_report(self.parse_stix(self.get_report(entity_id)), mode)
        if entity_type == 'threat-actor':
            bundle['objects'] = stix2.export_threat_actor(self.parse_stix(self.get_threat_actor(entity_id)))

        return bundle

    def stix2_export_bundle(self, types=[]):
        stix2 = OpenCTIStix2(self)
        uuids = []
        bundle = {
            'type': 'bundle',
            'id': 'bundle--' + str(uuid.uuid4()),
            'spec_version': '2.0',
            'objects': []
        }

        if 'Identity' in types:
            identities = self.get_identities()
            for identity in identities:
                if identity['entity_type'] != 'threat-actor':
                    identity_bundle = stix2.filter_objects(uuids, stix2.export_identity(identity))
                    uuids = uuids + [x['id'] for x in identity_bundle]
                    bundle['objects'] = bundle['objects'] + identity_bundle
        if 'Threat-Actor' in types:
            threat_actors = self.get_threat_actors()
            for threat_actor in threat_actors:
                threat_actor_bundle = stix2.filter_objects(uuids, stix2.export_threat_actor(threat_actor))
                uuids = uuids + [x['id'] for x in threat_actor_bundle]
                bundle['objects'] = bundle['objects'] + threat_actor_bundle
        if 'Intrusion-Set' in types:
            intrusion_sets = self.get_intrusion_sets()
            for intrusion_set in intrusion_sets:
                intrusion_set_bundle = stix2.filter_objects(uuids, stix2.export_intrusion_set(intrusion_set))
                uuids = uuids + [x['id'] for x in intrusion_set_bundle]
                bundle['objects'] = bundle['objects'] + intrusion_set_bundle
        if 'Campaign' in types:
            campaigns = self.get_campaigns()
            for campaign in campaigns:
                campaign_bundle = stix2.filter_objects(uuids, stix2.export_campaign(campaign))
                uuids = uuids + [x['id'] for x in campaign_bundle]
                bundle['objects'] = bundle['objects'] + campaign_bundle
        if 'Incident' in types:
            incidents = self.get_incidents()
            for incident in incidents:
                incident_bundle = stix2.filter_objects(uuids, stix2.export_incident(incident))
                uuids = uuids + [x['id'] for x in incident_bundle]
                bundle['objects'] = bundle['objects'] + incident_bundle
        if 'Malware' in types:
            malwares = self.get_malwares()
            for malware in malwares:
                malware_bundle = stix2.filter_objects(uuids, stix2.export_malware(malware))
                uuids = uuids + [x['id'] for x in malware_bundle]
                bundle['objects'] = bundle['objects'] + malware_bundle
        if 'Tool' in types:
            tools = self.get_tools()
            for tool in tools:
                tool_bundle = stix2.filter_objects(uuids, stix2.export_tool(tool))
                uuids = uuids + [x['id'] for x in tool_bundle]
                bundle['objects'] = bundle['objects'] + tool_bundle
        if 'Vulnerability' in types:
            vulnerabilities = self.get_vulnerabilities()
            for vulnerability in vulnerabilities:
                vulnerability_bundle = stix2.filter_objects(uuids, stix2.export_vulnerability(vulnerability))
                uuids = uuids + [x['id'] for x in vulnerability_bundle]
                bundle['objects'] = bundle['objects'] + vulnerability_bundle
        if 'Attack-Pattern' in types:
            attack_patterns = self.get_attack_patterns()
            for attack_pattern in attack_patterns:
                attack_pattern_bundle = stix2.filter_objects(uuids, stix2.export_attack_pattern(attack_pattern))
                uuids = uuids + [x['id'] for x in attack_pattern_bundle]
                bundle['objects'] = bundle['objects'] + attack_pattern_bundle
        if 'Course-Of-Action' in types:
            course_of_actions = self.get_course_of_actions()
            for course_of_action in course_of_actions:
                course_of_action_bundle = stix2.filter_objects(uuids,
                                                               stix2.export_course_of_action(course_of_action))
                uuids = uuids + [x['id'] for x in course_of_action_bundle]
                bundle['objects'] = bundle['objects'] + course_of_action_bundle
        if 'Report' in types:
            reports = self.get_reports()
            for report in reports:
                report_bundle = stix2.filter_objects(uuids, stix2.export_report(report))
                uuids = uuids + [x['id'] for x in report_bundle]
                bundle['objects'] = bundle['objects'] + report_bundle
        if 'Relationship' in types:
            stix_relations = self.get_stix_relations()
            for stix_relation in stix_relations:
                stix_relation_bundle = stix2.filter_objects(uuids, stix2.export_stix_relation(stix_relation))
                uuids = uuids + [x['id'] for x in stix_relation_bundle]
                bundle['objects'] = bundle['objects'] + stix_relation_bundle
        return bundle
