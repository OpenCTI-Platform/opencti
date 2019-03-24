# coding: utf-8

import os
import requests
import datetime
import json

from pycti.stix2 import Stix2

class OpenCti:
    """
        Python API for OpenCTI
        :param url: OpenCTI URL
        :param key: The API key
        :param verbose: Log all requests. Defaults to None
    """

    def __init__(self, url, key, verbose=True):
        self.verbose = verbose
        self.api_url = url + '/graphql'
        self.request_headers = {
            'Authorization': 'Bearer ' + key,
            'Content-Type': 'application/json'
        }

    def log(self, message):
        if self.verbose:
            print(message)

    def query(self, query, variables):
        r = requests.post(self.api_url, json={'query': query, 'variables': variables}, headers=self.request_headers)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            print(r.text)

    def parse_multiple(self, data):
        result = []
        for edge in data['edges']:
            result.append(edge['node'])
        return result

    def get_stix_domain_entity(self, id):
        """
            :param id: StixDomain entity identifier
            :return: StixDomainEntity
        """

        query = """
            query StixDomainEntity($id: String) {
                stixDomainEntity(id: $id) {
                    id
                    type
                    alias
                }
            }
        """
        result = self.query(query, {'id': id})
        return result['data']['stixDomainEntity']

    def get_stix_domain_entity_by_external_reference(self, id, type):
        query = """
            query StixDomainEntities($externalReferenceId: String, $type: String) {
                stixDomainEntities(externalReferenceId: $externalReferenceId, type: $type) {
                    edges {
                        node {
                            id
                            type
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
                            type
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
                            type
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

    def search_stix_domain_entities(self, name_or_alias, type='Stix-Domain-Entity'):
        query = """
               query StixDomainEntities($search: String, $type: String) {
                   stixDomainEntities(search: $search, type: $type) {
                       edges {
                           node {
                               id
                               type
                               alias
                           }
                       }
                   }
               }
           """
        result = self.query(query, {'search': name_or_alias, 'type': type})
        return self.parse_multiple(result['data']['stixDomainEntities'])

    def search_stix_domain_entity(self, name_or_alias, type='Stix-Domain-Entity'):
        result = self.search_stix_domain_entities(name_or_alias, type)
        if len(result) > 0:
            return result[0]
        else:
            return None

    def update_stix_domain_entity_field(self, id, key, value):
        self.log('Updating field ' + key + '...')
        query = """
            mutation StixDomainEntityEdit($id: ID!, $input: EditInput!) {
                stixDomainEntityEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                        type
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
        query = """
            query StixRelations($stix_id: String) {
                stixRelations(stix_id: $stix_id) {
                    edges {
                        node {
                            id
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

    def get_stix_relations(self, from_id, to_id, type='stix_relation', first_seen=None, last_seen=None):
        try:
            first_seen = datetime.datetime.strptime(first_seen, '%Y-%m-%d')
            first_seen_start = (first_seen + datetime.timedelta(days=-1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
            first_seen_stop = (first_seen + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
            last_seen = datetime.datetime.strptime(last_seen, '%Y-%m-%d')
            last_seen_start = (last_seen + datetime.timedelta(days=-1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
            last_seen_stop = (last_seen + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
        except:
            first_seen_start = None
            first_seen_stop = None
            last_seen_start = None
            last_seen_stop = None

        query = """
            query StixRelations($fromId: String, $toId: String, $relationType: String, $firstSeenStart, $firstSeenStop, $lastSeenStart, $lastSeenStop) {
                stixRelations(fromId: $fromId, toId: $toId, relationType: $relationType, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop) {
                    edges {
                        node {
                            id
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
            'lastSeenStop': last_seen_stop
        })
        return self.parse_multiple(result['data']['stixRelations'])

    def get_stix_relation(self, from_id, to_id, type='stix_relation', first_seen=None, last_seen=None):
        result = self.get_stix_relations(from_id, to_id, type, first_seen, last_seen)
        if len(result) > 0:
            return result[0]
        else:
            return None

    def create_relation(self, from_id, from_role, to_id, to_role, type, first_seen, last_seen, weight, stix_id=None):
        try:
            first_seen = datetime.datetime.strptime(first_seen, '%Y-%m-%d')
            last_seen = datetime.datetime.strptime(last_seen, '%Y-%m-%d')
        except:
            first_seen = None
            last_seen = None

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
                'first_seen': first_seen.strftime('%Y-%m-%dT%H:%M:%S+00:00'),
                'last_seen': last_seen.strftime('%Y-%m-%dT%H:%M:%S+00:00'),
                'weight': weight,
                'stix_id': stix_id
            }
        })
        return result['data']['stixRelationAdd']

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

    def create_external_reference(self, source_name, url, external_id='', description='', stix_id=None):
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
                'stix_id': stix_id
            }
        })
        return result['data']['externalReferenceAdd']

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

    def create_kill_chain_phase(self, kill_chain_name, phase_name, stix_id=None):
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
                'phase_order': 0,
                'stix_id': stix_id
            }
        })
        return result['data']['killChainPhaseAdd']

    def create_threat_actor(self, name, description, stix_id=None):
        self.log('Creating threat actor ' + name + '...')
        query = """
            mutation ThreatActorAdd($input: ThreatActorAddInput) {
                threatActorAdd(input: $input) {
                   id
                   type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['threatActorAdd']

    def create_intrusion_set(self, name, description, stix_id=None):
        self.log('Creating intrusion set ' + name + '...')
        query = """
            mutation IntrusionSetAdd($input: IntrusionSetAddInput) {
                intrusionSetAdd(input: $input) {
                   id
                   type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['intrusionSetAdd']

    def create_campaign(self, name, description, stix_id=None):
        self.log('Creating campaign ' + name + '...')
        query = """
            mutation CampaignAdd($input: CampaignAddInput) {
                campaignAdd(input: $input) {
                    id
                    type
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['campaignAdd']

    def create_incident(self, name, description, first_seen, last_seen, stix_id=None):
        self.log('Creating incident ' + name + '...')
        query = """
           mutation IncidentAdd($input: IncidentAddInput) {
               incidentAdd(input: $input) {
                   id
                   type
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
                'stix_id': stix_id
            }
        })
        return result['data']['incidentAdd']

    def create_malware(self, name, description, stix_id=None):
        self.log('Creating malware ' + name + '...')
        query = """
            mutation MalwareAdd($input: MalwareAddInput) {
                malwareAdd(input: $input) {
                   id
                   type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['malwareAdd']

    def create_tool(self, name, description, stix_id=None):
        self.log('Creating tool ' + name + '...')
        query = """
            mutation ToolAdd($input: ToolAddInput) {
                toolAdd(input: $input) {
                   id
                   type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['toolAdd']

    def create_vulnerability(self, name, description, stix_id=None):
        self.log('Creating tool ' + name + '...')
        query = """
            mutation VulnerabilityAdd($input: VulnerabilityAddInput) {
                vulnerabilityAdd(input: $input) {
                   id
                   type
                   alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['vulnerabilityAdd']

    def create_attack_pattern(self, name, description, platform, required_permission, stix_id=None):
        self.log('Creating attack pattern ' + name + '...')
        query = """
           mutation AttackPatternAdd($input: AttackPatternAddInput) {
               attackPatternAdd(input: $input) {
                   id
                   type
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
                'stix_id': stix_id
            }
        })
        return result['data']['attackPatternAdd']

    def create_course_of_action(self, name, description, stix_id=None):
        self.log('Creating course of action ' + name + '...')
        query = """
           mutation CourseOfActionAdd($input: CourseOfActionAddInput) {
               courseOfActionAdd(input: $input) {
                   id
                   type
                   alias
               }
           }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'stix_id': stix_id
            }
        })
        return result['data']['courseOfActionAdd']

    def create_identity(self, type, name, description, stix_id=None):
        self.log('Creating identity ' + name + '...')
        query = """
            mutation IdentityAdd($input: IdentityAddInput) {
                identityAdd(input: $input) {
                    id
                    type
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'type': type,
                'stix_id': stix_id
            }
        })
        return result['data']['identityAdd']

    def update_created_by_ref(self, object_id, identity_id):
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

    def add_kill_chain_phase(self, object_id, kill_chain_phase_id):
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
            return kill_chain_phase_id
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

    def add_external_reference(self, object_id, external_reference_id):
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
            return external_reference_id
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

    def add_object_ref_to_report(self, report_id, object_id):
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
        for ref in result['data']['report']['relationRefs']['edges']:
            refs_ids.append(ref['node']['id'])
        if object_id in refs_ids:
            return object_id
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

    def resolve_role(self, relation_type, from_type, to_type):
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
            },
            'mitigates': {
                'course-of-action': {
                    'attack-pattern': {'from_role': 'mitigation', 'to_role': 'problem'}
                }
            }
        }
        if relation_type in mapping and from_type in mapping[relation_type] and to_type in mapping[relation_type][
            from_type]:
            return mapping[relation_type][from_type][to_type]
        else:
            return None

    def import_stix2_bundle(self, file_path):
        if not os.path.isfile(file_path):
            self.log('The bundle file does not exists')
            return None

        with open(os.path.join(file_path)) as file:
            data = json.load(file)

        stix2 = Stix2(self)
        stix2.import_bundle(data)
