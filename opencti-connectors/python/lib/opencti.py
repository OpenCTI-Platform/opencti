# coding: utf-8

import yaml
import requests


class OpenCti:
    def __init__(self, config):
        self.config = config
        self.verbose = self.config['opencti']['verbose']
        self.api_url = self.config['opencti']['api_url'] + '/graphql'
        self.request_headers = {
            'Authorization': 'Bearer ' + self.config['opencti']['api_key'],
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

    def get_stix_domain_entity(self, id):
        query = """
            query StixDomainEntity($id: String) {
                stixDomainEntity(id: $id) {
                    id
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

    def search_stix_domain_entity(self, nameOrAlias, type='Stix-Domain-Entity'):
        query = """
            query StixDomainEntities($search: String, $type: String) {
                stixDomainEntities(search: $search, type: $type) {
                    edges {
                        node {
                            id
                            alias
                        }
                    }
                }
            }
        """
        result = self.query(query, {'search': nameOrAlias, 'type': type})
        if len(result['data']['stixDomainEntities']['edges']) > 0:
            return result['data']['stixDomainEntities']['edges'][0]['node']
        else:
            return None

    def update_stix_domain_entity_field(self, id, key, value):
        self.log('Updating field ' + key + '...')
        query = """
            mutation StixDomainEntityEdit($id: ID!, $input: EditInput!) {
                stixDomainEntityEdit(id: $id) {
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

    def get_relations(self, fromId, toId, type='stix_relation'):
        query = """
            query StixRelations($fromId: String, $toId: String, $relationType: String) {
                stixRelations(fromId: $fromId, toId: $toId, relationType: $relationType) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }  
        """
        result = self.query(query, {
            'fromId': fromId,
            'toId': toId,
            'relationType': type
        })
        if len(result['data']['stixRelations']['edges']) > 0:
            return result['data']['stixRelations']['edges'][0]['node']
        else:
            return None

    def create_relation(self, fromId, fromRole, toId, toRole, type, first_seen, last_seen, weight):
        self.log('Creating relation ' + fromRole + ' => ' + toRole + '...')
        query = """
             mutation StixRelationAdd($input: StixRelationAddInput!) {
                 stixRelationAdd(input: $input) {
                     id
                 }
             }
         """
        result = self.query(query, {
            'input': {
                'fromId': fromId,
                'fromRole': fromRole,
                'toId': toId,
                'toRole': toRole,
                'relationship_type': type,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'weight': weight
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

    def create_external_reference(self, source_name, url, external_id='', description=''):
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
                'url': url
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

    def create_kill_chain_phase(self, kill_chain_name, phase_name):
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
                'phase_order': 0
            }
        })
        return result['data']['killChainPhaseAdd']

    def create_attack_pattern(self, name, description, platform, required_permission, kill_chain_phases_ids=[]):
        self.log('Creating attack pattern ' + name + '...')
        query = """
               mutation AttackPatternAdd($input: AttackPatternAddInput) {
                   attackPatternAdd(input: $input) {
                       id
                   }
               }
            """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'platform': platform,
                'required_permission': required_permission,
                'killChainPhases': kill_chain_phases_ids
            }
        })
        return result['data']['attackPatternAdd']

    def create_threat_actor(self, name, description):
        self.log('Creating threat actor ' + name + '...')
        query = """
            mutation ThreatActorAdd($input: ThreatActorAddInput) {
                threatActorAdd(input: $input) {
                    id
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description
            }
        })
        return result['data']['threatActorAdd']

    def create_intrusion_set(self, name, description):
        self.log('Creating intrusion set ' + name + '...')
        query = """
            mutation IntrusionSetAdd($input: IntrusionSetAddInput) {
                intrusionSetAdd(input: $input) {
                    id
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description
            }
        })
        return result['data']['intrusionSetAdd']

    def create_campaign(self, name, description):
        self.log('Creating campaign ' + name + '...')
        query = """
            mutation CampaignAdd($input: CampaignAddInput) {
                campaignAdd(input: $input) {
                    id
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description
            }
        })
        return result['data']['campaignAdd']

    def create_malware(self, name, description):
        self.log('Creating malware ' + name + '...')
        query = """
            mutation MalwareAdd($input: MalwareAddInput) {
                malwareAdd(input: $input) {
                    id
                    alias
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description
            }
        })
        return result['data']['malwareAdd']

    def create_incident(self, data):
        self.log('Creating incident ' + data['name'] + '...')
        query = """
               mutation IncidentAdd($input: IncidentAddInput) {
                   incidentAdd(input: $input) {
                       id
                   }
               }
            """
        result = self.query(query, {
            'input': data
        })
        return result['data']['incidentAdd']

    def create_identity(self, type, name, description):
        self.log('Creating identity ' + name + '...')
        query = """
            mutation IdentityAdd($input: IdentityAddInput) {
                identityAdd(input: $input) {
                    id
                }
            }
        """
        result = self.query(query, {
            'input': {
                'name': name,
                'description': description,
                'type': type
            }
        })
        return result['data']['identityAdd']

    def update_created_by_ref(self, objectId, identityId):
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
        result = self.query(query, {'id': objectId})
        current_identity_id = None
        current_relation_id = None
        if result['data']['stixDomainEntity']['createdByRef'] is not None:
            current_identity_id = result['data']['stixDomainEntity']['createdByRef']['node']['id']
            current_relation_id = result['data']['stixDomainEntity']['createdByRef']['relation']['id']

        if current_identity_id == identityId:
            return identityId
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
                self.query(query, {'id': objectId, 'relationId': current_relation_id})
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
                'id': objectId,
                'input': {
                    'fromRole': 'so',
                    'toId': identityId,
                    'toRole': 'creator',
                    'through': 'created_by_ref'
                }
            }
            self.query(query, variables)

    def add_external_reference(self, objectId, externalReferenceId):
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
        result = self.query(query, {'objectId': objectId})
        refsIds = []
        for ref in result['data']['externalReferences']['edges']:
            refsIds.append(ref['node']['id'])

        if externalReferenceId in refsIds:
            return externalReferenceId
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
                'id': externalReferenceId,
                'input': {
                    'fromRole': 'external_reference',
                    'toId': objectId,
                    'toRole': 'so',
                    'through': 'external_references'
                }
            })

    def add_object_ref_to_report(self, reportId, toId):
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
        result = self.query(query, {'id': reportId})
        refsIds = []
        for ref in result['data']['report']['objectRefs']['edges']:
            refsIds.append(ref['node']['id'])
        for ref in result['data']['report']['relationRefs']['edges']:
            refsIds.append(ref['node']['id'])
        if toId in refsIds:
            return toId
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
                'id': reportId,
                'input': {
                    'fromRole': 'knowledge_aggregation',
                    'toId': toId,
                    'toRole': 'so',
                    'through': 'object_refs'
                }
            })

    def convertMarkDown(self, text):
        return text.\
            replace('<code>', '`').\
            replace('</code>', '`')
