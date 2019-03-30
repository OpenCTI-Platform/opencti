# coding: utf-8

import time
import datetime


class Stix2:
    """
        Python API for Stix2 in OpenCTI
        :param opencti: OpenCTI instance
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.mapping_cache = {}

    def unknown_type(self, stix_object):
        self.opencti.log('Unknown object type "' + stix_object['type'] + '", doing nothing...')

    def convert_markdown(self, text):
        return text. \
            replace('<code>', '`'). \
            replace('</code>', '`')

    def prepare_export(self, entity, stix_object):
        result = []
        if 'createdByRef' in entity and entity['createdByRef'] is not None:
            entity_created_by_ref = entity['createdByRef']
            if entity_created_by_ref['type'] == 'User':
                identity_class = 'individual'
            elif entity_created_by_ref['type'] == 'Sector':
                identity_class = 'class'
            else:
                identity_class = entity_created_by_ref['type'].lower()

            created_by_ref = {
                'id': entity_created_by_ref['stix_id'],
                'type': 'identity',
                'labels': entity_created_by_ref['stix_label'],
                'name': entity_created_by_ref['name'],
                'description': entity_created_by_ref['description'],
                'identity_class': identity_class,
                'created': entity_created_by_ref['created'],
                'modified': entity_created_by_ref['modified'],
                'x_opencti_aliases': entity_created_by_ref['alias']
            }
            stix_object['created_by_ref'] = created_by_ref['id']
            result.append(created_by_ref)
        if 'markingDefinitions' in entity and len(entity['markingDefinitions']) > 0:
            marking_definitions = []
            for entity_marking_definition in entity['markingDefinitions']:
                marking_definition = {
                    'id': entity_marking_definition['stix_id'],
                    'type': 'marking-definition',
                    'definition_type': entity_marking_definition['definition_type'],
                    'definition': {
                        entity_marking_definition['definition_type']: entity_marking_definition['definition']
                    },
                    'created': entity_marking_definition['created'],
                    'modified': entity_marking_definition['modified'],
                }
                marking_definitions.append(marking_definition['id'])
                result.append(marking_definition)
            stix_object['object_marking_refs'] = marking_definitions
        if 'killChainPhases' in entity and len(entity['killChainPhases']) > 0:
            kill_chain_phases = []
            for entity_kill_chain_phase in entity['killChainPhases']:
                kill_chain_phase = {
                    'id': entity_kill_chain_phase['stix_id'],
                    'kill_chain_name': entity_kill_chain_phase['kill_chain_name'],
                    'phase_name': entity_kill_chain_phase['phase_name'],
                    'x_opencti_phase_order': entity_kill_chain_phase['phase_order'],
                    'x_opencti_created': entity_kill_chain_phase['created'],
                    'x_opencti_modified': entity_kill_chain_phase['modified'],
                }
                kill_chain_phases.append(kill_chain_phase)
            stix_object['kill_chain_phases'] = kill_chain_phases
        if 'externalReferences' in entity and len(entity['externalReferences']) > 0:
            external_references = []
            for entity_external_reference in entity['externalReferences']:
                external_reference = {
                    'id': entity_external_reference['stix_id'],
                    'source_name': entity_external_reference['source_name'],
                    'description': entity_external_reference['description'],
                    'url': entity_external_reference['url'],
                    'hash': entity_external_reference['hash'],
                    'external_id': entity_external_reference['external_id'],
                    'x_opencti_created': entity_external_reference['created'],
                    'x_opencti_modified': entity_external_reference['modified'],
                }
                external_references.append(external_reference)
            stix_object['external_references'] = external_references
        if 'objectRefs' in entity and len(entity['objectRefs']) > 0:
            object_refs = []
            for entity_object_ref in entity['objectRefs']:
                object_refs.append(entity_object_ref['stix_id'])
            if 'relationRefs' in entity and len(entity['relationRefs']) > 0:
                for entity_relation_ref in entity['relationRefs']:
                    object_refs.append(entity_relation_ref['stix_id'])
            stix_object['object_refs'] = object_refs
        result.append(stix_object)

        return result

    def import_object(self, stix_object):
        # Created By Ref
        created_by_ref_id = None
        if 'created_by_ref' in stix_object:
            created_by_ref = stix_object['created_by_ref'].replace('identity', 'organization')
            if created_by_ref in self.mapping_cache:
                created_by_ref_result = self.mapping_cache[created_by_ref]
            else:
                created_by_ref_result = self.opencti.get_stix_domain_entity_by_stix_id(created_by_ref)
            if created_by_ref_result is not None:
                self.mapping_cache[created_by_ref] = {'id': created_by_ref_result['id']}
                created_by_ref_id = created_by_ref_result['id']

        # Object Marking Refs
        marking_definitions_ids = []
        if 'object_marking_refs' in stix_object:
            for object_marking_ref in stix_object['object_marking_refs']:
                if object_marking_ref in self.mapping_cache:
                    object_marking_ref_result = self.mapping_cache[object_marking_ref]
                else:
                    object_marking_ref_result = self.opencti.get_marking_definition_by_stix_id(object_marking_ref)
                if object_marking_ref_result is not None:
                    self.mapping_cache[object_marking_ref] = {'id': object_marking_ref_result['id']}
                    marking_definitions_ids.append(object_marking_ref_result['id'])

        # External References
        external_references_ids = []
        if 'external_references' in stix_object:
            for external_reference in stix_object['external_references']:
                if 'url' in external_reference and 'source_name' in external_reference:
                    url = external_reference['url']
                    source_name = external_reference['source_name']
                else:
                    continue
                if url in self.mapping_cache:
                    external_reference_result = self.mapping_cache[url]
                else:
                    external_reference_result = self.opencti.get_external_reference_by_url(url)

                if external_reference_result is not None:
                    external_reference_id = external_reference_result['id']
                else:
                    external_reference_id = self.opencti.create_external_reference(
                        source_name,
                        url,
                        external_reference['external_id'] if 'external_id' in external_reference else None,
                        external_reference['description'] if 'description' in external_reference else None,
                        external_reference['id'] if 'id' in external_reference else None,
                        external_reference['x_opencti_created'] if 'x_opencti_created' in external_reference else None,
                        external_reference['x_opencti_modified'] if 'x_opencti_modified' in external_reference else None,
                    )['id']
                self.mapping_cache[url] = {'id': external_reference_id}
                external_references_ids.append(external_reference_id)
        # Kill Chain Phases
        kill_chain_phases_ids = []
        if 'kill_chain_phases' in stix_object:
            for kill_chain_phase in stix_object['kill_chain_phases']:
                if kill_chain_phase['phase_name'] in self.mapping_cache:
                    kill_chain_phase_result = self.mapping_cache[kill_chain_phase['phase_name']]
                else:
                    kill_chain_phase_result = self.opencti.get_kill_chain_phase(kill_chain_phase['phase_name'])
                if kill_chain_phase_result is not None:
                    kill_chain_phase_id = kill_chain_phase_result['id']
                else:
                    kill_chain_phase_id = self.opencti.create_kill_chain_phase(
                        kill_chain_phase['kill_chain_name'],
                        kill_chain_phase['phase_name'],
                        kill_chain_phase[
                            'x_opencti_phase_order'] if 'x_opencti_phase_order' in kill_chain_phase else 0,
                        kill_chain_phase['id'] if 'id' in kill_chain_phase else None,
                        kill_chain_phase['x_opencti_created'] if 'x_opencti_created' in kill_chain_phase else None,
                        kill_chain_phase['x_opencti_modified'] if 'x_opencti_modified' in kill_chain_phase else None,
                    )['id']
                self.mapping_cache[kill_chain_phase['phase_name']] = {'id': kill_chain_phase_id}
                kill_chain_phases_ids.append(kill_chain_phase_id)
        # Object refs
        object_refs_ids = []
        if 'object_refs' in stix_object:
            for object_ref in stix_object['object_refs']:
                if object_ref in self.mapping_cache:
                    object_ref_result = self.mapping_cache[object_ref]
                elif 'relationship' in object_ref:
                    object_ref_result = self.opencti.get_stix_relation_by_stix_id(object_ref)
                else:
                    object_ref_result = self.opencti.get_stix_domain_entity_by_stix_id(object_ref)

                if object_ref_result is not None:
                    self.mapping_cache[object_ref] = {'id': object_ref_result['id']}
                    object_refs_ids.append(object_ref_result['id'])
        # Import
        if stix_object['type'] == 'marking-definition':
            stix_object_result = self.opencti.get_marking_definition_by_stix_id(stix_object['id'])
        else:
            stix_object_result = self.opencti.get_stix_domain_entity_by_stix_id(stix_object['id'])
        if stix_object_result is None:
            importer = {
                'marking-definition': self.create_marking_definition,
                'identity': self.create_identity,
                'threat-actor': self.create_threat_actor,
                'intrusion-set': self.create_intrusion_set,
                'campaign': self.create_campaign,
                'incident': self.create_incident,
                'malware': self.create_malware,
                'tool': self.create_tool,
                'vulnerability': self.create_vulnerability,
                'attack-pattern': self.create_attack_pattern,
                'course-of-action': self.create_course_of_action,
            }
            do_import = importer.get(stix_object['type'], lambda stix_object: self.unknown_type(stix_object))
            stix_object_result = do_import(stix_object)

        # Add embedded relationships
        if stix_object_result is not None:
            self.mapping_cache[stix_object['id']] = {'id': stix_object_result['id'], 'type': stix_object['type']}
            # Add aliases
            if 'aliases' in stix_object:
                new_aliases = stix_object_result['alias'] + list(
                    set(stix_object['aliases']) - set(stix_object_result['alias']))
                self.opencti.update_stix_domain_entity_field(stix_object_result['id'], 'alias', new_aliases)
            elif 'x_mitre_aliases' in stix_object:
                new_aliases = stix_object_result['alias'] + list(
                    set(stix_object['x_mitre_aliases']) - set(stix_object_result['alias']))
                self.opencti.update_stix_domain_entity_field(stix_object_result['id'], 'alias', new_aliases)
            elif 'x_opencti_aliases' in stix_object:
                new_aliases = stix_object_result['alias'] + list(
                    set(stix_object['x_opencti_aliases']) - set(stix_object_result['alias']))
                self.opencti.update_stix_domain_entity_field(stix_object_result['id'], 'alias', new_aliases)
            # Update created by ref
            if created_by_ref_id is not None and stix_object['type'] != 'marking-definition':
                self.opencti.update_stix_domain_entity_created_by_ref(stix_object_result['id'], created_by_ref_id)
            # Add marking definitions
            for marking_definition_id in marking_definitions_ids:
                self.opencti.add_marking_definition(stix_object_result['id'], marking_definition_id)
            # Add external references
            for external_reference_id in external_references_ids:
                self.opencti.add_external_reference(stix_object_result['id'], external_reference_id)
            # Add kill chain phases
            for kill_chain_phase_id in kill_chain_phases_ids:
                self.opencti.add_kill_chain_phase(stix_object_result['id'], kill_chain_phase_id)
            # Add object refs
            for object_refs_id in object_refs_ids:
                self.opencti.add_object_ref_to_report(stix_object_result['id'], object_refs_id)

        return stix_object_result

    def create_marking_definition(self, stix_object):
        stix_object_result = self.opencti.get_marking_definition_by_definition(stix_object['definition_type'],
                                                                               stix_object['definition'][
                                                                                   stix_object['definition_type']])
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_marking_definition(
                stix_object['definition_type'],
                stix_object['definition'][stix_object['definition_type']],
                stix_object['x_opencti_level'] if 'x_opencti_level' in stix_object else 0,
                stix_object['x_opencti_color'] if 'x_opencti_color' in stix_object else None,
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_identity(self, entity):
        if entity['type'] == 'User':
            identity_class = 'individual'
        elif entity['type'] == 'Sector':
            identity_class = 'class'
        else:
            identity_class = entity['type'].lower()

        identity = {
            'id': entity['stix_id'],
            'type': 'identity',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'identity_class': identity_class,
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, identity)

    def create_identity(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Identity')
        if stix_object_result is not None:
            return stix_object_result
        else:
            if stix_object['identity_class'] == 'individual':
                type = 'User'
            elif stix_object['identity_class'] == 'organization':
                type = 'Organization'
            elif stix_object['identity_class'] == 'group':
                type = 'Organization'
            elif stix_object['identity_class'] == 'class':
                type = 'Sector'
            elif stix_object['identity_class'] == 'region':
                type = 'Region'
            elif stix_object['identity_class'] == 'country':
                type = 'Country'
            elif stix_object['identity_class'] == 'city':
                type = 'City'
            else:
                return None
            stix_object_result = self.opencti.create_identity(
                type,
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['id'].replace('identity', type.lower()),
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_threat_actor(self, entity):
        threat_actor = {
            'id': entity['stix_id'],
            'type': 'threat-actor',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'aliases': entity['alias'],
            'description': entity['description'],
            'goals': entity['goal'],
            'sophistication': entity['sophistication'],
            'resource_level': entity['resource_level'],
            'primary_motivation': entity['primary_motivation'],
            'secondary_motivations': entity['secondary_motivation'],
            'personal_motivations': entity['personal_motivation'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, threat_actor)

    def create_threat_actor(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Threat-Actor')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_threat_actor(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['goals'] if 'goals' in stix_object else None,
                stix_object['sophistication'] if 'sophistication' in stix_object else None,
                stix_object['resource_level'] if 'resource_level' in stix_object else None,
                stix_object['primary_motivation'] if 'primary_motivation' in stix_object else None,
                stix_object['secondary_motivations'] if 'secondary_motivations' in stix_object else None,
                stix_object['personal_motivations'] if 'personal_motivations' in stix_object else None,
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_intrusion_set(self, entity):
        intrusion_set = {
            'id': entity['stix_id'],
            'type': 'intrusion-set',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'aliases': entity['alias'],
            'description': entity['description'],
            'goals': entity['goal'],
            'sophistication': entity['sophistication'],
            'resource_level': entity['resource_level'],
            'primary_motivation': entity['primary_motivation'],
            'secondary_motivations': entity['secondary_motivation'],
            'first_seen': entity['first_seen'],
            'last_seen': entity['last_seen'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, intrusion_set)

    def create_intrusion_set(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Intrusion-Set')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_intrusion_set(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['first_seen'] if 'first_seen' in stix_object else None,
                stix_object['last_seen'] if 'last_seen' in stix_object else None,
                stix_object['goals'] if 'goals' in stix_object else None,
                stix_object['sophistication'] if 'sophistication' in stix_object else None,
                stix_object['resource_level'] if 'resource_level' in stix_object else None,
                stix_object['primary_motivation'] if 'primary_motivation' in stix_object else None,
                stix_object['secondary_motivations'] if 'secondary_motivations' in stix_object else None,
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_campaign(self, entity):
        campaign = {
            'id': entity['stix_id'],
            'type': 'campaign',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'aliases': entity['alias'],
            'description': entity['description'],
            'objective': entity['objective'],
            'first_seen': entity['first_seen'],
            'last_seen': entity['last_seen'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, campaign)

    def create_campaign(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Campaign')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_campaign(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['objective'] if 'objective' in stix_object else None,
                stix_object['first_seen'] if 'first_seen' in stix_object else None,
                stix_object['last_seen'] if 'last_seen' in stix_object else None,
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_incident(self, entity):
        incident = {
            'id': entity['stix_id'],
            'type': 'incident',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'aliases': entity['alias'],
            'description': entity['description'],
            'objective': entity['objective'],
            'first_seen': entity['first_seen'],
            'last_seen': entity['last_seen'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, incident)

    def create_incident(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Incident')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_incident(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['objective'] if 'objective' in stix_object else None,
                stix_object['first_seen'] if 'first_seen' in stix_object else None,
                stix_object['last_seen'] if 'last_seen' in stix_object else None,
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_malware(self, entity):
        malware = {
            'id': entity['stix_id'],
            'type': 'malware',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, malware)

    def create_malware(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Malware')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_malware(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_tool(self, entity):
        tool = {
            'id': entity['stix_id'],
            'type': 'tool',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'tool_version': entity['tool_version'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, tool)

    def create_tool(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Tool')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_tool(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_vulnerability(self, entity):
        vulnerability = {
            'id': entity['stix_id'],
            'type': 'tool',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, vulnerability)

    def create_vulnerability(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Vulnerability')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_vulnerability(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_attack_pattern(self, entity):
        attack_pattern = {
            'id': entity['stix_id'],
            'type': 'attack-pattern',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_mitre_platforms': entity['platform'],
            'x_mitre_permissions_required': entity['required_permission'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, attack_pattern)

    def create_attack_pattern(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Attack-Pattern')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_attack_pattern(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['x_mitre_platforms'] if 'x_mitre_platforms' in stix_object else None,
                stix_object['x_mitre_permissions_required'] if 'x_mitre_permissions_required' in stix_object else None,
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_course_of_action(self, entity):
        course_of_action = {
            'id': entity['stix_id'],
            'type': 'course-of-action',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, course_of_action)

    def create_course_of_action(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Course-Of-Action')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_course_of_action(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_report(self, entity):
        report = {
            'id': entity['stix_id'],
            'type': 'report',
            'labels': entity['stix_label'],
            'name': entity['name'],
            'x_opencti_aliases': entity['alias'],
            'description': entity['description'],
            'published': entity['published'],
            'x_opencti_report_class': entity['report_class'],
            'x_opencti_object_status': entity['object_status'],
            'x_opencti_source_confidence_level': entity['source_confidence_level'],
            'x_opencti_graph_data': entity['graph_data'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, report)

    def create_report(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Report')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_report(
                stix_object['name'],
                stix_object['description'] if 'description' in stix_object else '',
                stix_object['published'] if 'published' in stix_object else '',
                stix_object['x_opencti_report_class'] if 'x_opencti_report_class' in stix_object else '',
                stix_object['x_opencti_object_status'] if 'x_opencti_object_status' in stix_object else '',
                stix_object['x_opencti_source_confidence_level'] if 'x_opencti_source_confidence_level' in stix_object else '',
                stix_object['x_opencti_graph_data'] if 'x_opencti_graph_data' in stix_object else '',
                stix_object['id'],
                stix_object['created'] if 'created' in stix_object else None,
                stix_object['modified'] if 'modified' in stix_object else None,
            )
            return stix_object_result

    def export_stix_relation(self, entity):
        stix_relation = {
            'id': entity['stix_id'],
            'type': 'relationship',
            'relationship_type': entity['relationship_type'],
            'description': entity['description'],
            'x_opencti_first_seen': entity['first_seen'],
            'x_opencti_last_seen': entity['last_seen'],
            'x_opencti_weight': entity['weight'],
            'source_ref': entity['from']['stix_id'],
            'target_ref': entity['to']['stix_id'],
            'created': entity['created'],
            'modified': entity['modified']
        }
        return self.prepare_export(entity, stix_relation)

    def import_relationship(self, stix_relation):
        # Check relation
        stix_relation_result = self.opencti.get_stix_relation_by_stix_id(stix_relation['id'])
        if stix_relation_result is not None:
            return stix_relation_result

        # Check entities
        if stix_relation['source_ref'] in self.mapping_cache:
            source_id = self.mapping_cache[stix_relation['source_ref']]['id']
            source_type = self.mapping_cache[stix_relation['source_ref']]['type']
        else:
            stix_object_result = self.opencti.get_stix_domain_entity_by_stix_id(stix_relation['source_ref'])
            if stix_object_result is not None:
                source_id = stix_object_result['id']
                source_type = stix_object_result['type']
            else:
                self.opencti.log('Source ref of the relationship not found, doing nothing...')
                return None

        if stix_relation['target_ref'] in self.mapping_cache:
            target_id = self.mapping_cache[stix_relation['target_ref']]['id']
            target_type = self.mapping_cache[stix_relation['target_ref']]['type']
        else:
            stix_object_result = self.opencti.get_stix_domain_entity_by_stix_id(stix_relation['target_ref'])
            if stix_object_result is not None:
                target_id = stix_object_result['id']
                target_type = stix_object_result['type']
            else:
                self.opencti.log('Target ref of the relationship not found, doing nothing...')
                return None

        # Check relation by attribute
        stix_relation_result = self.opencti.get_stix_relation(
            source_id,
            target_id,
            stix_relation['relationship_type'],
            stix_relation['x_opencti_first_seen'] if 'x_opencti_first_seen' in stix_relation else None,
            stix_relation['x_opencti_last_seen'] if 'x_opencti_last_seen' in stix_relation else None
        )

        if stix_relation_result is not None:
            return stix_relation_result['id']
        else:
            roles = self.opencti.resolve_role(stix_relation['relationship_type'], source_type, target_type)
            if roles is not None:
                final_source_id = source_id
                final_target_id = target_id
            else:
                roles = self.opencti.resolve_role(stix_relation['relationship_type'], target_type, source_type)
                if roles is not None:
                    final_source_id = target_id
                    final_target_id = source_id
                else:
                    self.opencti.log('Cannot resolve roles, doing nothing...')
                    return None

            if roles is not None:
                stix_relation_result = self.opencti.create_relation(
                    final_source_id,
                    roles['from_role'],
                    final_target_id,
                    roles['to_role'],
                    stix_relation['relationship_type'],
                    stix_relation['description'] if 'description' in stix_relation else '',
                    stix_relation[
                        'x_opencti_first_seen'] if 'x_opencti_first_seen' in stix_relation else datetime.datetime.utcnow().replace(
                        microsecond=0, tzinfo=datetime.timezone.utc).isoformat(),
                    stix_relation[
                        'x_opencti_last_seen'] if 'x_opencti_last_seen' in stix_relation else datetime.datetime.utcnow().replace(
                        microsecond=0, tzinfo=datetime.timezone.utc).isoformat(),
                    stix_relation['x_opencti_weight'] if 'x_opencti_weight' in stix_relation else 4,
                    stix_relation['id'],
                    stix_relation['created'] if 'created' in stix_relation else None,
                    stix_relation['modified'] if 'modified' in stix_relation else None,
                )
                return stix_relation_result['id']

    def import_bundle(self, stix_bundle):
        # Check if the bundle is correctly formated
        if 'type' not in stix_bundle or stix_bundle['type'] != 'bundle':
            self.opencti.log('JSON data type is not a STIX2 bundle')
            return None
        if 'objects' not in stix_bundle or len(stix_bundle['objects']) == 0:
            self.opencti.log('JSON data objects is empty')
            return None

        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'marking-definition':
                self.import_object(item)
        end_time = time.time()
        self.opencti.log("Marking definitions imported in: %ssecs" % round(end_time - start_time))

        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'identity':
                self.import_object(item)
        end_time = time.time()
        self.opencti.log("Identities imported in: %ssecs" % round(end_time - start_time))

        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] != 'relationship' and item['type'] != 'report':
                self.import_object(item)
        end_time = time.time()
        self.opencti.log("Objects imported in: %ssecs" % round(end_time - start_time))

        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'relationship':
                self.import_relationship(item)
        end_time = time.time()
        self.opencti.log("Relationships imported in: %ssecs" % round(end_time - start_time))

        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'report':
                self.import_relationship(item)
        end_time = time.time()
        self.opencti.log("Reports imported in: %ssecs" % round(end_time - start_time))
