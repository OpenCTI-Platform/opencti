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

    def convert_markdown(self, text):
        return text. \
            replace('<code>', '`'). \
            replace('</code>', '`')

    def prepare_object(self, stix_object):
        # Description
        if 'description' in stix_object:
            stix_object['description'] = self.convert_markdown(stix_object['description'])
        else:
            stix_object['description'] = None

        return stix_object

    def prepare_relationship(self, stix_relation):
        if 'x-opencti-description' not in stix_relation:
            stix_relation['x-opencti-description'] = None
        if 'x-opencti-first-seen' not in stix_relation:
            stix_relation['x-opencti-first-seen'] = None
        if 'x-opencti-last-seen' not in stix_relation:
            stix_relation['x-opencti-last-seen'] = None
        if 'x-opencti-weight' not in stix_relation:
            stix_relation['x-opencti-weight'] = None

        return stix_relation

    def import_object(self, stix_object):
        # External References
        external_references_ids = []
        if 'external_references' in stix_object:
            for external_reference in stix_object['external_references']:
                url = ''
                description = ''
                external_id = ''
                if 'url' in external_reference:
                    url = external_reference['url']
                if 'description' in external_reference:
                    description = external_reference['description']
                if 'external_id' in external_reference:
                    external_id = external_reference['external_id']

                external_reference_result = self.opencti.get_external_reference_by_url(url)
                if external_reference_result is not None:
                    external_reference_id = external_reference_result['id']
                else:
                    external_reference_id = self.opencti.create_external_reference(
                        external_reference['source_name'],
                        url,
                        external_id,
                        description,
                    )['id']
                external_references_ids.append(external_reference_id)
        # Kill Chain Phases
        kill_chain_phases_ids = []
        if 'kill_chain_phases' in stix_object:
            for kill_chain_phase in stix_object['kill_chain_phases']:
                kill_chain_phase_result = self.opencti.get_kill_chain_phase(kill_chain_phase['phase_name'])
                if kill_chain_phase_result is not None:
                    kill_chain_phase_id = kill_chain_phase_result['id']
                else:
                    kill_chain_phase_id = self.opencti.create_kill_chain_phase(
                        kill_chain_phase['kill_chain_name'],
                        kill_chain_phase['phase_name']
                    )['id']
                kill_chain_phases_ids.append(kill_chain_phase_id)

        # Import
        stix_object_result = self.opencti.get_stix_domain_entity_by_stix_id(stix_object['id'])
        if stix_object_result is None:
            stix_object = self.prepare_object(stix_object)
            importer = {
                'threat-actor': self.threat_actor,
                'intrusion-set': self.intrusion_set,
                'campaign': self.campaign,
                'incident': self.incident,
                'malware': self.malware,
                'tool': self.tool,
                'vulnerability': self.vulnerability,
                'attack-pattern': self.attack_pattern,
                'course-of-action': self.course_of_action,
            }
            do_import = importer.get(stix_object['type'], lambda: 'Invalid entity type')
            stix_object_result = do_import(stix_object)

        # Add embedded relationships
        if stix_object_result is not None:
            self.mapping_cache[stix_object['id']] = {'id': stix_object_result['id'], 'type': stix_object['type']}
            # Add aliases
            if 'aliases' in stix_object:
                new_aliases = stix_object_result['alias'] + list(set(stix_object['aliases']) - set(stix_object_result['alias']))
                self.opencti.update_stix_domain_entity_field(stix_object_result['id'], 'alias', new_aliases)
            elif 'x_mitre_aliases' in stix_object:
                new_aliases = stix_object_result['alias'] + list(set(stix_object['x_mitre_aliases']) - set(stix_object_result['alias']))
                self.opencti.update_stix_domain_entity_field(stix_object_result['id'], 'alias', new_aliases)
            # Add external references
            for external_reference_id in external_references_ids:
                self.opencti.add_external_reference(stix_object_result['id'], external_reference_id)
            # Add kill chain phases
            for kill_chain_phase_id in kill_chain_phases_ids:
                self.opencti.add_kill_chain_phase(stix_object_result['id'], kill_chain_phase_id)

        return stix_object_result

    def threat_actor(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Threat-Actor')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_threat_actor(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

    def intrusion_set(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Intrusion-Set')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_intrusion_set(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

    def campaign(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Campaign')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_campaign(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

    def incident(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Incident')
        if stix_object_result is not None:
            return stix_object_result
        else:
            if 'first_seen' not in stix_object:
                stix_object['first_seen'] = None
            if 'last_seen' not in stix_object:
                stix_object['last_seen'] = None
            stix_object_result = self.opencti.create_incident(
                stix_object['name'],
                stix_object['description'],
                stix_object['first_seen'],
                stix_object['last_seen'],
                stix_object['id']
            )
            return stix_object_result

    def malware(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Malware')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_malware(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

    def tool(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Tool')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_tool(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

    def vulnerability(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Vulnerability')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_vulnerability(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

    def attack_pattern(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Attack-Pattern')
        if stix_object_result is not None:
            return stix_object_result
        else:
            platforms = []
            if 'x_mitre_platforms' in stix_object:
                platforms = stix_object['x_mitre_platforms']
            permissions_required = []
            if 'x_mitre_permissions_required' in stix_object:
                permissions_required = stix_object['x_mitre_permissions_required']
            stix_object_result = self.opencti.create_attack_pattern(
                stix_object['name'],
                stix_object['description'],
                platforms,
                permissions_required,
                stix_object['id']
            )
            return stix_object_result

    def course_of_action(self, stix_object):
        stix_object_result = self.opencti.search_stix_domain_entity(stix_object['name'], 'Course-Of-Action')
        if stix_object_result is not None:
            return stix_object_result
        else:
            stix_object_result = self.opencti.create_course_of_action(
                stix_object['name'],
                stix_object['description'],
                stix_object['id']
            )
            return stix_object_result

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
            stix_relation['x-opencti-first-seen'],
            stix_relation['x-opencti-last-seen'],
        )

        if stix_relation_result is not None:
            return stix_relation_result['id']
        else:
            roles = self.opencti.resolve_role(stix_relation['relationship_type'], source_type, target_type)
            if roles is not None:
                stix_relation_result = self.opencti.create_relation(
                    source_id,
                    roles['from_role'],
                    target_id,
                    roles['to_role'],
                    stix_relation['relationship_type'],
                    datetime.datetime.today().strftime('%Y-%m-%d'),
                    datetime.datetime.today().strftime('%Y-%m-%d'),
                    4,
                    stix_relation['id']
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
            if item['type'] != 'relationship':
                self.import_object(item)
        end_time = time.time()
        self.opencti.log("Objects imported in: %ssecs" % (end_time - start_time))

        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'relationship':
                self.import_object(item)
        end_time = time.time()
        self.opencti.log("Relationships imported in: %ssecs" % (end_time - start_time))
