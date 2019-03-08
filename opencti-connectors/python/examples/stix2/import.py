# coding: utf-8

import os
import json
import re
import urllib3
import yaml
from opencti import OpenCti

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

config = yaml.load(open(os.path.dirname(__file__) + '/../../config.yml'))
opencti = OpenCti(config)
enterprise_attack_bundle_file_name = config['mitre'][
                                         'repository_path_cti'] + '/enterprise-attack/enterprise-attack.json'

with open(os.path.join(enterprise_attack_bundle_file_name)) as enterprise_attack_bundle_file:
    enterprise_attack_data = json.load(enterprise_attack_bundle_file)

# Check if the bundle is correctly formated
if 'type' not in enterprise_attack_data or enterprise_attack_data['type'] != 'bundle':
    opencti.log('JSON data type is not a STIX2 bundle')
    exit(1)
if 'objects' not in enterprise_attack_data or len(enterprise_attack_data['objects']) == 0:
    opencti.log('JSON data objects is empty')
    exit(1)

# First iteration, create marking definitions
for stix_object in enterprise_attack_data['objects']:
    # Create external references of the object if not exist
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

            external_reference_result = opencti.get_external_reference_by_url(url)
            if external_reference_result is not None:
                external_reference_id = external_reference_result['id']
            else:
                external_reference_id = opencti.create_external_reference(
                    external_reference['source_name'],
                    url,
                    external_id,
                    description
                )['id']
            external_references_ids.append(external_reference_id)

    # Create kill chain phases of the object if not exist
    kill_chain_phases_ids = []
    if 'kill_chain_phases' in stix_object:
        for kill_chain_phase in stix_object['kill_chain_phases']:
            kill_chain_phase_result = opencti.get_kill_chain_phase(kill_chain_phase['phase_name'])
            if kill_chain_phase_result is not None:
                kill_chain_phase_id = kill_chain_phase_result['id']
            else:
                kill_chain_phase_id = opencti.create_kill_chain_phase(
                    kill_chain_phase['kill_chain_name'],
                    kill_chain_phase['phase_name']
                )['id']
            kill_chain_phases_ids.append(kill_chain_phase_id)

    # Create entity if not exists
    stix_object_id = None
    stix_object_result = {}
    if stix_object['type'] == 'threat-actor':
        stix_object_result = opencti.get_stix_domain_entity_by_name(stix_object['name'], 'Threat-Actor')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
        else:
            stix_object_result = opencti.create_threat_actor(
                stix_object['name'],
                stix_object['description']
            )
            stix_object_id = stix_object_result['id']
    elif stix_object['type'] == 'intrusion-set':
        stix_object_result = opencti.get_stix_domain_entity_by_name(stix_object['name'], 'Intrusion-Set')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
        else:
            stix_object_result = opencti.create_intrusion_set(
                stix_object['name'],
                stix_object['description']
            )
            stix_object_id = stix_object_result['id']
    elif stix_object['type'] == 'attack-pattern':
        stix_object_result = opencti.get_stix_domain_entity_by_name(stix_object['name'], 'Attack-Pattern')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
            #opencti.update_stix_domain_entity_field(
            #    stix_object_id, 'description',
            #    opencti.convertMarkDown(stix_object['description'])
            #)
        else:
            platforms = []
            if 'x_mitre_platforms' in stix_object:
                platforms = stix_object['x_mitre_platforms']
            permissions_required = []
            if 'x_mitre_permissions_required' in stix_object:
                permissions_required = stix_object['x_mitre_permissions_required']

            stix_object_result = opencti.create_attack_pattern(
                stix_object['name'],
                opencti.convertMarkDown(stix_object['description']),
                platforms,
                permissions_required,
                kill_chain_phases_ids
            )
            stix_object_id = stix_object_result['id']

    # Update entity aliases if any
    if stix_object_id is not None:
        if 'aliases' in stix_object:
            new_aliases = stix_object_result['alias'] + list(set(stix_object['aliases']) - set(stix_object_result['alias']))
            opencti.update_stix_domain_entity_field(stix_object_id, 'alias', new_aliases)
        elif 'x_mitre_aliases' in stix_object:
            new_aliases = stix_object_result['alias'] + list(set(stix_object['x_mitre_aliases']) - set(stix_object_result['alias']))
            opencti.update_stix_domain_entity_field(stix_object_id, 'alias', new_aliases)

        # External references
        for external_reference_id in external_references_ids:
            opencti.add_external_reference(stix_object_id, external_reference_id)
