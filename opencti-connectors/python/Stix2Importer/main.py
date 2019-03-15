# coding: utf-8

import time
import os
import json
import urllib3
import yaml
from threading import Thread
from queue import Queue
from lib.opencti import OpenCti

# Disable SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Prepare parallel processing
task_queue = Queue()

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../lib/config.yml'))

# New OpenCTI instance
opencti = OpenCti(config)

# Script configuration
workers_number = 4
file_to_import = config['mitre']['repository_path_cti'] + '/enterprise-attack/enterprise-attack.json'

# Load the file
with open(os.path.join(file_to_import)) as file:
    data = json.load(file)

# Check if the bundle is correctly formated
if 'type' not in data or data['type'] != 'bundle':
    opencti.log('JSON data type is not a STIX2 bundle')
    exit(1)
if 'objects' not in data or len(data['objects']) == 0:
    opencti.log('JSON data objects is empty')
    exit(1)

# Store corresponding IDS
result_mapping = {}

# Definition of the STIX2 object importer
def import_object(stix_object):
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
    description = ''
    if 'description' in stix_object:
        description = opencti.convertMarkDown(stix_object['description'])

    if stix_object['type'] == 'threat-actor':
        stix_object_result = opencti.search_stix_domain_entity(stix_object['name'], 'Threat-Actor')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
        else:
            stix_object_result = opencti.create_threat_actor(
                stix_object['name'],
                description
            )
            stix_object_id = stix_object_result['id']
    elif stix_object['type'] == 'intrusion-set':
        stix_object_result = opencti.search_stix_domain_entity(stix_object['name'], 'Intrusion-Set')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
        else:
            stix_object_result = opencti.create_intrusion_set(
                stix_object['name'],
                description
            )
            stix_object_id = stix_object_result['id']
    elif stix_object['type'] == 'malware':
        stix_object_result = opencti.search_stix_domain_entity(stix_object['name'], 'Malware')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
        else:
            stix_object_result = opencti.create_malware(
                stix_object['name'],
                description
            )
            stix_object_id = stix_object_result['id']
    elif stix_object['type'] == 'tool':
        stix_object_result = opencti.search_stix_domain_entity(stix_object['name'], 'Tool')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
        else:
            stix_object_result = opencti.create_tool(
                stix_object['name'],
                description
            )
            stix_object_id = stix_object_result['id']
    elif stix_object['type'] == 'attack-pattern':
        stix_object_result = opencti.search_stix_domain_entity(stix_object['name'], 'Attack-Pattern')
        if stix_object_result is not None:
            stix_object_id = stix_object_result['id']
            opencti.update_stix_domain_entity_field(
                stix_object_id, 'description',
                description
            )
        else:
            platforms = []
            if 'x_mitre_platforms' in stix_object:
                platforms = stix_object['x_mitre_platforms']
            permissions_required = []
            if 'x_mitre_permissions_required' in stix_object:
                permissions_required = stix_object['x_mitre_permissions_required']

            stix_object_result = opencti.create_attack_pattern(
                stix_object['name'],
                description,
                platforms,
                permissions_required,
                kill_chain_phases_ids
            )
            stix_object_id = stix_object_result['id']

    # Update entity aliases if any
    if stix_object_id is not None:
        result_mapping[stix_object['id']] = {'id': stix_object_id, 'type': stix_object['type']}
        if 'aliases' in stix_object:
            new_aliases = stix_object_result['alias'] + list(set(stix_object['aliases']) - set(stix_object_result['alias']))
            opencti.update_stix_domain_entity_field(stix_object_id, 'alias', new_aliases)
        elif 'x_mitre_aliases' in stix_object:
            new_aliases = stix_object_result['alias'] + list(set(stix_object['x_mitre_aliases']) - set(stix_object_result['alias']))
            opencti.update_stix_domain_entity_field(stix_object_id, 'alias', new_aliases)

        # Add external references
        for external_reference_id in external_references_ids:
            opencti.add_external_reference(stix_object_id, external_reference_id)

# Definition of the STIX2 relationship importer
def import_relationship(stix_relation):
    if stix_relation['type'] != 'relationship':
        return

    # Check mapping
    if stix_relation['source_ref'] not in result_mapping or stix_relation['target_ref'] not in result_mapping:
        return

    stix_relation_id = None
    source_id = result_mapping[stix_relation['source_ref']]['id']
    target_id = result_mapping[stix_relation['target_ref']]['id']
    stix_relation_result = opencti.get_relations(source_id, target_id)
    if stix_relation_result is not None:
        stix_relation_id = stix_relation_result['id']
    else:
        stix_relation_result = opencti.create_relation(source_id, '', target_id, '', )

# Definition of the importer worker
def importer():
    while True:
        stix_object = task_queue.get()
        import_object(stix_object)
        task_queue.task_done()


# Start time
start_time = time.time()

# Create the worker threads
threads = [Thread(target=importer) for _ in range(workers_number)]

# Add the objects to import
[task_queue.put(item) for item in data['objects']]

# Start the workers
[thread.start() for thread in threads]

# Wait for all the tasks in the queue to be processed
task_queue.join()

# End time
end_time = time.time()

print("Data imported in: %ssecs" % (end_time - start_time))