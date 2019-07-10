# coding: utf-8

import os
import yaml

from pycti.opencti_api_client import OpenCTI

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../config.yml'))

# File to import
file_to_import = config['mitre']['repository_path_cti'] + '/enterprise-attack/enterprise-attack.json'

# OpenCTI initialization
opencti = OpenCTI(config['opencti']['api_url'], config['opencti']['api_key'], config['opencti']['log_file'], config['opencti']['verbose'])

# Get observables and their context
observables = opencti.get_stix_observables(10)

opencti.health_check()

for observable in observables:
    observable_value = observable['observable_value']
    for relation in observable['stixRelations']:
        first_seen = relation['first_seen']
        last_seen = relation['last_seen']
        print('Observable with value "' + observable_value + '" (first_seen: ' + first_seen + ', last_seen: ' + last_seen + ')')
