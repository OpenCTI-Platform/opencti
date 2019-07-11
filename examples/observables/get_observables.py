# coding: utf-8

import os
import yaml

from pycti import OpenCTIApiClient

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../config.yml'))

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(config['opencti']['url'], config['opencti']['token'], 'info')

# Get observables and their context
observables = opencti_api_client.get_stix_observables(10)

for observable in observables:
    observable_value = observable['observable_value']
    for relation in observable['stixRelations']:
        first_seen = relation['first_seen']
        last_seen = relation['last_seen']
        print('Observable with value "' + observable_value + '" (first_seen: ' + first_seen + ', last_seen: ' + last_seen + ')')
