# coding: utf-8

import os
import yaml
import json

from pycti import OpenCTIApiClient

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../config.yml'))

# Export file
export_file = './threat-actor.json'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(config['opencti']['url'], config['opencti']['token'])

# Import the bundle
bundle = opencti_api_client.stix2_export_entity('threat-actor', '{ID}', 'full', '{MAX_MARKING_DEFINITION_ID}')

with open(export_file, 'w') as file:
    json.dump(bundle, file, indent=4)
