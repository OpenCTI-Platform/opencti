# coding: utf-8

import os
import yaml
import json

from pycti.opencti import OpenCti

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

# Export file
export_file = './exports/bundle.json'

# OpenCTI initialization
opencti = OpenCti(config['opencti']['api_url'], config['opencti']['api_key'], config['opencti']['verbose'])

# Import the bundle
bundle = opencti.stix2_export_bundle([
    'Identity',
    'Threat-Actor',
    'Intrusion-Set',
    'Campaign',
    'Incident',
    'Malware',
    'Tool',
    'Vulnerability'
    'Attack-Pattern',
    'Course-Of-Action',
])

with open(export_file, 'w') as file:
    json.dump(bundle, file, indent=4)
