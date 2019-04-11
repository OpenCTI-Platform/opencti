# coding: utf-8

import os
import yaml
import json

from  python.pycti.opencti import OpenCTI

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

# Export file
export_file = './exports/bundle.json'

# OpenCTI initialization
opencti = OpenCTI(config['opencti']['api_url'], config['opencti']['api_key'], config['opencti']['verbose'])

# Import the bundle
bundle = opencti.stix2_export_entity('Report', 'V22806560', 'full')

with open(export_file, 'w') as file:
    json.dump(bundle, file, indent=4)
