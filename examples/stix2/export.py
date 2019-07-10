# coding: utf-8

import os
import yaml
import json

from opencti import OpenCTI

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../config.yml'))

# Export file
export_file = './report.json'

# OpenCTI initialization
opencti = OpenCTI(config['opencti']['api_url'], config['opencti']['token'])

# Import the bundle
bundle = opencti.stix2_export_entity('report', '{REPORT_ID}', 'full')

with open(export_file, 'w') as file:
    json.dump(bundle, file, indent=4)
