# coding: utf-8

import os
import yaml

from python.pycti.opencti import OpenCTI

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

# File to import
file_to_import = config['mitre']['repository_path_cti'] + '/enterprise-attack/enterprise-attack.json'

# OpenCTI initialization
opencti = OpenCTI(config['opencti']['api_url'], config['opencti']['api_key'], config['opencti']['log_file'], config['opencti']['verbose'])

opencti.create_identity_if_not_exists('Organization', 'The Guardian', '')