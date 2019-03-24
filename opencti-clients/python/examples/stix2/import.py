# coding: utf-8

import os
import yaml

from pycti.opencti import OpenCti

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

# File to import
file_to_import = config['mitre']['repository_path_cti'] + '/enterprise-attack/enterprise-attack.json'

# OpenCTI initialization
opencti = OpenCti(config['opencti']['api_url'], config['opencti']['api_key'], config['opencti']['verbose'])

# Import the bundle
opencti.stix2_import_bundle(file_to_import)