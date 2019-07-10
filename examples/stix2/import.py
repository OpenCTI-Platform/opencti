# coding: utf-8

import os
import yaml

from opencti import OpenCTI

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../config.yml'))

# File to import
file_to_import = './enterprise-attack.json'

# OpenCTI initialization
opencti = OpenCTI(config['opencti']['api_url'], config['opencti']['token'])

# Import the bundle
opencti.stix2_import_bundle_from_file(file_to_import, False)