# coding: utf-8

import os
import yaml

from pycti import OpenCTIApiClient

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/../config.yml'))

# File to import
file_to_import = './enterprise-attack.json'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(config['opencti']['url'], config['opencti']['token'])

# Import the bundle
opencti_api_client.send(file_to_import, False)
