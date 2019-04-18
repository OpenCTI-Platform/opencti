# coding: utf-8

import os
import yaml

from python.pycti.opencti import OpenCTI

# Load configuration
config = yaml.load(open(os.path.dirname(__file__) + '/config.yml'))

# File to import
file_to_import = '/home/oxid/poison.json'

# OpenCTI initialization
opencti = OpenCTI(config['opencti']['api_url'], config['opencti']['api_key'], config['opencti']['log_file'], config['opencti']['verbose'])

#test = opencti.search_stix_domain_entity_by_name('Stone Panda')
#print(test)
#exit(0)

# Import the bundle
opencti.stix2_import_bundle_from_file(file_to_import)