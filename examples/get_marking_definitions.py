# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = 'c2d944bb-aea6-4bd6-b3d7-6c10451e2256'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get all marking definitions
marking_definitions = opencti_api_client.marking_definition.list()

# Print
for marking_definition in marking_definitions:
    print('[' + marking_definition['definition_type'] + '] ' + marking_definition['definition'])
