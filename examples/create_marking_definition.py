# coding: utf-8

from pycti import OpenCTIApiClient, MarkingDefinition

# Variables
api_url = 'https://demo.opencti.io'
api_token = 'c2d944bb-aea6-4bd6-b3d7-6c10451e2256'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the marking definition
marking_definition = opencti_api_client.marking_definition.create(
    definition_type='TLP',
    definition='TLP:BLACK',
    level=10,
    color='#000000'
)

# Print
print(marking_definition)
