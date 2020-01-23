# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the marking definition
marking_definition = opencti_api_client.marking_definition.create(
    definition_type="TLP", definition="TLP:BLACK", level=10, color="#000000"
)

# Print
print(marking_definition)
