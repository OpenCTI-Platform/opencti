# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the marking definition
marking_definition = opencti_api_client.marking_definition.create(
    definition_type="TLP",
    definition="TLP:BLACK",
    x_opencti_order=10,
    x_opencti_color="#000000",
)

# Print
print(marking_definition)
