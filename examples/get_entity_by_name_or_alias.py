# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the ANSSI entity
anssi = opencti_api_client.stix_domain_object.get_by_stix_id_or_name(name="ANSSI")

# Print
print(anssi)
