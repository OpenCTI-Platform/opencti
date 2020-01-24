# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the ANSSI entity
anssi = opencti_api_client.stix_domain_entity.get_by_stix_id_or_name(name="ANSSI")

# Print
print(anssi)
