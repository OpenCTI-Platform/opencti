# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the ANSSI entity
anssi = opencti_api_client.stix_domain_object.get_by_stix_id_or_name(name="ANSSI")

# Print
print(anssi)
