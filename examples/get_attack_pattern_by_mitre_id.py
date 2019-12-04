# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = '8f053d6e-cc8f-4ae3-ae24-107130510795'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the Attack-Pattern T1514
attack_pattern = opencti_api_client.attack_pattern.read(filters=[{'key': 'external_id', 'values': ['T1514']}])

# Print
print(attack_pattern)