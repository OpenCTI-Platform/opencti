# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the Attack-Pattern T1514
attack_pattern = opencti_api_client.attack_pattern.read(
    filters={
        "mode": "and",
        "filters": [{"key": "x_mitre_id", "values": ["T1514"]}],
        "filterGroups": [],
    }
)

# Print
print(attack_pattern)
