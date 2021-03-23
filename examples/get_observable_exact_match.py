# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Exact IP match
print("IP ADDRESS")
observable = opencti_api_client.stix_cyber_observable.read(
    filters=[{"key": "value", "values": ["110.172.180.180"]}]
)
print(observable)

# Exact File name match
print("FILE NAME")
observable = opencti_api_client.stix_cyber_observable.read(
    filters=[{"key": "name", "values": ["activeds.dll"]}]
)
print(observable)

# Exact File name match
print("FILE MD5")
observable = opencti_api_client.stix_cyber_observable.read(
    filters=[{"key": "hashes_MD5", "values": ["3aad33e025303dbae12c12b4ec5258c1"]}]
)
print(observable)
