# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Exact IP match
opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="IPv4-Addr.value", simple_observable_value="110.172.180.180"
)
print("IP ADDRESS")
observable = opencti_api_client.stix_cyber_observable.read(
    filters={
        "mode": "and",
        "filters": [{"key": "value", "values": ["110.172.180.180"]}],
        "filterGroups": [],
    }
)
print(observable)

# Exact File name match
opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="File.name", simple_observable_value="activeds.dll"
)
print("FILE NAME")
observable = opencti_api_client.stix_cyber_observable.read(
    filters={
        "mode": "and",
        "filters": [{"key": "name", "values": ["activeds.dll"]}],
        "filterGroups": [],
    }
)
print(observable)

# Exact File name match
opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="File.hashes.MD5",
    simple_observable_value="3aad33e025303dbae12c12b4ec5258c1",
)
print("FILE MD5")
observable = opencti_api_client.stix_cyber_observable.read(
    filters={
        "mode": "and",
        "filters": [
            {"key": "hashes.MD5", "values": ["3aad33e025303dbae12c12b4ec5258c1"]}
        ],
        "filterGroups": [],
    }
)
print(observable)
