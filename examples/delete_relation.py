# coding: utf-8

import json
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the intrusion set APT28
intrusion_set = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": ["APT28"]}]
)

# Get the malware DealersChoice
malware = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": ["DealersChoice"]}]
)

# Get the relations between APT28 and DealersChoice
relations = opencti_api_client.stix_relation.list(
    fromId=intrusion_set["id"],
    fromTypes=["Intrusion-Set"],
    toId=malware["id"],
    toTypes=["Malware"],
    relationType="uses",
)

# Delete the relations
for relation in relations:
    opencti_api_client.stix_relation.delete(id=relation["id"])
