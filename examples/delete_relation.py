# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

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
relations = opencti_api_client.stix_core_relationship.list(
    fromId=intrusion_set["id"],
    fromTypes=["Intrusion-Set"],
    toId=malware["id"],
    toTypes=["Malware"],
    relationship_type="uses",
)

# Delete the relations
for relation in relations:
    opencti_api_client.stix_core_relationship.delete(id=relation["id"])
