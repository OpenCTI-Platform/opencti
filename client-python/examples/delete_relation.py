# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

intrusion_set = opencti_api_client.intrusion_set.create(name="EvilSET123")

malware = opencti_api_client.malware.create(
    name="TheWorm", description="A new evil worm."
)

opencti_api_client.stix_core_relationship.create(
    fromId=intrusion_set["id"],
    fromTypes=["Intrusion-Set"],
    toId=malware["id"],
    toTypes=["Malware"],
    relationship_type="uses",
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
