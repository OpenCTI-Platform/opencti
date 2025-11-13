# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

tool = opencti_api_client.tool.create(
    name="powashell.exe", description="A new evil tool."
)

print(tool)

intrusion_set = opencti_api_client.intrusion_set.create(name="APT_EVIL")

print(intrusion_set)

# Create the relation
relation = opencti_api_client.stix_core_relationship.create(
    fromType="IntrusionSet",
    fromId=intrusion_set["id"],
    toType="Tool",
    toId=tool["id"],
    relationship_type="uses",
    description="APT_EVIL uses the tool powashell.exe",
)

print(relation)
