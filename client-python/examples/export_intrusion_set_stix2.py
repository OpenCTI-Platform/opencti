# coding: utf-8
import json
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the bundle
bundle = opencti_api_client.stix2.get_stix_bundle_or_object_from_entity_id(
    entity_type="Intrusion-Set",
    entity_id="4ecc2f52-d10a-4e10-bb9b-1ab5df2b282e",
    mode="full",
)
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("intrusion-set.json", "w")
f.write(json_bundle)
f.close()
