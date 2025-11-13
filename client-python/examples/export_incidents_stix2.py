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
bundle = opencti_api_client.stix2.export_list("Incident")
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("Incidents.json", "w")
f.write(json_bundle)
f.close()
