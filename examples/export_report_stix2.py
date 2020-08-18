# coding: utf-8

import json
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the bundle
bundle = opencti_api_client.stix2.export_entity(
    "Report", "e7c349a7-9809-4e98-87a2-ad39f32aef19", "full"
)
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("report.json", "w")
f.write(json_bundle)
f.close()
