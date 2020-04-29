# coding: utf-8

import json
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the report
report = opencti_api_client.report.read(id="5a3878d7-2949-4fd9-87c7-2a38c65bfa59")

# Create the bundle
bundle = opencti_api_client.stix2.export_entity("report", report["id"], "full")
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("report.json", "w")
f.write(json_bundle)
f.close()
