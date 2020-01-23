# coding: utf-8

import json
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the report
report = opencti_api_client.report.read(id="f465e240-9bfe-41dd-888c-70d7d85143c1")

# Create the bundle
bundle = opencti_api_client.stix2.export_entity("report", report["id"], "full")
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("Unit42_Sofacy.json", "w")
f.write(json_bundle)
f.close()
