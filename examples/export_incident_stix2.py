# coding: utf-8

import json

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

opencti_api_client.incident.create(name="My new incident")

# Get the incident created in the create_incident_with_ttps_and_indicators.py
incident = opencti_api_client.incident.read(
    filters=[{"key": "name", "values": ["My new incident"]}]
)

# Create the bundle
bundle = opencti_api_client.stix2.export_entity("Incident", incident["id"], "full")
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("My new incident.json", "w")
f.write(json_bundle)
f.close()
