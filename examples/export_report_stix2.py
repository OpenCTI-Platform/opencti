# coding: utf-8

import json
from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = '22566f94-9091-49ba-b583-efd76cf8b29c'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the report
report = opencti_api_client.report.read(id='b52201d6-8da3-4e98-a3f5-e53318d8fb52')

# Create the bundle
bundle = opencti_api_client.stix2.export_entity('report', report['id'], 'full')
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open('Unit42_Sofacy.json', 'w')
f.write(json_bundle)
f.close()
