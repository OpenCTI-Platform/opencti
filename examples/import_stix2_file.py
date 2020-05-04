# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://localhost:4000"
api_token = "0b23f787-d013-41a8-8078-97bee84cc99d"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# File to import
file_to_import = "./test.json"

# Import the bundle
opencti_api_client.stix2.import_bundle_from_file(file_to_import, True)
