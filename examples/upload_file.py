# coding: utf-8
import os

from stix2 import TLP_GREEN

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get a marking
TLP_GREEN_CTI = opencti_api_client.marking_definition.read(id=TLP_GREEN["id"])

# Upload the file (note that markings are optional)
file = opencti_api_client.upload_file(
    file_name="./upload_file_example.pdf", file_markings=[TLP_GREEN["id"]]
)
print(file)
