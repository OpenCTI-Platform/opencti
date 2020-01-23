# coding: utf-8

import datetime
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Upload the file
file = opencti_api_client.upload_file(file_name="./2005_002_001_14428.pdf",)
print(file)
