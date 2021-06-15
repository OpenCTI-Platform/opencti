# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

artifact = opencti_api_client.stix_cyber_observable.upload_artifact(
    file_name="./test.exe",
    mime_type="application/octet-stream",
    x_opencti_description="Test",
)
print(artifact)
