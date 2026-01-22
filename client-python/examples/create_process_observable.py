# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

process = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "Process",
        "x_opencti_description": "A process",
        "cwd": "C:\Process.exe",
        "pid": 19000,
        "command_line": "--run exe",
        "x_opencti_score": 90,
    }
)

print(process)
