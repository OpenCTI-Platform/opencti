# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

process = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "Process",
        "x_opencti_description": "A process",
        "cwd": "C:\Process.exe",
        "pid": "19000",
        "command_line": "--run exe",
        "x_opencti_score": 90,
    }
)

print(process)
