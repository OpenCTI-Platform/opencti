# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "98481988-5aac-42e3-9be1-e1328ef86419"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create observable
observable = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "file",
        "hashes": {
            "md5": "fcd76de79819813b631d949b18b1e996",
            "sha-1": "e08b42d92fa579c095834909b893d49259b158be",
            "sha-256": "7cca822e0fdfeca033762213bf16a3f04d7cac8c345f84a0d740324d97f671c0",
        },
    }
)

print(observable)
