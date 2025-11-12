# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

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
