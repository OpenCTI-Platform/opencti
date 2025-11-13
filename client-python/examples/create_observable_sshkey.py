# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

observable_sshkey = opencti_api_client.stix_cyber_observable.create(
    observableData={"type": "SSH-Key", "fingerprint_sha256": "sha256_test"}
)

print(observable_sshkey)
