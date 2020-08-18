# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create observable
observable = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "file",
        "hashes": {
            "md5": "16b3f663d0f0371a4706642c6ac04e42",
            "sha1": "3a1f908941311fc357051b5c35fd2a4e0c834e37",
            "sha256": "bcc70a49fab005b4cdbe0cbd87863ec622c6b2c656987d201adbb0e05ec03e56",
        },
    }
)

print(observable)
