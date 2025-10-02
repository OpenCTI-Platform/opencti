# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

observable = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "file",
        "hashes": {
            "md5": "16b3f663d0f0371a4706642c6ac04e42",
            "sha-1": "3a1f908941311fc357051b5c35fd2a4e0c834e37",
            "sha-256": "bcc70a49fab005b4cdbe0cbd87863ec622c6b2c656987d201adbb0e05ec03e56",
        },
    }
)

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

author = opencti_api_client.identity.create(
    name="John's Work",
    description="Automated Toolkit",
    type="Organization",
)

opencti_api_client.stix_core_relationship.create(
    toId=observable["id"],
    fromId=process["id"],
    confidence=90,
    createdBy=author["id"],
    relationship_type="related-to",
    description="Relation between the File and Process objects",
)
