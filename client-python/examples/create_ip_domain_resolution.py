# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

observable_domain = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "domain-name",
        "value": "dns.google",
    }
)

observable_ip = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "ipv4-addr",
        "value": "8.8.8.8",
    }
)

opencti_api_client.stix_nested_ref_relationship.create(
    fromId=observable_domain["id"],
    toId=observable_ip["id"],
    relationship_type="resolves-to",
)

relationships = opencti_api_client.stix_nested_ref_relationship.list(
    elementId=observable_domain["id"]
)

print(relationships)
