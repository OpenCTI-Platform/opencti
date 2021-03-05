# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

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

opencti_api_client.stix_cyber_observable_relationship.create(
    fromId=observable_domain["id"],
    toId=observable_ip["id"],
    relationship_type="resolves-to",
)

relationships = opencti_api_client.stix_cyber_observable_relationship.list(
    elementId=observable_domain["id"]
)

print(relationships)
