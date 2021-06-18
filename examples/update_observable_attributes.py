# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create an observable
observable = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "file",
        "x_opencti_description": "A malicious file",
        "hashes": {
            "MD5": "348aefbb6142d4fff8cf26fc5dc97f8a",
            "SHA-1": "486e7e66c3a098c1c8f42e26c78f259d6b3108a6",
            "SHA-256": "42c5e1fe01e689e550ba700b3c5dd4a04a84798c1868ba53c02abcbe21491515",
        },
        #        "x_opencti_score": "90",
    }
)

# Update the fields

reference = opencti_api_client.external_reference.create(
    source_name="Jen", url="https://janedoe.com", description="Sample Report"
)

opencti_api_client.stix_cyber_observable.add_external_reference(
    id=observable["id"], external_reference_id=reference["id"]
)

label = opencti_api_client.label.create(
    value="Suspicious",
    color="#ffa500",
)

opencti_api_client.stix_cyber_observable.add_marking_definition(
    id=observable["id"], marking_definition_id=label["id"]
)

author = opencti_api_client.identity.create(
    name="John's Work",
    description="Automated Toolkit",
    type="Organization",
)

opencti_api_client.stix_cyber_observable.update_created_by(
    id=observable["id"], identity_id=author["id"]
)
