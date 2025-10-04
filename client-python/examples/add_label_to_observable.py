# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the observable
url = opencti_api_client.stix_cyber_observable.create(
    observableData={"type": "url", "value": "http://johndoe.com"}
)
# Create the tag (if not exists)
label = opencti_api_client.label.create(
    value="Suspicious",
    color="#ffa500",
)

# Add the tag
opencti_api_client.stix_cyber_observable.add_label(id=url["id"], label_id=label["id"])

# Read the observable
obs = opencti_api_client.stix_cyber_observable.read(id=url["id"])
print(obs)
