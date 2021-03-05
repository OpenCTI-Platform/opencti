# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

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
