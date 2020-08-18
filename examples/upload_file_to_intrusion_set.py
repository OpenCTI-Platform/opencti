# coding: utf-8

import datetime
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the Intrusion Set
intrusion_set = opencti_api_client.intrusion_set.create(
    name="My new Intrusion Set",
    description="Evil Cluster",
    first_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    last_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    update=True,
)

# Print
print(intrusion_set)

# Upload the file
file = opencti_api_client.stix_domain_object.add_file(
    id=intrusion_set["id"], file_name="./file.pdf",
)
print(file)
