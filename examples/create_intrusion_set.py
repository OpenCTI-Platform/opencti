# coding: utf-8

import datetime
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "bb4aca90-b98c-49ee-9582-7eac92b61b82"

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
