# coding: utf-8
import datetime
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

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
