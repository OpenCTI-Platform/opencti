# coding: utf-8
import datetime

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the Intrusion Set
opencti_api_client.intrusion_set.create(
    name="APT28",
    description="Evil hackers",
    first_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    last_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    update=True,
)

# Get the intrusion set APT28
intrusion_set = opencti_api_client.intrusion_set.read(
    filters={
        "mode": "and",
        "filters": [{"key": "name", "values": ["APT28"]}],
        "filterGroups": [],
    }
)

# Update the description
opencti_api_client.stix_domain_object.update_field(
    id=intrusion_set["id"], input={"key": "description", "value": "This is APT28!"}
)
