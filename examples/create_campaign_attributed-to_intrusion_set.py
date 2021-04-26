# coding: utf-8

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Define the date
date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

# Create the Intrusion Set
intrusion_set = opencti_api_client.intrusion_set.create(
    name="My new Intrusion Set",
    description="Evil Cluster",
    first_seen=date,
    last_seen=date,
    update=True,
)
print(intrusion_set)

# Create the Campaign
campaign = opencti_api_client.campaign.create(
    name="My new Campaign",
    description="Large SpearPhishing and intrusions followed by ransomware",
    objective="Financial gain",
    first_seen=date,
    last_seen=date,
    update=True,
)
print(campaign)

# Attribute the Campaign to the Intrusion Set
relation = opencti_api_client.stix_core_relationship.create(
    fromType="Campaign",
    fromId=campaign["id"],
    toType="Intrusion-Set",
    toId=intrusion_set["id"],
    relationship_type="attributed-to",
    first_seen=date,
    last_seen=date,
    description="My new campaign is attributed to my new Intrusion Set, the evil cluster.",
)

# Print
print(relation)
