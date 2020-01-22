# coding: utf-8

import datetime

from dateutil.parser import parse
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "bb4aca90-b98c-49ee-9582-7eac92b61b82"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Define the date
date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

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

# Create the indicator
indicator = opencti_api_client.indicator.create(
    name="C2 server of the new campaign",
    description="This is the C2 server of the campaign",
    pattern_type="stix",
    indicator_pattern="[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']",
    main_observable_type="IPv4-Addr",
    valid_from=date,
)
print(indicator)

# Create the relation
relation = opencti_api_client.stix_relation.create(
    fromType="Indicator",
    fromId=indicator["id"],
    toType="Campaign",
    toId=campaign["id"],
    relationship_type="indicates",
    first_seen=date,
    last_seen=date,
    description="This is the C2 server of the campaign.",
)
print(relation)

# Create the observables (optional)
observable_1 = opencti_api_client.stix_observable.create(
    type="Domain", observable_value="www.5z8.info"
)
observable_2 = opencti_api_client.stix_observable.create(
    type="IPv4-Addr", observable_value="198.51.100.1"
)
# Create the relation between observables and the indicator
opencti_api_client.indicator.add_stix_observable(
    id=indicator["id"], stix_observable_id=observable_1["id"]
)
opencti_api_client.indicator.add_stix_observable(
    id=indicator["id"], stix_observable_id=observable_2["id"]
)
