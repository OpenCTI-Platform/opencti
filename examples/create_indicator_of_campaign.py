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
    pattern="[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']",
    x_opencti_main_observable_type="IPv4-Addr",
    valid_from=date,
)
print(indicator)

# Create the relation
relation = opencti_api_client.stix_core_relationship.create(
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
observable_1 = opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="Domain-Name.value", simple_observable_value="www.5z8.info"
)
observable_2 = opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="IPv4-Addr.value", simple_observable_value="198.51.100.1"
)
# Create the relation between observables and the indicator
opencti_api_client.indicator.add_stix_cyber_observable(
    id=indicator["id"], stix_cyber_observable_id=observable_1["id"]
)
opencti_api_client.indicator.add_stix_cyber_observable(
    id=indicator["id"], stix_cyber_observable_id=observable_2["id"]
)
