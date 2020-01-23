# coding: utf-8

import datetime

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the sector
sector = opencti_api_client.identity.read(
    filters=[{"key": "name", "values": ["Banking institutions"]}]
)

# Create the organization
organization = opencti_api_client.identity.create(
    type="Organization", name="BNP Paribas", description="A french bank."
)

# Create the relation
relation = opencti_api_client.stix_relation.create(
    fromType="Organization",
    fromId=organization["id"],
    toType="Sector",
    toId=sector["id"],
    relationship_type="gathering",
    description="BNP Paribas is part of the sector Banking institutions.",
    ignore_dates=True,
)

# Print
print(relation)
