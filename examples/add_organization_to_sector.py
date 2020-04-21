# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

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
