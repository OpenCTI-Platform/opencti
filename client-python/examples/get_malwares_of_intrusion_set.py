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

# Get the relations from APT28 to malwares
stix_relations = opencti_api_client.stix_core_relationship.list(
    fromId=intrusion_set["id"], toTypes=["Malware"]
)

# Print
for stix_relation in stix_relations:
    print("[" + stix_relation["to"]["stix_id"] + "] " + stix_relation["to"]["name"])
