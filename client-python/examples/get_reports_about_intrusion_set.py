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
    name="Sandworm Team",
    description="Evil hackers",
    first_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    last_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    update=True,
)

# Get the intrusion set Sandworm
intrusion_set = opencti_api_client.intrusion_set.read(
    filters={
        "mode": "and",
        "filters": [{"key": "name", "values": ["Sandworm Team"]}],
        "filterGroups": [],
    }
)

# Get all reports
reports = opencti_api_client.report.list(
    filters={
        "mode": "and",
        "filters": [{"key": "objects", "values": [intrusion_set["id"]]}],
        "filterGroups": [],
    },
    orderBy="published",
    orderMode="asc",
)

# Print
if not reports:
    print(f"No {intrusion_set['name']} reports available")
else:
    for report in reports:
        print(
            "["
            + report["standard_id"]
            + "] "
            + report["name"]
            + " ("
            + report["published"]
            + ")"
        )
