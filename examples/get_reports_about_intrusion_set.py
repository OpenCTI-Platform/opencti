# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the intrusion set APT28
intrusion_set = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": ["APT28"]}]
)

# Get all reports
reports = opencti_api_client.report.list(
    filters=[{"key": "objectContains", "values": [intrusion_set["id"]]}],
    orderBy="published",
    orderMode="asc",
)

# Print
for report in reports:
    print(
        "["
        + report["stix_id"]
        + "] "
        + report["name"]
        + " ("
        + report["published"]
        + ")"
    )
