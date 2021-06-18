# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the intrusion set APT28
intrusion_set = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": ["Sandworm Team"]}]
)

# Get all reports
reports = opencti_api_client.report.list(
    filters=[{"key": "objectContains", "values": [intrusion_set["id"]]}],
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
