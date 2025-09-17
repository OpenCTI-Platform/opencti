# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get all reports using the pagination
custom_attributes = """
    id
    name
    published
    description
"""

final_reports = []
data = {"pagination": {"hasNextPage": True, "endCursor": None}}
while data["pagination"]["hasNextPage"]:
    after = data["pagination"]["endCursor"]
    if after:
        print("Listing reports after " + after)
    data = opencti_api_client.report.list(
        first=50,
        after=after,
        customAttributes=custom_attributes,
        withPagination=True,
        orderBy="created_at",
        orderMode="asc",
    )
    final_reports = final_reports + data["entities"]

# Print
for report in final_reports:
    print("[" + report["published"] + "] " + report["name"])
