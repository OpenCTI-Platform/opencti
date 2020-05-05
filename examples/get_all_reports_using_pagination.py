# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

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
data = opencti_api_client.report.list(
    first=50, customAttributes=custom_attributes, withPagination=True
)
final_reports = final_reports + data["entities"]

while data["pagination"]["hasNextPage"]:
    after = data["pagination"]["endCursor"]
    print("Listing reports after " + after)
    data = opencti_api_client.report.list(
        first=50, after=after, customAttributes=custom_attributes, withPagination=True
    )
    final_reports = final_reports + data["entities"]

# Print
for report in final_reports:
    print("[" + report["published"] + "] " + report["name"])
