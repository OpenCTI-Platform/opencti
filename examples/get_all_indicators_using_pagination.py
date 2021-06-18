# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get all reports using the pagination
custom_attributes = """
    id
    pattern_type
    created
"""

final_indicators = []
data = {"pagination": {"hasNextPage": True, "endCursor": 0}}
while data["pagination"]["hasNextPage"]:
    after = data["pagination"]["endCursor"]
    if after:
        print("Listing indicators after " + after)
    data = opencti_api_client.indicator.list(
        first=50,
        after=after,
        customAttributes=custom_attributes,
        withPagination=True,
        orderBy="created_at",
        orderMode="asc",
    )
    final_indicators += data["entities"]

for indicator in final_indicators:
    print("[" + indicator["created"] + "] " + indicator["id"])
