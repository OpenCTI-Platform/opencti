# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get all reports using the pagination
custom_attributes = """
    id
    pattern_type
    created
"""

final_indicators = []
data = {"pagination": {"hasNextPage": True, "endCursor": None}}
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
