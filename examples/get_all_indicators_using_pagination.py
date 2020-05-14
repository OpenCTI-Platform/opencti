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
    indicator_pattern
    created
"""

final_indicators = []
data = opencti_api_client.indicator.list(
    first=50, customAttributes=custom_attributes, withPagination=True
)
final_indicators = final_indicators + data["entities"]

while data["pagination"]["hasNextPage"]:
    after = data["pagination"]["endCursor"]
    print("Listing indicators after " + after)
    data = opencti_api_client.indicator.list(
        first=50, after=after, customAttributes=custom_attributes, withPagination=True
    )
    final_indicators = final_indicators + data["entities"]

# Print
for indicator in final_indicators:
    print("[" + indicator["created"] + "] " + indicator["indicator_pattern"])
