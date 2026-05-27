# coding: utf-8
import os
from datetime import datetime, timezone

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

opencti_api_client = OpenCTIApiClient(api_url, api_token)

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)


# Search
all_coverages = opencti_api_client.security_coverage.list(
    first=50,
    getAll=True,
)
print(f"Found {len(all_coverages)} Security Coverages")

# Read one by id (using the first listed item)
if all_coverages:
    security_coverage_id = all_coverages[0]["id"]
    security_coverage = opencti_api_client.security_coverage.read(
        id=security_coverage_id
    )
    print("Read by id:")
    print(security_coverage)

# Search by name via filters (matches what create_security_coverage.py creates)
security_coverage_by_name = opencti_api_client.security_coverage.read(
    filters={
        "mode": "and",
        "filters": [{"key": "name", "values": ["SC2"]}],
        "filterGroups": [],
    }
)
print("Read by name filter:")
print(security_coverage_by_name)
