# coding: utf-8
import os
from pprint import pprint

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Search
all_results = opencti_api_client.security_coverage_result.list(getAll=True)
print(f"Found {len(all_results)} Security Coverage Results")
pprint(all_results)

# Get by ID
scr = opencti_api_client.security_coverage_result.read(
    id="security-coverage-result--7e7aed66-151d-52c4-956c-ee68322dda69"
)
pprint(scr)
