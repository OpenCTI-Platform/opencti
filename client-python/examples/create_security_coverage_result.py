# coding: utf-8
import os
from datetime import datetime, timedelta, timezone
from pprint import pprint

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)
now = datetime.now(timezone.utc)
in_4_weeks = now + timedelta(weeks=4)

# Setup, create a security coverage to link to the result
report = opencti_api_client.report.create(
    name="Report for SCR",
    published=now.isoformat(),
)
if not report or "id" not in report:
    raise RuntimeError("Failed to create report")
securityCoverage = opencti_api_client.security_coverage.create(
    name="SC for SCR",
    description="Super Security Coverage",
    objectCovered=report["id"],
    auto_enrichment_disable=False,
)
if not securityCoverage or "id" not in report:
    raise RuntimeError("Failed to create security coverage")

# Create a security coverage result
scr = opencti_api_client.security_coverage_result.create(
    resultOf=securityCoverage["id"],
    external_uri="my-oaev-instance-1",
    coverage_last_result=now.isoformat(),
    coverage_valid_from=now.isoformat(),
    coverage_valid_to=in_4_weeks.isoformat(),
    coverage_information=[
        {"coverage_name": "Prevention", "coverage_score": 45},
        {"coverage_name": "Detection", "coverage_score": 90},
    ],
)
pprint(scr)
