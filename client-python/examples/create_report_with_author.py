# coding: utf-8

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Define the date
date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

# Create the author (if not exists)
organization = opencti_api_client.identity.create(
    type="Organization",
    name="My organization",
    alias=["my-organization"],
    description="A new organization.",
)

# Create the report
report = opencti_api_client.report.create(
    name="My new report of my organization",
    description="A report wrote by my organization",
    published=date,
    report_types=["internal-report"],
    createdBy=organization["id"],
)

# Print
print(report)
