# coding: utf-8
import os

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Define the date
date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

# Create the report
report = opencti_api_client.report.create(
    name="My test report",
    description="A new threat report.",
    published=date,
    report_class="Threat Report",
)

# Create the external reference
external_reference = opencti_api_client.external_reference.create(
    source_name="Wikipedia", url="https://en.wikipedia.org/wiki/Fancy_Bear"
)

# Add the external reference to the report
opencti_api_client.stix_domain_object.add_external_reference(
    id=report["id"], external_reference_id=external_reference["id"]
)

# Get the report
report = opencti_api_client.report.read(id=report["id"])

# Print
print(report)
