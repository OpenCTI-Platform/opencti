# coding: utf-8

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

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
