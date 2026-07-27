# coding: utf-8
import os
from datetime import datetime, timezone

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)


# Create 2 covered objects + 2 security coverages
def create_coverage(
    report_name: str, sc_name: str, prevention_score: int, detection_score: int
) -> dict:
    report = opencti_api_client.report.create(
        name=report_name,
        published=datetime.now(timezone.utc).isoformat(),
    )
    if not report or "id" not in report:
        raise RuntimeError(f"Failed to create report {report_name}")

    coverage = opencti_api_client.security_coverage.create(
        name=sc_name,
        description="Super Security Coverage",
        objectCovered=report["id"],
        auto_enrichment_disable=False,
        coverage_information=[
            {"coverage_name": "Prevention", "coverage_score": prevention_score},
            {"coverage_name": "Detection", "coverage_score": detection_score},
        ],
    )
    if not coverage or not isinstance(coverage, dict):
        raise RuntimeError(f"Failed to create security coverage {sc_name}")

    return coverage


sc1 = create_coverage("Report1", "SC1", 10, 20)
sc2 = create_coverage("Report2", "SC2", 30, 40)

print("SC1:")
print(sc1)

print("SC2:")
print(sc2)
