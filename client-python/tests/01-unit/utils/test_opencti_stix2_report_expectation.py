from unittest.mock import MagicMock

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2

WORK_ID = "work-id"
ATTACK_PATTERN = {
    "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "type": "attack-pattern",
    "spec_version": "2.1",
    "name": "Spearphishing",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
}


class FakePlatform:
    """Stands for the platform behind session.post, confirming the report only when it supports it."""

    def __init__(self, confirms_report: bool):
        self.confirms_report = confirms_report
        self.calls = []

    def post(self, url, **kwargs):
        query = kwargs["json"]["query"] if "json" in kwargs else ""
        headers = kwargs["headers"]
        self.calls.append({"query": query, "headers": headers})
        response = MagicMock()
        response.status_code = 200
        requested = headers.get("opencti-report-expectation") == "true"
        response.headers = (
            {"opencti-expectation-reported": "true"}
            if requested and self.confirms_report
            else {}
        )
        if "reportExpectation" in query:
            response.json.return_value = {
                "data": {"workEdit": {"reportExpectation": WORK_ID}}
            }
        else:
            response.json.return_value = {"data": {"attackPatternAdd": _created()}}
        return response

    def report_expectation_calls(self):
        return [c for c in self.calls if "reportExpectation" in c["query"]]

    def flagged_calls(self):
        return [
            c
            for c in self.calls
            if c["headers"].get("opencti-report-expectation") == "true"
        ]


def _created():
    return {
        "id": "internal-id",
        "standard_id": ATTACK_PATTERN["id"],
        "entity_type": "Attack-Pattern",
        "parent_types": ["Stix-Domain-Object"],
    }


def _build_stix2(platform: FakePlatform) -> OpenCTIStix2:
    api_client = OpenCTIApiClient(
        "http://fake:4000", "fake", ssl_verify=False, perform_health_check=False
    )
    api_client.session.post = platform.post
    api_client.set_work_id(WORK_ID)
    stix2 = OpenCTIStix2(api_client)
    # A running worker has already loaded the vocabularies after its first object
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    return stix2


def test_platform_reports_with_the_create_and_worker_skips_its_call():
    platform = FakePlatform(confirms_report=True)
    stix2 = _build_stix2(platform)
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    assert len(platform.flagged_calls()) == 1
    assert "attackPatternAdd" in platform.flagged_calls()[0]["query"]
    assert platform.report_expectation_calls() == []


def test_one_less_http_call_than_without_confirmation():
    confirming = FakePlatform(confirms_report=True)
    _build_stix2(confirming).import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    old_platform = FakePlatform(confirms_report=False)
    _build_stix2(old_platform).import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    assert len(old_platform.calls) - len(confirming.calls) == 1


def test_worker_reports_itself_when_the_platform_does_not_confirm():
    platform = FakePlatform(confirms_report=False)
    stix2 = _build_stix2(platform)
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    report_calls = platform.report_expectation_calls()
    assert len(report_calls) == 1
    assert "opencti-report-expectation" not in report_calls[0]["headers"]


def test_worker_reports_itself_when_the_item_sends_no_create():
    platform = FakePlatform(confirms_report=True)
    stix2 = _build_stix2(platform)
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID, types=["malware"])
    assert platform.flagged_calls() == []
    assert len(platform.report_expectation_calls()) == 1


def test_confirmation_of_one_item_does_not_skip_the_next_one():
    platform = FakePlatform(confirms_report=True)
    stix2 = _build_stix2(platform)
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID, types=["malware"])
    assert len(platform.report_expectation_calls()) == 1


def test_no_header_and_no_report_without_work():
    platform = FakePlatform(confirms_report=True)
    stix2 = _build_stix2(platform)
    stix2.opencti.bundle_send_to_queue = False
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    assert platform.flagged_calls() == []
    assert platform.report_expectation_calls() == []


@pytest.mark.parametrize("confirms_report", [True, False])
def test_header_is_sent_once_only(confirms_report):
    platform = FakePlatform(confirms_report=confirms_report)
    stix2 = _build_stix2(platform)
    stix2.import_item(dict(ATTACK_PATTERN), work_id=WORK_ID)
    stix2.opencti.query("query { about { version } }")
    assert len(platform.flagged_calls()) == 1
