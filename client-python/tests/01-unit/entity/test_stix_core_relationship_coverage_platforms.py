# coding: utf-8
"""Unit tests of the per security platform coverage of relationships (OpenCTI-Platform/opencti#18679)."""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship

SUPPORTED_INPUT = {
    "data": {
        "__type": {
            "inputFields": [
                {"name": "fromId"},
                {"name": "coverage_information"},
                {"name": "coverage_platforms_information"},
            ]
        }
    }
}
UNSUPPORTED_INPUT = {
    "data": {
        "__type": {
            "inputFields": [{"name": "fromId"}, {"name": "coverage_information"}]
        }
    }
}
CREATED = {"data": {"stixCoreRelationshipAdd": {"id": "relationship-1"}}}
COVERAGE_PLATFORMS = [
    {
        "platform_ref": "identity--fd6bb94b-46b7-5e41-90d0-2a0fcf171ca2",
        "coverage_name": "DETECTION",
        "coverage_score": 75,
    }
]
SUPPORTED_OUTPUT = {
    "data": {
        "__type": {
            "fields": [
                {"name": "id"},
                {"name": "coverage_information"},
                {"name": "coverage_platforms_information"},
            ]
        }
    }
}
UNSUPPORTED_OUTPUT = {
    "data": {"__type": {"fields": [{"name": "id"}, {"name": "coverage_information"}]}}
}
HAS_COVERED = {
    "id": "relationship-1",
    "relationship_type": "has-covered",
    "coverage_information": [{"coverage_name": "DETECTION", "coverage_score": 75}],
    "coverage_platforms_information": COVERAGE_PLATFORMS,
}
PAGE_INFO = {
    "startCursor": None,
    "endCursor": None,
    "hasNextPage": False,
    "hasPreviousPage": False,
    "globalCount": 1,
}


@pytest.fixture
def local_api_client():
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


def relationship_with(client, responses):
    client.query = MagicMock(side_effect=responses)
    return StixCoreRelationship(client)


def create_has_covered(relationship, **kwargs):
    return relationship.create(
        fromId="security-coverage--1",
        toId="attack-pattern--1",
        relationship_type="has-covered",
        **kwargs,
    )


def sent_input(client):
    return client.query.call_args_list[-1].args[1]["input"]


def sent_query(client):
    return client.query.call_args_list[-1].args[0]


def listed(nodes):
    edges = [{"node": node} for node in nodes]
    return {"data": {"stixCoreRelationships": {"edges": edges, "pageInfo": PAGE_INFO}}}


def test_coverage_platforms_are_sent_to_a_platform_that_knows_them(local_api_client):
    relationship = relationship_with(local_api_client, [SUPPORTED_INPUT, CREATED])
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    assert sent_input(local_api_client)["coverage_platforms_information"] == (
        COVERAGE_PLATFORMS
    )


def test_coverage_platforms_are_left_out_for_an_older_platform(local_api_client):
    relationship = relationship_with(local_api_client, [UNSUPPORTED_INPUT, CREATED])
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    assert "coverage_platforms_information" not in sent_input(local_api_client)
    local_api_client.app_logger.warning.assert_called_once()


def test_the_detection_runs_once_per_client(local_api_client):
    relationship = relationship_with(
        local_api_client, [SUPPORTED_INPUT, CREATED, CREATED]
    )
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    create_has_covered(relationship, coverage_platforms_information=[])
    assert local_api_client.query.call_count == 3
    assert sent_input(local_api_client)["coverage_platforms_information"] == []


def test_a_failed_detection_leaves_the_field_out_until_it_is_retried(local_api_client):
    relationship = relationship_with(
        local_api_client,
        [
            Exception("introspection disabled"),
            CREATED,
            CREATED,
            SUPPORTED_INPUT,
            CREATED,
        ],
    )
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    assert "coverage_platforms_information" not in sent_input(local_api_client)
    assert local_api_client.query.call_count == 3
    relationship._input_fields_retry_at = 0.0
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    assert sent_input(local_api_client)["coverage_platforms_information"] == (
        COVERAGE_PLATFORMS
    )


def test_an_older_platform_is_checked_again_after_the_retry_delay(local_api_client):
    relationship = relationship_with(
        local_api_client,
        [UNSUPPORTED_INPUT, CREATED, CREATED, SUPPORTED_INPUT, CREATED, CREATED],
    )
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    assert "coverage_platforms_information" not in sent_input(local_api_client)
    assert local_api_client.query.call_count == 3
    # The platform was upgraded meanwhile: once the delay is over, the field is detected and kept
    relationship._input_fields_retry_at = 0.0
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    create_has_covered(relationship, coverage_platforms_information=COVERAGE_PLATFORMS)
    assert sent_input(local_api_client)["coverage_platforms_information"] == (
        COVERAGE_PLATFORMS
    )
    assert local_api_client.query.call_count == 6


def test_a_relationship_without_coverage_platforms_needs_no_detection(
    local_api_client,
):
    relationship = relationship_with(local_api_client, [CREATED])
    create_has_covered(relationship)
    assert local_api_client.query.call_count == 1
    assert "coverage_platforms_information" not in sent_input(local_api_client)


def test_read_returns_the_coverage_platforms_of_a_platform_that_knows_them(
    local_api_client,
):
    relationship = relationship_with(
        local_api_client,
        [SUPPORTED_OUTPUT, {"data": {"stixCoreRelationship": dict(HAS_COVERED)}}],
    )
    read = relationship.read(id="relationship-1")
    assert "coverage_platforms_information {" in sent_query(local_api_client)
    assert read["coverage_platforms_information"] == COVERAGE_PLATFORMS


def test_list_returns_the_coverage_platforms_and_detects_once(local_api_client):
    relationship = relationship_with(
        local_api_client,
        [SUPPORTED_OUTPUT, listed([dict(HAS_COVERED)]), listed([dict(HAS_COVERED)])],
    )
    first = relationship.list(relationship_type="has-covered")
    second = relationship.list(relationship_type="has-covered")
    assert "coverage_platforms_information {" in sent_query(local_api_client)
    assert first[0]["coverage_platforms_information"] == COVERAGE_PLATFORMS
    assert second[0]["coverage_platforms_information"] == COVERAGE_PLATFORMS
    assert local_api_client.query.call_count == 3


def test_an_older_platform_is_read_without_the_coverage_platforms(local_api_client):
    older = {
        key: value
        for key, value in HAS_COVERED.items()
        if key != "coverage_platforms_information"
    }
    relationship = relationship_with(
        local_api_client,
        [UNSUPPORTED_OUTPUT, {"data": {"stixCoreRelationship": older}}],
    )
    read = relationship.read(id="relationship-1")
    assert "coverage_platforms_information" not in sent_query(local_api_client)
    assert read["coverage_information"] == HAS_COVERED["coverage_information"]


STIX_PLATFORM_REF = "identity--fd6bb94b-46b7-5e41-90d0-2a0fcf171ca2"


def stix_coverage(**overrides):
    return {
        "platform_ref": STIX_PLATFORM_REF,
        "name": "DETECTION",
        "score": 75,
        **overrides,
    }


@pytest.mark.parametrize(
    "malformed",
    [
        stix_coverage(platform_ref=42),
        stix_coverage(platform_ref=""),
        stix_coverage(name=12),
        stix_coverage(name=""),
        stix_coverage(score="none"),
        stix_coverage(score=True),
        stix_coverage(score=float("nan")),
        stix_coverage(score=float("inf")),
        {"platform_ref": STIX_PLATFORM_REF, "name": "DETECTION"},
    ],
)
def test_a_malformed_coverage_platform_is_skipped(malformed):
    converted = StixCoreRelationship.convert_coverage_platforms(
        [malformed, stix_coverage()]
    )
    assert converted == COVERAGE_PLATFORMS


def test_a_decimal_coverage_platform_score_is_rounded_half_up():
    converted = StixCoreRelationship.convert_coverage_platforms(
        [stix_coverage(score=74.5), stix_coverage(score=60.2)]
    )
    assert [c["coverage_score"] for c in converted] == [75, 60]


def test_custom_attributes_need_no_detection(local_api_client):
    relationship = relationship_with(
        local_api_client, [{"data": {"stixCoreRelationship": {"id": "relationship-1"}}}]
    )
    relationship.read(id="relationship-1", customAttributes="id")
    assert local_api_client.query.call_count == 1
