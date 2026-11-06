# coding: utf-8
"""Custom field values carried by STIX objects must be forwarded on import,
for entities as well as for relationships and sightings."""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2
from pycti.entities.opencti_security_coverage_result import SecurityCoverageResult
from pycti.utils.opencti_stix2_utils import (
    build_custom_field_values_input,
    is_custom_field_input_value,
)


@pytest.fixture
def local_api_client():
    """A real OpenCTIApiClient instance, without hitting the network."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


@pytest.fixture
def opencti_stix2(local_api_client):
    instance = OpenCTIStix2(local_api_client)
    # Pre-seed the vocabulary cache so extract_embedded_relationships() does
    # not attempt a network call to fetch vocabulary categories.
    instance.mapping_cache_permanent["vocabularies_definition_fields"] = []
    return instance


def test_extract_custom_field_values_reads_top_level_and_extensions():
    stix_object = {
        "type": "report",
        "name": "Report",
        "x_opencti_cf_priority": "P1",
        "x_opencti_cf_empty": None,
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "x_opencti_cf_priority": "P3",
                "x_opencti_cf_score": 80,
            }
        },
    }

    assert OpenCTIStix2.extract_custom_field_values(stix_object) == [
        {"field_name": "x_opencti_cf_priority", "value": "P1"},
        {"field_name": "x_opencti_cf_score", "value": 80},
    ]


def test_extract_custom_field_values_skips_values_that_cannot_be_custom_fields():
    # The files are already sent as uploads: sending their base64 content again
    # as a custom field value doubles the request size (issue #19617)
    stix_file = {
        "name": "report.pdf",
        "data": "SGVsbG8=",
        "mime_type": "application/pdf",
    }
    stix_object = {
        "type": "report",
        "name": "Report",
        "x_opencti_files": [stix_file],
        "x_opencti_kill_chain_phases": [{"kill_chain_name": "k", "phase_name": "p"}],
        "x_opencti_cf_priority": "P1",
        "x_opencti_cf_tags": ["tag1", "tag2"],
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "x_opencti_files": [stix_file],
                "x_opencti_cf_details": {"nested": "object"},
                "x_opencti_cf_score": 80,
            }
        },
    }

    assert OpenCTIStix2.extract_custom_field_values(stix_object) == [
        {"field_name": "x_opencti_cf_priority", "value": "P1"},
        {"field_name": "x_opencti_cf_tags", "value": ["tag1", "tag2"]},
        {"field_name": "x_opencti_cf_score", "value": 80},
    ]


def test_extract_custom_field_values_keeps_top_level_precedence_for_skipped_values():
    stix_object = {
        "type": "report",
        "name": "Report",
        "x_opencti_cf_priority": {"level": "high"},
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "x_opencti_cf_priority": "P1",
            }
        },
    }

    assert OpenCTIStix2.extract_custom_field_values(stix_object) is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("text", True),
        (80, True),
        (12.5, True),
        (False, True),
        ("2026-11-05T00:00:00Z", True),
        (["tag1", "tag2"], True),
        ([], True),
        (None, False),
        ({"name": "report.pdf"}, False),
        ([{"name": "report.pdf"}], False),
        (["tag1", {"name": "report.pdf"}], False),
        ([["tag1"]], False),
    ],
)
def test_is_custom_field_input_value(value, expected):
    assert is_custom_field_input_value(value) is expected


def test_build_custom_field_values_input_skips_values_that_cannot_be_custom_fields():
    custom_properties = {
        "x_opencti_files": [{"name": "report.pdf", "data": "SGVsbG8="}],
        "x_opencti_cf_priority": "P1",
    }

    assert build_custom_field_values_input(None, custom_properties) == [
        {"field_name": "x_opencti_cf_priority", "value": "P1"}
    ]


def test_extract_custom_field_values_returns_none_without_custom_property():
    assert OpenCTIStix2.extract_custom_field_values({"type": "report"}) is None


def test_import_relationship_forwards_custom_field_values(opencti_stix2: OpenCTIStix2):
    stix_relation = {
        "type": "relationship",
        "id": "relationship--1e5e9e1b-5d6b-4c5e-9a3f-2c8d1c7a4b11",
        "relationship_type": "uses",
        "source_ref": "intrusion-set--2a3a0f2c-0c8e-4b6a-8f39-6f5f2c2b7d10",
        "target_ref": "malware--5b8e8b9c-3d3e-4f6a-9c1d-7e2f4a6b8c20",
        "x_opencti_cf_confidence_level": 80,
    }

    with patch.object(
        opencti_stix2.opencti.stix_core_relationship,
        "import_from_stix2",
        return_value=None,
    ) as mocked_import:
        opencti_stix2.import_relationship(stix_relation)

    extras = mocked_import.call_args.kwargs["extras"]
    assert extras["custom_field_values"] == [
        {"field_name": "x_opencti_cf_confidence_level", "value": 80}
    ]


def test_import_sighting_forwards_custom_field_values(opencti_stix2: OpenCTIStix2):
    stix_sighting = {
        "type": "sighting",
        "id": "sighting--3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e70",
        "sighting_of_ref": "indicator--4d5e6f7a-8b9c-4d1e-9f2a-3b4c5d6e7f80",
        "where_sighted_refs": ["identity--5e6f7a8b-9c1d-4e2f-8a3b-4c5d6e7f8a90"],
        "x_opencti_cf_triage_status": "confirmed",
    }

    with patch.object(
        opencti_stix2.opencti.stix_sighting_relationship,
        "create",
        return_value=None,
    ) as mocked_create:
        opencti_stix2.import_sighting(
            stix_sighting,
            from_id="indicator--4d5e6f7a-8b9c-4d1e-9f2a-3b4c5d6e7f80",
            to_id="identity--5e6f7a8b-9c1d-4e2f-8a3b-4c5d6e7f8a90",
        )

    assert mocked_create.call_args.kwargs["custom_field_values"] == [
        {"field_name": "x_opencti_cf_triage_status", "value": "confirmed"}
    ]


def test_import_security_coverage_result_sends_custom_field_values(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = {
        "type": "security-coverage-result",
        "id": "security-coverage-result--6f7a8b9c-1d2e-4f3a-8b4c-5d6e7f8a9b10",
        "name": "Result",
        "result_of_ref": "security-coverage--7a8b9c1d-2e3f-4a4b-9c5d-6e7f8a9b1c20",
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"securityCoverageResultAdd": {"id": "security-coverage-result--fake"}}
    }

    with patch.object(
        opencti_stix2.opencti.session, "post", return_value=mock_response
    ) as mocked_post:
        SecurityCoverageResult(opencti_stix2.opencti).import_from_stix2(
            stixObject=stix_object,
            extras={
                "custom_field_values": [
                    {"field_name": "x_opencti_cf_review", "value": ["done"]}
                ]
            },
        )

    sent_input = mocked_post.call_args.kwargs["json"]["variables"]["input"]
    assert sent_input["customFieldValues"] == [
        {"field_name": "x_opencti_cf_review", "value": ["done"]}
    ]


@pytest.mark.parametrize(
    "entity, kwargs",
    [
        (
            "identity",
            {
                "type": "Organization",
                "name": "Vendor",
                "custom_properties": {
                    "x_opencti_reliability": "B - Usually reliable",
                    "x_opencti_organization_type": "vendor",
                },
            },
        ),
        (
            "location",
            {
                "type": "City",
                "name": "Paris",
                "custom_properties": {"x_opencti_location_type": "City"},
            },
        ),
    ],
)
def test_create_converts_stix_custom_properties_into_custom_field_values(
    local_api_client, entity, kwargs
):
    mock_response = MagicMock()
    mock_response.status_code = 200
    created = {"id": "fake", "standard_id": "fake", "entity_type": "fake"}
    mock_response.json.return_value = {
        "data": {"organizationAdd": created, "locationAdd": created}
    }

    with patch.object(
        local_api_client.session, "post", return_value=mock_response
    ) as mocked_post:
        getattr(local_api_client, entity).create(**kwargs)

    # Converted as for a STIX import: the platform maps each property to a custom field
    # by name or alias, and ignores it if none matches, instead of rejecting the creation
    sent_input = mocked_post.call_args.kwargs["json"]["variables"]["input"]
    assert sent_input["customFieldValues"] == [
        {"field_name": key, "value": value}
        for key, value in kwargs["custom_properties"].items()
    ]
