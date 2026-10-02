# coding: utf-8
"""Custom field values carried by STIX objects must be forwarded on import,
for entities as well as for relationships and sightings."""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2


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


def test_extract_custom_properties_reads_top_level_and_extensions():
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

    assert OpenCTIStix2.extract_custom_properties(stix_object) == [
        {"field_name": "x_opencti_cf_priority", "value": "P1"},
        {"field_name": "x_opencti_cf_score", "value": 80},
    ]


def test_extract_custom_properties_returns_none_without_custom_property():
    assert OpenCTIStix2.extract_custom_properties({"type": "report"}) is None


def test_import_relationship_forwards_custom_properties(opencti_stix2: OpenCTIStix2):
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
    assert extras["custom_properties"] == [
        {"field_name": "x_opencti_cf_confidence_level", "value": 80}
    ]


def test_import_sighting_forwards_custom_properties(opencti_stix2: OpenCTIStix2):
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

    assert mocked_create.call_args.kwargs["custom_properties"] == [
        {"field_name": "x_opencti_cf_triage_status", "value": "confirmed"}
    ]
