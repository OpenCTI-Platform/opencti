import re

import pytest

from pycti import OpenCTIApiClient
from pycti.entities.opencti_stix_object_or_stix_relationship import (
    StixObjectOrStixRelationship,
)
from pycti.utils.opencti_stix2 import (
    PROVENANCE_READ_ONLY_FIELDS,
    STIX_EXT_OCTI_PROVENANCE,
    OpenCTIStix2,
)


@pytest.fixture
def api_client_no_server():
    return OpenCTIApiClient(
        "http://localhost:4000",
        "test-token",
        ssl_verify=False,
        perform_health_check=False,
    )


def test_get_provenance_extension_returns_summary():
    summary = {"corroboration_count": 3, "has_conflicts": False}
    stix_object = {
        "type": "malware",
        "extensions": {STIX_EXT_OCTI_PROVENANCE: summary},
    }
    assert OpenCTIApiClient.get_provenance_extension(stix_object) == summary


def test_get_provenance_extension_without_extension():
    assert OpenCTIApiClient.get_provenance_extension({"type": "malware"}) is None
    assert (
        OpenCTIApiClient.get_provenance_extension(
            {"type": "malware", "extensions": None}
        )
        is None
    )


def test_read_only_provenance_fields_cover_the_platform_side_channel():
    # PROVENANCE_SIDE_CHANNEL_FIELDS of the platform, which no client input may set
    side_channel = {
        "x_opencti_assertions",
        "assertion_source_ids",
        "assertion_source_kinds",
        "conflict_fields",
        "corroboration_count",
        "last_asserted_at",
        "single_sourced",
        "has_conflicts",
        "x_opencti_conflicts",
        "procedures",
        "freshness_stale",
        "freshness_stale_at",
        "freshness_rule_id",
    }
    assert side_channel <= set(PROVENANCE_READ_ONLY_FIELDS)


def test_generate_export_drops_read_only_provenance_fields(api_client_no_server):
    entity = {
        "id": "internal-id",
        "standard_id": "malware--8cd5b1a2-4d42-5c8e-9a0f-1d6e0e8a2b11",
        "entity_type": "Malware",
        "parent_types": ["Stix-Domain-Object"],
        "name": "Emotet",
        "is_family": True,
    }
    # A custom projection can return any of them, each with a non-empty value
    for field in PROVENANCE_READ_ONLY_FIELDS:
        entity[field] = [f"{field}-value"]
    stix = OpenCTIStix2(api_client_no_server).generate_export(entity)
    for field in PROVENANCE_READ_ONLY_FIELDS:
        assert field not in stix
    assert stix["name"] == "Emotet"
    assert stix["type"] == "malware"


def test_provenance_properties_cover_objects_and_relationships(
    api_client_no_server,
):
    properties = StixObjectOrStixRelationship(
        api_client_no_server
    ).provenance_properties
    for fragment in (
        "... on StixCoreObject",
        "... on StixCoreRelationship",
        "... on StixSightingRelationship",
    ):
        assert fragment in properties
    assert properties.count("x_opencti_assertions") == 3
    assert "procedures" in properties


def test_default_properties_carry_the_whole_provenance_summary(api_client_no_server):
    # Every helper of a STIX object selects spec_version; nested ref relationships carry no provenance
    helpers = {
        name: helper
        for name, helper in vars(api_client_no_server).items()
        if name != "stix_nested_ref_relationship"
        and isinstance(getattr(helper, "properties", None), str)
        and "spec_version" in helper.properties
    }
    assert {
        "opencti_stix_object_or_stix_relationship",
        "malware",
        "security_coverage",
        "security_coverage_result",
        "stix_core_relationship",
        "stix_sighting_relationship",
    } <= set(helpers)
    for name, helper in helpers.items():
        properties = helper.properties
        summaries = properties.count("corroboration_count")
        assert summaries > 0, name
        for field in ("single_sourced", "freshness_stale_at", "freshness_stale"):
            assert properties.count(field) >= summaries, (name, field)
        # Each field of the summary is selected once per summary, never twice
        for field in ("single_sourced", "freshness_stale_at", "has_conflicts"):
            assert len(re.findall(rf"\b{field}\b", properties)) == summaries, (
                name,
                field,
            )
