"""Unit tests covering the import of a procedure component (component-of
relationship) with its position and type, x_component_index and
x_component_type, into the stixCoreRelationshipAdd mutation.
"""

from unittest.mock import MagicMock

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship


@pytest.fixture
def opencti_mock():
    mock = MagicMock()
    mock.query.return_value = {"data": {"stixCoreRelationshipAdd": {}}}
    mock.process_multiple_fields.side_effect = lambda x: x
    mock.get_attribute_in_extension.side_effect = (
        OpenCTIApiClient.get_attribute_in_extension
    )
    return mock


def _stix_relationship(relationship_type, **properties):
    return {
        "id": "relationship--3f1a9a52-5c0e-4b52-9c1f-6a2f1c7d9e10",
        "type": "relationship",
        "spec_version": "2.1",
        "relationship_type": relationship_type,
        "source_ref": "text--0b1f0e3c-8f4e-5f3a-9a1b-2c3d4e5f6a7b",
        "target_ref": "x-opencti-procedure--6c2d9a1e-4b3f-4e8a-9d7c-1a2b3c4d5e6f",
        **properties,
    }


def _mutation_input(opencti_mock):
    _, variables = opencti_mock.query.call_args[0]
    return variables["input"]


class TestComponentOfImport:
    def test_component_index_and_type_reach_the_mutation(self, opencti_mock):
        stix_relation = _stix_relationship(
            "component-of", x_component_index=2, x_component_type="secondary"
        )

        StixCoreRelationship(opencti_mock).import_from_stix2(stixRelation=stix_relation)

        mutation_input = _mutation_input(opencti_mock)
        assert mutation_input["component_index"] == 2
        assert mutation_input["component_type"] == "secondary"

    def test_component_index_zero_is_kept(self, opencti_mock):
        stix_relation = _stix_relationship(
            "component-of", x_component_index=0, x_component_type="primary"
        )

        StixCoreRelationship(opencti_mock).import_from_stix2(stixRelation=stix_relation)

        mutation_input = _mutation_input(opencti_mock)
        assert mutation_input["component_index"] == 0
        assert mutation_input["component_type"] == "primary"

    def test_other_relationships_send_no_component_fields(self, opencti_mock):
        StixCoreRelationship(opencti_mock).import_from_stix2(
            stixRelation=_stix_relationship("uses")
        )

        mutation_input = _mutation_input(opencti_mock)
        assert "component_index" not in mutation_input
        assert "component_type" not in mutation_input
