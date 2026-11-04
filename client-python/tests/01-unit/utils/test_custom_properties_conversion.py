# coding: utf-8
"""The dict of STIX x_* custom properties given to a create method (the stix2 convention
used by the connectors) is converted into custom field inputs, as for a STIX import, so that
the platform maps it to a custom field by name or alias."""

from unittest.mock import MagicMock

import pytest

from pycti.entities.opencti_identity import Identity
from pycti.utils.opencti_stix2_utils import build_custom_field_values_input


def test_keeps_the_explicit_custom_field_values_without_custom_properties():
    explicit = [{"field_name": "x_opencti_cf_score", "value": 5}]
    assert build_custom_field_values_input(explicit, None) is explicit
    assert build_custom_field_values_input(None, None) is None


def test_converts_the_dict_of_stix_custom_properties():
    custom_properties = {
        "x_opencti_cf_score": 5,
        "x_priority": ["P1", "P2"],
        "x_empty": None,
        "not_custom": "ignored",
    }
    assert build_custom_field_values_input(None, custom_properties) == [
        {"field_name": "x_opencti_cf_score", "value": 5},
        {"field_name": "x_priority", "value": ["P1", "P2"]},
    ]
    assert build_custom_field_values_input(None, {}) is None
    assert build_custom_field_values_input(None, {"x_empty": None}) is None


def test_the_explicit_custom_field_value_wins_for_a_same_name():
    explicit = [{"field_name": "x_priority", "value": "P1"}]
    custom_properties = {"x_priority": "P3", "x_opencti_cf_score": 5}
    assert build_custom_field_values_input(explicit, custom_properties) == [
        {"field_name": "x_priority", "value": "P1"},
        {"field_name": "x_opencti_cf_score", "value": 5},
    ]


@pytest.mark.parametrize(
    "custom_properties", [[{"field_name": "x_priority", "value": "P1"}], "x_priority"]
)
def test_ignores_custom_properties_that_are_not_a_dict(custom_properties):
    logger = MagicMock()
    assert build_custom_field_values_input(None, custom_properties, logger) is None
    logger.warning.assert_called_once()


def test_identity_creation_with_a_dict_of_stix_custom_properties():
    # As the GreyNoise Feed connector: no error, the platform keeping the properties
    # matching a custom field (by name or alias) and ignoring the other ones
    opencti = MagicMock()
    opencti.query.return_value = {"data": {"organizationAdd": {"id": "identity-id"}}}
    Identity(opencti).create(
        type="Organization",
        name="GreyNoise Feed",
        custom_properties={
            "x_opencti_reliability": "B - Usually reliable",
            "x_opencti_organization_type": "vendor",
        },
    )
    variables = opencti.query.call_args[0][1]
    assert variables["input"]["customFieldValues"] == [
        {"field_name": "x_opencti_reliability", "value": "B - Usually reliable"},
        {"field_name": "x_opencti_organization_type", "value": "vendor"},
    ]
