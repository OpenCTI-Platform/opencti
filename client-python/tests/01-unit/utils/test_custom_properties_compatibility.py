# coding: utf-8
"""custom_properties of the create methods: the dict of STIX x_* custom properties (the stix2
convention used by the connectors) is converted into custom field inputs, a list of custom field
inputs is forwarded as is, any other value is ignored with a warning instead of making the
creation fail."""

from unittest.mock import MagicMock

import pytest

from pycti.entities.opencti_identity import Identity
from pycti.utils.opencti_stix2_utils import normalize_custom_field_values_input


def test_converts_a_dict_of_stix_custom_properties():
    logger = MagicMock()
    custom_properties = {
        "x_opencti_cf_score": 5,
        "x_priority": ["P1", "P2"],
        "x_empty": None,
        "not_custom": "ignored",
    }
    assert normalize_custom_field_values_input(custom_properties, logger) == [
        {"field_name": "x_opencti_cf_score", "value": 5},
        {"field_name": "x_priority", "value": ["P1", "P2"]},
    ]
    assert normalize_custom_field_values_input({}, logger) is None
    assert normalize_custom_field_values_input({"x_empty": None}, logger) is None
    logger.warning.assert_not_called()


def test_forwards_a_list_of_custom_field_inputs():
    logger = MagicMock()
    inputs = [{"field_name": "x_opencti_cf_score", "value": 5}]
    assert normalize_custom_field_values_input(inputs, logger) == inputs
    assert normalize_custom_field_values_input([], logger) == []
    assert normalize_custom_field_values_input(None, logger) is None
    logger.warning.assert_not_called()


def test_skips_the_list_inputs_without_a_name_or_a_value():
    logger = MagicMock()
    valid = {"field_name": "x_opencti_cf_score", "value": 5}
    custom_properties = [
        valid,
        {"field_name": "x_opencti_cf_score"},
        {"field_name": "x_opencti_cf_score", "value": None},
        {"field_name": None, "value": 5},
        {"x_opencti_cf_score": 5},
        "x_opencti_cf_score",
    ]
    assert normalize_custom_field_values_input(custom_properties, logger) == [valid]
    logger.warning.assert_called_once()


@pytest.mark.parametrize("custom_properties", ["x_opencti_cf_score", 5, True])
def test_ignores_any_other_value_with_a_warning(custom_properties):
    logger = MagicMock()
    assert normalize_custom_field_values_input(custom_properties, logger) is None
    logger.warning.assert_called_once()


def test_identity_creation_with_a_dict_of_stix_custom_properties():
    # As the GreyNoise Feed connector, which crashed since the custom fields: the platform
    # keeps the properties matching a custom field definition and ignores the other ones
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
    opencti.app_logger.warning.assert_not_called()
