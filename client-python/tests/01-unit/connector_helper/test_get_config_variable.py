"""Tests for get_config_variable handling of explicitly-null config values.

Regression coverage for the case where a configuration key is present in the
YAML/dict config but its value is explicitly ``None`` (e.g. a Pydantic settings
model that dumps unset Optional fields as ``null``). Previously this reached
``int(None)`` when ``isNumber=True`` and crashed the connector at startup.
"""

from unittest import TestCase

from pycti.connector.opencti_connector_helper import get_config_variable


class GetConfigVariableNoneTest(TestCase):
    def test_explicit_none_number_falls_back_to_default(self):
        # Reproduces the reported servicenow crash: the key exists but is None
        # and isNumber=True should return the default instead of raising.
        config = {"connector": {"send_to_directory_retention": None}}
        result = get_config_variable(
            "CONNECTOR_SEND_TO_DIRECTORY_RETENTION",
            ["connector", "send_to_directory_retention"],
            config,
            isNumber=True,
            default=7,
        )
        self.assertEqual(result, 7)

    def test_explicit_none_non_number_falls_back_to_default(self):
        config = {"connector": {"some_value": None}}
        result = get_config_variable(
            "CONNECTOR_SOME_VALUE",
            ["connector", "some_value"],
            config,
            default="fallback",
        )
        self.assertEqual(result, "fallback")

    def test_explicit_none_required_without_default_raises(self):
        config = {"connector": {"mandatory": None}}
        with self.assertRaises(ValueError):
            get_config_variable(
                "CONNECTOR_MANDATORY",
                ["connector", "mandatory"],
                config,
                required=True,
            )

    def test_present_number_still_parsed(self):
        # Guard against regressions: a real value must still be returned as int.
        config = {"connector": {"send_to_directory_retention": 30}}
        result = get_config_variable(
            "CONNECTOR_SEND_TO_DIRECTORY_RETENTION",
            ["connector", "send_to_directory_retention"],
            config,
            isNumber=True,
            default=7,
        )
        self.assertEqual(result, 30)

    def test_absent_key_still_returns_default(self):
        result = get_config_variable(
            "CONNECTOR_MISSING",
            ["connector", "missing"],
            {"connector": {}},
            isNumber=True,
            default=7,
        )
        self.assertEqual(result, 7)
