"""Tests for scope normalization in OpenCTIConnector.

Verifies that ``scope`` accepts either a comma-separated string or a
list/tuple of strings, and is always normalized to a ``list`` on the
resulting instance.
"""

from unittest import TestCase

from pycti.connector.opencti_connector import OpenCTIConnector

BASE_KWARGS = {
    "connector_id": "550e8400-e29b-41d4-a716-446655440000",
    "connector_name": "TestConnector",
    "connector_type": "EXTERNAL_IMPORT",
    "auto": False,
    "only_contextual": False,
    "playbook_compatible": False,
    "auto_update": False,
    "enrichment_resolution": "none",
}


class TestOpenCTIConnectorScope(TestCase):
    """Test that scope is normalized regardless of the input type."""

    def test_scope_as_comma_separated_string(self):
        """A comma-separated string should be split into a list."""
        connector = OpenCTIConnector(scope="Report,Indicator", **BASE_KWARGS)
        self.assertEqual(connector.scope, ["Report", "Indicator"])

    def test_scope_as_single_string(self):
        """A single scope string without commas should become a one-item list."""
        connector = OpenCTIConnector(scope="Report", **BASE_KWARGS)
        self.assertEqual(connector.scope, ["Report"])

    def test_scope_as_list(self):
        """A list of strings should be kept as-is (copied into a list)."""
        connector = OpenCTIConnector(scope=["Report", "Indicator"], **BASE_KWARGS)
        self.assertEqual(connector.scope, ["Report", "Indicator"])

    def test_scope_as_tuple(self):
        """A tuple of strings should be normalized to a list."""
        connector = OpenCTIConnector(scope=("Report", "Indicator"), **BASE_KWARGS)
        self.assertEqual(connector.scope, ["Report", "Indicator"])
        self.assertIsInstance(connector.scope, list)

    def test_scope_empty_string(self):
        """An empty string should result in an empty list."""
        connector = OpenCTIConnector(scope="", **BASE_KWARGS)
        self.assertEqual(connector.scope, [])

    def test_scope_none(self):
        """None should result in an empty list."""
        connector = OpenCTIConnector(scope=None, **BASE_KWARGS)
        self.assertEqual(connector.scope, [])

    def test_scope_empty_list(self):
        """An empty list should result in an empty list."""
        connector = OpenCTIConnector(scope=[], **BASE_KWARGS)
        self.assertEqual(connector.scope, [])

    def test_to_input_reflects_normalized_scope(self):
        """to_input() should expose the normalized list, regardless of input type."""
        connector_from_str = OpenCTIConnector(scope="Report,Indicator", **BASE_KWARGS)
        connector_from_list = OpenCTIConnector(
            scope=["Report", "Indicator"], **BASE_KWARGS
        )

        self.assertEqual(
            connector_from_str.to_input()["input"]["scope"],
            connector_from_list.to_input()["input"]["scope"],
        )
