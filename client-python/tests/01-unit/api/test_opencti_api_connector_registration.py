"""Tests for connector registration compatibility."""

from unittest.mock import MagicMock

from pycti.api.opencti_api_connector import OpenCTIApiConnector
from pycti.connector.opencti_connector import OpenCTIConnector


def _connector():
    return OpenCTIConnector(
        connector_id="550e8400-e29b-41d4-a716-446655440000",
        connector_name="Test Connector",
        connector_type="EXTERNAL_IMPORT",
        scope="Report",
        auto=False,
        only_contextual=False,
        playbook_compatible=False,
        auto_update=False,
        enrichment_resolution="none",
        version="1.2.3",
        slug="test-connector",
    )


def test_register_sends_version_and_slug():
    api = MagicMock()
    api.query.side_effect = [
        {
            "data": {
                "__type": {
                    "inputFields": [
                        {"name": "version"},
                        {"name": "slug"},
                    ]
                }
            }
        },
        {"data": {"registerConnector": {"id": "connector-id"}}},
    ]

    result = OpenCTIApiConnector(api).register(_connector())

    assert result == {"id": "connector-id"}
    variables = api.query.call_args_list[1].args[1]
    assert variables["input"]["version"] == "1.2.3"
    assert variables["input"]["slug"] == "test-connector"
    assert api.query.call_count == 2


def test_register_omits_version_and_slug_for_older_platform():
    api = MagicMock()
    api.query.side_effect = [
        {
            "data": {
                "__type": {
                    "inputFields": [
                        {"name": "id"},
                        {"name": "name"},
                    ]
                }
            }
        },
        {"data": {"registerConnector": {"id": "connector-id"}}},
    ]

    result = OpenCTIApiConnector(api).register(_connector())

    assert result == {"id": "connector-id"}
    variables = api.query.call_args_list[1].args[1]
    assert "version" not in variables["input"]
    assert "slug" not in variables["input"]
    api.app_logger.info.assert_called_once()


def test_register_rechecks_registration_metadata_support():
    api = MagicMock()
    api.query.side_effect = [
        {
            "data": {
                "__type": {
                    "inputFields": [
                        {"name": "version"},
                        {"name": "slug"},
                    ]
                }
            }
        },
        {"data": {"registerConnector": {"id": "connector-id"}}},
        {
            "data": {
                "__type": {
                    "inputFields": [
                        {"name": "version"},
                        {"name": "slug"},
                    ]
                }
            }
        },
        {"data": {"registerConnector": {"id": "connector-id"}}},
    ]
    api_connector = OpenCTIApiConnector(api)

    api_connector.register(_connector())
    api_connector.register(_connector())

    assert api.query.call_count == 4
