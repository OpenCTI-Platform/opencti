"""Tests for connector registration compatibility."""

from unittest.mock import MagicMock

import pytest

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
    api.query.return_value = {"data": {"registerConnector": {"id": "connector-id"}}}

    result = OpenCTIApiConnector(api).register(_connector())

    assert result == {"id": "connector-id"}
    variables = api.query.call_args.args[1]
    assert variables["input"]["version"] == "1.2.3"
    assert variables["input"]["slug"] == "test-connector"
    api.query.assert_called_once()


def test_register_retries_without_version_and_slug_for_older_platform():
    api = MagicMock()
    api.query.side_effect = [
        ValueError(
            {
                "name": "GRAPHQL_VALIDATION_FAILED",
                "error_message": (
                    'Field "version" is not defined by type '
                    '"RegisterConnectorInput".'
                ),
            }
        ),
        {"data": {"registerConnector": {"id": "connector-id"}}},
    ]
    connector = _connector()

    result = OpenCTIApiConnector(api).register(connector)

    assert result == {"id": "connector-id"}
    first_variables = connector.to_input()
    legacy_variables = connector.to_input()
    legacy_variables["input"].pop("version")
    legacy_variables["input"].pop("slug")
    first_call, second_call = api.query.call_args_list
    assert first_call.args[0] == second_call.args[0]
    assert first_call.args[1] == first_variables
    assert second_call.args[1] == legacy_variables
    api.app_logger.info.assert_called_once()


def test_register_does_not_retry_other_errors():
    api = MagicMock()
    error = ValueError(
        {
            "name": "VALIDATION_ERROR",
            "error_message": "Connector version is not a valid semantic version",
        }
    )
    api.query.side_effect = error

    with pytest.raises(ValueError) as raised:
        OpenCTIApiConnector(api).register(_connector())

    assert raised.value is error
    api.query.assert_called_once()
