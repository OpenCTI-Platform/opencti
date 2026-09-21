"""Tests for centralized OpenCTI API compatibility detection."""

from unittest.mock import MagicMock

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.api.opencti_api_compatibility import OpenCTIApiCompatibility


def _compatibility_response(version, input_fields):
    return {
        "data": {
            "about": {"version": version},
            "registerConnectorInput": {
                "inputFields": [{"name": name} for name in input_fields]
            },
        }
    }


def test_compatibility_is_loaded_lazily_and_reused():
    api = MagicMock()
    api.query.return_value = _compatibility_response(
        "7.0.0",
        ["id", "version", "slug"],
    )
    compatibility = OpenCTIApiCompatibility(api)

    assert compatibility.connector_registration_metadata is True
    assert compatibility.platform_version == "7.0.0"
    api.query.assert_called_once()


def test_refresh_updates_compatibility_after_backend_change():
    api = MagicMock()
    api.query.side_effect = [
        _compatibility_response("6.7.0", ["id"]),
        _compatibility_response("7.0.0", ["id", "version", "slug"]),
    ]
    compatibility = OpenCTIApiCompatibility(api)

    assert compatibility.connector_registration_metadata is False

    compatibility.refresh()

    assert compatibility.platform_version == "7.0.0"
    assert compatibility.connector_registration_metadata is True
    assert api.query.call_count == 2


def test_introspection_failure_uses_legacy_compatibility():
    api = MagicMock()
    api.query.side_effect = ValueError("Introspection disabled")
    compatibility = OpenCTIApiCompatibility(api)

    assert compatibility.connector_registration_metadata is False
    api.app_logger.warning.assert_called_once()
    assert compatibility.connector_registration_metadata is False
    api.query.assert_called_once()


def test_health_check_refreshes_compatibility():
    api_client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    api_client.app_logger = MagicMock()
    api_client.compatibility = MagicMock()
    api_client.query = MagicMock(return_value={"data": {"about": {"version": "7.0.0"}}})

    assert api_client.health_check() is True
    api_client.query.assert_called_once()
    api_client.compatibility.refresh.assert_called_once()


def test_health_check_succeeds_when_compatibility_refresh_fails():
    api_client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    api_client.app_logger = MagicMock()
    api_client.compatibility = MagicMock()
    api_client.compatibility.refresh.side_effect = ValueError("Introspection disabled")
    api_client.query = MagicMock(return_value={"data": {"about": {"version": "7.0.0"}}})

    assert api_client.health_check() is True
    api_client.app_logger.warning.assert_called_once()
