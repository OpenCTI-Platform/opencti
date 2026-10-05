# coding: utf-8
"""Unit tests of the detection rule metadata of indicators (OpenCTI-Platform/opencti#18679)."""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.entities.indicator.opencti_indicator_properties import (
    INDICATOR_RULE_PROPERTIES,
)
from pycti.entities.opencti_indicator import Indicator

SUPPORTED_FIELDS = {
    "data": {
        "__type": {
            "fields": [
                {"name": "pattern"},
                {"name": "x_opencti_rule_status"},
                {"name": "x_opencti_rule_level"},
                {"name": "x_opencti_rule_logsource"},
            ]
        }
    }
}
UNSUPPORTED_FIELDS = {"data": {"__type": {"fields": [{"name": "pattern"}]}}}


@pytest.fixture
def local_api_client():
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


def indicator_with(client, responses):
    client.query = MagicMock(side_effect=responses)
    return Indicator(client)


def test_default_selection_has_the_rule_metadata_on_a_platform_that_knows_it(
    local_api_client,
):
    indicator = indicator_with(local_api_client, [SUPPORTED_FIELDS])
    assert INDICATOR_RULE_PROPERTIES in indicator.properties
    assert INDICATOR_RULE_PROPERTIES in indicator.properties_with_files
    # The detection runs once per client
    assert local_api_client.query.call_count == 1


def test_default_selection_leaves_the_rule_metadata_out_on_an_older_platform(
    local_api_client,
):
    indicator = indicator_with(local_api_client, [UNSUPPORTED_FIELDS])
    assert "x_opencti_rule_status" not in indicator.properties
    assert "x_opencti_rule_status" not in indicator.properties_with_files


def test_a_failed_detection_selects_no_rule_metadata_until_it_is_retried(
    local_api_client,
):
    indicator = indicator_with(
        local_api_client, [Exception("introspection disabled"), SUPPORTED_FIELDS]
    )
    assert "x_opencti_rule_status" not in indicator.properties
    # The failure is kept until the retry delay is over, the platform is not asked again before
    assert "x_opencti_rule_status" not in indicator.properties_with_files
    assert local_api_client.query.call_count == 1
    indicator._rule_metadata_retry_at = 0.0
    assert INDICATOR_RULE_PROPERTIES in indicator.properties
    assert local_api_client.query.call_count == 2


def test_an_older_platform_is_checked_again_after_the_retry_delay(local_api_client):
    indicator = indicator_with(local_api_client, [UNSUPPORTED_FIELDS, SUPPORTED_FIELDS])
    assert "x_opencti_rule_status" not in indicator.properties
    assert "x_opencti_rule_status" not in indicator.properties
    assert local_api_client.query.call_count == 1
    # The platform was upgraded meanwhile: once the delay is over, the client sees it
    indicator._rule_metadata_retry_at = 0.0
    assert INDICATOR_RULE_PROPERTIES in indicator.properties
    assert INDICATOR_RULE_PROPERTIES in indicator.properties
    assert local_api_client.query.call_count == 2


def test_rule_metadata_input_keeps_the_set_values_for_a_platform_that_knows_it(
    local_api_client,
):
    indicator = indicator_with(local_api_client, [SUPPORTED_FIELDS])
    assert indicator._rule_metadata_input("stable", None, {"product": "windows"}) == {
        "x_opencti_rule_status": "stable",
        "x_opencti_rule_logsource": {"product": "windows"},
    }


def test_rule_metadata_input_is_left_out_for_an_older_platform(local_api_client):
    indicator = indicator_with(local_api_client, [UNSUPPORTED_FIELDS])
    assert indicator._rule_metadata_input("stable", "high", None) == {}
    local_api_client.app_logger.warning.assert_called_once()


def test_unset_rule_metadata_needs_no_detection(local_api_client):
    indicator = indicator_with(local_api_client, [])
    assert indicator._rule_metadata_input(None, None, None) == {}
    local_api_client.query.assert_not_called()
