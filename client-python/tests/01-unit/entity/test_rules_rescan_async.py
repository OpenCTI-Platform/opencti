import re
from unittest.mock import MagicMock, patch

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_stix_core_object import StixCoreObject
from pycti.utils.opencti_stix2 import OpenCTIStix2

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


@pytest.fixture
def opencti_mock():
    """A mocked API client whose rescan reports it is finished at once."""
    mock = MagicMock()
    mock.query.return_value = {"data": {"rulesRescanAsync": True}}
    return mock


@pytest.fixture
def local_api_client():
    """A real OpenCTIApiClient instance, without hitting the network."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            "http://localhost:4000",
            "test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
    client.app_logger = MagicMock()
    return client


class TestRulesRescanAsync:
    """Rules rescan of an element, as run by the background task (#20145)."""

    def test_mutation_declares_and_passes_the_execution_id(self, opencti_mock):
        """Both variables are declared on the operation and passed to the field."""
        StixCoreObject(opencti_mock).rule_rescan_async(
            element_id="element-1", execution_id="bundle-1"
        )
        query, variables = opencti_mock.query.call_args[0]
        signature = re.search(r"mutation\s+\w+\s*\(([^)]*)\)", query).group(1)
        assert "$elementId: ID!" in signature
        assert "$executionId: ID!" in signature
        field_args = re.search(r"rulesRescanAsync\s*\(([^)]*)\)", query).group(1)
        assert "elementId: $elementId" in field_args
        assert "executionId: $executionId" in field_args
        assert variables == {"elementId": "element-1", "executionId": "bundle-1"}

    def test_polls_until_the_rescan_is_finished(self, opencti_mock):
        """The mutation is called again while the platform answers not finished."""
        opencti_mock.query.side_effect = [
            {"data": {"rulesRescanAsync": False}},
            {"data": {"rulesRescanAsync": False}},
            {"data": {"rulesRescanAsync": True}},
        ]
        StixCoreObject(opencti_mock).rule_rescan_async(
            element_id="element-1", execution_id="bundle-1"
        )
        assert opencti_mock.query.call_count == 3

    def test_does_nothing_without_execution_id(self, opencti_mock):
        """Without an execution id no mutation is sent."""
        StixCoreObject(opencti_mock).rule_rescan_async(element_id="element-1")
        opencti_mock.query.assert_not_called()

    def test_rules_rescan_operation_calls_the_async_rescan(self, local_api_client):
        """The rules_rescan operation of a bundle reaches rule_rescan_async."""
        stix2 = OpenCTIStix2(local_api_client)
        item = {
            "id": "ipv4-addr--0b2a9c3e-7a39-5f3a-9a2a-1f0b9d3c1a11",
            "type": "ipv4-addr",
            "extensions": {OPENCTI_EXTENSION_ID: {"opencti_operation": "rules_rescan"}},
        }
        with patch.object(
            local_api_client.stix_core_object, "rule_rescan_async"
        ) as rule_rescan_async:
            stix2.apply_opencti_operation(item, "rules_rescan", "bundle-1")
        rule_rescan_async.assert_called_once_with(
            element_id=item["id"], execution_id="bundle-1"
        )
