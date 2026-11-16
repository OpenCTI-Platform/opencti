from unittest.mock import MagicMock, patch

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_stix_core_object import StixCoreObject
from pycti.utils.opencti_stix2 import OpenCTIStix2

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


@pytest.fixture
def opencti_mock():
    """A mocked API client whose query returns an empty data payload."""
    mock = MagicMock()
    mock.query.return_value = {"data": {}}
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


class TestAskEnrichmentInvestigation:
    """Forwarding of the investigation id by the enrichment calls of pycti."""

    def test_ask_enrichments_without_investigation_sends_none(self, opencti_mock):
        """Without an investigation, ask_enrichments sends a null investigation id."""
        StixCoreObject(opencti_mock).ask_enrichments(
            element_id="element-1", connector_ids=["c1"]
        )
        query, variables = opencti_mock.query.call_args[0]
        assert "investigationId: $investigationId" in query
        assert variables == {
            "id": "element-1",
            "connectorIds": ["c1"],
            "investigationId": None,
        }

    def test_ask_enrichment_without_investigation_sends_none(self, opencti_mock):
        """Without an investigation, ask_enrichment sends a null investigation id."""
        StixCoreObject(opencti_mock).ask_enrichment(
            element_id="element-1", connector_id="c1"
        )
        query, variables = opencti_mock.query.call_args[0]
        assert "investigationId: $investigationId" in query
        assert variables == {
            "id": "element-1",
            "connectorId": "c1",
            "investigationId": None,
        }

    def test_ask_enrichments_sends_the_investigation_when_set(self, opencti_mock):
        """ask_enrichments adds $investigationId when an investigation is given."""
        StixCoreObject(opencti_mock).ask_enrichments(
            element_id="element-1", connector_ids=["c1"], investigation_id="inv-1"
        )
        query, variables = opencti_mock.query.call_args[0]
        assert "investigationId: $investigationId" in query
        assert variables["investigationId"] == "inv-1"

    def test_ask_enrichment_sends_the_investigation_when_set(self, opencti_mock):
        """ask_enrichment adds $investigationId when an investigation is given."""
        StixCoreObject(opencti_mock).ask_enrichment(
            element_id="element-1", connector_id="c1", investigation_id="inv-1"
        )
        query, variables = opencti_mock.query.call_args[0]
        assert "investigationId: $investigationId" in query
        assert variables == {
            "id": "element-1",
            "connectorId": "c1",
            "investigationId": "inv-1",
        }

    def test_enrichment_operation_forwards_the_investigation(self, local_api_client):
        """The enrichment operation passes the investigation id to ask_enrichments."""
        stix2 = OpenCTIStix2(local_api_client)
        item = {
            "id": "intrusion-set--0b2a9c3e-7a39-5f3a-9a2a-1f0b9d3c1a11",
            "type": "intrusion-set",
            "extensions": {
                OPENCTI_EXTENSION_ID: {
                    "opencti_operation": "enrichment",
                    "connector_ids": ["c1"],
                    "investigation_id": "inv-1",
                }
            },
        }
        with patch.object(
            local_api_client.stix_core_object, "ask_enrichments"
        ) as ask_enrichments:
            stix2.apply_opencti_operation(item, "enrichment", "bundle-1")
        ask_enrichments.assert_called_once_with(
            element_id=item["id"], connector_ids=["c1"], investigation_id="inv-1"
        )

    def test_enrichment_operation_without_investigation(self, local_api_client):
        """The enrichment operation passes None when the item has no investigation id."""
        stix2 = OpenCTIStix2(local_api_client)
        item = {
            "id": "intrusion-set--0b2a9c3e-7a39-5f3a-9a2a-1f0b9d3c1a11",
            "type": "intrusion-set",
            "extensions": {
                OPENCTI_EXTENSION_ID: {
                    "opencti_operation": "enrichment",
                    "connector_ids": ["c1"],
                }
            },
        }
        with patch.object(
            local_api_client.stix_core_object, "ask_enrichments"
        ) as ask_enrichments:
            stix2.apply_opencti_operation(item, "enrichment", "bundle-1")
        ask_enrichments.assert_called_once_with(
            element_id=item["id"], connector_ids=["c1"], investigation_id=None
        )
