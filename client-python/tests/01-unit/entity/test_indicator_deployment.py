# coding: utf-8
"""Unit tests of the dissemination assurance write-back (OpenCTI-Platform/opencti#18680)."""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.entities.opencti_indicator_deployment import IndicatorDeployment

SUPPORTED_FIELDS = {
    "data": {
        "__type": {
            "fields": [
                {"name": "indicatorReportDeployment"},
                {"name": "indicatorReportDeployments"},
                {"name": "indicatorReportHits"},
            ]
        }
    }
}
UNSUPPORTED_FIELDS = {"data": {"__type": {"fields": [{"name": "stixBundlePush"}]}}}


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


def deployment_with(client, responses):
    client.query = MagicMock(side_effect=responses)
    return IndicatorDeployment(client)


def test_report_sends_the_contract_mutation(local_api_client):
    relationship = {"id": "rel-1", "deployment_status": "deployed"}
    deployment = deployment_with(
        local_api_client,
        [SUPPORTED_FIELDS, {"data": {"indicatorReportDeployment": relationship}}],
    )
    result = deployment.report(
        "indicator-1",
        "platform-1",
        "deployed",
        external_id="ti-1",
        synced_at="2026-10-03T10:00:00Z",
    )
    assert result == relationship
    query, variables = local_api_client.query.call_args_list[1].args
    assert "indicatorReportDeployment(" in query
    assert variables == {
        "indicatorId": "indicator-1",
        "platformId": "platform-1",
        "status": "deployed",
        "externalId": "ti-1",
        "metadata": {"last_sync_at": "2026-10-03T10:00:00Z"},
    }


def test_feature_detection_is_cached_and_degrades_gracefully(local_api_client):
    deployment = deployment_with(local_api_client, [UNSUPPORTED_FIELDS])
    assert deployment.report("indicator-1", "platform-1", "deployed") is None
    assert (
        deployment.report_hits(
            "indicator-1", "platform-1", 2, last_hit="2026-10-03T10:00:00Z"
        )
        is None
    )
    assert (
        deployment.report_batch(
            "platform-1", [{"indicator_id": "i", "status": "active"}]
        )
        is None
    )
    assert list(deployment.list_for_platform("platform-1")) == []
    # A single introspection query, no mutation sent
    assert local_api_client.query.call_count == 1


def test_errors_never_raise(local_api_client):
    deployment = deployment_with(
        local_api_client,
        [
            SUPPORTED_FIELDS,
            ValueError(
                {"name": "FUNCTIONAL_ERROR", "error_message": "Too many requests"}
            ),
        ],
    )
    assert (
        deployment.report("indicator-1", "platform-1", "failed", error_message="quota")
        is None
    )
    local_api_client.app_logger.warning.assert_called()


def test_invalid_status_is_rejected_locally(local_api_client):
    deployment = deployment_with(local_api_client, [])
    assert deployment.report("indicator-1", "platform-1", "expired") is None
    assert local_api_client.query.call_count == 0


def test_batch_is_chunked_and_aggregated(local_api_client):
    chunk_result = {
        "data": {
            "indicatorReportDeployments": {
                "processed": 500,
                "created": 10,
                "updated": 5,
                "unchanged": 485,
                "errors": [],
            }
        }
    }
    last_chunk = {
        "data": {
            "indicatorReportDeployments": {
                "processed": 1,
                "created": 0,
                "updated": 0,
                "unchanged": 1,
                "errors": [{"indicatorId": "x", "message": "not found"}],
            }
        }
    }
    deployment = deployment_with(
        local_api_client, [SUPPORTED_FIELDS, chunk_result, last_chunk]
    )
    reports = [
        {
            "indicator_id": f"indicator-{i}",
            "status": "active",
            "external_id": f"ext-{i}",
        }
        for i in range(501)
    ] + [{"indicator_id": "bad", "status": "unknown"}]
    result = deployment.report_batch("platform-1", reports)
    assert result == {
        "processed": 501,
        "created": 10,
        "updated": 5,
        "unchanged": 486,
        "errors": [
            {"indicatorId": "bad", "message": "Unsupported deployment status: unknown"},
            {"indicatorId": "x", "message": "not found"},
        ],
    }
    first_inputs = local_api_client.query.call_args_list[1].args[1]["reports"]
    assert len(first_inputs) == 500
    assert first_inputs[0] == {
        "indicatorId": "indicator-0",
        "status": "active",
        "externalId": "ext-0",
    }


def test_report_hits_validates_count(local_api_client):
    sighting = {"id": "sighting-1", "attribute_count": 3}
    deployment = deployment_with(
        local_api_client,
        [SUPPORTED_FIELDS, {"data": {"indicatorReportHits": sighting}}],
    )
    assert (
        deployment.report_hits(
            "indicator-1", "platform-1", 0, last_hit="2026-10-03T10:00:00Z"
        )
        is None
    )
    assert (
        deployment.report_hits(
            "indicator-1", "platform-1", 3, last_hit="2026-10-03T10:00:00Z"
        )
        == sighting
    )
    variables = local_api_client.query.call_args_list[1].args[1]
    assert variables["count"] == 3
    assert variables["lastHit"] == "2026-10-03T10:00:00Z"
    assert variables["reportId"] is None


def test_report_hits_forwards_the_report_id(local_api_client):
    sighting = {"id": "sighting-1", "attribute_count": 2}
    deployment = deployment_with(
        local_api_client,
        [SUPPORTED_FIELDS, {"data": {"indicatorReportHits": sighting}}],
    )
    # Two reports ending at the same instant are told apart by their id
    assert (
        deployment.report_hits(
            "indicator-1",
            "platform-1",
            2,
            last_hit="2026-10-03T10:00:00Z",
            report_id="report-2",
        )
        == sighting
    )
    query, variables = local_api_client.query.call_args_list[1].args
    assert "reportId: $reportId" in query
    assert variables["reportId"] == "report-2"


def test_report_hits_requires_the_last_hit(local_api_client):
    deployment = deployment_with(local_api_client, [SUPPORTED_FIELDS])
    # Without the vendor time of the newest hit, a retried report would be counted twice
    assert deployment.report_hits("indicator-1", "platform-1", 1, last_hit="") is None
    assert deployment.report_hits("indicator-1", "platform-1", 1, None) is None
    assert local_api_client.query.call_count == 0
    local_api_client.app_logger.warning.assert_called()


def test_security_platform_resolution_is_cached(local_api_client):
    platform = {
        "id": "platform-1",
        "standard_id": "identity--x",
        "name": "Microsoft Sentinel",
    }
    deployment = deployment_with(
        local_api_client, [{"data": {"securityPlatformAdd": platform}}]
    )
    assert (
        deployment.get_or_create_security_platform("Microsoft Sentinel", "SIEM")
        == platform
    )
    assert (
        deployment.get_or_create_security_platform(" microsoft sentinel ", "SIEM")
        == platform
    )
    assert local_api_client.query.call_count == 1
    variables = local_api_client.query.call_args.args[1]
    assert variables == {
        "input": {
            "name": "Microsoft Sentinel",
            "security_platform_type": "SIEM",
            "update": True,
        }
    }


def test_list_for_platform_paginates(local_api_client):
    page_1 = {
        "data": {
            "stixCoreRelationships": {
                "edges": [{"node": {"id": "rel-1"}}],
                "pageInfo": {"endCursor": "c1", "hasNextPage": True},
            }
        }
    }
    page_2 = {
        "data": {
            "stixCoreRelationships": {
                "edges": [{"node": {"id": "rel-2"}}],
                "pageInfo": {"endCursor": "c2", "hasNextPage": False},
            }
        }
    }
    deployment = deployment_with(local_api_client, [SUPPORTED_FIELDS, page_1, page_2])
    nodes = list(deployment.list_for_platform("platform-1", ["deployed", "active"]))
    assert [node["id"] for node in nodes] == ["rel-1", "rel-2"]
    variables = local_api_client.query.call_args_list[2].args[1]
    assert variables["after"] == "c1"
    assert variables["filters"]["filters"][0] == {
        "key": "deployment_status",
        "values": ["deployed", "active"],
    }


def test_import_of_deployed_on_carries_the_lifecycle(local_api_client):
    local_api_client.stix_core_relationship.create = MagicMock(
        return_value={"id": "rel-1"}
    )
    stix_relation = {
        "type": "relationship",
        "id": "relationship--9b1d3f5a-3333-4c4d-9e5f-fedcbafedcba",
        "relationship_type": "deployed-on",
        "source_ref": "indicator--3f6b4c1e-8f5e-4c43-9e52-0f8d5f0e5a11",
        "target_ref": "identity--7a0c2d4e-2222-4b3c-8d4e-abcdefabcdef",
        "validation_status": "missed",
        "last_validation_at": "2026-10-03T10:00:00Z",
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "validation_run_id": "request-1",
            }
        },
    }
    local_api_client.stix_core_relationship.import_from_stix2(
        stixRelation=stix_relation, extras={}
    )
    deployment = local_api_client.stix_core_relationship.create.call_args.kwargs[
        "deployment"
    ]
    assert deployment == {
        "validation_status": "missed",
        "last_validation_at": "2026-10-03T10:00:00Z",
        "validation_run_id": "request-1",
    }


def test_import_of_deployed_on_ignores_the_inferred_date(local_api_client):
    local_api_client.stix_core_relationship.create = MagicMock(
        return_value={"id": "rel-1"}
    )
    stix_relation = {
        "type": "relationship",
        "id": "relationship--9b1d3f5a-3333-4c4d-9e5f-fedcbafedcba",
        "relationship_type": "deployed-on",
        "source_ref": "indicator--3f6b4c1e-8f5e-4c43-9e52-0f8d5f0e5a11",
        "target_ref": "identity--7a0c2d4e-2222-4b3c-8d4e-abcdefabcdef",
    }
    local_api_client.stix_core_relationship.import_from_stix2(
        stixRelation=stix_relation, extras={}, defaultDate="2026-09-01T00:00:00Z"
    )
    kwargs = local_api_client.stix_core_relationship.create.call_args.kwargs
    assert kwargs["start_time"] is None
    assert kwargs["stop_time"] is None


def test_import_of_other_relationships_has_no_lifecycle(local_api_client):
    local_api_client.stix_core_relationship.create = MagicMock(
        return_value={"id": "rel-1"}
    )
    stix_relation = {
        "type": "relationship",
        "id": "relationship--9b1d3f5a-3333-4c4d-9e5f-fedcbafedcba",
        "relationship_type": "indicates",
        "source_ref": "indicator--3f6b4c1e-8f5e-4c43-9e52-0f8d5f0e5a11",
        "target_ref": "malware--7a0c2d4e-2222-4b3c-8d4e-abcdefabcdef",
        "validation_status": "missed",
    }
    local_api_client.stix_core_relationship.import_from_stix2(
        stixRelation=stix_relation, extras={}
    )
    assert (
        local_api_client.stix_core_relationship.create.call_args.kwargs["deployment"]
        is None
    )


def test_create_only_sends_present_deployment_fields(local_api_client):
    local_api_client.query = MagicMock(
        return_value={
            "data": {
                "stixCoreRelationshipAdd": {
                    "id": "rel-1",
                    "standard_id": "x",
                    "entity_type": "deployed-on",
                    "parent_types": [],
                }
            }
        }
    )
    local_api_client.stix_core_relationship.create(
        fromId="indicator-1",
        toId="platform-1",
        relationship_type="deployed-on",
        deployment={"validation_status": "detected", "hit_count": None, "unknown": "x"},
    )
    sent = local_api_client.query.call_args.args[1]["input"]
    assert sent["validation_status"] == "detected"
    assert "hit_count" not in sent
    assert "unknown" not in sent
    local_api_client.stix_core_relationship.create(
        fromId="indicator-1", toId="malware-1", relationship_type="indicates"
    )
    sent = local_api_client.query.call_args.args[1]["input"]
    assert "validation_status" not in sent


def test_batch_reports_every_rejected_entry(local_api_client):
    deployment = deployment_with(local_api_client, [])
    result = deployment.report_batch(
        "platform-1",
        [
            {"indicator_id": "indicator-1", "status": "expired"},
            {"indicator_id": "indicator-2"},
        ],
    )
    assert result == {
        "processed": 0,
        "created": 0,
        "updated": 0,
        "unchanged": 0,
        "errors": [
            {
                "indicatorId": "indicator-1",
                "message": "Unsupported deployment status: expired",
            },
            {
                "indicatorId": "indicator-2",
                "message": "Unsupported deployment status: None",
            },
        ],
    }
    assert local_api_client.query.call_count == 0
