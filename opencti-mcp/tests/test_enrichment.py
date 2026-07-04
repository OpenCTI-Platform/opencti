# coding: utf-8
"""Tests for enrichment tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import enrichment

MOCK_CONNECTORS = [
    {
        "id": "conn--1",
        "name": "AbuseIPDB",
        "connector_type": "INTERNAL_ENRICHMENT",
        "connector_scope": ["IPv4-Addr"],
        "active": True,
        "auto": True,
    },
    {
        "id": "conn--2",
        "name": "VirusTotal",
        "connector_type": "INTERNAL_ENRICHMENT",
        "connector_scope": ["StixFile", "IPv4-Addr", "Domain-Name"],
        "active": True,
        "auto": False,
    },
    {
        "id": "conn--3",
        "name": "ImportReport",
        "connector_type": "INTERNAL_IMPORT_FILE",
        "connector_scope": ["application/pdf"],
        "active": True,
        "auto": False,
    },
]

MOCK_WORK = {
    "id": "work--xyz",
    "name": "Enrichment (ipv4-addr--abc)",
    "status": "complete",
    "timestamp": "2024-01-01T00:00:00Z",
    "completed_time": "2024-01-01T00:01:00Z",
    "tracking": {"import_expected_number": 1, "import_processed_number": 1},
    "messages": [],
    "errors": [],
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.connector.list.return_value = MOCK_CONNECTORS
    mock.stix_cyber_observable.ask_for_enrichment.return_value = "work--xyz"
    mock.work.get_work.return_value = MOCK_WORK
    mock.stix_core_object.read.return_value = {
        "id": "ipv4-addr--abc",
        "standard_id": "ipv4-addr--abc",
        "entity_type": "IPv4-Addr",
    }
    mock.query.return_value = {"data": {"works": {"edges": [{"node": MOCK_WORK}]}}}
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestListEnrichmentConnectors:
    def test_returns_enrichment_connectors_only(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            enrichment.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_enrichment_connectors"].fn
            result = tool_fn()
            data = json.loads(result)
            assert isinstance(data, list)
            # ImportReport connector should be excluded
            names = [c["name"] for c in data]
            assert "ImportReport" not in names
            assert "AbuseIPDB" in names

    def test_filters_by_entity_type(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            enrichment.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_enrichment_connectors"].fn
            result = tool_fn(entity_type="StixFile")
            data = json.loads(result)
            names = [c["name"] for c in data]
            assert "VirusTotal" in names
            assert "AbuseIPDB" not in names


class TestEnrichEntity:
    def test_returns_work_id(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            enrichment.register(mcp)
            tool_fn = mcp._tool_manager._tools["enrich_entity"].fn
            result = tool_fn(entity_id="ipv4-addr--abc", connector_id="conn--1")
            data = json.loads(result)
            assert data.get("work_id") == "work--xyz"

    def test_error_returned_as_json(self) -> None:
        mock = _mock_client()
        mock.stix_cyber_observable.ask_for_enrichment.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            enrichment.register(mcp)
            tool_fn = mcp._tool_manager._tools["enrich_entity"].fn
            result = tool_fn(entity_id="ipv4-addr--abc")
            data = json.loads(result)
            assert "error" in data


class TestGetEnrichmentStatus:
    def test_returns_work_status(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            enrichment.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_enrichment_status"].fn
            result = tool_fn(work_id="work--xyz")
            data = json.loads(result)
            assert data["status"] == "complete"


class TestGetEntityConnectors:
    def test_returns_works_for_entity(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            enrichment.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_entity_connectors"].fn
            result = tool_fn(entity_id="ipv4-addr--abc")
            data = json.loads(result)
            assert isinstance(data, list)
            assert data[0]["status"] == "complete"
