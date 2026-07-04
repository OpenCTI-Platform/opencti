# coding: utf-8
"""Tests for search tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import search

MOCK_ENTITY = {
    "id": "malware--abc",
    "standard_id": "malware--abc",
    "entity_type": "Malware",
    "name": "TestMalware",
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.stix_core_object.list.return_value = [MOCK_ENTITY]
    mock.stix_core_object.read.return_value = MOCK_ENTITY
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestGlobalSearch:
    def test_returns_list(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["global_search"].fn
            result = tool_fn(query="TestMalware")
            data = json.loads(result)
            assert isinstance(data, list)
            assert data[0]["id"] == "malware--abc"

    def test_with_types_distributes_limit(self) -> None:
        """When types are specified limit should be distributed per type."""
        mock = _mock_client()
        mock.stix_core_object.list.return_value = []
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["global_search"].fn
            tool_fn(query="x", types=["Malware", "Indicator"], limit=20)
            # Each type call should use per_type = 20 // 2 = 10
            for c in mock.stix_core_object.list.call_args_list:
                _, kwargs = c
                assert kwargs["first"] == 10

    def test_with_types_total_capped(self) -> None:
        """Combined results from multiple types must not exceed limit."""
        mock = _mock_client()
        # Return 10 items per type
        mock.stix_core_object.list.return_value = [MOCK_ENTITY] * 10
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["global_search"].fn
            result = tool_fn(query="x", types=["Malware", "Indicator"], limit=10)
            data = json.loads(result)
            assert len(data) <= 10

    def test_clamps_limit(self) -> None:
        mock = _mock_client()
        mock.stix_core_object.list.return_value = []
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["global_search"].fn
            tool_fn(query="x", limit=9999)
            _, kwargs = mock.stix_core_object.list.call_args
            assert kwargs["first"] == 200

    def test_api_error_returns_empty_list(self) -> None:
        mock = _mock_client()
        mock.stix_core_object.list.side_effect = RuntimeError("network error")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["global_search"].fn
            result = tool_fn(query="x")
            data = json.loads(result)
            assert isinstance(data, list)
            assert data == []


class TestFindByStixId:
    def test_returns_entity(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["find_by_stix_id"].fn
            result = tool_fn(stix_id="malware--abc")
            data = json.loads(result)
            assert data["id"] == "malware--abc"

    def test_not_found_returns_error(self) -> None:
        mock = _mock_client()
        mock.stix_core_object.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["find_by_stix_id"].fn
            result = tool_fn(stix_id="malware--missing")
            data = json.loads(result)
            assert "error" in data

    def test_api_error_returns_json_error(self) -> None:
        mock = _mock_client()
        mock.stix_core_object.read.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["find_by_stix_id"].fn
            result = tool_fn(stix_id="malware--abc")
            data = json.loads(result)
            assert "error" in data


class TestFindByExternalReference:
    def test_returns_list(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            search.register(mcp)
            tool_fn = mcp._tool_manager._tools["find_by_external_reference"].fn
            result = tool_fn(source_name="MITRE ATT&CK", external_id="T1059")
            data = json.loads(result)
            assert isinstance(data, list)
