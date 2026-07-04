# coding: utf-8
"""Tests for investigation tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import investigations

MOCK_WORKSPACE = {
    "id": "workspace--w1",
    "name": "Test Investigation",
    "type": "investigation",
    "investigated_entities_ids": [],
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.workspace.create.return_value = MOCK_WORKSPACE
    mock.workspace.read.return_value = MOCK_WORKSPACE
    mock.workspace.list.return_value = [MOCK_WORKSPACE]
    mock.workspace.add_investigated_entity.return_value = None
    mock.workspace.to_stix_bundle.return_value = '{"type":"bundle","id":"bundle--x"}'
    mock.workspace.add_from_container.return_value = MOCK_WORKSPACE
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestCreateInvestigation:
    def test_creates_workspace(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_investigation"].fn
            result = tool_fn(name="Test Investigation")
            data = json.loads(result)
            assert data["id"] == "workspace--w1"
            mock.workspace.create.assert_called_once()

    def test_error_propagated(self) -> None:
        mock = _mock_client()
        mock.workspace.create.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_investigation"].fn
            result = tool_fn(name="Bad")
            data = json.loads(result)
            assert "error" in data


class TestGetInvestigation:
    def test_returns_workspace(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_investigation"].fn
            result = tool_fn(investigation_id="workspace--w1")
            data = json.loads(result)
            assert data["name"] == "Test Investigation"

    def test_not_found(self) -> None:
        mock = _mock_client()
        mock.workspace.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_investigation"].fn
            result = tool_fn(investigation_id="missing")
            data = json.loads(result)
            assert "error" in data


class TestListInvestigations:
    def test_returns_list(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_investigations"].fn
            result = tool_fn()
            data = json.loads(result)
            assert isinstance(data, list)
            assert data[0]["id"] == "workspace--w1"


class TestAddToInvestigation:
    def test_returns_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["add_to_investigation"].fn
            result = tool_fn(investigation_id="workspace--w1", object_id="malware--m1")
            data = json.loads(result)
            assert data.get("success") is True


class TestExportInvestigationAsReport:
    def test_returns_bundle_string(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["export_investigation_as_report"].fn
            result = tool_fn(investigation_id="workspace--w1")
            # Should be a raw JSON string (not wrapped in another JSON)
            assert '"type":"bundle"' in result

    def test_export_failed_returns_error(self) -> None:
        mock = _mock_client()
        mock.workspace.to_stix_bundle.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["export_investigation_as_report"].fn
            result = tool_fn(investigation_id="workspace--w1")
            data = json.loads(result)
            assert "error" in data


class TestStartInvestigationFromContainer:
    def test_creates_from_container(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            investigations.register(mcp)
            tool_fn = mcp._tool_manager._tools["start_investigation_from_container"].fn
            result = tool_fn(container_id="report--r1")
            data = json.loads(result)
            assert data["id"] == "workspace--w1"
