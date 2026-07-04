# coding: utf-8
"""Tests for report tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import reports

MOCK_REPORT = {
    "id": "report--r1",
    "standard_id": "report--r1",
    "entity_type": "Report",
    "name": "Threat Report Alpha",
    "published": "2024-01-15T00:00:00Z",
    "objects": [{"id": "malware--m1", "entity_type": "Malware", "name": "Foo"}],
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.report.read.return_value = MOCK_REPORT
    mock.report.list.return_value = [MOCK_REPORT]
    mock.report.create.return_value = MOCK_REPORT
    mock.report.add_stix_object_or_stix_relationship.return_value = None
    mock.report.to_stix2.return_value = '{"type":"bundle","id":"bundle--x"}'
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestLookupReport:
    def test_finds_by_id(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_report"].fn
            result = tool_fn(name_or_id="report--r1")
            data = json.loads(result)
            assert data["id"] == "report--r1"

    def test_falls_back_to_search(self) -> None:
        mock = _mock_client()
        mock.report.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_report"].fn
            result = tool_fn(name_or_id="Threat Report Alpha")
            data = json.loads(result)
            assert isinstance(data, list)


class TestCreateReport:
    def test_creates_report(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_report"].fn
            result = tool_fn(name="New Report", published="2024-06-01T00:00:00Z")
            data = json.loads(result)
            assert data["id"] == "report--r1"

    def test_failed_objects_reported(self) -> None:
        """Object link failures must be listed in failed_objects, not silently dropped."""
        mock = _mock_client()
        mock.report.add_stix_object_or_stix_relationship.side_effect = RuntimeError("link failed")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_report"].fn
            result = tool_fn(
                name="New Report",
                published="2024-06-01T00:00:00Z",
                object_ids=["malware--m1", "indicator--i1"],
            )
            data = json.loads(result)
            assert "failed_objects" in data
            assert "malware--m1" in data["failed_objects"]
            assert "indicator--i1" in data["failed_objects"]

    def test_no_failed_objects_key_on_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_report"].fn
            result = tool_fn(
                name="New Report",
                published="2024-06-01T00:00:00Z",
                object_ids=["malware--m1"],
            )
            data = json.loads(result)
            # No failures → failed_objects key absent (or empty list)
            assert data.get("failed_objects", []) == []


class TestAddObjectToReport:
    def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["add_object_to_report"].fn
            result = tool_fn(report_id="report--r1", object_id="malware--m1")
            data = json.loads(result)
            assert data.get("success") is True

    def test_error_returned(self) -> None:
        mock = _mock_client()
        mock.report.add_stix_object_or_stix_relationship.side_effect = RuntimeError("bad")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["add_object_to_report"].fn
            result = tool_fn(report_id="report--r1", object_id="malware--m1")
            data = json.loads(result)
            assert "error" in data


class TestGetReportObjects:
    def test_returns_objects(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_report_objects"].fn
            result = tool_fn(report_id="report--r1")
            data = json.loads(result)
            assert isinstance(data, list)
            assert data[0]["entity_type"] == "Malware"

    def test_not_found(self) -> None:
        mock = _mock_client()
        mock.report.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            reports.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_report_objects"].fn
            result = tool_fn(report_id="missing")
            data = json.loads(result)
            assert "error" in data
