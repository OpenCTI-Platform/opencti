# coding: utf-8
"""Tests for case management tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import cases

MOCK_CASE = {
    "id": "case-incident--abc123",
    "standard_id": "case-incident--abc123",
    "entity_type": "Case-Incident",
    "name": "Test incident",
    "severity": "high",
    "priority": "P2",
}

MOCK_RFI = {
    "id": "case-rfi--def456",
    "standard_id": "case-rfi--def456",
    "entity_type": "Case-Rfi",
    "name": "RFI: Investigate domain",
    "priority": "P3",
}

MOCK_TASK = {
    "id": "task--ghi789",
    "standard_id": "task--ghi789",
    "entity_type": "Task",
    "name": "Triage logs",
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.case_incident.create.return_value = MOCK_CASE
    mock.case_incident.read.return_value = MOCK_CASE
    mock.case_incident.list.return_value = [MOCK_CASE]
    mock.case_rfi.create.return_value = MOCK_RFI
    mock.case_rfi.read.return_value = None
    mock.case_rfi.list.return_value = []
    mock.case_rft.read.return_value = None
    mock.case_rft.list.return_value = []
    mock.task.create.return_value = MOCK_TASK
    mock.task.update_field.return_value = MOCK_TASK
    mock.stix_domain_object.update_field.return_value = MOCK_CASE
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestCreateIncidentCase:
    def test_creates_case(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_incident_case"].fn
            result = tool_fn(name="Test incident", severity="high", priority="P2")
            data = json.loads(result)
            assert data["id"] == "case-incident--abc123"

    def test_error_propagated(self) -> None:
        mock = _mock_client()
        mock.case_incident.create.side_effect = ValueError("API error")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_incident_case"].fn
            result = tool_fn(name="Bad case")
            data = json.loads(result)
            assert "error" in data


class TestCreateRfi:
    def test_creates_rfi(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_rfi"].fn
            result = tool_fn(name="RFI: Investigate domain", priority="P3")
            data = json.loads(result)
            assert data["entity_type"] == "Case-Rfi"


class TestLookupCase:
    def test_finds_by_id(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_case"].fn
            result = tool_fn(name_or_id="case-incident--abc123")
            data = json.loads(result)
            assert data["id"] == "case-incident--abc123"

    def test_falls_back_to_search(self) -> None:
        mock = _mock_client()
        mock.case_incident.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_case"].fn
            result = tool_fn(name_or_id="Test incident")
            data = json.loads(result)
            assert isinstance(data, list)


class TestAddObjectToCase:
    def test_returns_simple_error_when_all_case_types_fail(self) -> None:
        mock = _mock_client()
        for case_api in (mock.case_incident, mock.case_rfi, mock.case_rft):
            case_api.add_stix_object_or_stix_relationship.side_effect = ValueError("api failure")

        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["add_object_to_case"].fn
            result = tool_fn(
                case_id="case-incident--abc123",
                object_id="indicator--abc123",
            )
            data = json.loads(result)
            assert data == {
                "error": "Could not add object to case: case ID may be invalid or inaccessible"
            }


class TestCreateTask:
    def test_creates_task(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_task"].fn
            result = tool_fn(name="Triage logs", case_id="case-incident--abc123")
            data = json.loads(result)
            assert data["entity_type"] == "Task"


class TestCompleteTask:
    def test_marks_complete(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            cases.register(mcp)
            tool_fn = mcp._tool_manager._tools["complete_task"].fn
            result = tool_fn(task_id="task--ghi789")
            data = json.loads(result)
            assert "error" not in data
            mock.task.update_field.assert_called_once()
            _, kwargs = mock.task.update_field.call_args
            assert kwargs["input"] == [{"key": "completed", "value": [True]}]
