# coding: utf-8
"""Tests for STIX export resources."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.resources import stix_export

MOCK_INDICATOR = {
    "id": "indicator--abc",
    "entity_type": "Indicator",
    "pattern": "[ipv4-addr:value = '1.2.3.4']",
}

MOCK_OBSERVABLE = {
    "id": "ipv4-addr--abc",
    "entity_type": "IPv4-Addr",
    "observable_value": "1.2.3.4",
}

MOCK_REPORT = {
    "id": "report--r1",
    "entity_type": "Report",
    "name": "Alpha",
    "objects": [],
}

MOCK_CASE = {
    "id": "case-incident--c1",
    "entity_type": "Case-Incident",
    "name": "Incident Alpha",
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.indicator.read.return_value = MOCK_INDICATOR
    mock.stix_cyber_observable.read.return_value = MOCK_OBSERVABLE
    mock.report.read.return_value = MOCK_REPORT
    mock.case_incident.read.return_value = MOCK_CASE
    mock.case_rfi.read.return_value = None
    mock.case_rft.read.return_value = None
    mock.workspace.to_stix_bundle.return_value = '{"type":"bundle","id":"bundle--x"}'
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestIndicatorResource:
    def test_returns_json(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://indicator/{indicator_id}"].fn
            result = resource_fn(indicator_id="indicator--abc")
            data = json.loads(result)
            assert data["id"] == "indicator--abc"

    def test_not_found(self) -> None:
        mock = _mock_client()
        mock.indicator.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://indicator/{indicator_id}"].fn
            result = resource_fn(indicator_id="missing")
            data = json.loads(result)
            assert "error" in data

    def test_api_error_returns_json_error(self) -> None:
        mock = _mock_client()
        mock.indicator.read.side_effect = RuntimeError("API down")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://indicator/{indicator_id}"].fn
            result = resource_fn(indicator_id="indicator--abc")
            data = json.loads(result)
            assert "error" in data


class TestObservableResource:
    def test_returns_json(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates[
                "opencti://observable/{observable_id}"
            ].fn
            result = resource_fn(observable_id="ipv4-addr--abc")
            data = json.loads(result)
            assert data["id"] == "ipv4-addr--abc"

    def test_api_error_returns_json_error(self) -> None:
        mock = _mock_client()
        mock.stix_cyber_observable.read.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates[
                "opencti://observable/{observable_id}"
            ].fn
            result = resource_fn(observable_id="ipv4-addr--abc")
            data = json.loads(result)
            assert "error" in data


class TestReportResource:
    def test_returns_json(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://report/{report_id}"].fn
            result = resource_fn(report_id="report--r1")
            data = json.loads(result)
            assert data["id"] == "report--r1"

    def test_api_error_returns_json_error(self) -> None:
        mock = _mock_client()
        mock.report.read.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://report/{report_id}"].fn
            result = resource_fn(report_id="report--r1")
            data = json.loads(result)
            assert "error" in data


class TestCaseResource:
    def test_returns_incident(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://case/{case_id}"].fn
            result = resource_fn(case_id="case-incident--c1")
            data = json.loads(result)
            assert data["id"] == "case-incident--c1"

    def test_not_found_returns_error(self) -> None:
        mock = _mock_client()
        mock.case_incident.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            stix_export.register(mcp)
            resource_fn = mcp._resource_manager._templates["opencti://case/{case_id}"].fn
            result = resource_fn(case_id="missing")
            data = json.loads(result)
            assert "error" in data
