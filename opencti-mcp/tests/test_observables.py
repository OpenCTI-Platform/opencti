# coding: utf-8
"""Tests for observable tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import observables

MOCK_OBSERVABLE = {
    "id": "ipv4-addr--abc123",
    "standard_id": "ipv4-addr--abc123",
    "entity_type": "IPv4-Addr",
    "observable_value": "1.2.3.4",
}

MOCK_REL = {
    "id": "relationship--r1",
    "entity_type": "stix-core-relationship",
    "relationship_type": "related-to",
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.stix_cyber_observable.list.return_value = [MOCK_OBSERVABLE]
    mock.stix_cyber_observable.read.return_value = MOCK_OBSERVABLE
    mock.stix_cyber_observable.create.return_value = MOCK_OBSERVABLE
    mock.stix_cyber_observable.ask_for_enrichment.return_value = "work--xyz"
    mock.stix_core_relationship.list.return_value = [MOCK_REL]
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestListObservables:
    def test_returns_list(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_observables"].fn
            result = tool_fn(search="1.2.3.4")
            data = json.loads(result)
            assert isinstance(data, list)
            assert data[0]["observable_value"] == "1.2.3.4"

    def test_no_args_returns_list(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_observables"].fn
            result = tool_fn()
            data = json.loads(result)
            assert isinstance(data, list)

    def test_type_filter_applied(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_observables"].fn
            tool_fn(observable_type="IPv4-Addr")
            _, kwargs = mock.stix_cyber_observable.list.call_args
            assert kwargs["types"] == ["IPv4-Addr"]

    def test_clamps_limit(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_observables"].fn
            tool_fn(limit=9999)
            _, kwargs = mock.stix_cyber_observable.list.call_args
            assert kwargs["first"] == 200

    def test_error_returns_json(self) -> None:
        mock = _mock_client()
        mock.stix_cyber_observable.list.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["list_observables"].fn
            result = tool_fn(search="bad")
            data = json.loads(result)
            assert "error" in data


class TestGetObservable:
    def test_returns_observable(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_observable"].fn
            result = tool_fn(observable_id="ipv4-addr--abc123")
            data = json.loads(result)
            assert data["id"] == "ipv4-addr--abc123"

    def test_not_found(self) -> None:
        mock = _mock_client()
        mock.stix_cyber_observable.read.return_value = None
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_observable"].fn
            result = tool_fn(observable_id="missing")
            data = json.loads(result)
            assert "error" in data


class TestAddObservable:
    def test_creates_observable(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["add_observable"].fn
            result = tool_fn(observable_key="IPv4-Addr.value", observable_value="1.2.3.4")
            data = json.loads(result)
            assert data["id"] == "ipv4-addr--abc123"
            mock.stix_cyber_observable.create.assert_called_once()


class TestGetObservableRelationships:
    def test_returns_combined_both_directions(self) -> None:
        """Relationships from both directions are returned without truncation."""
        mock = _mock_client()
        from_rel = dict(MOCK_REL, id="relationship--from")
        to_rel = dict(MOCK_REL, id="relationship--to")
        mock.stix_core_relationship.list.side_effect = [[from_rel], [to_rel]]
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            observables.register(mcp)
            tool_fn = mcp._tool_manager._tools["get_observable_relationships"].fn
            result = tool_fn(observable_id="ipv4-addr--abc123", limit=1)
            data = json.loads(result)
            # Both directions are included — total may exceed the per-direction limit
            assert len(data) == 2
            ids = {r["id"] for r in data}
            assert "relationship--from" in ids
            assert "relationship--to" in ids
