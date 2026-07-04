# coding: utf-8
"""Tests for relationship tools."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import opencti_mcp.client as client_module
from opencti_mcp.tools import relationships

MOCK_REL = {
    "id": "relationship--r1",
    "entity_type": "stix-core-relationship",
    "relationship_type": "uses",
    "fromId": "threat-actor--ta1",
    "toId": "malware--m1",
}

MOCK_SIGHTING = {
    "id": "sighting--s1",
    "entity_type": "stix-sighting-relationship",
    "attribute_count": 3,
}


def _mock_client() -> MagicMock:
    mock = MagicMock()
    mock.stix_core_relationship.create.return_value = MOCK_REL
    mock.stix_core_relationship.list.return_value = [MOCK_REL]
    mock.stix_sighting_relationship.create.return_value = MOCK_SIGHTING
    return mock


def _patch_client(mock: MagicMock) -> AbstractContextManager[None]:
    return patch.object(client_module, "_client", mock)


class TestCreateRelationship:
    def test_creates_and_returns(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_relationship"].fn
            result = tool_fn(
                from_id="threat-actor--ta1",
                relationship_type="uses",
                to_id="malware--m1",
            )
            data = json.loads(result)
            assert data["id"] == "relationship--r1"

    def test_error_returned(self) -> None:
        mock = _mock_client()
        mock.stix_core_relationship.create.side_effect = RuntimeError("fail")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_relationship"].fn
            result = tool_fn(from_id="a", relationship_type="uses", to_id="b")
            data = json.loads(result)
            assert "error" in data


class TestLookupRelationships:
    def test_direction_both_returns_all(self) -> None:
        """With direction='both', results from both sides are included without truncation."""
        mock = _mock_client()
        from_rel = dict(MOCK_REL, id="relationship--from")
        to_rel = dict(MOCK_REL, id="relationship--to")
        mock.stix_core_relationship.list.side_effect = [[from_rel], [to_rel]]
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_relationships"].fn
            result = tool_fn(entity_id="threat-actor--ta1", limit=1)
            data = json.loads(result)
            # Both relationships must be present — limit applies per-direction
            ids = {r["id"] for r in data}
            assert "relationship--from" in ids
            assert "relationship--to" in ids

    def test_direction_from(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_relationships"].fn
            tool_fn(entity_id="threat-actor--ta1", direction="from")
            # Only one call (fromId)
            assert mock.stix_core_relationship.list.call_count == 1

    def test_direction_to(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_relationships"].fn
            tool_fn(entity_id="malware--m1", direction="to")
            assert mock.stix_core_relationship.list.call_count == 1

    def test_error_returns_json(self) -> None:
        mock = _mock_client()
        mock.stix_core_relationship.list.side_effect = RuntimeError("network error")
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["lookup_relationships"].fn
            result = tool_fn(entity_id="ta1")
            data = json.loads(result)
            assert "error" in data


class TestCreateSighting:
    def test_creates_sighting(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("test")
            relationships.register(mcp)
            tool_fn = mcp._tool_manager._tools["create_sighting"].fn
            result = tool_fn(
                observable_id="ipv4-addr--abc",
                target_id="identity--org1",
                count=3,
            )
            data = json.loads(result)
            assert data["id"] == "sighting--s1"
            mock.stix_sighting_relationship.create.assert_called_once()
