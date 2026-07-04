# coding: utf-8
"""Shared pytest fixtures for the OpenCTI MCP test suite."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import opencti_mcp.client as client_module


@pytest.fixture()
def mock_client() -> MagicMock:
    """Return a MagicMock pre-wired with common client attributes.

    The mock is patched into ``opencti_mcp.client._client`` for the duration
    of each test.  Individual tests can override specific return values as
    needed before calling tool functions.
    """
    mock = MagicMock()
    with patch.object(client_module, "_client", mock):
        yield mock


def make_mcp():
    """Create a fresh FastMCP instance for tool registration."""
    from mcp.server.fastmcp import FastMCP

    return FastMCP("test")


def get_tool(mcp, name: str):
    """Return the raw callable for a registered tool by name."""
    return mcp._tool_manager._tools[name].fn
