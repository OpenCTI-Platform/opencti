# coding: utf-8
"""Investigation (workspace) tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register all investigation tools onto *mcp*."""

    @mcp.tool()
    def create_investigation(
        name: str,
        object_ids: list[str] | None = None,
        description: str | None = None,
    ) -> str:
        """Create a new Investigation workspace in OpenCTI.

        An investigation is a visual canvas that lets analysts map and link
        threat-intelligence entities interactively.

        :param name: investigation title.
        :param object_ids: list of entity IDs to pre-populate the canvas with.
        :param description: optional description.
        :return: JSON-encoded created workspace object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.workspace.create(
                type="investigation",
                name=name,
                description=description,
                investigated_entities_ids=object_ids or [],
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_investigation(investigation_id: str) -> str:
        """Retrieve details of an investigation workspace.

        :param investigation_id: OpenCTI internal ID of the workspace.
        :return: JSON-encoded workspace object including the list of
            investigated entity IDs, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.workspace.read(id=investigation_id)
            if result is None:
                return json.dumps({"error": "Investigation not found"})
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def list_investigations(search: str | None = None, limit: int = 50) -> str:
        """List investigation workspaces.

        :param search: optional free-text search keyword applied to workspace
            names.
        :param limit: maximum number of results (1–200, default 50).
        :return: JSON-encoded list of workspace objects.
        """
        client = get_client()
        limit = max(1, min(limit, 200))
        try:
            results = client.workspace.list(
                type="investigation",
                search=search,
                first=limit,
            )
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def add_to_investigation(investigation_id: str, object_id: str) -> str:
        """Add an entity to an investigation workspace canvas.

        :param investigation_id: OpenCTI internal ID of the workspace.
        :param object_id: OpenCTI internal ID or STIX standard ID of the
            entity to add.
        :return: JSON with ``{"success": true}`` or ``{"error": …}``.
        """
        client = get_client()
        try:
            client.workspace.add_investigated_entity(
                id=investigation_id,
                entity_id=object_id,
            )
            return json.dumps({"success": True})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def export_investigation_as_report(investigation_id: str) -> str:
        """Export an investigation workspace as a STIX 2.1 Report bundle.

        The bundle contains a STIX Report object with all investigated
        entities included as object references, along with the full STIX
        representation of each entity.

        :param investigation_id: OpenCTI internal ID of the workspace.
        :return: STIX 2.1 bundle JSON string, or ``{"error": …}``.
        """
        client = get_client()
        try:
            bundle = client.workspace.to_stix_bundle(id=investigation_id)
            return bundle if bundle else json.dumps({"error": "Export failed"})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def start_investigation_from_container(container_id: str) -> str:
        """Create a new investigation by pivoting from an existing container.

        Supported container types are Reports, Cases (Incident/RFI/RFT),
        and Groupings.  All objects from the container are copied into the
        new investigation's canvas.

        :param container_id: OpenCTI internal ID or STIX standard ID of the
            source container.
        :return: JSON-encoded new workspace object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.workspace.add_from_container(id=container_id)
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
