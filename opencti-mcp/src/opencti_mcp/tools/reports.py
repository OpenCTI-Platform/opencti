# coding: utf-8
"""Report tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register all report tools onto *mcp*."""

    @mcp.tool()
    def lookup_report(name_or_id: str, limit: int = 10) -> str:
        """Find a report by its name, ID, or a keyword search.

        First attempts an exact ID look-up; falls back to a free-text search
        against report names and descriptions.

        :param name_or_id: OpenCTI/STIX ID or a name / keyword.
        :param limit: maximum search results when falling back (default 10).
        :return: JSON-encoded report object (ID look-up) or list of matching
            report objects (search), or ``{"error": …}``.
        """
        client = get_client()
        # Try direct ID read first
        try:
            result = client.report.read(id=name_or_id)
            if result is not None:
                return json.dumps(result, default=str)
        except Exception:
            logger.debug("lookup_report: ID read failed, falling back to search", exc_info=True)
        # Fall back to free-text search
        try:
            results = client.report.list(search=name_or_id, first=limit)
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def list_reports(
        search: str | None = None,
        report_class: str | None = None,
        limit: int = 50,
    ) -> str:
        """List threat-intelligence reports with optional filtering.

        :param search: optional free-text search keyword.
        :param report_class: optional report type/class filter (e.g.
            ``"Threat Report"``, ``"Internal Report"``,
            ``"Malware Analysis"``).
        :param limit: maximum number of results (1–200, default 50).
        :return: JSON-encoded list of report objects.
        """
        client = get_client()
        limit = max(1, min(limit, 200))
        filters = None
        if report_class:
            filters = {
                "mode": "and",
                "filters": [{"key": "report_types", "values": [report_class]}],
                "filterGroups": [],
            }
        try:
            results = client.report.list(
                search=search,
                filters=filters,
                first=limit,
            )
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def create_report(
        name: str,
        published: str,
        description: str | None = None,
        report_types: list[str] | None = None,
        labels: list[str] | None = None,
        markings: list[str] | None = None,
        author_id: str | None = None,
        object_ids: list[str] | None = None,
    ) -> str:
        """Create a new threat-intelligence report in OpenCTI.

        :param name: report title.
        :param published: publication date as ISO-8601 string (e.g.
            ``"2024-06-15T00:00:00Z"``).
        :param description: optional free-text description / executive summary.
        :param report_types: list of report type labels (e.g.
            ``["threat-report"]``, ``["internal-report"]``).
        :param labels: list of label IDs to attach.
        :param markings: list of TLP marking definition IDs.
        :param author_id: OpenCTI ID of the authoring identity.
        :param object_ids: list of entity IDs to include in the report's
            object list from the start.
        :return: JSON-encoded created report object (with a ``failed_objects``
            key listing any IDs that could not be linked), or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.report.create(
                name=name,
                published=published,
                description=description,
                report_types=report_types,
                objectLabel=labels,
                objectMarking=markings,
                createdBy=author_id,
            )
            failed_objects: list[str] = []
            if result and object_ids:
                for oid in object_ids:
                    try:
                        client.report.add_stix_object_or_stix_relationship(
                            id=result["id"],
                            stixObjectOrStixRelationshipId=oid,
                        )
                    except Exception:
                        logger.debug(
                            f'"create_report: failed to add object {oid!r}"', exc_info=True
                        )
                        failed_objects.append(oid)
            if failed_objects:
                result = dict(result or {})
                result["failed_objects"] = failed_objects
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def add_object_to_report(report_id: str, object_id: str) -> str:
        """Link an existing STIX object or relationship to a report.

        :param report_id: OpenCTI internal ID or STIX standard ID of the
            report.
        :param object_id: OpenCTI internal ID or STIX standard ID of the
            entity/relationship to add.
        :return: JSON with ``{"success": true}`` or ``{"error": …}``.
        """
        client = get_client()
        try:
            client.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=object_id,
            )
            return json.dumps({"success": True})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_report_objects(report_id: str) -> str:
        """Return all STIX objects and relationships contained in a report.

        :param report_id: OpenCTI internal ID or STIX standard ID.
        :return: JSON-encoded list of contained objects (id, entity_type,
            name/observable_value), or ``{"error": …}``.
        """
        client = get_client()
        try:
            report = client.report.read(id=report_id)
            if report is None:
                return json.dumps({"error": "Report not found"})
            objects = report.get("objects", [])
            return json.dumps(objects, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def export_report_stix(report_id: str) -> str:
        """Export a report as a STIX 2.1 bundle JSON string.

        The bundle includes the report object and all its referenced STIX
        objects.

        :param report_id: OpenCTI internal ID or STIX standard ID.
        :return: STIX 2.1 bundle JSON string, or ``{"error": …}``.
        """
        client = get_client()
        try:
            stix = client.report.to_stix2(id=report_id)
            return stix if stix else json.dumps({"error": "Export failed"})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
