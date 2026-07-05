# coding: utf-8
"""Case management tools (incident response, RFIs, RFTs, tasks) for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register all case tools onto *mcp*."""

    # -------------------------------------------------------------------------
    # Incident cases
    # -------------------------------------------------------------------------

    @mcp.tool()
    def create_incident_case(
        name: str,
        severity: str = "low",
        priority: str = "P4",
        description: str | None = None,
        labels: list[str] | None = None,
        markings: list[str] | None = None,
        assignees: list[str] | None = None,
        object_ids: list[str] | None = None,
    ) -> str:
        """Create a new Incident Response case in OpenCTI.

        :param name: case name / title.
        :param severity: severity level — one of ``"low"``, ``"medium"``,
            ``"high"``, ``"critical"`` (default ``"low"``).
        :param priority: priority level — one of ``"P1"``, ``"P2"``, ``"P3"``,
            ``"P4"`` (default ``"P4"``).
        :param description: optional free-text description.
        :param labels: list of label IDs.
        :param markings: list of TLP marking definition IDs.
        :param assignees: list of user IDs to assign to the case.
        :param object_ids: list of entity IDs to link to the case at creation
            time.
        :return: JSON-encoded created case object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.case_incident.create(
                name=name,
                severity=severity,
                priority=priority,
                description=description,
                objectLabel=labels,
                objectMarking=markings,
                objectAssignee=assignees,
                objects=object_ids,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    # -------------------------------------------------------------------------
    # Request for Information (RFI)
    # -------------------------------------------------------------------------

    @mcp.tool()
    def create_rfi(
        name: str,
        priority: str = "P4",
        description: str | None = None,
        information_types: list[str] | None = None,
        labels: list[str] | None = None,
        markings: list[str] | None = None,
        assignees: list[str] | None = None,
    ) -> str:
        """Create a new Request for Information (RFI) case.

        :param name: RFI title.
        :param priority: priority level — ``"P1"``–``"P4"`` (default ``"P4"``).
        :param description: optional description of the information requested.
        :param information_types: list of information-type labels (e.g.
            ``["indicators", "ttps"]``).
        :param labels: list of label IDs.
        :param markings: list of TLP marking definition IDs.
        :param assignees: list of user IDs to assign.
        :return: JSON-encoded created RFI object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.case_rfi.create(
                name=name,
                priority=priority,
                description=description,
                information_types=information_types,
                objectLabel=labels,
                objectMarking=markings,
                objectAssignee=assignees,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    # -------------------------------------------------------------------------
    # Generic case operations
    # -------------------------------------------------------------------------

    @mcp.tool()
    def lookup_case(name_or_id: str, limit: int = 10) -> str:
        """Find any case (Incident / RFI / RFT) by name or ID.

        First attempts exact ID look-ups across all case types; falls back to
        free-text search.

        :param name_or_id: OpenCTI/STIX ID or name/keyword.
        :param limit: maximum results on keyword search (default 10).
        :return: JSON-encoded case object (ID match) or list of matching cases.
        """
        client = get_client()
        # Try incident
        for reader in (
            client.case_incident.read,
            client.case_rfi.read,
            client.case_rft.read,
        ):
            try:
                result = reader(id=name_or_id)
                if result is not None:
                    return json.dumps(result, default=str)
            except Exception:
                logger.debug("lookup_case: ID read attempt failed", exc_info=True)

        # Fall back to search across all types
        results: list[Any] = []
        for lister in (
            client.case_incident.list,
            client.case_rfi.list,
            client.case_rft.list,
        ):
            try:
                found = lister(search=name_or_id, first=limit)
                results.extend(found or [])
            except Exception:
                logger.debug("lookup_case: search attempt failed", exc_info=True)
        return json.dumps(results[:limit], default=str)

    @mcp.tool()
    def list_cases(
        case_type: str = "all",
        search: str | None = None,
        limit: int = 50,
    ) -> str:
        """List cases with optional type and keyword filters.

        :param case_type: ``"incident"``, ``"rfi"``, ``"rft"``, or ``"all"``
            (default ``"all"``).
        :param search: optional free-text search keyword.
        :param limit: maximum results per case type (1–200, default 50).
        :return: JSON-encoded list of case objects.
        """
        client = get_client()
        limit = max(1, min(limit, 200))
        results: list[Any] = []
        mapping = {
            "incident": [client.case_incident.list],
            "rfi": [client.case_rfi.list],
            "rft": [client.case_rft.list],
            "all": [client.case_incident.list, client.case_rfi.list, client.case_rft.list],
        }
        listers = mapping.get(case_type.lower(), mapping["all"])
        for lister in listers:
            try:
                found = lister(search=search, first=limit)
                results.extend(found or [])
            except Exception:
                logger.debug("list_cases: lister call failed", exc_info=True)
        return json.dumps(results[:limit], default=str)

    @mcp.tool()
    def add_object_to_case(case_id: str, object_id: str) -> str:
        """Link a STIX object or relationship to a case.

        The case type (incident / RFI / RFT) is detected automatically by
        trying each case API in turn.

        :param case_id: OpenCTI internal ID or STIX standard ID of the case.
        :param object_id: OpenCTI internal ID or STIX standard ID of the
            entity/relationship to add.
        :return: JSON with ``{"success": true}`` or ``{"error": …}``.
        """
        client = get_client()
        for adder_type in (client.case_incident, client.case_rfi, client.case_rft):
            try:
                adder_type.add_stix_object_or_stix_relationship(
                    id=case_id,
                    stixObjectOrStixRelationshipId=object_id,
                )
                return json.dumps({"success": True})
            except Exception:
                logger.debug("add_object_to_case: attempt failed", exc_info=True)
        return json.dumps(
            {"error": "Could not add object to case: case ID may be invalid or inaccessible"}
        )

    @mcp.tool()
    def update_case_status(case_id: str, status_id: str) -> str:
        """Update the workflow status of a case.

        Retrieve available status IDs from the OpenCTI platform's workflow
        configuration.  The status must already exist in the workflow for the
        relevant case type.

        :param case_id: OpenCTI internal ID.
        :param status_id: target workflow status ID.
        :return: JSON-encoded updated case object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.stix_domain_object.update_field(
                id=case_id,
                input=[{"key": "x_opencti_workflow_id", "value": [status_id]}],
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    # -------------------------------------------------------------------------
    # Tasks
    # -------------------------------------------------------------------------

    @mcp.tool()
    def create_task(
        name: str,
        case_id: str | None = None,
        description: str | None = None,
        assignees: list[str] | None = None,
        due_date: str | None = None,
    ) -> str:
        """Create a task, optionally linked to a case.

        :param name: task name.
        :param case_id: optional OpenCTI ID of the case to attach the task to.
        :param description: optional free-text description.
        :param assignees: list of user IDs to assign.
        :param due_date: ISO-8601 due date string (e.g.
            ``"2024-07-01T00:00:00Z"``).
        :return: JSON-encoded created task object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.task.create(
                name=name,
                description=description,
                objectAssignee=assignees,
                due_date=due_date,
                objects=[case_id] if case_id else None,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def complete_task(task_id: str) -> str:
        """Mark a task as completed.

        :param task_id: OpenCTI internal ID of the task.
        :return: JSON-encoded updated task object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.task.update_field(
                id=task_id,
                input=[{"key": "completed", "value": [True]}],
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
