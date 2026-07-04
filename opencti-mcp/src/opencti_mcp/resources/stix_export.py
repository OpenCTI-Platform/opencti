# coding: utf-8
"""MCP resources (read-only context) for STIX object export."""

from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register MCP resources for read-only STIX object context."""

    @mcp.resource("opencti://indicator/{indicator_id}")
    def indicator_resource(indicator_id: str) -> str:
        """Full indicator details including decay score and pattern.

        :param indicator_id: OpenCTI ID or STIX standard ID.
        :return: JSON-encoded indicator object.
        """
        client = get_client()
        try:
            result = client.indicator.read(id=indicator_id)
            return json.dumps(result, default=str) if result else json.dumps({"error": "Not found"})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.resource("opencti://observable/{observable_id}")
    def observable_resource(observable_id: str) -> str:
        """Full observable details including related indicators and sightings.

        :param observable_id: OpenCTI ID or STIX standard ID.
        :return: JSON-encoded observable object.
        """
        client = get_client()
        try:
            result = client.stix_cyber_observable.read(id=observable_id)
            return json.dumps(result, default=str) if result else json.dumps({"error": "Not found"})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.resource("opencti://report/{report_id}")
    def report_resource(report_id: str) -> str:
        """Full report with all contained objects.

        :param report_id: OpenCTI ID or STIX standard ID.
        :return: JSON-encoded report object.
        """
        client = get_client()
        try:
            result = client.report.read(id=report_id)
            return json.dumps(result, default=str) if result else json.dumps({"error": "Not found"})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.resource("opencti://case/{case_id}")
    def case_resource(case_id: str) -> str:
        """Full case (Incident/RFI/RFT) details including tasks and objects.

        :param case_id: OpenCTI ID or STIX standard ID.
        :return: JSON-encoded case object.
        """
        client = get_client()
        for reader in (
            client.case_incident.read,
            client.case_rfi.read,
            client.case_rft.read,
        ):
            try:
                result = reader(id=case_id)
                if result:
                    return json.dumps(result, default=str)
            except Exception:
                logger.debug("case_resource: reader attempt failed", exc_info=True)
        return json.dumps({"error": "Case not found"})

    @mcp.resource("opencti://investigation/{investigation_id}")
    def investigation_resource(investigation_id: str) -> str:
        """Investigation workspace as a STIX 2.1 bundle.

        :param investigation_id: OpenCTI workspace ID.
        :return: STIX 2.1 bundle JSON string.
        """
        client = get_client()
        try:
            bundle = client.workspace.to_stix_bundle(id=investigation_id)
            return bundle if bundle else json.dumps({"error": "Export failed"})
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
