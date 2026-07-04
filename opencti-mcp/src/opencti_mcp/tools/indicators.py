# coding: utf-8
"""Indicator tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register all indicator tools onto *mcp*."""

    @mcp.tool()
    def list_indicators(
        search: str | None = None,
        pattern_type: str | None = None,
        limit: int = 50,
    ) -> str:
        """Search and list indicators with optional filtering.

        Covers all use cases from a simple value look-up to a filtered list.

        :param search: optional free-text search keyword — can be an IP,
            domain, hash, URL, indicator name, or any partial STIX pattern
            fragment.
        :param pattern_type: optional filter on pattern type (e.g. ``"stix"``,
            ``"sigma"``, ``"yara"``).
        :param limit: maximum number of results to return (1–200, default 50).
        :return: JSON-encoded list of indicator objects.
        """
        client = get_client()
        limit = max(1, min(limit, 200))
        filters: dict[str, Any] | None = None
        if pattern_type:
            filters = {
                "mode": "and",
                "filters": [{"key": "pattern_type", "values": [pattern_type]}],
                "filterGroups": [],
            }
        try:
            results = client.indicator.list(
                search=search,
                filters=filters,
                first=limit,
            )
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_indicator(indicator_id: str) -> str:
        """Get full details of a single indicator by its OpenCTI or STIX ID.

        :param indicator_id: OpenCTI internal ID or STIX standard ID of the
            indicator (e.g. ``"indicator--4e11b23f-…"``).
        :return: JSON-encoded indicator object, or ``{"error": …}`` if not found.
        """
        client = get_client()
        try:
            result = client.indicator.read(id=indicator_id)
            if result is None:
                return json.dumps({"error": "Indicator not found"})
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def add_indicator(
        name: str,
        pattern: str,
        pattern_type: str,
        main_observable_type: str,
        valid_from: str | None = None,
        valid_until: str | None = None,
        score: int = 50,
        description: str | None = None,
        labels: list[str] | None = None,
        markings: list[str] | None = None,
    ) -> str:
        """Create a new STIX indicator in OpenCTI.

        :param name: human-readable name for the indicator.
        :param pattern: STIX pattern string (e.g.
            ``"[ipv4-addr:value = '1.2.3.4']"``).
        :param pattern_type: pattern language — one of ``"stix"``, ``"sigma"``,
            ``"yara"``, ``"snort"``, ``"tanium-signal"``, ``"spl"``.
        :param main_observable_type: the primary observable type this indicator
            represents (e.g. ``"IPv4-Addr"``, ``"Domain-Name"``,
            ``"StixFile"``).
        :param valid_from: ISO-8601 datetime string when the indicator becomes
            valid (e.g. ``"2024-01-01T00:00:00Z"``).  Defaults to now.
        :param valid_until: ISO-8601 datetime string when the indicator expires.
        :param score: threat score 0–100 (default 50).
        :param description: optional free-text description.
        :param labels: list of label IDs to attach.
        :param markings: list of TLP marking definition IDs to attach.
        :return: JSON-encoded created indicator object, or ``{"error": …}``
            on failure.
        """
        client = get_client()
        try:
            result = client.indicator.create(
                name=name,
                pattern=pattern,
                pattern_type=pattern_type,
                x_opencti_main_observable_type=main_observable_type,
                valid_from=valid_from,
                valid_until=valid_until,
                x_opencti_score=score,
                description=description,
                objectLabel=labels,
                objectMarking=markings,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def update_indicator(
        indicator_id: str,
        score: int | None = None,
        valid_until: str | None = None,
        revoked: bool | None = None,
        description: str | None = None,
    ) -> str:
        """Update one or more fields of an existing indicator.

        Only the fields you supply will be changed; omitted fields are left
        unchanged.

        :param indicator_id: OpenCTI internal ID or STIX standard ID.
        :param score: new threat score (0–100).
        :param valid_until: new expiry date as an ISO-8601 string.
        :param revoked: set to ``True`` to revoke the indicator.
        :param description: updated description text.
        :return: JSON-encoded updated indicator object, or ``{"error": …}``.
        """
        client = get_client()
        inputs: list[dict[str, Any]] = []
        if score is not None:
            inputs.append({"key": "x_opencti_score", "value": [str(score)]})
        if valid_until is not None:
            inputs.append({"key": "valid_until", "value": [valid_until]})
        if revoked is not None:
            # Pass the Python bool directly — do NOT convert to a string.
            inputs.append({"key": "revoked", "value": [revoked]})
        if description is not None:
            inputs.append({"key": "description", "value": [description]})
        if not inputs:
            return json.dumps({"error": "No fields to update were provided"})
        try:
            result = client.indicator.update_field(
                id=indicator_id,
                input=inputs,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def promote_observable_to_indicator(observable_id: str) -> str:
        """Promote an existing STIX cyber observable to a full indicator.

        OpenCTI will automatically create the corresponding STIX pattern and
        link the new indicator back to the observable via a ``based-on``
        relationship.

        :param observable_id: OpenCTI internal ID or STIX standard ID of the
            observable to promote.
        :return: JSON-encoded new indicator object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.stix_cyber_observable.promote_to_indicator_v2(id=observable_id)
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_indicator_relationships(indicator_id: str, limit: int = 50) -> str:
        """Fetch the relationships attached to an indicator.

        Typically returns ``indicates`` and ``based-on`` relationships, but
        all relationship types are included.

        :param indicator_id: OpenCTI internal ID or STIX standard ID.
        :param limit: maximum relationships to return (default 50).
        :return: JSON-encoded list of relationship objects.
        """
        client = get_client()
        try:
            results = client.stix_core_relationship.list(
                fromId=indicator_id,
                first=limit,
            )
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
