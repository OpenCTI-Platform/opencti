# coding: utf-8
"""Relationship tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register all relationship tools onto *mcp*."""

    @mcp.tool()
    def create_relationship(
        from_id: str,
        relationship_type: str,
        to_id: str,
        description: str | None = None,
        start_time: str | None = None,
        stop_time: str | None = None,
        confidence: int | None = None,
        markings: list[str] | None = None,
    ) -> str:
        """Create a STIX core relationship between two entities.

        Common relationship types include:
        ``"uses"``, ``"indicates"``, ``"attributed-to"``,
        ``"targets"``, ``"mitigates"``, ``"related-to"``,
        ``"impersonates"``, ``"based-on"``.

        :param from_id: OpenCTI internal ID or STIX standard ID of the source
            entity.
        :param relationship_type: STIX relationship type string.
        :param to_id: OpenCTI internal ID or STIX standard ID of the target
            entity.
        :param description: optional description of the relationship.
        :param start_time: ISO-8601 start time (e.g. ``"2024-01-01T00:00:00Z"``).
        :param stop_time: ISO-8601 stop time.
        :param confidence: confidence level 0–100.
        :param markings: list of TLP marking definition IDs.
        :return: JSON-encoded created relationship object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                description=description,
                start_time=start_time,
                stop_time=stop_time,
                confidence=confidence,
                objectMarking=markings,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def lookup_relationships(
        entity_id: str,
        relationship_type: str | None = None,
        direction: str = "both",
        limit: int = 50,
    ) -> str:
        """List relationships attached to an entity.

        The *limit* applies independently per direction, so up to
        ``2 × limit`` relationships may be returned when *direction* is
        ``"both"``.

        :param entity_id: OpenCTI internal ID or STIX standard ID.
        :param relationship_type: optional filter on relationship type (e.g.
            ``"uses"``, ``"indicates"``).
        :param direction: ``"from"`` (entity is source), ``"to"`` (entity is
            target), or ``"both"`` (default).
        :param limit: maximum relationships per direction (default 50).
        :return: JSON-encoded list of relationship objects.
        """
        client = get_client()
        results: list[Any] = []
        try:
            if direction in ("from", "both"):
                from_rels = client.stix_core_relationship.list(
                    fromId=entity_id,
                    relationship_type=relationship_type,
                    first=limit,
                )
                results.extend(from_rels or [])
            if direction in ("to", "both"):
                to_rels = client.stix_core_relationship.list(
                    toId=entity_id,
                    relationship_type=relationship_type,
                    first=limit,
                )
                results.extend(to_rels or [])
            return json.dumps(results, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def create_sighting(
        observable_id: str,
        target_id: str,
        first_seen: str | None = None,
        last_seen: str | None = None,
        count: int = 1,
        confidence: int | None = None,
        description: str | None = None,
        markings: list[str] | None = None,
    ) -> str:
        """Record a STIX sighting relationship between an observable and a target.

        A sighting asserts that an observable was seen at a specific location
        (identity, sector, region, etc.).

        :param observable_id: OpenCTI internal ID or STIX standard ID of the
            observable or indicator that was sighted.
        :param target_id: OpenCTI internal ID or STIX standard ID of the
            target entity where the sighting occurred (e.g. an Organization or
            Identity).
        :param first_seen: ISO-8601 datetime when first observed.
        :param last_seen: ISO-8601 datetime when last observed.
        :param count: number of times the observable was sighted (default 1).
        :param confidence: confidence level 0–100.
        :param description: optional description.
        :param markings: list of TLP marking definition IDs.
        :return: JSON-encoded created sighting relationship, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.stix_sighting_relationship.create(
                fromId=observable_id,
                toId=target_id,
                first_seen=first_seen,
                last_seen=last_seen,
                attribute_count=count,
                confidence=confidence,
                description=description,
                objectMarking=markings,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
