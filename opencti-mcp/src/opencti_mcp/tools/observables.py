# coding: utf-8
"""Observable (IoC) tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Register all observable tools onto *mcp*."""

    @mcp.tool()
    def list_observables(
        search: str | None = None,
        observable_type: str | None = None,
        limit: int = 50,
    ) -> str:
        """Search and list STIX cyber observables with optional filtering.

        Covers all observable types: IP addresses, domain names, URLs, file
        hashes, email addresses, hostnames, cryptocurrency wallets, and more.

        :param search: optional free-text search keyword — can be an IP,
            domain, hash, URL, or any observable value fragment.
        :param observable_type: optional STIX type filter (e.g.
            ``"IPv4-Addr"``, ``"Domain-Name"``, ``"StixFile"``,
            ``"Email-Addr"``).  When omitted all types are searched.
        :param limit: maximum number of results to return (1–200, default 50).
        :return: JSON-encoded list of observable objects.
        """
        client = get_client()
        limit = max(1, min(limit, 200))
        try:
            results = client.stix_cyber_observable.list(
                types=[observable_type] if observable_type else None,
                search=search,
                first=limit,
            )
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_observable(observable_id: str) -> str:
        """Get full details of a single STIX cyber observable by its ID.

        :param observable_id: OpenCTI internal ID or STIX standard ID.
        :return: JSON-encoded observable object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.stix_cyber_observable.read(id=observable_id)
            if result is None:
                return json.dumps({"error": "Observable not found"})
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def add_observable(
        observable_key: str,
        observable_value: str,
        score: int = 50,
        description: str | None = None,
        labels: list[str] | None = None,
        markings: list[str] | None = None,
        create_indicator: bool = False,
    ) -> str:
        """Create a new STIX cyber observable in OpenCTI.

        Use the ``<Type>.<field>`` key format, e.g.:

        * ``"IPv4-Addr.value"`` / ``"1.2.3.4"``
        * ``"Domain-Name.value"`` / ``"evil.example.com"``
        * ``"Url.value"`` / ``"https://evil.example.com/payload"``
        * ``"Email-Addr.value"`` / ``"attacker@evil.com"``
        * ``"File.hashes.SHA-256"`` / ``"<sha256 hex>"``
        * ``"File.hashes.MD5"`` / ``"<md5 hex>"``
        * ``"File.name"`` / ``"malware.exe"``
        * ``"StixFile.name"`` — same as ``File.name``

        :param observable_key: STIX property key in ``<Type>.<field>`` format.
        :param observable_value: the raw observable value.
        :param score: threat score 0–100 (default 50).
        :param description: optional free-text description.
        :param labels: list of label IDs to attach.
        :param markings: list of TLP marking definition IDs.
        :param create_indicator: when ``True`` an indicator is automatically
            created and linked to this observable (default ``False``).
        :return: JSON-encoded created observable object, or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.stix_cyber_observable.create(
                simple_observable_key=observable_key,
                simple_observable_value=observable_value,
                simple_observable_description=description,
                x_opencti_score=score,
                objectLabel=labels,
                objectMarking=markings,
                createIndicator=create_indicator,
            )
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def enrich_observable(observable_id: str, connector_id: str | None = None) -> str:
        """Trigger enrichment connectors for a STIX cyber observable.

        When *connector_id* is omitted all active enrichment connectors
        compatible with the observable's type are triggered automatically.

        :param observable_id: OpenCTI internal ID or STIX standard ID.
        :param connector_id: optional ID of a specific enrichment connector to
            use.  List connectors with the ``list_enrichment_connectors`` tool.
        :return: JSON object with ``work_id`` (or list of work IDs) that can be
            polled with ``get_enrichment_status``, or ``{"error": …}``.
        """
        client = get_client()
        try:
            work_id = client.stix_cyber_observable.ask_for_enrichment(
                id=observable_id,
                connector_id=connector_id,
            )
            return json.dumps({"work_id": work_id}, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_observable_indicators(observable_id: str, limit: int = 50) -> str:
        """List indicators that are based on a specific observable.

        Returns all indicators linked to this observable via ``based-on``
        relationships.

        :param observable_id: OpenCTI internal ID or STIX standard ID.
        :param limit: maximum number of results to return (default 50).
        :return: JSON-encoded list of indicator objects.
        """
        client = get_client()
        try:
            results = client.stix_core_relationship.list(
                toId=observable_id,
                relationship_type="based-on",
                first=limit,
            )
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_observable_relationships(
        observable_id: str,
        limit: int = 50,
    ) -> str:
        """List all relationships attached to a STIX cyber observable.

        The *limit* applies independently to each direction (from / to), so
        the response may contain up to ``2 × limit`` relationships in total.

        :param observable_id: OpenCTI internal ID or STIX standard ID.
        :param limit: maximum number of relationships per direction (default 50).
        :return: JSON-encoded list of relationship objects.
        """
        client = get_client()
        try:
            from_rels = client.stix_core_relationship.list(fromId=observable_id, first=limit)
            to_rels = client.stix_core_relationship.list(toId=observable_id, first=limit)
            combined: list[Any] = []
            combined.extend(from_rels or [])
            combined.extend(to_rels or [])
            return json.dumps(combined, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
