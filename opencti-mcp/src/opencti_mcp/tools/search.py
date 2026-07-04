# coding: utf-8
"""Cross-entity search tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)

# Minimal attribute set for summary search results; keeps responses concise.
_SEARCH_CUSTOM_ATTRIBUTES = (
    "id standard_id entity_type "
    "... on StixDomainObject { name } "
    "... on StixCyberObservable { observable_value }"
)


def register(mcp: FastMCP) -> None:
    """Register all search tools onto *mcp*."""

    @mcp.tool()
    def global_search(query: str, types: list[str] | None = None, limit: int = 20) -> str:
        """Free-text search across all STIX entity types in OpenCTI.

        Use this to find any threat-intelligence object when you only have a
        keyword or partial name.  Returns a JSON list of matching entities with
        their id, entity_type, name/observable_value, and standard_id.

        :param query: search keyword or phrase.
        :param types: optional list of STIX type names to restrict the search
            (e.g. ``["Indicator", "Malware", "Report"]``).  When omitted all
            types are searched.
        :param limit: maximum number of results to return (1–200, default 20).
            When *types* is provided the budget is distributed evenly across
            each type so the combined result does not exceed *limit*.
        :return: JSON-encoded list of matching entity summaries.
        """
        client = get_client()
        limit = max(1, min(limit, 200))
        results: list[dict[str, Any]] = []

        if types:
            # Distribute the result budget evenly so total ≤ limit.
            per_type = max(1, limit // len(types))
            for entity_type in types:
                try:
                    raw = client.stix_core_object.list(
                        types=[entity_type],
                        search=query,
                        first=per_type,
                        customAttributes=_SEARCH_CUSTOM_ATTRIBUTES,
                    )
                    results.extend(raw or [])
                except Exception:
                    logger.debug(
                        f'"global_search: failed for type {entity_type!r}"',
                        exc_info=True,
                    )
        else:
            try:
                raw = client.stix_core_object.list(
                    search=query,
                    first=limit,
                    customAttributes=_SEARCH_CUSTOM_ATTRIBUTES,
                )
                results.extend(raw or [])
            except Exception:
                logger.debug("global_search: list call failed", exc_info=True)

        return json.dumps(results[:limit], default=str)

    @mcp.tool()
    def find_by_stix_id(stix_id: str) -> str:
        """Retrieve any OpenCTI entity by its STIX standard ID.

        Works for any STIX object type (indicators, observables, reports,
        cases, relationships, etc.).

        :param stix_id: STIX 2.1 standard ID (e.g.
            ``"indicator--4e11b23f-…"``).
        :return: JSON-encoded entity dict, or ``{"error": "Not found"}`` if the
            entity does not exist or is not accessible.
        """
        client = get_client()
        try:
            result = client.stix_core_object.read(id=stix_id)
            if result is None:
                return json.dumps({"error": "Not found"})
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def find_by_external_reference(source_name: str, external_id: str) -> str:
        """Look up an entity by external reference (e.g. a CVE ID or MITRE ATT&CK ID).

        :param source_name: the source system name (e.g. ``"MITRE ATT&CK"`` or
            ``"NVD"``)
        :param external_id: the identifier in the external system (e.g.
            ``"T1059"`` or ``"CVE-2024-1234"``).
        :return: JSON-encoded list of matching entities.
        """
        client = get_client()
        try:
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "externalReferences.source_name", "values": [source_name]},
                    {"key": "externalReferences.external_id", "values": [external_id]},
                ],
                "filterGroups": [],
            }
            results = client.stix_core_object.list(filters=filters, first=50)
            return json.dumps(results or [], default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
