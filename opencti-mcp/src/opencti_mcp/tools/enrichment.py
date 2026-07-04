# coding: utf-8
"""Enrichment tools for the OpenCTI MCP server."""

from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import get_client
from opencti_mcp.errors import safe_error_response

logger = logging.getLogger(__name__)

# GraphQL query used to retrieve recent works associated with a specific entity.
_ENRICHMENT_WORKS_QUERY = """
query EnrichmentWorks($filters: FilterGroup) {
    works(first: 50, filters: $filters, orderBy: timestamp, orderMode: desc) {
        edges {
            node {
                id
                name
                status
                timestamp
                completed_time
                tracking {
                    import_expected_number
                    import_processed_number
                }
                errors {
                    timestamp
                    message
                }
            }
        }
    }
}
"""


def register(mcp: FastMCP) -> None:
    """Register all enrichment tools onto *mcp*."""

    @mcp.tool()
    def list_enrichment_connectors(entity_type: str | None = None) -> str:
        """List active enrichment connectors available in this OpenCTI instance.

        :param entity_type: optional STIX type to filter connectors by scope
            (e.g. ``"IPv4-Addr"``, ``"Domain-Name"``).  When omitted all
            active enrichment connectors are returned.
        :return: JSON-encoded list of connector summaries (id, name,
            connector_scope, active).
        """
        client = get_client()
        try:
            all_connectors = client.connector.list()
            enrichment = [
                c
                for c in (all_connectors or [])
                if c.get("connector_type") == "INTERNAL_ENRICHMENT" and c.get("active", False)
            ]
            if entity_type:
                entity_type_lower = entity_type.lower()
                enrichment = [
                    c
                    for c in enrichment
                    if any(s.lower() == entity_type_lower for s in (c.get("connector_scope") or []))
                ]
            summaries = [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "connector_scope": c.get("connector_scope"),
                    "active": c.get("active"),
                    "auto": c.get("auto"),
                }
                for c in enrichment
            ]
            return json.dumps(summaries, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def enrich_entity(entity_id: str, connector_id: str | None = None) -> str:
        """Trigger enrichment connectors for a STIX cyber observable.

        This tool operates on **STIX Cyber Observables** (SCOs) only — e.g.
        IP addresses, domain names, file hashes, URLs.  To enrich other
        entity types (Malware, Threat Actor, etc.) use the enrichment
        connectors' native interfaces.

        When *connector_id* is omitted all compatible enrichment connectors
        for the observable's type are triggered automatically.

        :param entity_id: OpenCTI internal ID or STIX standard ID of the
            STIX Cyber Observable to enrich.
        :param connector_id: optional ID of a specific connector.  Use
            ``list_enrichment_connectors`` to discover valid IDs.
        :return: JSON object with ``work_id`` returned by the enrichment
            request, or ``{"error": …}``.
        """
        client = get_client()
        try:
            work_id = client.stix_cyber_observable.ask_for_enrichment(
                id=entity_id,
                connector_id=connector_id,
            )
            return json.dumps({"work_id": work_id}, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_enrichment_status(work_id: str) -> str:
        """Poll the status of an enrichment work job.

        :param work_id: work ID returned by ``enrich_entity`` or
            ``enrich_observable``.
        :return: JSON-encoded work status object with fields ``id``,
            ``status``, ``tracking`` (counts), ``messages``, and ``errors``;
            or ``{"error": …}``.
        """
        client = get_client()
        try:
            result = client.work.get_work(work_id=work_id)
            return json.dumps(result, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)

    @mcp.tool()
    def get_entity_connectors(entity_id: str) -> str:
        """List enrichment connectors that have run on a specific entity.

        Returns connector works associated with the entity, showing which
        connectors have processed it and their completion status.

        :param entity_id: OpenCTI internal ID or STIX standard ID.
        :return: JSON-encoded list of work objects, or ``{"error": …}``.
        """
        client = get_client()
        try:
            entity = client.stix_core_object.read(id=entity_id)
            if entity is None:
                return json.dumps({"error": "Entity not found"})
            # Fetch recent works filtered to this entity's standard_id
            standard_id = entity.get("standard_id") or entity_id
            filters = {
                "mode": "and",
                "filters": [{"key": "event_source_id", "values": [standard_id]}],
                "filterGroups": [],
            }
            result = client.query(_ENRICHMENT_WORKS_QUERY, {"filters": filters})
            edges = result.get("data", {}).get("works", {}).get("edges", [])
            works = [e["node"] for e in edges]
            return json.dumps(works, default=str)
        except Exception as exc:
            return safe_error_response(logger, __name__, exc)
